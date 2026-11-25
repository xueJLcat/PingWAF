import { createSocket } from 'node:dgram'
import { once } from 'node:events'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test, expect } from '../fixtures/app'

test('remove a deleted site from a paused destination without losing the remaining site', async ({ app }) => {
  test.skip(process.env.PINGWAF_SMOKE_SYSLOG !== '1', 'Uses disposable sites and destination')
  const { page } = app
  const endpoint = app.adminUrl('/log-buffer')
  const stamp = Date.now()
  const kept = `syslog-keep-${stamp}.e2e.test`
  const removed = `syslog-gone-${stamp}.e2e.test`
  try {
    const keepId = await app.createSite({ name: kept, domain: kept, upstream: '127.0.0.1:18090' })
    const goneId = await app.createSite({ name: removed, domain: removed, upstream: '127.0.0.1:18090' })
    await page.goto(endpoint)
    await page.getByRole('button', { name: 'Configure forwarding' }).click()
    await page.getByLabel('Transport', {exact:true}).selectOption('udp')
    await page.getByLabel('Site scope').selectOption('selected')
    const search = page.getByLabel('Find sites')
    for (const domain of [kept, removed]) {
      await search.fill(domain)
      await page.getByRole('checkbox', { name: new RegExp(domain.replaceAll('.', '\\.')) }).check()
    }
    await page.getByRole('button', { name: 'Save and apply' }).click()
    await expect(page.getByText('Configuration saved', { exact: true })).toBeVisible()
    await app.deleteSite(removed)
    await page.goto(endpoint)
    for (const commit of [false, true]) {
      await page.getByRole('button', {name:'Edit', exact:true}).click()
      const lookup = !commit ? page.waitForResponse(r => {
        const url = new URL(r.url())
        return url.pathname === '/api/v1/sites' && url.searchParams.get('ids')?.includes(goneId) === true
      }) : undefined
      await page.getByText('2 selected', { exact: true }).click()
      if (lookup) {
        const resolved = await (await lookup).json()
        expect(resolved.items.map((site: { id: string }) => site.id)).toEqual([keepId])
      }
      await expect(page.getByRole('button', { name: new RegExp('Remove .*' + kept.replaceAll('.', '\\.')) })).toBeVisible()
      await page.getByRole('button', { name: `Remove ${goneId} from selection`, exact: true }).click()
      if (commit) {
        const saved = page.waitForResponse(r => r.url().endsWith('/settings/syslog') && r.request().method() === 'PUT')
        await page.getByRole('button', {name:'Save and apply'}).click()
        expect((await (await saved).json()).config.sites).toEqual([keepId])
      } else {
        await page.getByRole('button', { name:'Cancel', exact:true }).click()
      }
    }
    await page.reload()
    await page.getByRole('button', {name:'Edit', exact:true}).click()
    await page.getByText('1 selected', { exact: true }).click()
    await expect(page.getByRole('button', { name: new RegExp('Remove .*' + kept.replaceAll('.', '\\.')) })).toBeVisible()
    await page.getByRole('button', { name:'Cancel', exact:true }).click()
    await page.getByRole('button', {name:'Remove destination'}).click()
    await page.getByRole('dialog').getByRole('button',{name:'Confirm'}).click()
    await expect(page.getByRole('button',{name:'Configure forwarding'})).toBeVisible()
  } finally {
    await app.deleteSiteIfPresent(removed)
    await app.deleteSiteIfPresent(kept)
  }
})

test('maintain a log destination across desktop and mobile with a real UDP receiver', async ({ app }) => {
  test.skip(process.env.PINGWAF_SMOKE_SYSLOG !== '1', 'Requires disposable control plane and same loopback namespace')
  const { page } = app
  const socket = createSocket('udp4')
  socket.bind(0, '127.0.0.1')
  await once(socket, 'listening')
  const endpoint = app.adminUrl('/log-buffer')
  const files = mkdtempSync(join(tmpdir(), 'pingwaf-syslog-pem-'))
  try {
    await page.goto(endpoint)
    await expect(page.getByRole('heading', {name:'Log services', exact:true})).toBeVisible()
    const toggleTheme = page.getByRole('button', { name: 'Toggle theme', exact: true })
    for (const theme of ['light', 'dark']) {
      if (await page.locator('html').getAttribute('data-theme') !== theme) await toggleTheme.click()
      for (const title of ['Syslog forwarding', 'Elasticsearch log buffer directory']) {
        const heading = page.getByRole('heading', { name: title, exact: true })
        await expect(heading).toBeVisible()
        const contrast = await heading.evaluate(el => {
          function luminance(rgb: string) {
            const [r, g, b] = rgb.match(/[\d.]+/g)!.slice(0, 3).map(value => {
              const v = Number(value) / 255
              return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4
            })
            return 0.2126 * r + 0.7152 * g + 0.0722 * b
          }
          const surface = el.closest('.bg-elevated')!
          const text = luminance(getComputedStyle(el).color)
          const bg = luminance(getComputedStyle(surface).backgroundColor)
          return (Math.max(text, bg) + 0.05) / (Math.min(text, bg) + 0.05)
        })
        expect(contrast, title + ' in ' + theme).toBeGreaterThanOrEqual(4.5)
      }
    }
    await toggleTheme.click()
    await page.getByRole('button', {name:'Configure forwarding'}).click()
    const host = page.getByLabel('Server address', {exact:true})
    const transport = page.getByLabel('Transport', {exact:true})
    await transport.selectOption('udp')
    await expect(page.getByRole('spinbutton', {name:/^Port/})).toHaveValue('514')
    await host.fill('127.0.0.1')
    await page.getByRole('spinbutton', {name:/^Port/}).fill(String(socket.address().port))
    const received = once(socket,'message', {signal:AbortSignal.timeout(10000)})
    const testResponse = page.waitForResponse(r => r.url().endsWith('/settings/syslog/test') && r.request().method()==='POST')
    await page.getByRole('button',{name:'Test draft'}).click()
    const testId = (await (await testResponse).json()).id
    expect((await received)[0].toString()).toContain(testId)
    await page.getByRole('switch',{name:'Enable forwarding'}).click()
    const second = await page.context().newPage()
    await second.goto(endpoint)
    await second.getByRole('button',{name:'Configure forwarding'}).click()
    await second.getByLabel('Destination name').fill('Stale draft')
    await page.getByRole('button',{name:'Save and apply'}).click()
    await expect(page.getByText('Configuration saved', {exact:true})).toBeVisible()
    await second.getByRole('button',{name:'Save and apply'}).click()
    await expect(second.getByRole('alert').filter({hasText:/revision/})).toBeVisible()
    await expect(second.getByLabel('Destination name')).toHaveValue('Stale draft')
    await second.getByRole('button',{name:'Reload',exact:true}).click()
    await expect(second.getByLabel('Server address')).toHaveValue('127.0.0.1')
    await second.close()
    await page.setViewportSize({width:390,height:844})
    await page.reload()
    await page.getByRole('button',{name:'Edit',exact:true}).click()
    await page.getByRole('switch',{name:'Enable forwarding'}).click()
    await page.getByRole('button',{name:'Save and apply'}).click()
    await expect(page.getByText(/Paused.*UDP/)).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    await page.getByRole('button',{name:'Edit',exact:true}).click()
    await transport.selectOption('tls')
    await page.getByLabel('Server trust').selectOption('custom')
    await page.getByRole('switch',{name:'Use mutual TLS'}).click()
    const cert = join(files,'client.pem')
    const key = join(files,'client.key')
    for (const commonName of ['first','replacement']) {
      execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN='+commonName,'-keyout',key,'-out',cert],{stdio:'ignore'})
      await page.getByLabel('CA bundle (PEM)').setInputFiles(cert)
      await page.getByLabel('Client certificate chain (PEM)').setInputFiles(cert)
      await page.getByLabel('Client private key (unencrypted PEM)').setInputFiles(key)
      const updated=page.waitForResponse(r=>r.url().endsWith('/settings/syslog') && r.request().method()==='PUT')
      await page.getByRole('button',{name:'Save and apply'}).click()
      const result=await (await updated).json()
      expect(result.has_key).toBe(true)
      expect(JSON.stringify(result)).not.toContain('PRIVATE KEY')
      await page.getByRole('button',{name:'Edit',exact:true}).click()
      await expect(page.getByText(result.cert_info.sha256,{exact:false}).first()).toBeVisible()
    }
    await page.getByRole('button',{name:'Cancel',exact:true}).click()
    await page.getByRole('button',{name:'Remove destination'}).click()
    await page.getByRole('dialog').getByRole('button',{name:'Cancel'}).click()
    await page.getByRole('button',{name:'Remove destination'}).click()
    const other = await page.context().newPage()
    await other.goto(endpoint)
    await other.getByRole('button',{name:'Edit',exact:true}).click()
    await other.getByLabel('Destination name').fill('Updated by another administrator')
    const saveOther = other.waitForResponse(r=>r.url().endsWith('/settings/syslog') && r.request().method()==='PUT')
    await other.getByRole('button',{name:'Save and apply'}).click()
    const latest = await (await saveOther).json()
    await page.clock.setFixedTime(new Date(Date.now()+60_000))
    const refetched = page.waitForResponse(r=>r.url().endsWith('/settings/syslog') && r.request().method()==='GET', {timeout:15000})
    await page.bringToFront()
    await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange', {bubbles:true})))
    expect((await (await refetched).json()).revision).toBe(latest.revision)
    await expect(page.getByText(new RegExp('Saved / active revision '+latest.revision+' /'))).toBeAttached()
    const staleDelete = page.waitForResponse(r=>r.url().endsWith('/settings/syslog') && r.request().method()==='DELETE')
    await page.getByRole('dialog').getByRole('button',{name:'Confirm'}).click()
    expect((await staleDelete).status()).toBe(409)
    await page.getByRole('button',{name:'Reload',exact:true}).click()
    await page.getByRole('button',{name:'Remove destination'}).click()
    await expect(page.getByRole('dialog')).toContainText('Updated by another administrator')
    await other.close()
    await page.getByRole('dialog').getByRole('button',{name:'Confirm'}).click()
    await expect(page.getByRole('button',{name:'Configure forwarding'})).toBeVisible()
  } finally {
    socket.close()
    rmSync(files,{recursive:true,force:true})
  }
})
