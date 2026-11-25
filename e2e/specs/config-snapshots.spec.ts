import { test, expect } from '../fixtures/app'

test('backup forms can select a later site and discard a cancelled upload preview', async ({ app }) => {
  const { page } = app
  const sites = Array.from({ length: 201 }, (_, index) => ({
    id: String(index + 1), domain: `site-${index + 1}.test`,
  }))
  await page.route('**/api/v1/sites?*', route => {
    const params = new URL(route.request().url()).searchParams
    const matches = sites.filter(site => site.domain.includes(params.get('search') ?? ''))
    const start = (Number(params.get('page') ?? 1) - 1) * 200
    return route.fulfill({ json: { items: matches.slice(start, start + 200), total: matches.length } })
  })
  await page.goto(app.adminUrl('/config-versions'))
  await page.getByLabel('Backup scope', { exact: true }).selectOption('site')
  const field = page.getByRole('group', { name: 'Site', exact: true })
  const site = field.getByRole('combobox')
  await field.getByRole('button', { name: 'Load more sites' }).click()
  await site.selectOption('201')
  await field.getByRole('searchbox').fill('site-101')
  await expect(site.locator('option')).toHaveCount(3)
  await expect(site).toHaveValue('201')

  const open = page.getByRole('button', { name: 'Upload backup file' })
  await open.click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Backup scope').selectOption('site')
  await dialog.getByRole('searchbox').fill('site-201')
  await dialog.getByRole('combobox', { name: 'Site', exact: true }).selectOption('201')
  await dialog.getByLabel('Backup password').fill('fixture-only-passphrase')
  await dialog.locator('input[type=file]').setInputFiles({
    name: 'fixture.pwb.json', mimeType: 'application/json', buffer: Buffer.from('{}'),
  })
  const uploadPath = '**/api/v1/config-backups/upload'
  let release!: () => void
  const gate = new Promise<void>(resolve => { release = resolve })
  await page.route(uploadPath, async route => {
    await gate
    await route.fulfill({ json: { backup: { id: 'old' }, preview: {
      tables: [], warnings: [], owner_changes: [], sites_to_remove: [],
    } } })
  })
  const request = page.waitForRequest(uploadPath)
  await dialog.getByRole('button', { name: 'Validate and preview' }).click()
  await request
  try {
    await dialog.getByRole('button', { name: 'Cancel' }).click()
    await open.click()
    const response = page.waitForResponse(uploadPath)
    release()
    await (await response).finished()
    await expect(dialog.getByRole('button', { name: 'Validate and preview' })).toBeDisabled()
    await expect(dialog.getByRole('button', { name: 'Confirm full replacement' })).toHaveCount(0)
  } finally {
    release()
  }
})

test('older snapshot batches use the last displayed ID and retain the list on failure', async ({ app }) => {
  const { page } = app
  let failOnce = true
  const snapshot = (id: number) => ({
    id, scope: 'site', site_id: '00000000-0000-0000-0000-000000000001',
    site_domain: `history-${id}.e2e.test`, config_hash: String(id),
    source: 'api', actor: null, summary: {}, created_at: '2026-11-25T12:00:00Z',
  })
  await page.route('**/api/v1/config-versions?*', async route => {
    const params = new URL(route.request().url()).searchParams
    if (params.has('site_id')) return route.fulfill({ json: [] })
    if (!params.has('before_id')) {
      return route.fulfill({ json: Array.from({ length: 51 }, (_, index) => snapshot(60 - index)) })
    }
    expect(params.get('before_id')).toBe('11')
    if (failOnce) {
      failOnce = false
      return route.fulfill({status:400,json:{error:{code:'bad_request',message:'Cannot load older snapshots'}}})
    }
    return route.fulfill({ json: Array.from({ length: 10 }, (_, index) => snapshot(10 - index)) })
  })
  await page.goto(app.adminUrl('/config-versions'))
  const more = page.getByRole('button', { name: 'Load older snapshots' })
  await more.click()
  await expect(page.getByText('Cannot load older snapshots', {exact:true}).first()).toBeVisible()
  await expect(page.getByText('history-60.e2e.test', { exact: true })).toBeVisible()
  await more.click()
  await expect(more).toHaveCount(0)
  const next = page.getByRole('button', { name:'Next', exact:true })
  await next.click()
  await next.click()
  const oldest = page.getByRole('row').filter({hasText:'history-1.e2e.test'})
  await oldest.getByRole('button', {name:'Delete snapshot'}).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText('history-1.e2e.test')
  await dialog.getByRole('button', {name:'Cancel'}).click()
  await page.getByRole('combobox', {name:'Scope', exact:true}).selectOption('global')
  await expect(oldest).toHaveCount(0)
})

test('refresh reconciles the visible snapshot page when the list shrinks', async ({ app }) => {
  const { page } = app
  let count = 50
  await page.route('**/api/v1/config-versions?*', route => route.fulfill({
    json: Array.from({ length: count }, (_, index) => ({
      id: index + 1, scope: 'global', site_id: null, site_domain: null,
      config_hash: String(index), source: 'api', actor: null, summary: {},
      created_at: '2026-11-25T12:00:00Z',
    })),
  }))
  await page.goto(app.adminUrl('/config-versions'))
  const next = page.getByRole('button', { name: 'Next', exact: true })
  const refresh = page.getByRole('button', { name: 'Refresh', exact: true })
  await next.click()
  await next.click()
  await expect(page.getByText('3 / 3', { exact: true })).toBeVisible()
  count = 21
  await refresh.click()
  await expect(page.getByText('2 / 2', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Previous', exact: true }).click()
  await expect(page.getByText('1 / 2', { exact: true })).toBeVisible()
  count = 50
  await refresh.click()
  await expect(page.getByText('1 / 3', { exact: true })).toBeVisible()
})

test('snapshot icons explain keyboard actions and delete only the selected history', async ({ app }) => {
  const { page } = app
  const domain = `snapshot-${Date.now()}.e2e.test`
  await app.createSite({ name: domain, domain, upstream: '127.0.0.1:18090' })
  try {
    await page.goto(app.adminUrl('/config-versions'))
    const row = page.getByRole('row').filter({ has: page.getByText(domain, { exact: true }) }).first()
    await expect(async () => {
      await page.getByRole('button', { name: 'Refresh', exact: true }).click()
      await expect(row).toBeVisible({ timeout: 2000 })
    }).toPass({ timeout: 20000 })
    const inspect = row.getByRole('button', { name: 'Inspect' })
    await inspect.focus()
    for (const label of ['Inspect', 'Roll back', 'Delete snapshot']) {
      const button = row.getByRole('button', { name: label, exact: true })
      await expect(button).toBeFocused()
      await expect(button).toHaveText('')
      const tip = page.getByRole('tooltip').filter({ hasText: label })
      await expect(tip).toBeVisible()
      expect(await tip.evaluate(el => {
        const box = el.getBoundingClientRect()
        const region = el.closest('[role="region"]')!.getBoundingClientRect()
        return box.left >= region.left && box.right <= region.right &&
          box.top >= region.top && box.bottom <= region.bottom
      })).toBe(true)
      await button.press('Escape')
      await expect(tip).toHaveCount(0)
      if (label !== 'Delete snapshot') await button.press('Tab')
    }
    await row.getByRole('button', { name: 'Delete snapshot' }).click()
    const dialog = page.getByRole('dialog', { name: /Delete version #/ })
    const title = await dialog.getByRole('heading').innerText()
    const id = title.match(/#(\d+)/)?.[1]
    expect(id).toBeTruthy()
    await expect(dialog.getByText(new RegExp(domain.replaceAll('.', '\\.')))).toBeVisible()
    await dialog.getByRole('button', { name: 'Cancel' }).click()
    await expect(row).toBeVisible()
    await row.getByRole('button', { name: 'Delete snapshot' }).click()
    const endpoint = `/api/v1/config-versions/${id}`
    await page.route(`**${endpoint}`, route => route.fulfill({
      status: 503,
      json: { error: { code: 'unavailable', message: 'Snapshot store temporarily unavailable' } },
    }), { times: 1 })
    const failed = page.waitForResponse(r => r.request().method() === 'DELETE' &&
      new URL(r.url()).pathname === endpoint)
    await dialog.getByRole('button', { name: 'Delete snapshot' }).click()
    expect((await failed).status()).toBe(503)
    await expect(dialog).toBeVisible()
    await expect(row).toBeAttached()
    const deleted = page.waitForResponse(r => r.request().method() === 'DELETE' &&
      new URL(r.url()).pathname === endpoint)
    await dialog.getByRole('button', { name: 'Delete snapshot' }).click()
    expect((await deleted).status()).toBe(204)
    await expect(dialog).toHaveCount(0)
    await page.reload()
    const refresh = page.getByRole('button', { name: 'Refresh', exact: true })
    await expect(refresh).toBeEnabled()
    const refreshed = page.waitForResponse(r => r.request().method() === 'GET' &&
      new URL(r.url()).pathname === '/api/v1/config-versions')
    await refresh.click()
    const rows = await (await refreshed).json()
    expect(rows.some((version: { id: number }) => String(version.id) === id)).toBe(false)
  } finally {
    await app.deleteSite(domain)
  }
})
