import { test, expect } from '../fixtures/app'

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
  await page.getByRole('combobox', {name:/scope/i}).selectOption('global')
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
