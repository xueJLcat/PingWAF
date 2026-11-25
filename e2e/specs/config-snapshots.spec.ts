import { test, expect } from '../fixtures/app'

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
