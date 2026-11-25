import { test, expect } from '../fixtures/app'

test('maintain a disabled ServerChan channel without exposing its SendKey', async ({ app }) => {
  const { page } = app
  const name = `ServerChan-${Date.now()}`
  await page.goto(app.adminUrl('/notifications'))
  await page.getByRole('button', { name: 'Add channel' }).first().click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Name', { exact: true }).fill(name)
  await dialog.getByLabel('Type', { exact: true }).selectOption('serverchan')
  await dialog.getByLabel('SendKey').fill('SCTisolatedtest')
  await dialog.getByRole('checkbox', { name: 'Enabled', exact: true }).uncheck()
  const created = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/notifications/channels'))
  await dialog.getByRole('button', { name: 'Create', exact: true }).click()
  const creation = await created
  expect(creation.ok()).toBe(true)
  const saved = await creation.json()
  expect(saved.config.send_key).toBe('__REDACTED__')
  const row = page.getByRole('row').filter({ hasText: name })
  await expect(row).toContainText('Disabled')
  for (const rotate of [false, true]) {
    await row.getByRole('button', { name: 'Edit' }).click()
    if (rotate) await dialog.getByLabel('SendKey').fill('sctp123tisolatedtest')
    const updated = page.waitForResponse(r => r.request().method() === 'PUT' && r.url().endsWith('/' + saved.id))
    await dialog.getByRole('button', { name: 'Save', exact: true }).click()
    const response = await updated
    expect(response.ok()).toBe(true)
    expect((await response.json()).config.send_key).toBe('__REDACTED__')
    await expect(dialog).toHaveCount(0)
  }
  await page.reload()
  await row.getByRole('button', { name: 'Delete' }).click()
  await dialog.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(row).toHaveCount(0)
})
