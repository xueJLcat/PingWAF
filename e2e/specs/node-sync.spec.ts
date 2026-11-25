import { test, expect } from '../fixtures/app'

test('sync one online node from its list and detail and wait for its receipt', async ({ app }) => {
  const { page } = app
  const listing = () => page.waitForResponse(r => r.request().method() === 'GET' &&
    new URL(r.url()).pathname === '/api/v1/agents')
  const before = listing()
  await page.goto(app.adminUrl('/agents'))
  type Node = { id: string; manual_sync?: { requested_at: string }; last_config_sync_at: string | null }
  const initial: Node[] = (await (await before).json()).items
  const row = page.getByRole('row').filter({ has: page.getByRole('button', { name: 'Sync now' }) }).first()
  const button = row.getByRole('button', { name: 'Sync now' })
  await expect(button).toBeEnabled()
  const command = () => page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/commands'))
  const first = command()
  await button.click()
  const response = await first
  expect(response.status()).toBe(202)
  const { agent_id, delivered, queued } = await response.json()
  expect(delivered).toBe(true)
  expect(queued).toBe(false)
  await expect(row.getByText('Node confirmed configuration')).toBeVisible({ timeout: 60000 })
  const refreshed = listing()
  await page.reload()
  const current: Node[] = (await (await refreshed).json()).items
  for (const node of initial) {
    const latest = current.find(n => n.id === node.id)!
    if (node.id === agent_id) expect(latest.last_config_sync_at).toBe(node.last_config_sync_at)
    else expect(latest.manual_sync?.requested_at).toBe(node.manual_sync?.requested_at)
  }
  await row.focus()
  await row.press('Enter')
  const dialog = page.getByRole('dialog')
  const second = command()
  await dialog.getByRole('button', { name: 'Sync now' }).click()
  expect((await (await second).json()).agent_id).toBe(agent_id)
  await expect(dialog.getByText('Node confirmed configuration')).toBeVisible({ timeout: 60000 })
})
