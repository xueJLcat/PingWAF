import { test, expect } from '../fixtures/app'

test('sync one online node from its list and detail and wait for its receipt', async ({ app }) => {
  const { page } = app
  const listing = () => page.waitForResponse(r => r.request().method() === 'GET' &&
    new URL(r.url()).pathname === '/api/v1/agents')
  const before = listing()
  await page.goto(app.adminUrl('/agents'))
  type Node = { id: string; config_hash: string; manual_sync?: { requested_at: string; status: string }; last_config_sync_at: string | null }
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
  // A previous site test may still have a configuration change in flight.
  // The first confirmed receipt establishes the baseline for the unchanged replay.
  const confirmed = current.find(n => n.id === agent_id)!
  expect(confirmed.manual_sync?.status).toBe('confirmed')
  expect(confirmed.config_hash).toBeTruthy()
  expect(confirmed.last_config_sync_at).toBeTruthy()
  await row.focus()
  await row.press('Enter')
  const dialog = page.getByRole('dialog')
  const second = command()
  await dialog.getByRole('button', { name: 'Sync now' }).click()
  expect((await (await second).json()).agent_id).toBe(agent_id)
  await expect(dialog.getByText('Node confirmed configuration')).toBeVisible({ timeout: 60000 })
  await expect.poll(async () => {
    const refreshed = listing()
    await page.reload()
    const nodes: Node[] = (await (await refreshed).json()).items
    const replay = nodes.find(n => n.id === agent_id)!
    if (!replay.manual_sync || replay.manual_sync.requested_at === confirmed.manual_sync?.requested_at ||
        replay.manual_sync.status !== 'confirmed') return false
    expect(replay.config_hash).toBe(confirmed.config_hash)
    expect(replay.last_config_sync_at).toBe(confirmed.last_config_sync_at)
    for (const node of initial.filter(n => n.id !== agent_id)) {
      expect(nodes.find(n => n.id === node.id)!.manual_sync?.requested_at).toBe(node.manual_sync?.requested_at)
    }
    return true
  }, { timeout: 60000 }).toBe(true)
})
