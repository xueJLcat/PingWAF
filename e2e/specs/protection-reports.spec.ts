import { test, expect } from '../fixtures/app'

test('generate a report, download both formats, cancel deletion and then delete it', async ({ app }) => {
  const { page } = app
  await page.goto('/reports')
  await expect(page.getByText('正在加载报告任务…')).toBeHidden()
  const rows = page.locator('tr[data-report-id]')
  const before = await rows.evaluateAll(elements => elements.map(row => row.getAttribute('data-report-id')))
  await page.getByRole('button', {name: '生成报告'}).click()
  await expect(rows).toHaveCount(before.length + 1)
  const created = await rows.evaluateAll((elements, previous) =>
    elements.map(row => row.getAttribute('data-report-id')).filter(id => !previous.includes(id)), before)
  expect(created).toHaveLength(1)
  const row = page.locator(`tr[data-report-id="${created[0]}"]`)
  await expect(row.getByText('已生成')).toBeVisible({timeout: 90_000})
  for (const format of ['PDF', 'CSV']) {
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      row.getByRole('button', {name: `下载 ${format} 报告`}).click(),
    ])
    expect(download.suggestedFilename()).toBe(`pingwaf-${created[0]}.${format.toLowerCase()}`)
    expect(await download.failure()).toBeNull()
  }
  await row.getByRole('button', {name: '删除报告'}).click()
  await page.getByRole('dialog').getByRole('button', {name: 'Cancel'}).click()
  await expect(row).toBeVisible()
  await row.getByRole('button', {name: '删除报告'}).click()
  await page.getByRole('dialog').getByRole('button', {name: '删除报告'}).click()
  await expect(row).toHaveCount(0)
  await page.reload()
  await expect(rows).toHaveCount(before.length)
})
