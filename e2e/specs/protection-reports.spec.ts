import { test, expect } from '../fixtures/app'

test('generate a report, download both formats, cancel deletion and then delete it', async ({ app }) => {
  const { page } = app
  await page.goto('/reports')
  const [created] = await Promise.all([
    page.waitForResponse(res => new URL(res.url()).pathname === '/api/v1/reports' && res.request().method() === 'POST'),
    page.getByRole('button', {name: '生成报告'}).click(),
  ])
  expect(created.ok()).toBeTruthy()
  const id = await created.json()
  expect(id).toMatch(/^[0-9a-f-]{36}$/i)
  const row = page.locator(`tr[data-report-id="${id}"]`)
  await expect(row.getByText('已生成')).toBeVisible({timeout: 90_000})
  for (const format of ['PDF', 'CSV']) {
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      row.getByRole('button', {name: `下载 ${format} 报告`}).click(),
    ])
    expect(download.suggestedFilename()).toBe(`pingwaf-${id}.${format.toLowerCase()}`)
    expect(await download.failure()).toBeNull()
  }
  await row.getByRole('button', {name: '删除报告'}).click()
  await page.getByRole('dialog').getByRole('button', {name: 'Cancel'}).click()
  await expect(row).toBeVisible()
  await row.getByRole('button', {name: '删除报告'}).click()
  await page.getByRole('dialog').getByRole('button', {name: '删除报告'}).click()
  await expect(row).toHaveCount(0)
  await Promise.all([
    page.waitForResponse(res => new URL(res.url()).pathname === '/api/v1/reports' && res.request().method() === 'GET' && res.ok()),
    page.reload(),
  ])
  await expect(page.getByText('正在加载报告任务…')).toBeHidden()
  await expect(row).toHaveCount(0)
})
