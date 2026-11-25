import { test, expect } from '../fixtures/app'

test('site types line up in the table and stay with the identity on mobile', async ({ app }) => {
  const { page } = app
  const kinds = [
    [undefined, 'Reverse proxy'], ['zip', 'Static ZIP'],
    ['static', 'Static directory'], ['redirect', 'Redirect'],
  ] as const
  const sites = kinds.map(([kind], i) => ({
    id: `00000000-0000-4000-8000-00000000000${i + 1}`,
    name: `Layout site ${i + 1}`, domain: `layout-${i + 1}.example.test`,
    ...(kind && { site_handler: { kind } }),
    ingress_protocol: 'http', ingress_port: 81, status: 'active', alternate_domains: [],
    created_at: '2026-11-25T00:00:00Z',
  }))
  await page.route(url => url.pathname === '/api/v1/sites', route =>
    route.fulfill({ json: { items: sites, page: 1, page_size: 20, total: sites.length } }))
  await page.goto(app.adminUrl('/sites'))
  const table = page.getByRole('table')
  const header = table.getByRole('columnheader', { name: 'Site type' })
  await expect(header).toBeVisible()
  const typeColumn = await header.evaluate(el => (el as HTMLTableCellElement).cellIndex)
  const lefts: number[] = []
  for (const [i, [, label]] of kinds.entries()) {
    const row = table.getByRole('row').filter({ hasText: sites[i].domain })
    const cell = row.getByRole('cell').nth(typeColumn)
    await expect(cell).toHaveText(label)
    lefts.push(await cell.getByText(label, { exact: true }).evaluate(el => el.getBoundingClientRect().left))
    await expect(row.getByRole('link', { name: 'Page protection' })).toHaveCount(0)
  }
  expect(Math.max(...lefts) - Math.min(...lefts)).toBeLessThan(1)
  await expect(page.getByRole('navigation').getByRole('link', { name: 'Page protection' })).toBeVisible()
  await page.setViewportSize({ width: 390, height: 844 })
  for (const [i, [, label]] of kinds.entries()) {
    const card = page.getByRole('main').getByRole('listitem').filter({ hasText: sites[i].domain })
    const identity = card.getByRole('button', { name: new RegExp(sites[i].name) })
    const category = identity.getByText(label, { exact: true })
    await expect(category).toBeVisible()
    const bounds = await category.boundingBox()
    const name = await identity.getByText(sites[i].name, { exact: true }).boundingBox()
    expect(Math.abs(bounds!.x - name!.x)).toBeLessThan(1)
    await expect(card.getByRole('button', { name: 'Edit' })).toBeVisible()
    await expect(card.getByRole('link', { name: 'Page protection' })).toHaveCount(0)
  }
})
