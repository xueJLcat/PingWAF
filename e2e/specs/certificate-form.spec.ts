import { test, expect } from '../fixtures/app'

test('selecting a site preserves the ACME application and its eligibility', async ({ app }) => {
  const { page } = app
  const sites = [
    { id: '00000000-0000-4000-8000-000000000001', domain: 'mixed.example', ingress_port: 81 },
    { id: '00000000-0000-4000-8000-000000000002', domain: 'standard.example', ingress_port: 80 },
  ].map(site => ({ ...site, name: site.domain, alternate_domains: [], ingress_protocol: 'http', additional_ingresses: ['https:443'] }))
  await page.route(url => url.pathname === '/api/v1/sites', route => {
    const number = Number(new URL(route.request().url()).searchParams.get('page') ?? '1')
    return route.fulfill({ json: { items: sites.slice(number - 1, number), page: number, page_size: 1, total: sites.length } })
  })
  const issuerId = '00000000-0000-4000-8000-000000000007'
  await page.route(url => url.pathname === '/api/v1/agents', route => {
    const params = new URL(route.request().url()).searchParams
    const number = Number(params.get('page') ?? '1')
    if (params.get('site_id') !== sites[1].id) {
      return route.fulfill({ json: { items: [], page: number, page_size: 1, total: 0 } })
    }
    const agent = number === 2 ? { id: issuerId, hostname: 'later-issuer', acme_issuer: true }
      : { id: sites[0].id, hostname: 'consumer', acme_issuer: false }
    return route.fulfill({ json: { items: [agent], page: number, page_size: 1, total: 2 } })
  })
  await page.goto(app.adminUrl('/ssl'))
  await page.getByRole('button', { name: 'Apply or upload' }).first().click()
  const dialog = page.getByRole('dialog', { name: 'Apply for or upload a certificate' })
  const apply = dialog.getByRole('button', { name: 'Submit application' })
  const site = dialog.getByRole('combobox', { name: 'Site', exact: true })
  const email = dialog.getByLabel('ACME email')
  const acme = dialog.getByRole('tab', { name: /ACME/ })
  await expect(apply).toBeDisabled()
  await site.selectOption(sites[1].id)
  await expect(apply).toBeDisabled()
  await email.fill('operator@example.test')
  const challenge = dialog.getByLabel('Challenge type')
  await expect(challenge).toHaveValue('http-01')
  await challenge.selectOption('dns-01')
  await dialog.getByRole('combobox', { name: 'Issuer agent' }).selectOption(issuerId)
  await site.selectOption(sites[0].id)
  await expect(dialog.getByRole('combobox', { name: 'Issuer agent' })).toHaveValue('')
  await expect(acme).toHaveAttribute('aria-selected', 'true')
  await expect(dialog.getByRole('alert')).toContainText('HTTP 80 or HTTPS 443')
  await expect(apply).toBeDisabled()
  await dialog.getByRole('tab', { name: 'Manual upload' }).click()
  await expect(dialog.getByRole('button', { name: 'Upload certificate' })).toBeEnabled()
  await site.selectOption(sites[1].id)
  await expect(dialog.getByRole('tab', { name: 'Manual upload' })).toHaveAttribute('aria-selected', 'true')
  await acme.click()
  await site.selectOption(sites[0].id)
  await site.selectOption(sites[1].id)
  await expect(apply).toBeEnabled()
  await expect(email).toHaveValue('operator@example.test')
  await expect(challenge).toHaveValue('dns-01')
  await dialog.getByRole('combobox', { name: 'Issuer agent' }).selectOption(issuerId)
  await expect(dialog.getByLabel('Domain', { exact: true })).toHaveValue(sites[1].domain)
  await page.route('**/api/v1/certificates', route => route.fulfill({
    status: 503, json: { error: { message: 'Isolated test' } },
  }))
  const sending = page.waitForRequest(r => r.method() === 'POST' && new URL(r.url()).pathname === '/api/v1/certificates')
  await apply.click()
  expect((await sending).postDataJSON()).toMatchObject({
    acme_issuer_agent_id: issuerId,
    site_id: sites[1].id, domain: sites[1].domain, acme_email: 'operator@example.test', acme_challenge_type: 'dns-01',
  })
})

test('application log fetches the selected page and resets the page on filter change', async ({ app }) => {
  const { page } = app
  await page.setViewportSize({ width: 390, height: 844 })
  await page.route(url => url.pathname === '/api/v1/ssl-events', route => {
    const query = new URL(route.request().url()).searchParams
    const number = Number(query.get('page') ?? '1')
    const filtered = query.get('event_type') === 'failed'
    const event = {
      id: 'event-' + number, event_type: 'failed', created_at: new Date().toISOString(),
      message: (filtered ? 'Filtered' : 'Unfiltered') + ' result on page ' + number
        + (query.get('oldest_first') === 'true' ? ' ascending' : ''),
    }
    return route.fulfill({ json: { items: [event], page: number, page_size: 20, total: filtered ? 1 : 61 } })
  })
  await page.goto(app.adminUrl('/ssl'))
  const hint = page.getByText(/filter.*site.*status/i)
  await expect(hint).toBeVisible()
  expect((await hint.boundingBox())!.width).toBeGreaterThan(230)
  await page.getByRole('tab', { name: 'Application log' }).click()
  await page.getByRole('button', { name: '4', exact: true }).click()
  await expect(page.getByText('Unfiltered result on page 4')).toBeVisible()
  await page.getByRole('button', { name: /Time ↓/ }).click()
  await expect(page.getByText('Unfiltered result on page 1 ascending')).toBeVisible()
  await page.getByRole('combobox', { name: 'Event', exact: true }).selectOption('failed')
  await expect(page.getByText('Filtered result on page 1')).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
})
