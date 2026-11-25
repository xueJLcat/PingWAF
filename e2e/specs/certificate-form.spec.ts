import { test, expect } from '../fixtures/app'

test('selecting a site preserves the ACME application and its eligibility', async ({ app }) => {
  const { page } = app
  const sites = [
    { id: '00000000-0000-4000-8000-000000000001', domain: 'mixed.example', ingress_port: 81 },
    { id: '00000000-0000-4000-8000-000000000002', domain: 'standard.example', ingress_port: 80 },
  ].map(site => ({ ...site, name: site.domain, alternate_domains: [], ingress_protocol: 'http', additional_ingresses: ['https:443'] }))
  await page.route(url => url.pathname === '/api/v1/sites', route =>
    route.fulfill({ json: { items: sites, page: 1, page_size: 20, total: sites.length } }))
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
  await site.selectOption(sites[0].id)
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
  await expect(dialog.getByLabel('Domain', { exact: true })).toHaveValue(sites[1].domain)
  await page.route('**/api/v1/certificates', route => route.fulfill({
    status: 503, json: { error: { message: 'Isolated test' } },
  }))
  const sending = page.waitForRequest(r => r.method() === 'POST' && new URL(r.url()).pathname === '/api/v1/certificates')
  await apply.click()
  expect((await sending).postDataJSON()).toMatchObject({
    site_id: sites[1].id, domain: sites[1].domain, acme_email: 'operator@example.test', acme_challenge_type: 'dns-01',
  })
})
