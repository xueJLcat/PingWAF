import { test, expect } from '../fixtures/app'
import { requiredEnv } from '../support/env'

const run = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
const originA = requiredEnv('E2E_ORIGIN_URL')
const originB = requiredEnv('E2E_ORIGIN_B_URL')

test.describe('multi-upstream and health handling', () => {
  test('a second origin can be added and the site keeps serving', async ({ app, request }) => {
    const domain = `upstream-${run}.e2e.test`
    const alternate = `upstream-alt-${run}.e2e.test`
    const siteId = await app.createSite({
      name: `E2E upstream ${run}`,
      domain,
      alternateDomains: [alternate],
      upstream: originA,
    })
    try {
      await app.waitForSite(domain)
      await app.page.goto(app.adminUrl(`/sites/${siteId}/basic`))
      await app.addNode(originB)
      await app.waitForSite(domain)
      const seen = new Set<string>()
      // An HTTP client issues exactly one request per probe. Browser favicon
      // fetches can consume every other turn of a two-node round robin.
      await expect.poll(async () => {
        for (const host of [domain, alternate]) {
          const response = await request.get(`http://${requiredEnv('E2E_EDGE_IP')}/`, {
            headers: { Host: host },
          })
          if (response.status() === 503) {
            seen.clear()
            return []
          }
          expect(response.status()).toBe(200)
          seen.add((await response.json()).origin)
        }
        return [...seen].sort()
      }, { timeout: 45_000, intervals: [1_000] }).toEqual(['a', 'b'])
      for (const host of [domain, alternate, domain, alternate]) {
        const response = await request.get(`http://${requiredEnv('E2E_EDGE_IP')}/`, { headers: { Host: host } })
        expect(response.status()).toBe(200)
        expect(['a', 'b']).toContain((await response.json()).origin)
      }
    } finally {
      await app.deleteSite(domain)
    }
  })
})
