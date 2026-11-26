import type { Page } from './types'

/** Collect inventory rows for controls that operate on the full filtered list. */
export async function readInventory<T extends { id: string }>(
  fetchPage: (page: number) => Promise<Page<T>>,
) {
  const rows = new Map<string, T>()
  for (let page = 1; ; page++) {
    const result = await fetchPage(page)
    if (result.page !== page || result.page_size < 1) {
      throw new Error('Invalid pagination response')
    }
    for (const item of result.items) rows.set(item.id, item)
    if (!result.items.length || page * result.page_size >= result.total) break
  }
  return { items: [...rows.values()], total: rows.size }
}
