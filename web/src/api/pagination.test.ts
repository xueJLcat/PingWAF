import { describe, expect, it, vi } from 'vitest'
import { readInventory } from './pagination'

describe('readInventory', () => {
  it('reads later pages at the server page size and deduplicates moving rows', async () => {
    const load = vi.fn(async (page: number) => ({
      items: (page === 1 ? ['a', 'b'] : ['b', 'c']).map(id => ({ id })),
      page, page_size: 2, total: 4,
    }))
    expect(await readInventory(load)).toEqual({ items: [{ id: 'a' }, { id: 'b' }, { id: 'c' }], total: 3 })
    expect(load.mock.calls).toEqual([[1], [2]])
  })

  it('stops on an empty or single page', async () => {
    for (const items of [[], [{ id: 'a' }]]) {
      const load = vi.fn(async () => ({ items, page: 1, page_size: 10, total: items.length }))
      expect((await readInventory(load)).items).toEqual(items)
      expect(load).toHaveBeenCalledTimes(1)
    }
  })

  it('propagates a later-page failure instead of reporting a partial inventory', async () => {
    await expect(readInventory(async page => {
      if (page === 2) throw new Error('second page unavailable')
      return { items: [{ id: 'a' }], page, page_size: 1, total: 2 }
    })).rejects.toThrow('second page unavailable')
  })
})
