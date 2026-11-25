import { describe, expect, it } from 'vitest'
import { directoryPathError } from './directoryPath'

describe('directory selection', () => {
  it.each(['relative', '/srv/www-other', '/srv/www/../private', '/srv/www/bad\0path'])('rejects %s', path => {
    expect(directoryPathError(path, '/srv/www', true)).toBeTruthy()
  })

  it('allows the configured root for log buffers and requires a child for node directories', () => {
    expect(directoryPathError('/srv/www/', '/srv/www', true)).toBeUndefined()
    expect(directoryPathError('/srv/www/.', '/srv/www/', false)).toBeTruthy()
    expect(directoryPathError('/srv//www/./public', '/srv/www/', false)).toBeUndefined()
    expect(directoryPathError('/logs', '/', true)).toBeUndefined()
  })
})
