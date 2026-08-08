import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'

/**
 * src/lists.ts is the one definition of the two operator-editable lists, shared
 * by index.ts and server.ts (and, once someone routes it, mcp.ts). It is tested
 * directly here rather than only through its two callers, because the whole
 * point of extracting it was that a caller-only test proves the caller works —
 * not that both callers agree.
 *
 * node:fs is mocked so malformed and missing files can be forced without
 * touching the real data/ fixtures other agents rely on.
 */

/**
 * `undefined` forces ENOENT, the string `'real'` passes the read through to the
 * file that actually ships — anything else is served verbatim as the contents.
 */
const fsState = vi.hoisted(() => ({
  watchlist: undefined as string | undefined,
  denylist: undefined as string | undefined,
}))

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    readFileSync: (path: Parameters<typeof actual.readFileSync>[0], enc?: BufferEncoding) => {
      const p = String(path)
      const stub = p.includes('watchlist.json')
        ? fsState.watchlist
        : p.includes('denylist.json')
          ? fsState.denylist
          : 'real'
      if (stub === 'real') return actual.readFileSync(path, enc)
      if (stub === undefined) {
        throw Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT' })
      }
      return stub
    },
  }
})

async function load(): Promise<typeof import('../src/lists.js')> {
  return import('../src/lists.js')
}

beforeEach(() => {
  vi.resetModules()
  fsState.watchlist = JSON.stringify({
    '11155111': [{ address: '0xToken1111111111111111111111111111111111' }],
    '1': [{ address: '0xMainnetTokenBBBBBBBBBBBBBBBBBBBBBBBBBBBB' }],
  })
  fsState.denylist = JSON.stringify({
    addresses: [{ address: '0xSpenderAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }],
  })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('loadWatchlist', () => {
  it('returns only the addresses keyed under the requested chain id', async () => {
    const { loadWatchlist } = await load()

    expect(loadWatchlist(11155111)).toEqual(['0xToken1111111111111111111111111111111111'])
  })

  it('never leaks another chain’s tokens into a run', async () => {
    const { loadWatchlist } = await load()

    // The safety property the chain-id key exists for: a Sepolia run must not
    // be able to scan — and therefore revoke against — a mainnet token.
    expect(loadWatchlist(11155111)).not.toContain('0xMainnetTokenBBBBBBBBBBBBBBBBBBBBBBBBBBBB')
  })

  it('degrades to [] for a chain id the file says nothing about', async () => {
    const { loadWatchlist } = await load()

    expect(loadWatchlist(31337)).toEqual([])
  })

  it('degrades to [] when the file is missing', async () => {
    fsState.watchlist = undefined
    const { loadWatchlist } = await load()

    expect(loadWatchlist(11155111)).toEqual([])
  })

  it('degrades to [] rather than throwing when the file is malformed', async () => {
    // An operator's stray comma must not take down a running sentinel.
    fsState.watchlist = '{ not valid json'
    const { loadWatchlist } = await load()

    expect(() => loadWatchlist(11155111)).not.toThrow()
    expect(loadWatchlist(11155111)).toEqual([])
  })
})

describe('loadDenylist', () => {
  it('returns the addresses verbatim, without normalising case', async () => {
    const { loadDenylist } = await load()

    expect(loadDenylist()).toEqual(['0xSpenderAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'])
  })

  it('degrades to [] when the file parses but carries no addresses key', async () => {
    fsState.denylist = JSON.stringify({ updated: '2026-08-08' })
    const { loadDenylist } = await load()

    expect(loadDenylist()).toEqual([])
  })

  it('degrades to [] when the file is missing', async () => {
    fsState.denylist = undefined
    const { loadDenylist } = await load()

    expect(loadDenylist()).toEqual([])
  })

  it('degrades to [] rather than throwing when the file is malformed', async () => {
    fsState.denylist = '{ also not valid'
    const { loadDenylist } = await load()

    expect(() => loadDenylist()).not.toThrow()
    expect(loadDenylist()).toEqual([])
  })
})

describe('against the files that actually ship', () => {
  it('resolves data/ relative to src/lists.ts and reads the real lists', async () => {
    // Guards the extraction itself. `new URL('../data/…', import.meta.url)` is
    // resolved relative to the MODULE, so moving these loaders to a new file
    // could have pointed them at a directory that does not exist — and the
    // catch that correctly degrades a corrupt file to [] would have degraded
    // "the path is wrong" to [] just as quietly. A watcher with an empty
    // watchlist reports no threats and looks healthy doing it.
    fsState.watchlist = 'real'
    fsState.denylist = 'real'
    const { loadDenylist, loadWatchlist } = await load()

    expect(loadWatchlist(11155111)).toEqual(['0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb'])
    expect(loadDenylist()).toEqual(['0x8eBf8540EdE8e40CD94825C418758d4029D8892e'])
  })
})
