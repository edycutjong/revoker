import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/**
 * index.ts calls `main().catch(...)` at module top level: importing it for
 * real launches the unattended watcher loop forever. ./watcher.js is mocked so
 * run()/scan() resolve immediately instead of looping, and ./config.js is
 * mocked so its getters don't demand real KH_* env vars. node:fs is partially
 * mocked (watchlist/denylist reads only) so missing/malformed-file handling
 * can be forced without touching the real data/ fixtures.
 */

interface CapturedWatcherOptions {
  owner: string
  tokens?: string[]
  denylist?: string[]
  dryRun?: boolean
}

const watcherMock = vi.hoisted(() => {
  const instances: { options: CapturedWatcherOptions }[] = []
  const run = vi.fn().mockResolvedValue(undefined)
  const scan = vi.fn().mockResolvedValue(undefined)
  const stop = vi.fn()
  class Watcher {
    options: CapturedWatcherOptions
    run = run
    scan = scan
    stop = stop
    constructor(options: CapturedWatcherOptions) {
      this.options = options
      instances.push(this)
    }
  }
  return { Watcher, instances, run, scan, stop }
})
vi.mock('../src/watcher.js', () => ({ Watcher: watcherMock.Watcher }))

const configMock = {
  walletAddress: '0x1234567890123456789012345678901234567890',
  network: 'sepolia',
  chainId: 11155111,
}
vi.mock('../src/config.js', () => ({ config: configMock }))

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
      if (p.includes('watchlist.json')) {
        if (fsState.watchlist === undefined) {
          throw Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT' })
        }
        return fsState.watchlist
      }
      if (p.includes('denylist.json')) {
        if (fsState.denylist === undefined) {
          throw Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT' })
        }
        return fsState.denylist
      }
      return actual.readFileSync(path, enc)
    },
  }
})

let dir: string
let originalArgv: string[]

async function flushMicrotasks(): Promise<void> {
  for (let i = 0; i < 5; i++) await Promise.resolve()
}

beforeEach(() => {
  vi.resetModules()
  watcherMock.instances.length = 0
  watcherMock.run.mockClear()
  watcherMock.run.mockResolvedValue(undefined)
  watcherMock.scan.mockClear()
  watcherMock.scan.mockResolvedValue(undefined)
  watcherMock.stop.mockClear()

  dir = mkdtempSync(join(tmpdir(), 'revoker-index-'))
  process.env['REVOKER_AUDIT_LOG'] = join(dir, 'audit.jsonl')

  fsState.watchlist = JSON.stringify({
    '11155111': [{ address: '0xToken1111111111111111111111111111111111' }],
  })
  fsState.denylist = JSON.stringify({
    addresses: [{ address: '0xSpenderAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }],
  })

  originalArgv = process.argv
  process.exitCode = undefined
  vi.spyOn(console, 'log').mockImplementation(() => undefined)
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
})

afterEach(() => {
  process.argv = originalArgv
  process.exitCode = undefined
  rmSync(dir, { recursive: true, force: true })
  delete process.env['REVOKER_AUDIT_LOG']
  process.removeAllListeners('SIGINT')
  process.removeAllListeners('SIGTERM')
  vi.restoreAllMocks()
})

describe('index.ts — argument parsing', () => {
  it('--once runs a single scan() and returns, without entering run()', async () => {
    process.argv = [...originalArgv, '--once']

    await import('../src/index.js')
    await flushMicrotasks()

    expect(watcherMock.scan).toHaveBeenCalledTimes(1)
    expect(watcherMock.run).not.toHaveBeenCalled()
  })

  it('without --once, it loops via run() and never calls scan() directly', async () => {
    await import('../src/index.js')
    await flushMicrotasks()

    expect(watcherMock.run).toHaveBeenCalledTimes(1)
    expect(watcherMock.scan).not.toHaveBeenCalled()
  })

  it('--dry-run reaches the Watcher constructor', async () => {
    process.argv = [...originalArgv, '--dry-run', '--once']

    await import('../src/index.js')
    await flushMicrotasks()

    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.dryRun).toBe(true)
  })

  it('defaults dryRun to false without the flag', async () => {
    process.argv = [...originalArgv, '--once']

    await import('../src/index.js')
    await flushMicrotasks()

    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.dryRun).toBe(false)
  })

  it('loads watchlist/denylist addresses into the Watcher for valid files', async () => {
    await import('../src/index.js')
    await flushMicrotasks()

    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.tokens).toEqual(['0xToken1111111111111111111111111111111111'])
    expect(instance?.options.denylist).toEqual(['0xSpenderAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'])
  })

  it('degrades to [] when watchlist/denylist files are missing', async () => {
    fsState.watchlist = undefined
    fsState.denylist = undefined

    await import('../src/index.js')
    await flushMicrotasks()

    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.tokens).toEqual([])
    expect(instance?.options.denylist).toEqual([])
  })

  it('degrades to [] when watchlist/denylist files contain malformed JSON', async () => {
    fsState.watchlist = '{ not valid json'
    fsState.denylist = '{ also not valid'

    await import('../src/index.js')
    await flushMicrotasks()

    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.tokens).toEqual([])
    expect(instance?.options.denylist).toEqual([])
  })

  it('degrades to [] when the denylist parses but carries no addresses key', async () => {
    fsState.denylist = JSON.stringify({ updated: '2026-08-08' })

    await import('../src/index.js')
    await flushMicrotasks()

    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.denylist).toEqual([])
    expect(instance?.options.tokens).toEqual(['0xToken1111111111111111111111111111111111'])
  })

  it('degrades to [] when the watchlist has no entry for the configured chainId', async () => {
    fsState.watchlist = JSON.stringify({
      '1': [{ address: '0xMainnetTokenBBBBBBBBBBBBBBBBBBBBBBBBBBBB' }],
    })

    await import('../src/index.js')
    await flushMicrotasks()

    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.tokens).toEqual([])
    expect(instance?.options.denylist).toEqual(['0xSpenderAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'])
  })
})

describe('index.ts — exit-code behaviour', () => {
  it('sets process.exitCode = 1 when the watcher loop rejects', async () => {
    watcherMock.run.mockRejectedValue(new Error('RPC exploded'))

    await import('../src/index.js')
    await flushMicrotasks()

    expect(process.exitCode).toBe(1)
  })

  it('stringifies a non-Error rejection into the fatal message', async () => {
    watcherMock.run.mockRejectedValue('RPC exploded, but nobody threw an Error')

    await import('../src/index.js')
    await flushMicrotasks()

    expect(console.error).toHaveBeenCalledWith('\nfatal: RPC exploded, but nobody threw an Error')
    expect(process.exitCode).toBe(1)
  })

  it('leaves exitCode unset on a clean --once run', async () => {
    process.argv = [...originalArgv, '--once']

    await import('../src/index.js')
    await flushMicrotasks()

    expect(process.exitCode).toBeUndefined()
  })
})

describe('index.ts — graceful shutdown', () => {
  it('SIGINT stops the watcher without forcing process.exit', async () => {
    await import('../src/index.js')
    await flushMicrotasks()

    const handler = process.listeners('SIGINT').at(-1) as (() => void) | undefined
    expect(handler).toBeDefined()
    handler?.()

    expect(watcherMock.stop).toHaveBeenCalledTimes(1)
  })
})
