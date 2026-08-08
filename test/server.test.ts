import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { EventEmitter } from 'node:events'
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'

/**
 * server.ts calls main() at module top level: importing it for real starts an
 * HTTP server and kicks off a Watcher. To test it without a real socket or an
 * infinite watcher loop, node:http is mocked so the request listener passed to
 * createServer() can be captured and invoked directly with synthetic req/res
 * objects — this also means "closing the server" needs no real handle, and no
 * listening port is ever bound. ./watcher.js and ./config.js are mocked so the
 * agent loop never runs and config getters never demand real env vars.
 *
 * node:fs is partially mocked: only the watchlist/denylist reads are
 * intercepted (so missing/malformed-file behaviour can be forced without
 * touching the real data/ fixtures other agents rely on); everything else,
 * including the real public/verify.html, passes through untouched.
 */

interface CapturedWatcherOptions {
  owner: string
  tokens?: string[]
  denylist?: string[]
  dryRun?: boolean
}

const httpMock = vi.hoisted(() => {
  const serverInstance = {
    listen: vi.fn((_port: number, cb?: () => void) => {
      cb?.()
      return serverInstance
    }),
    close: vi.fn((cb?: () => void) => {
      cb?.()
      return serverInstance
    }),
  }
  let listener: ((req: IncomingMessage, res: ServerResponse) => void) | undefined
  const createServer = vi.fn((l: (req: IncomingMessage, res: ServerResponse) => void) => {
    listener = l
    return serverInstance
  })
  return {
    createServer,
    serverInstance,
    getListener: () => listener,
    reset: () => {
      listener = undefined
      serverInstance.listen.mockClear()
      serverInstance.close.mockClear()
      createServer.mockClear()
    },
  }
})
vi.mock('node:http', () => ({ createServer: httpMock.createServer }))

const watcherMock = vi.hoisted(() => {
  const instances: { options: CapturedWatcherOptions }[] = []
  const run = vi.fn().mockResolvedValue(undefined)
  const stop = vi.fn()
  class Watcher {
    options: CapturedWatcherOptions
    run = run
    stop = stop
    constructor(options: CapturedWatcherOptions) {
      this.options = options
      instances.push(this)
    }
  }
  return { Watcher, instances, run, stop }
})
vi.mock('../src/watcher.js', () => ({ Watcher: watcherMock.Watcher }))

const configMock = {
  walletAddress: '0x1234567890123456789012345678901234567890',
  network: 'sepolia',
  chainId: 11155111,
  explorerBase: 'https://sepolia.etherscan.io',
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

function makeReq(url?: string): IncomingMessage {
  const emitter = new EventEmitter()
  return Object.assign(emitter, { url }) as unknown as IncomingMessage
}

function makeRes(write?: ReturnType<typeof vi.fn>): {
  writeHead: ReturnType<typeof vi.fn>
  write: ReturnType<typeof vi.fn>
  end: ReturnType<typeof vi.fn>
} {
  return {
    writeHead: vi.fn(),
    write: write ?? vi.fn(),
    end: vi.fn(),
  }
}

let dir: string
let originalArgv: string[]

beforeEach(() => {
  vi.resetModules()
  httpMock.reset()
  watcherMock.instances.length = 0
  watcherMock.run.mockClear()
  watcherMock.stop.mockClear()

  dir = mkdtempSync(join(tmpdir(), 'revoker-server-'))
  process.env['REVOKER_AUDIT_LOG'] = join(dir, 'audit.jsonl')
  process.env['PORT'] = '0'

  fsState.watchlist = JSON.stringify({
    '11155111': [{ address: '0xToken1111111111111111111111111111111111' }],
  })
  fsState.denylist = JSON.stringify({
    addresses: [{ address: '0xSpenderAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }],
  })

  originalArgv = process.argv
  vi.spyOn(console, 'log').mockImplementation(() => undefined)
})

afterEach(() => {
  process.argv = originalArgv
  rmSync(dir, { recursive: true, force: true })
  delete process.env['REVOKER_AUDIT_LOG']
  delete process.env['PORT']
  process.removeAllListeners('SIGINT')
  process.removeAllListeners('SIGTERM')
  vi.restoreAllMocks()
})

async function loadServer(): Promise<
  (req: IncomingMessage, res: ServerResponse) => void
> {
  await import('../src/server.js')
  const listener = httpMock.getListener()
  if (!listener) throw new Error('server.ts did not call createServer()')
  return listener
}

describe('server.ts — startup', () => {
  it('binds the http server and starts the watcher (real server instance, closeable)', async () => {
    await loadServer()

    expect(httpMock.serverInstance.listen).toHaveBeenCalledTimes(1)
    expect(watcherMock.run).toHaveBeenCalledTimes(1)

    // The instance is the real fake returned by createServer(); prove it is
    // closeable so a suite built around it can exit cleanly.
    httpMock.serverInstance.close()
    expect(httpMock.serverInstance.close).toHaveBeenCalledTimes(1)
  })

  it('listens on $PORT when it is set', async () => {
    process.env['PORT'] = '4321'

    await loadServer()

    expect(httpMock.serverInstance.listen).toHaveBeenCalledWith(4321, expect.any(Function))
    const logged = vi.mocked(console.log).mock.calls.map((c: unknown[]) => String(c[0]))
    expect(logged).toContain('  http://localhost:4321/verify')
  })

  it('falls back to port 3000 when $PORT is unset', async () => {
    delete process.env['PORT']

    await loadServer()

    expect(httpMock.serverInstance.listen).toHaveBeenCalledWith(3000, expect.any(Function))
    const logged = vi.mocked(console.log).mock.calls.map((c: unknown[]) => String(c[0]))
    expect(logged).toContain('  http://localhost:3000/verify')
  })

  it('loads watchlist/denylist addresses into the Watcher for a valid, well-formed file', async () => {
    await loadServer()

    const instance = watcherMock.instances.at(-1)
    expect(instance).toBeDefined()
    expect(instance?.options.tokens).toEqual(['0xToken1111111111111111111111111111111111'])
    expect(instance?.options.denylist).toEqual(['0xSpenderAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'])
  })

  it('degrades to [] when watchlist/denylist files are missing', async () => {
    fsState.watchlist = undefined
    fsState.denylist = undefined

    await loadServer()

    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.tokens).toEqual([])
    expect(instance?.options.denylist).toEqual([])
  })

  it('degrades to [] when watchlist/denylist files contain malformed JSON', async () => {
    fsState.watchlist = '{ not valid json'
    fsState.denylist = '{ also not valid'

    await loadServer()

    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.tokens).toEqual([])
    expect(instance?.options.denylist).toEqual([])
  })

  it('degrades to [] when the files parse but hold nothing for this chain', async () => {
    // Well-formed JSON, wrong shape: a mainnet-only watchlist and a denylist
    // with no `addresses` key at all. Neither may leak into a sepolia run.
    fsState.watchlist = JSON.stringify({
      '1': [{ address: '0xMainnetOnly11111111111111111111111111111' }],
    })
    fsState.denylist = JSON.stringify({ version: 1 })

    await loadServer()

    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.tokens).toEqual([])
    expect(instance?.options.denylist).toEqual([])
  })

  it('propagates --dry-run into meta.dryRun and into the Watcher', async () => {
    process.argv = [...originalArgv, '--dry-run']
    const listener = await loadServer()

    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.dryRun).toBe(true)

    const req = makeReq('/api/meta')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const body = res.end.mock.calls[0]?.[0] as string
    expect(JSON.parse(body)).toMatchObject({ dryRun: true })
  })

  it('defaults dryRun to false without the flag', async () => {
    const listener = await loadServer()
    const instance = watcherMock.instances.at(-1)
    expect(instance?.options.dryRun).toBe(false)

    const req = makeReq('/api/meta')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const body = res.end.mock.calls[0]?.[0] as string
    expect(JSON.parse(body)).toMatchObject({ dryRun: false })
  })
})

describe('server.ts — routing', () => {
  it('GET / returns the dashboard HTML', async () => {
    const listener = await loadServer()
    const req = makeReq('/')
    const res = makeRes()

    listener(req, res as unknown as ServerResponse)

    expect(res.writeHead).toHaveBeenCalledWith(200, { 'Content-Type': 'text/html; charset=utf-8' })
    const body = res.end.mock.calls[0]?.[0] as string
    expect(body).toContain('<!doctype html>')
  })

  it('GET /verify returns the same dashboard HTML as /', async () => {
    const listener = await loadServer()
    const req = makeReq('/verify')
    const res = makeRes()

    listener(req, res as unknown as ServerResponse)

    expect(res.writeHead).toHaveBeenCalledWith(200, { 'Content-Type': 'text/html; charset=utf-8' })
    const realHtml = readFileSync(new URL('../public/verify.html', import.meta.url), 'utf8')
    expect(res.end).toHaveBeenCalledWith(realHtml)
  })

  it('GET /api/meta returns the expected JSON shape', async () => {
    const listener = await loadServer()
    const req = makeReq('/api/meta')
    const res = makeRes()

    listener(req, res as unknown as ServerResponse)

    expect(res.writeHead).toHaveBeenCalledWith(200, { 'Content-Type': 'application/json' })
    const body = res.end.mock.calls[0]?.[0] as string
    expect(JSON.parse(body)).toEqual({
      wallet: configMock.walletAddress,
      network: configMock.network,
      chainId: configMock.chainId,
      explorer: configMock.explorerBase,
      dryRun: false,
    })
  })

  it('a request with no url is treated as / and returns the dashboard HTML', async () => {
    const listener = await loadServer()
    const req = makeReq()
    const res = makeRes()

    listener(req, res as unknown as ServerResponse)

    expect(res.writeHead).toHaveBeenCalledWith(200, { 'Content-Type': 'text/html; charset=utf-8' })
    const realHtml = readFileSync(new URL('../public/verify.html', import.meta.url), 'utf8')
    expect(res.end).toHaveBeenCalledWith(realHtml)
  })

  it('an unknown path returns 404', async () => {
    const listener = await loadServer()
    const req = makeReq('/nope')
    const res = makeRes()

    listener(req, res as unknown as ServerResponse)

    expect(res.writeHead).toHaveBeenCalledWith(404, { 'Content-Type': 'text/plain' })
    expect(res.end).toHaveBeenCalledWith('not found')
  })
})

describe('server.ts — /api/stream (SSE)', () => {
  it('sets SSE headers on connect', async () => {
    const listener = await loadServer()
    const req = makeReq('/api/stream')
    const res = makeRes()

    listener(req, res as unknown as ServerResponse)

    expect(res.writeHead).toHaveBeenCalledWith(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    })

    req.emit('close') // clear the 15s keep-alive interval before the test ends
  })

  it('pushes a live audit entry to a connected client', async () => {
    const listener = await loadServer()
    const req = makeReq('/api/stream')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const { audit } = await import('../src/audit.js')
    audit('threat.detected', { spender: '0xdead' })

    const pushed = res.write.mock.calls.map((c: unknown[]) => c[0] as string)
    expect(pushed.some((frame) => frame.includes('"stage":"threat.detected"'))).toBe(true)
    expect(pushed.some((frame) => frame.includes('"spender":"0xdead"'))).toBe(true)

    req.emit('close')
  })

  it('broadcast survives a client whose write throws, and still reaches the others', async () => {
    const listener = await loadServer()

    const throwingWrite = vi.fn(() => {
      throw new Error('client socket exploded')
    })
    const reqBroken = makeReq('/api/stream')
    const resBroken = makeRes(throwingWrite)
    listener(reqBroken, resBroken as unknown as ServerResponse)

    const reqHealthy = makeReq('/api/stream')
    const resHealthy = makeRes()
    listener(reqHealthy, resHealthy as unknown as ServerResponse)

    const { audit } = await import('../src/audit.js')

    expect(() => audit('threat.detected', { spender: '0xbroken-test' })).not.toThrow()

    expect(throwingWrite).toHaveBeenCalledTimes(1)
    const healthyPushed = resHealthy.write.mock.calls.map((c: unknown[]) => c[0] as string)
    expect(healthyPushed.some((frame) => frame.includes('0xbroken-test'))).toBe(true)

    // The broken client must have been dropped: a second broadcast does not
    // attempt to write to it again.
    audit('threat.detected', { spender: '0xsecond-test' })
    expect(throwingWrite).toHaveBeenCalledTimes(1)

    reqBroken.emit('close')
    reqHealthy.emit('close')
  })

  it('replays prior history to a newly connected client', async () => {
    const listener = await loadServer()
    const { audit } = await import('../src/audit.js')
    audit('watch.start', { owner: '0xabc' })

    const req = makeReq('/api/stream')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const pushed = res.write.mock.calls.map((c: unknown[]) => c[0] as string)
    expect(pushed.some((frame) => frame.includes('"stage":"watch.start"'))).toBe(true)

    req.emit('close')
  })

  it('caps replayed history at 200 entries, dropping the oldest first', async () => {
    const listener = await loadServer()
    const { audit } = await import('../src/audit.js')
    for (let seq = 0; seq < 201; seq += 1) audit('watch.scan', { seq })

    const req = makeReq('/api/stream')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const pushed = res.write.mock.calls.map((c: unknown[]) => c[0] as string)
    expect(pushed).toHaveLength(200)
    expect(pushed.some((frame) => frame.includes('"seq":0}'))).toBe(false)
    expect(pushed[0]).toContain('"seq":1}')
    expect(pushed.at(-1)).toContain('"seq":200}')

    req.emit('close')
  })

  it('sends a periodic keep-alive comment frame', async () => {
    vi.useFakeTimers()
    try {
      const listener = await loadServer()
      const req = makeReq('/api/stream')
      const res = makeRes()
      listener(req, res as unknown as ServerResponse)
      res.write.mockClear()

      await vi.advanceTimersByTimeAsync(15_000)

      expect(res.write).toHaveBeenCalledWith(': keep-alive\n\n')
      req.emit('close')
    } finally {
      vi.useRealTimers()
    }
  })

  it('stops its own keep-alive interval if a tick write throws', async () => {
    vi.useFakeTimers()
    try {
      const listener = await loadServer()
      const throwingWrite = vi.fn(() => {
        throw new Error('client gone')
      })
      const req = makeReq('/api/stream')
      const res = makeRes(throwingWrite)
      listener(req, res as unknown as ServerResponse)
      throwingWrite.mockClear()

      await vi.advanceTimersByTimeAsync(15_000)
      expect(throwingWrite).toHaveBeenCalledTimes(1)

      // interval must be cleared after the throw — no further ticks
      await vi.advanceTimersByTimeAsync(30_000)
      expect(throwingWrite).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('server.ts — replaying the durable trail after a restart', () => {
  /** One JSONL line, as audit.ts would have appended it. */
  function line(stage: string, detail: Record<string, unknown> = {}): string {
    return JSON.stringify({ ts: new Date().toISOString(), stage, ...detail })
  }

  it('backfills history from the audit log on boot, so a restart is not a blank page', async () => {
    // The trail on disk and the dashboard used to disagree after every
    // restart: the JSONL held the whole run, the UI showed nothing.
    writeFileSync(
      join(dir, 'audit.jsonl'),
      `${line('watch.start', { owner: '0xabc' })}\n${line('revoke.confirmed', { txHash: '0xfeed' })}\n`,
    )

    const listener = await loadServer()
    const req = makeReq('/api/stream')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const pushed = res.write.mock.calls.map((c: unknown[]) => c[0] as string)
    expect(pushed).toHaveLength(2)
    expect(pushed[0]).toContain('"stage":"watch.start"')
    expect(pushed[1]).toContain('0xfeed')

    req.emit('close')
  })

  it('replays only the last 200 lines of a long log', async () => {
    // Same cap the live buffer honours. The trailing newline of the final
    // append must not count as an entry and push the oldest one out.
    const lines = Array.from({ length: 250 }, (_, seq) => line('watch.scan', { seq }))
    writeFileSync(join(dir, 'audit.jsonl'), `${lines.join('\n')}\n`)

    const listener = await loadServer()
    const req = makeReq('/api/stream')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const pushed = res.write.mock.calls.map((c: unknown[]) => c[0] as string)
    expect(pushed).toHaveLength(200)
    expect(pushed[0]).toContain('"seq":50')
    expect(pushed.at(-1)).toContain('"seq":249')

    req.emit('close')
  })

  it('skips a torn final line instead of losing the whole replay', async () => {
    // A process killed mid-append leaves half a line. Parsing the tail in one
    // go would drop every good entry with it.
    writeFileSync(
      join(dir, 'audit.jsonl'),
      `${line('watch.start', { owner: '0xabc' })}\n{"ts":"2026-08-08T00:00:00.0`,
    )

    const listener = await loadServer()
    const req = makeReq('/api/stream')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const pushed = res.write.mock.calls.map((c: unknown[]) => c[0] as string)
    expect(pushed).toHaveLength(1)
    expect(pushed[0]).toContain('"stage":"watch.start"')

    req.emit('close')
  })

  it('starts empty when no audit log exists yet', async () => {
    const listener = await loadServer()
    const req = makeReq('/api/stream')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    expect(res.write).not.toHaveBeenCalled()

    req.emit('close')
  })
})

describe('server.ts — the dashboard it serves', () => {
  it('has a failures tile that counts every stage where the allowance survived', async () => {
    // Scans / Threats / Revokes confirmed / Last response are all success-only,
    // so the aggregate a judge glances at could never go down. A stage the
    // KIND map does not know renders with no headline and counts as nothing.
    const listener = await loadServer()
    const req = makeReq('/verify')
    const res = makeRes()

    listener(req, res as unknown as ServerResponse)

    const body = res.end.mock.calls[0]?.[0] as string
    expect(body).toContain('id="s-failures"')
    for (const stage of ['revoke.failed', 'revoke.reverted', 'watch.error']) {
      expect(body).toContain(`'${stage}':`)
    }
    expect(body).toMatch(/FAILURE\s*=\s*new Set\(\[[^\]]*'watch\.error'/)
  })
})

describe('server.ts — graceful shutdown', () => {
  it('SIGINT stops the watcher, closes the server, and exits 0', async () => {
    await loadServer()
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => undefined as never)

    const handler = process.listeners('SIGINT').at(-1) as (() => void) | undefined
    expect(handler).toBeDefined()
    handler?.()

    expect(watcherMock.stop).toHaveBeenCalledTimes(1)
    expect(httpMock.serverInstance.close).toHaveBeenCalled()
    expect(exitSpy).toHaveBeenCalledWith(0)
  })
})
