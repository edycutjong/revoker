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

/**
 * POST /revoke calls straight into the real revoke module, which would reach
 * KeeperHub and the chain. Both are mocked so the callback tests assert ROUTING
 * — which of the two revoke functions was reached, with what arguments — while
 * the functions themselves stay covered by test/revoke.test.ts. The KeeperHub
 * constructor is a spy so the "no credentials" failure can be forced.
 */
const revokeMock = vi.hoisted(() => ({
  revokeApproval: vi.fn(),
  revokePermit2Allowances: vi.fn(),
}))
vi.mock('../src/revoke.js', () => revokeMock)

const khMock = vi.hoisted(() => {
  const construct = vi.fn()
  class KeeperHub {
    constructor() {
      construct()
    }
  }
  return { KeeperHub, construct }
})
vi.mock('../src/keeperhub.js', () => ({ KeeperHub: khMock.KeeperHub }))

const configMock = {
  walletAddress: '0x1234567890123456789012345678901234567890',
  network: 'sepolia',
  chainId: 11155111,
  explorerBase: 'https://sepolia.etherscan.io',
  // A getter, mirroring the real config: server.ts now takes its port from
  // config.ts rather than reading process.env behind config's back, and the
  // $PORT tests below have to keep exercising that.
  get port(): number {
    return Number(process.env['PORT'] ?? 3000)
  },
}
vi.mock('../src/config.js', () => ({ config: configMock }))

/**
 * `'real'` passes the read through to the file that actually ships, so the
 * replay tests exercise data/demo-run.jsonl itself rather than a fixture that
 * could drift away from it; `'enoent'` forces the missing-file path.
 */
const fsState = vi.hoisted(() => ({
  watchlist: undefined as string | undefined,
  denylist: undefined as string | undefined,
  replay: 'real',
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
      if (p.includes('demo-run.jsonl')) {
        if (fsState.replay === 'enoent') {
          throw Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT' })
        }
        if (fsState.replay !== 'real') return fsState.replay
        return actual.readFileSync(path, enc)
      }
      return actual.readFileSync(path, enc)
    },
  }
})

function makeReq(
  url?: string,
  init: { method?: string; headers?: Record<string, string> } = {},
): IncomingMessage {
  const emitter = new EventEmitter()
  return Object.assign(emitter, {
    url,
    method: init.method ?? 'GET',
    headers: init.headers ?? {},
  }) as unknown as IncomingMessage
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

/** The shared secret the callback tests configure. Never a real credential. */
const SECRET = 'test-callback-secret'
const TOKEN = '0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb'
const SPENDER = '0x8eBf8540EdE8e40CD94825C418758d4029D8892e'
const APPROVAL_TX = `0x${'ab'.repeat(32)}`

/** `allowanceAfter` is a bigint on purpose — JSON.stringify throws on those. */
const ERC20_OUTCOME = {
  executed: true,
  latencyMs: 1234,
  allowanceAfter: 0n,
  transactionHash: '0xfeed',
  explorerUrl: 'https://sepolia.etherscan.io/tx/0xfeed',
  disposition: 'confirmed',
}
const PERMIT2_OUTCOME = {
  ...ERC20_OUTCOME,
  pairs: [{ token: TOKEN, spender: SPENDER }],
  cleared: [{ token: TOKEN, spender: SPENDER }],
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
  fsState.replay = 'real'

  revokeMock.revokeApproval.mockReset().mockResolvedValue(ERC20_OUTCOME)
  revokeMock.revokePermit2Allowances.mockReset().mockResolvedValue(PERMIT2_OUTCOME)
  khMock.construct.mockReset()

  originalArgv = process.argv
  vi.spyOn(console, 'log').mockImplementation(() => undefined)
})

afterEach(() => {
  process.argv = originalArgv
  rmSync(dir, { recursive: true, force: true })
  delete process.env['REVOKER_AUDIT_LOG']
  delete process.env['PORT']
  delete process.env['REVOKER_DEMO']
  delete process.env['REVOKER_CALLBACK_SECRET']
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
      // Present on a live run too, and false: "is this a recording?" must have
      // a machine-readable answer in both directions, not only the alarming one.
      replay: false,
      // Live, but no secret configured — so the callback answers, and refuses.
      revokeCallback: 'unconfigured',
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

describe('server.ts — demo mode cannot arm', () => {
  it('an ARMED invocation under REVOKER_DEMO still builds a dry-run Watcher', async () => {
    // config.ts injects --dry-run at module load, and every entrypoint imports
    // it. Loading the REAL module here rather than the mock is the point: this
    // asserts the production side effect, not a restatement of it.
    process.argv = ['node', 'src/server.ts'] // no flags at all
    process.env['REVOKER_DEMO'] = '1'
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)

    await vi.importActual('../src/config.js')
    await loadServer()

    expect(process.argv).toContain('--dry-run')
    expect(watcherMock.instances.at(-1)?.options.dryRun).toBe(true)
  })
})

describe('server.ts — --replay', () => {
  /** One replay tick. */
  const TICK = 500

  async function loadReplayServer(): Promise<
    (req: IncomingMessage, res: ServerResponse) => void
  > {
    process.argv = [...originalArgv, '--replay']
    return loadServer()
  }

  it('watches nothing: no Watcher is constructed at all', async () => {
    await loadReplayServer()
    expect(watcherMock.instances).toHaveLength(0)
    expect(watcherMock.run).not.toHaveBeenCalled()
  })

  it('does not mix the local durable trail into the recording', async () => {
    // A judge who has run the agent once locally must not get their own rows
    // interleaved with the recorded ones: the result would be neither run.
    writeFileSync(
      join(dir, 'audit.jsonl'),
      `${JSON.stringify({ ts: new Date().toISOString(), stage: 'watch.start', owner: '0xlocal' })}\n`,
    )

    const listener = await loadReplayServer()
    const req = makeReq('/api/stream')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    expect(res.write).not.toHaveBeenCalled()
    req.emit('close')
  })

  it('reports itself as a replay in /api/meta, with the recorded window', async () => {
    const listener = await loadReplayServer()
    const req = makeReq('/api/meta')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const meta = JSON.parse(res.end.mock.calls[0]?.[0] as string) as Record<string, unknown>
    expect(meta['replay']).toBe(true)
    expect(meta['dryRun']).toBe(true)
    expect(meta['replaySource']).toBe('data/demo-run.jsonl')
    expect(meta['replayEntries']).toBeGreaterThan(0)
    expect(String(meta['recordedFrom'])).toMatch(/^\d{4}-\d{2}-\d{2}T/)
    expect(String(meta['recordedTo'])).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  it('stamps the served page so a recording cannot be read as a live agent', async () => {
    const listener = await loadReplayServer()
    const req = makeReq('/verify')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const body = res.end.mock.calls[0]?.[0] as string
    expect(body).toContain('id="replay-flag"')
    expect(body).toContain('NOT a live agent')
    expect(body).toContain('data/demo-run.jsonl')
    // The header indicator says "live" the moment the SSE stream opens, which
    // during a replay is true of the stream and false of the agent.
    expect(body).toContain(`conn.textContent = 'replay'`)
    expect(body).toContain(`dot.classList.remove('live', 'armed')`)
    expect(body).toContain('</body>')
  })

  it('leaves the live dashboard completely unstamped', async () => {
    const listener = await loadServer()
    const req = makeReq('/verify')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const body = res.end.mock.calls[0]?.[0] as string
    expect(body).not.toContain('replay-flag')
    expect(body).toBe(readFileSync(new URL('../public/verify.html', import.meta.url), 'utf8'))
  })

  it('streams the recording through broadcast, in order, marked as a replay', async () => {
    vi.useFakeTimers()
    try {
      const listener = await loadReplayServer()
      const req = makeReq('/api/stream')
      const res = makeRes()
      listener(req, res as unknown as ServerResponse)
      res.write.mockClear()

      await vi.advanceTimersByTimeAsync(TICK * 3)

      const frames = res.write.mock.calls
        .map((c: unknown[]) => String(c[0]))
        .filter((f) => f.startsWith('data: '))
        .map((f) => JSON.parse(f.slice(6)) as Record<string, unknown>)

      expect(frames).toHaveLength(3)
      // Every row that reaches a browser says what it is...
      expect(frames.every((f) => f['replay'] === true)).toBe(true)
      // ...while the recorded timestamps are passed through untouched, so the
      // dashboard shows when this actually happened.
      expect(frames[0]?.['stage']).toBe('watch.start')
      expect(frames[0]?.['ts']).toBe('2026-08-08T01:48:53.069Z')

      req.emit('close')
    } finally {
      vi.useRealTimers()
    }
  })

  it('replays the whole recording, then stops the timer', async () => {
    vi.useFakeTimers()
    try {
      const listener = await loadReplayServer()

      const metaReq = makeReq('/api/meta')
      const metaRes = makeRes()
      listener(metaReq, metaRes as unknown as ServerResponse)
      const meta = JSON.parse(metaRes.end.mock.calls[0]?.[0] as string) as { replayEntries: number }

      const req = makeReq('/api/stream')
      const res = makeRes()
      listener(req, res as unknown as ServerResponse)
      res.write.mockClear()

      // One extra tick past the end: the interval must clear itself there.
      await vi.advanceTimersByTimeAsync(TICK * (meta.replayEntries + 1))
      const delivered = res.write.mock.calls.filter((c: unknown[]) => String(c[0]).startsWith('data: '))
      expect(delivered).toHaveLength(meta.replayEntries)

      const logged = vi.mocked(console.log).mock.calls.map((c: unknown[]) => String(c[0]))
      expect(logged).toContain(`  replay complete — ${meta.replayEntries} recorded entries`)

      // Nothing more is ever sent, and the completion notice is not repeated.
      res.write.mockClear()
      await vi.advanceTimersByTimeAsync(TICK * 20)
      expect(res.write.mock.calls.filter((c: unknown[]) => String(c[0]).startsWith('data: '))).toHaveLength(0)

      req.emit('close')
    } finally {
      vi.useRealTimers()
    }
  })

  it('announces REPLAY on the console instead of a watched address', async () => {
    await loadReplayServer()
    const logged = vi.mocked(console.log).mock.calls.map((c: unknown[]) => String(c[0]))
    expect(logged.some((l) => l.includes('mode     REPLAY'))).toBe(true)
    expect(logged.some((l) => l.includes('NOT a live agent'))).toBe(true)
    expect(logged.some((l) => l.includes('watching'))).toBe(false)
  })

  it('SIGINT stops the replay timer and closes the server', async () => {
    vi.useFakeTimers()
    try {
      const listener = await loadReplayServer()
      const req = makeReq('/api/stream')
      const res = makeRes()
      listener(req, res as unknown as ServerResponse)

      const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => undefined as never)
      const handler = process.listeners('SIGINT').at(-1) as (() => void) | undefined
      handler?.()

      expect(httpMock.serverInstance.close).toHaveBeenCalled()
      expect(exitSpy).toHaveBeenCalledWith(0)

      res.write.mockClear()
      await vi.advanceTimersByTimeAsync(TICK * 10)
      expect(res.write.mock.calls.filter((c: unknown[]) => String(c[0]).startsWith('data: '))).toHaveLength(0)

      req.emit('close')
    } finally {
      vi.useRealTimers()
    }
  })

  it('degrades to an empty replay when the recording is missing', async () => {
    fsState.replay = 'enoent'

    const listener = await loadReplayServer()
    const req = makeReq('/api/meta')
    const res = makeRes()
    listener(req, res as unknown as ServerResponse)

    const meta = JSON.parse(res.end.mock.calls[0]?.[0] as string) as Record<string, unknown>
    expect(meta['replayEntries']).toBe(0)
    expect(meta['recordedFrom']).toBeUndefined()
    expect(meta['recordedTo']).toBeUndefined()

    // The banner still has to appear: an empty replay is still not a live run.
    const pageReq = makeReq('/verify')
    const pageRes = makeRes()
    listener(pageReq, pageRes as unknown as ServerResponse)
    const body = pageRes.end.mock.calls[0]?.[0] as string
    expect(body).toContain('id="replay-flag"')
    expect(body).toContain('an earlier run')
  })

  it('skips an unparseable row instead of losing the recording', async () => {
    fsState.replay = [
      JSON.stringify({ ts: '2026-08-08T01:48:53.069Z', stage: 'watch.start' }),
      '{"ts":"2026-08-08T01:48:54.0',
      JSON.stringify({ ts: '2026-08-08T01:48:55.000Z', stage: 'watch.scan', block: '11442145' }),
      '',
    ].join('\n')

    vi.useFakeTimers()
    try {
      const listener = await loadReplayServer()
      const req = makeReq('/api/stream')
      const res = makeRes()
      listener(req, res as unknown as ServerResponse)
      res.write.mockClear()

      await vi.advanceTimersByTimeAsync(TICK * 4)
      const frames = res.write.mock.calls
        .map((c: unknown[]) => String(c[0]))
        .filter((f) => f.startsWith('data: '))
      expect(frames).toHaveLength(2)

      req.emit('close')
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('data/demo-run.jsonl — the recording that ships', () => {
  /**
   * The replay is the only view a judge without credentials gets of the audit
   * trail, since audit/ is gitignored. If its content ever stops telling the
   * whole story, the replay quietly becomes a highlight reel.
   */
  const entries = readFileSync(new URL('../data/demo-run.jsonl', import.meta.url), 'utf8')
    .split('\n')
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as Record<string, unknown>)

  it('is a plausible slice: long enough to read as a run, short enough to watch', () => {
    expect(entries.length).toBeGreaterThanOrEqual(60)
    expect(entries.length).toBeLessThanOrEqual(120)
  })

  it('is in chronological order', () => {
    const timestamps = entries.map((e) => String(e['ts']))
    expect([...timestamps].sort()).toEqual(timestamps)
  })

  it('carries a full threat.detected -> revoke.submit -> revoke.confirmed sequence', () => {
    const stages = entries.map((e) => String(e['stage']))
    const detected = stages.indexOf('threat.detected')
    expect(detected).toBeGreaterThanOrEqual(0)
    expect(stages[detected + 1]).toBe('revoke.submit')
    expect(stages[detected + 2]).toBe('revoke.confirmed')
  })

  it('carries real 32-byte transaction hashes the dashboard can link to', () => {
    const confirmed = entries.filter((e) => e['stage'] === 'revoke.confirmed')
    expect(confirmed.length).toBeGreaterThan(0)
    for (const entry of confirmed) {
      expect(String(entry['txHash'])).toMatch(/^0x[0-9a-f]{64}$/)
    }
  })

  it('shows a revoke that never reached a terminal state, not only the wins', () => {
    // A recording of nothing but successes is the "successes more prominent
    // than failures" problem in a new costume. This submit has no confirmation
    // because the process was killed mid-revoke; the trail records what it saw.
    const submits = entries.filter((e) => e['stage'] === 'revoke.submit').length
    const terminal = entries.filter((e) =>
      ['revoke.confirmed', 'revoke.failed', 'revoke.reverted', 'revoke.skipped'].includes(
        String(e['stage']),
      ),
    ).length
    expect(submits).toBeGreaterThan(terminal)
  })

  it('contains no test-fixture rows — every line is from a real run', () => {
    // The durable trail interleaves genuine rows with placeholder ones written
    // by the suite. Shipping one of those as evidence would be fabrication.
    for (const entry of entries) {
      const line = JSON.stringify(entry)
      expect(line).not.toContain('0xtoken0000')
      expect(line).not.toContain('0xspender000')
      expect(line).not.toContain('0xowner0000')
      expect(line).not.toContain('"txHash":"0xhash"')
    }
  })
})

describe('server.ts — POST /revoke (the workflow callback)', () => {
  /**
   * Drain the microtask queue. The handler suspends on the request body stream
   * and resumes through several resolved promises; `await Promise.resolve()` in
   * a loop advances all of that without a timer, so these tests work identically
   * under fake and real timers.
   */
  async function flush(): Promise<void> {
    for (let tick = 0; tick < 12; tick += 1) await Promise.resolve()
  }

  type Res = ReturnType<typeof makeRes>

  /**
   * Fire one request at /revoke and wait for the answer.
   *
   * `chunks` rather than a single body so the size ceiling can be driven the
   * way a real socket drives it — in pieces.
   */
  async function call(
    listener: (req: IncomingMessage, res: ServerResponse) => void,
    opts: {
      body?: unknown
      chunks?: string[]
      auth?: string | null
      method?: string
      res?: Res
      emitError?: unknown
      skipEnd?: boolean
    } = {},
  ): Promise<Res> {
    const headers: Record<string, string> = {}
    const auth = opts.auth === undefined ? `Bearer ${SECRET}` : opts.auth
    if (auth !== null) headers['authorization'] = auth

    const req = makeReq('/revoke', { method: opts.method ?? 'POST', headers })
    const res = opts.res ?? makeRes()
    listener(req, res as unknown as ServerResponse)
    await flush()

    const chunks = opts.chunks ?? (opts.body === undefined ? ['{}'] : [JSON.stringify(opts.body)])
    for (const chunk of chunks) req.emit('data', chunk)
    if (opts.emitError !== undefined) req.emit('error', opts.emitError)
    if (opts.skipEnd !== true) req.emit('end')
    await flush()
    return res
  }

  /** The JSON body the handler answered with. */
  function answer(res: Res): Record<string, unknown> {
    return JSON.parse(res.end.mock.calls[0]?.[0] as string) as Record<string, unknown>
  }

  function status(res: Res): number {
    return res.writeHead.mock.calls[0]?.[0] as number
  }

  async function armedServer(): Promise<(req: IncomingMessage, res: ServerResponse) => void> {
    process.env['REVOKER_CALLBACK_SECRET'] = SECRET
    return loadServer()
  }

  const GOOD = { token: TOKEN, spender: SPENDER }

  describe('when the agent is not armed', () => {
    it('is unreachable in --replay: a judge running the recording gets a 404', async () => {
      process.env['REVOKER_CALLBACK_SECRET'] = SECRET
      process.argv = [...originalArgv, '--replay']
      const listener = await loadServer()

      const res = await call(listener, { body: GOOD })

      expect(status(res)).toBe(404)
      expect(res.end).toHaveBeenCalledWith('not found')
      expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
    })

    it('is unreachable in demo mode, which forces --dry-run before this module loads', async () => {
      process.env['REVOKER_CALLBACK_SECRET'] = SECRET
      process.argv = ['node', 'src/server.ts']
      process.env['REVOKER_DEMO'] = '1'
      vi.spyOn(console, 'warn').mockImplementation(() => undefined)

      await vi.importActual('../src/config.js')
      const listener = await loadServer()

      const res = await call(listener, { body: GOOD })

      expect(status(res)).toBe(404)
      expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
    })

    it('is unreachable in --dry-run, and says so in /api/meta and on the console', async () => {
      process.env['REVOKER_CALLBACK_SECRET'] = SECRET
      process.argv = [...originalArgv, '--dry-run']
      const listener = await loadServer()

      expect(status(await call(listener, { body: GOOD }))).toBe(404)

      const metaRes = makeRes()
      listener(makeReq('/api/meta'), metaRes as unknown as ServerResponse)
      expect(answer(metaRes)['revokeCallback']).toBe('disabled')

      const logged = vi.mocked(console.log).mock.calls.map((c: unknown[]) => String(c[0]))
      expect(logged).toContain('  callback POST /revoke — disabled')
    })
  })

  describe('authentication', () => {
    it('rejects an unauthenticated call with 401 and executes nothing', async () => {
      const listener = await armedServer()

      const res = await call(listener, { body: GOOD, auth: null })

      expect(status(res)).toBe(401)
      expect(answer(res)).toEqual({ ok: false, error: 'missing or invalid bearer credential' })
      expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
    })

    it('rejects a bearer token of the wrong length', async () => {
      const listener = await armedServer()
      expect(status(await call(listener, { body: GOOD, auth: 'Bearer short' }))).toBe(401)
    })

    it('rejects a wrong token of exactly the right length', async () => {
      // The interesting case: same length, so the comparison reaches
      // timingSafeEqual rather than being short-circuited by the length guard.
      const listener = await armedServer()
      const wrong = 'x'.repeat(SECRET.length)
      expect(status(await call(listener, { body: GOOD, auth: `Bearer ${wrong}` }))).toBe(401)
    })

    it('rejects a credential that is not a Bearer scheme at all', async () => {
      const listener = await armedServer()
      expect(status(await call(listener, { body: GOOD, auth: `Basic ${SECRET}` }))).toBe(401)
    })

    it('fails closed with 503 when REVOKER_CALLBACK_SECRET is unset, and names the variable', async () => {
      const listener = await loadServer() // armed agent, no secret configured

      const res = await call(listener, { body: GOOD })

      expect(status(res)).toBe(503)
      expect(String(answer(res)['error'])).toContain('REVOKER_CALLBACK_SECRET')
      expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
    })

    it('treats an exported-but-blank secret as unset rather than as a password', async () => {
      process.env['REVOKER_CALLBACK_SECRET'] = ''
      const listener = await loadServer()

      expect(status(await call(listener, { body: GOOD, auth: 'Bearer ' }))).toBe(503)

      const metaRes = makeRes()
      listener(makeReq('/api/meta'), metaRes as unknown as ServerResponse)
      expect(answer(metaRes)['revokeCallback']).toBe('unconfigured')
    })

    it('reports itself armed in /api/meta and on the console once configured', async () => {
      const listener = await armedServer()

      const metaRes = makeRes()
      listener(makeReq('/api/meta'), metaRes as unknown as ServerResponse)
      expect(answer(metaRes)['revokeCallback']).toBe('armed')

      const logged = vi.mocked(console.log).mock.calls.map((c: unknown[]) => String(c[0]))
      expect(logged).toContain('  callback POST /revoke — armed')
    })

    it('refuses any method other than POST, without spending a rate-limit slot', async () => {
      const listener = await armedServer()

      const res = await call(listener, { body: GOOD, method: 'GET' })

      expect(status(res)).toBe(405)
      expect(answer(res)).toEqual({ ok: false, error: 'POST only' })
    })
  })

  describe('request validation', () => {
    async function reject(body: unknown): Promise<Record<string, unknown>> {
      const listener = await armedServer()
      const res = await call(listener, { body })
      expect(status(res)).toBe(400)
      expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
      return answer(res)
    }

    it('rejects a body that is not JSON', async () => {
      const listener = await armedServer()
      const res = await call(listener, { chunks: ['{ not json'] })
      expect(status(res)).toBe(400)
      expect(answer(res)['error']).toBe('body is not valid JSON')
    })

    it('rejects a JSON scalar', async () => {
      expect((await reject('a string')).error).toBe('body must be a JSON object')
    })

    it('rejects a JSON null', async () => {
      // `typeof null === 'object'`, so this is the case the null check exists for.
      expect((await reject(null)).error).toBe('body must be a JSON object')
    })

    it('rejects a missing token', async () => {
      expect((await reject({ spender: SPENDER })).error).toBe(
        'token must be a 20-byte hex address',
      )
    })

    it('rejects a malformed token', async () => {
      expect((await reject({ token: '0xnope', spender: SPENDER })).error).toBe(
        'token must be a 20-byte hex address',
      )
    })

    it('rejects a missing spender', async () => {
      expect((await reject({ token: TOKEN })).error).toBe('spender must be a 20-byte hex address')
    })

    it('rejects a malformed spender', async () => {
      expect((await reject({ token: TOKEN, spender: '0x00' })).error).toBe(
        'spender must be a 20-byte hex address',
      )
    })

    it('rejects an unknown `via`', async () => {
      expect((await reject({ ...GOOD, via: 'flashbots' })).error).toBe(
        "via must be 'erc20' or 'permit2'",
      )
    })

    it('rejects a non-string txHash', async () => {
      expect((await reject({ ...GOOD, txHash: 42 })).error).toBe(
        'txHash must be a 32-byte hex transaction hash',
      )
    })

    it('rejects a txHash of the wrong length', async () => {
      expect((await reject({ ...GOOD, txHash: '0xdeadbeef' })).error).toBe(
        'txHash must be a 32-byte hex transaction hash',
      )
    })

    it('refuses an oversized body with 413 and stops buffering it', async () => {
      const listener = await armedServer()
      const chunk = 'x'.repeat(3_000)

      // Three chunks: the first fits, the second crosses the ceiling, the third
      // must be dropped rather than appended to a buffer nobody will read.
      const res = await call(listener, { chunks: [chunk, chunk, chunk] })

      expect(status(res)).toBe(413)
      expect(answer(res)['error']).toBe('payload too large')
      expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
    })

    it('answers 400 when the request stream errors mid-body', async () => {
      const listener = await armedServer()

      const res = await call(listener, {
        chunks: [],
        emitError: new Error('ECONNRESET'),
        skipEnd: true,
      })

      expect(status(res)).toBe(400)
      expect(answer(res)['error']).toBe('ECONNRESET')
    })

    it('answers 400 when the stream fails with a non-Error', async () => {
      const listener = await armedServer()

      const res = await call(listener, { chunks: [], emitError: 'socket hung up', skipEnd: true })

      expect(status(res)).toBe(400)
      expect(answer(res)['error']).toBe('request body could not be read')
    })
  })

  describe('routing to the right revoke path', () => {
    it('routes the default (no `via`) to the ERC-20 approve(spender, 0) path', async () => {
      const listener = await armedServer()

      const res = await call(listener, { body: GOOD })

      expect(status(res)).toBe(200)
      expect(revokeMock.revokePermit2Allowances).not.toHaveBeenCalled()
      expect(revokeMock.revokeApproval).toHaveBeenCalledTimes(1)
      expect(revokeMock.revokeApproval.mock.calls[0]?.[0]).toMatchObject({
        token: TOKEN,
        spender: SPENDER,
        // Never taken from the request: KeeperHub signs for one account only.
        owner: configMock.walletAddress,
      })
    })

    it('routes via: "erc20" to the same path', async () => {
      const listener = await armedServer()
      await call(listener, { body: { ...GOOD, via: 'erc20' } })

      expect(revokeMock.revokeApproval).toHaveBeenCalledTimes(1)
      expect(revokeMock.revokePermit2Allowances).not.toHaveBeenCalled()
    })

    it('routes via: "permit2" to lockdown(), as a one-pair batch', async () => {
      const listener = await armedServer()

      const res = await call(listener, { body: { ...GOOD, via: 'permit2' } })

      expect(status(res)).toBe(200)
      expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
      expect(revokeMock.revokePermit2Allowances).toHaveBeenCalledTimes(1)
      expect(revokeMock.revokePermit2Allowances.mock.calls[0]?.[0]).toMatchObject({
        owner: configMock.walletAddress,
        pairs: [{ token: TOKEN, spender: SPENDER }],
      })
      expect(answer(res)['via']).toBe('permit2')
    })

    it('derives an idempotency key from the Approval tx, so a retried node cannot double-submit', async () => {
      const listener = await armedServer()

      await call(listener, { body: { ...GOOD, txHash: APPROVAL_TX } })

      expect(revokeMock.revokeApproval.mock.calls[0]?.[0]).toMatchObject({
        idempotencyKey: `wf-${APPROVAL_TX}`,
      })
    })

    it('omits the idempotency key when the workflow forwarded no tx hash', async () => {
      const listener = await armedServer()

      await call(listener, { body: GOOD })

      expect(revokeMock.revokeApproval.mock.calls[0]?.[0]).not.toHaveProperty('idempotencyKey')
    })

    it('serialises the bigint allowance instead of throwing on it', async () => {
      const listener = await armedServer()

      const res = await call(listener, { body: GOOD })

      expect(answer(res)).toMatchObject({
        ok: true,
        via: 'erc20',
        disposition: 'confirmed',
        // 0n survived JSON.stringify as a string rather than killing the response.
        allowanceAfter: '0',
        explorerUrl: 'https://sepolia.etherscan.io/tx/0xfeed',
      })
    })

    it('returns 500 when the process has no KeeperHub credentials', async () => {
      const listener = await armedServer()
      khMock.construct.mockImplementationOnce(() => {
        throw new Error('Missing KH_API_KEY.')
      })

      const res = await call(listener, { body: GOOD })

      expect(status(res)).toBe(500)
      expect(String(answer(res)['error'])).toContain('KH_API_KEY')
      expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
    })

    it('returns 500 when the KeeperHub client fails with a non-Error', async () => {
      const listener = await armedServer()
      khMock.construct.mockImplementationOnce(() => {
        // A bare string on purpose: the handler must not assume every failure
        // arrives as an Error, and this is the branch that proves it.
        // eslint-disable-next-line @typescript-eslint/only-throw-error
        throw 'nope'
      })

      const res = await call(listener, { body: GOOD })

      expect(status(res)).toBe(500)
      expect(answer(res)['error']).toBe('KeeperHub unavailable')
    })
  })

  describe('the audit trail', () => {
    it('records the escalation as a threat before executing, tagged as workflow-sourced', async () => {
      const listener = await armedServer()
      const streamReq = makeReq('/api/stream')
      const streamRes = makeRes()
      listener(streamReq, streamRes as unknown as ServerResponse)

      await call(listener, { body: { ...GOOD, txHash: APPROVAL_TX } })

      const frames = streamRes.write.mock.calls
        .map((c: unknown[]) => String(c[0]))
        .filter((f) => f.startsWith('data: '))
        .map((f) => JSON.parse(f.slice(6)) as Record<string, unknown>)

      const detected = frames.find((f) => f['stage'] === 'threat.detected')
      expect(detected).toMatchObject({
        source: 'keeperhub-workflow',
        endpoint: 'POST /revoke',
        token: TOKEN,
        spender: SPENDER,
        via: 'erc20',
        approvalTx: APPROVAL_TX,
      })

      streamReq.emit('close')
    })

    it('records a refused callback too — probing a revoke endpoint is a signal', async () => {
      const listener = await armedServer()
      const streamReq = makeReq('/api/stream')
      const streamRes = makeRes()
      listener(streamReq, streamRes as unknown as ServerResponse)

      await call(listener, { body: GOOD, auth: null })

      const frames = streamRes.write.mock.calls
        .map((c: unknown[]) => String(c[0]))
        .filter((f) => f.startsWith('data: '))
        .map((f) => JSON.parse(f.slice(6)) as Record<string, unknown>)

      expect(frames.find((f) => f['stage'] === 'watch.error')).toMatchObject({
        endpoint: 'POST /revoke',
        status: 401,
      })

      streamReq.emit('close')
    })
  })

  describe('rate limiting', () => {
    it('caps callbacks at 20 a minute, counting unauthenticated attempts too', async () => {
      // Counted before the secret is checked on purpose: a bucket that only
      // counts authenticated calls does not bound guessing the secret at all.
      const listener = await armedServer()

      for (let n = 0; n < 20; n += 1) {
        expect(status(await call(listener, { body: GOOD, auth: null }))).toBe(401)
      }

      const res = await call(listener, { body: GOOD })
      expect(status(res)).toBe(429)
      expect(String(answer(res)['error'])).toContain('20 callbacks in one minute')
      expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
    })

    it('lets the window slide: attempts older than a minute stop counting', async () => {
      vi.useFakeTimers()
      try {
        const listener = await armedServer()

        for (let n = 0; n < 20; n += 1) await call(listener, { body: GOOD, auth: null })
        expect(status(await call(listener, { body: GOOD }))).toBe(429)

        await vi.advanceTimersByTimeAsync(61_000)

        const res = await call(listener, { body: GOOD })
        expect(status(res)).toBe(200)
        expect(revokeMock.revokeApproval).toHaveBeenCalledTimes(1)
      } finally {
        vi.useRealTimers()
      }
    })
  })

  describe('when the revoke itself explodes', () => {
    it('answers 500 rather than leaving an unhandled rejection in an unattended agent', async () => {
      const listener = await armedServer()
      revokeMock.revokeApproval.mockRejectedValueOnce(new Error('KeeperHub unreachable'))

      const res = await call(listener, { body: GOOD })

      expect(status(res)).toBe(500)
      expect(answer(res)['error']).toBe('KeeperHub unreachable')
    })

    it('stringifies a non-Error rejection', async () => {
      const listener = await armedServer()
      revokeMock.revokeApproval.mockRejectedValueOnce('exploded')

      const res = await call(listener, { body: GOOD })

      expect(status(res)).toBe(500)
      expect(answer(res)['error']).toBe('exploded')
    })

    it('swallows a failure to even report the failure, when the socket is already gone', async () => {
      const listener = await armedServer()
      revokeMock.revokeApproval.mockRejectedValueOnce(new Error('boom'))

      const res = makeRes()
      res.writeHead.mockImplementation(() => {
        throw new Error('socket closed')
      })

      // The assertion is that this resolves at all: an exception escaping the
      // last-resort handler would surface as an unhandled rejection.
      await expect(call(listener, { body: GOOD, res })).resolves.toBeDefined()
      expect(res.end).not.toHaveBeenCalled()
    })
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
