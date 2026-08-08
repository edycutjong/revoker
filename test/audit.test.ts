import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/**
 * The audit trail is a security property: it is how a revoke gets justified
 * after the fact. It must survive bigints, must never take down a revoke in
 * flight, and must not let one broken subscriber break the loop.
 */

let dir: string
let logPath: string

beforeEach(() => {
  vi.resetModules()
  dir = mkdtempSync(join(tmpdir(), 'revoker-audit-'))
  logPath = join(dir, 'nested', 'revoker.jsonl')
  process.env['REVOKER_AUDIT_LOG'] = logPath
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
  delete process.env['REVOKER_AUDIT_LOG']
})

function readEntries(): Record<string, unknown>[] {
  return readFileSync(logPath, 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as Record<string, unknown>)
}

describe('audit', () => {
  it('writes one JSON object per line and creates the directory', async () => {
    const { audit } = await import('../src/audit.js')

    audit('watch.start', { owner: '0xabc' })
    audit('threat.detected', { spender: '0xdef' })

    const entries = readEntries()
    expect(entries).toHaveLength(2)
    expect(entries[0]).toMatchObject({ stage: 'watch.start', owner: '0xabc' })
    expect(entries[1]).toMatchObject({ stage: 'threat.detected', spender: '0xdef' })
  })

  it('stamps an ISO timestamp on every entry', async () => {
    const { audit } = await import('../src/audit.js')
    const entry = audit('watch.scan', {})
    expect(entry.ts).toMatch(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/)
  })

  it('serialises bigints — JSON.stringify would otherwise throw', async () => {
    // Allowances and block numbers are bigints. An unhandled bigint here would
    // throw inside the logging path of a live revoke.
    const { audit } = await import('../src/audit.js')

    audit('threat.detected', {
      allowance: (1n << 256n) - 1n,
      block: 11_440_000n,
      nested: { atRisk: 10_000_000_000n },
      list: [1n, 2n],
    })

    const [entry] = readEntries()
    expect(entry!['allowance']).toBe(
      '115792089237316195423570985008687907853269984665640564039457584007913129639935',
    )
    expect(entry!['block']).toBe('11440000')
    expect(entry!['nested']).toEqual({ atRisk: '10000000000' })
    expect(entry!['list']).toEqual(['1', '2'])
  })

  it('notifies subscribers, and unsubscribes cleanly', async () => {
    const { audit, onAudit } = await import('../src/audit.js')
    const seen: string[] = []

    const off = onAudit((e) => seen.push(e.stage))
    audit('watch.scan', {})
    off()
    audit('threat.detected', {})

    expect(seen).toEqual(['watch.scan'])
  })

  it('does not let a throwing subscriber break the loop', async () => {
    // A broken /verify client must never stop the agent from revoking.
    const { audit, onAudit } = await import('../src/audit.js')
    const seen: string[] = []

    onAudit(() => {
      throw new Error('dashboard exploded')
    })
    onAudit((e) => seen.push(e.stage))

    expect(() => audit('revoke.confirmed', {})).not.toThrow()
    expect(seen).toEqual(['revoke.confirmed'])
  })

  it('survives an unwritable log path rather than failing the revoke', async () => {
    // Losing the log is bad. Failing to revoke because of it is worse.
    //
    // The unwritable path is built by putting a regular FILE where audit.ts
    // expects a parent directory, so mkdirSync fails with ENOTDIR instantly on
    // every OS. Do not reach for a magic system path here: this test used to
    // use /proc/definitely/not/writable/x.jsonl, which on macOS fails fast
    // (no procfs) but on Linux makes Node's recursive mkdirSync hang forever —
    // that one line wedged every CI run on this repo for its whole history.
    const blocker = join(dir, 'this-is-a-file-not-a-dir')
    writeFileSync(blocker, 'x')
    process.env['REVOKER_AUDIT_LOG'] = join(blocker, 'nested', 'revoker.jsonl')
    vi.resetModules()
    const { audit } = await import('../src/audit.js')

    expect(() => audit('revoke.confirmed', { txHash: '0xabc' })).not.toThrow()
  })
})

describe('the default log path', () => {
  it('falls back to audit/revoker.jsonl when REVOKER_AUDIT_LOG is unset', async () => {
    // The default branch is the one that runs in production, so leaving it
    // untested means the shipped path is the untested path. It is safe to
    // exercise as long as the relative default cannot resolve to the real repo
    // file: chdir into a temp dir first, so 'audit/revoker.jsonl' lands there.
    const cwd = process.cwd()
    const sandbox = mkdtempSync(join(tmpdir(), 'revoker-default-'))
    delete process.env['REVOKER_AUDIT_LOG']
    process.chdir(sandbox)
    try {
      vi.resetModules()
      const { audit } = await import('../src/audit.js')
      audit('watch.start', { owner: '0xabc' })

      const written = readFileSync(join(sandbox, 'audit', 'revoker.jsonl'), 'utf8')
      expect(JSON.parse(written.trim())).toMatchObject({ stage: 'watch.start', owner: '0xabc' })
    } finally {
      process.chdir(cwd)
      rmSync(sandbox, { recursive: true, force: true })
    }
  })
})

describe('logLine', () => {
  it('renders values without [object Object]', async () => {
    const { audit, logLine } = await import('../src/audit.js')
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})

    logLine(
      audit('threat.detected', {
        rules: [{ rule: 'denylisted' }],
        count: 2,
        ok: true,
        // A plain string is the one primitive that must pass through verbatim
        // rather than through JSON.stringify (which would wrap it in quotes).
        reason: 'spender is deny-listed',
      }),
    )

    const line = spy.mock.calls[0]![0] as string
    expect(line).not.toContain('[object Object]')
    expect(line).toContain('threat.detected')
    expect(line).toContain('count=2')
    expect(line).toContain('ok=true')
    expect(line).toContain('reason=spender is deny-listed')
    spy.mockRestore()
  })

  it('handles null and undefined without throwing', async () => {
    const { audit, logLine } = await import('../src/audit.js')
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})

    expect(() => logLine(audit('revoke.failed', { error: null, hash: undefined }))).not.toThrow()
    spy.mockRestore()
  })

  it('falls back to "?" for a value JSON.stringify cannot represent', async () => {
    // A function is neither null/undefined, an object, a string, nor a
    // number/boolean/bigint, so formatValue falls through to the final
    // JSON.stringify(value) — which returns `undefined` for a function, not a
    // string. The `?? '?'` guard is what stops that from rendering as the
    // literal text "undefined" in the audit line.
    const { logLine } = await import('../src/audit.js')
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})

    logLine({
      ts: new Date().toISOString(),
      stage: 'watch.scan',
      weird: () => 'unrepresentable',
    })

    const line = spy.mock.calls[0]![0] as string
    expect(line).toContain('weird=?')
    spy.mockRestore()
  })
})
