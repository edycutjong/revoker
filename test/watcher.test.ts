import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Address } from 'viem'

/**
 * The watcher is the loop that decides to move funds, and it was the only
 * uncovered module in src/. Everything it gets wrong is expensive in a
 * direction that is hard to notice: revoking twice, revoking when told not to,
 * or quietly giving up on a threat it already saw.
 *
 * chain.ts is mocked because it holds a module-level viem client that would
 * otherwise reach for a real RPC. revoke.ts is mocked so the decision to revoke
 * can be observed without executing one — this suite is about the loop's
 * judgement, not about the transaction (test/revoke.test.ts covers that).
 * keeperhub.ts is mocked because a watcher built without one constructs its
 * own, which would demand credentials this suite has no business holding.
 */

const MAX = (1n << 256n) - 1n
const TOKEN = '0x4facb5fd1682c4449cad42b7590861f7ed5c88cb' as Address
const SPENDER = '0x8ebf8540ede8e40cd94825c418758d4029d8892e' as Address
const OWNER = '0x5e2e5fd3ad7fdc9b94482930db8b5f45e439bab7' as Address
/** A token that reverts on the ERC-20 view calls the scan depends on. */
const HOSTILE = '0xdeadbeef00000000000000000000000000000001' as Address

const chain = vi.hoisted(() => ({
  fetchApprovals: vi.fn(),
  readAllowance: vi.fn(),
  readBalance: vi.fn(),
  tokenSymbol: vi.fn(),
  publicClient: { getBlockNumber: vi.fn() },
}))
const revoke = vi.hoisted(() => ({ revokeApproval: vi.fn() }))
const rules = vi.hoisted(() => ({ assess: vi.fn() }))
const keeperhub = vi.hoisted(() => ({
  KeeperHub: vi.fn(() => ({ getHeldTokens: vi.fn().mockResolvedValue([]) })),
}))

vi.mock('../src/chain.js', () => chain)
vi.mock('../src/revoke.js', () => revoke)
vi.mock('../src/rules.js', () => rules)
vi.mock('../src/keeperhub.js', () => keeperhub)

let dir: string

beforeEach(() => {
  vi.clearAllMocks()
  dir = mkdtempSync(join(tmpdir(), 'revoker-watcher-'))
  process.env['REVOKER_AUDIT_LOG'] = join(dir, 'audit.jsonl')

  chain.publicClient.getBlockNumber.mockResolvedValue(11_443_000n)
  chain.fetchApprovals.mockResolvedValue([{ token: TOKEN, spender: SPENDER }])
  chain.readAllowance.mockResolvedValue(MAX)
  chain.readBalance.mockResolvedValue(10_000_000_000n)
  chain.tokenSymbol.mockResolvedValue('mUSDC')
  rules.assess.mockResolvedValue({
    threat: true,
    fired: [{ rule: 'denylisted', reason: 'spender is deny-listed', evidence: {} }],
    all: [{ rule: 'denylisted', fired: true }],
  })
  revoke.revokeApproval.mockResolvedValue({ executed: true, allowanceAfter: 0n, txHash: '0xabc' })
})

afterEach(() => {
  vi.useRealTimers()
  rmSync(dir, { recursive: true, force: true })
  delete process.env['REVOKER_AUDIT_LOG']
})

/**
 * Only the surface the watcher actually touches. getHeldTokens is the one call
 * it makes on KeeperHub directly — everything else it needs goes through
 * revoke.ts and rules.ts, both mocked above.
 */
function makeKh() {
  return { getHeldTokens: vi.fn().mockResolvedValue([]) } as never
}

/** The audit trail this scan wrote, one parsed object per line. */
function readEntries(): Record<string, unknown>[] {
  return readFileSync(join(dir, 'audit.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l) as Record<string, unknown>)
}

async function makeWatcher(overrides: Record<string, unknown> = {}) {
  const { Watcher } = await import('../src/watcher.js')
  return new Watcher({
    owner: OWNER,
    kh: makeKh(),
    tokens: [TOKEN],
    denylist: [SPENDER],
    ...overrides,
  })
}

describe('Watcher — option defaults', () => {
  it('builds its own KeeperHub, and hands that one to the rules and the revoke', async () => {
    // src/index.ts constructs the watcher without a hub. If the default were
    // ever a different instance from the one the rules see, a revoke would be
    // decided against one wallet and executed through another.
    const { Watcher } = await import('../src/watcher.js')
    const w = new Watcher({ owner: OWNER })

    await w.scan()

    expect(keeperhub.KeeperHub).toHaveBeenCalledTimes(1)
    const built = keeperhub.KeeperHub.mock.results[0]?.value
    expect((rules.assess.mock.calls[0]?.[0] as { kh?: unknown }).kh).toBe(built)
    expect((revoke.revokeApproval.mock.calls[0]?.[0] as { kh?: unknown }).kh).toBe(built)
  })

  it('watches nothing but the held tokens, deny-lists nothing, and still executes', async () => {
    // The bare options object: no watchlist, no denylist, no dryRun. Each of
    // those defaulting to undefined instead of empty would throw on the spread
    // — or, for dryRun, silently turn a live agent into a reporting one.
    const { Watcher } = await import('../src/watcher.js')
    const w = new Watcher({ owner: OWNER })

    await w.scan()

    // 5_000n back from the head, the documented default lookback
    expect(chain.fetchApprovals).toHaveBeenCalledWith(OWNER, [], 11_438_000n, 11_443_000n)
    expect(rules.assess).toHaveBeenCalledWith(expect.objectContaining({ denylist: new Set() }))
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
  })

  it('polls every 5s when no interval is given', async () => {
    rules.assess.mockResolvedValue({ threat: false, fired: [], all: [{ rule: 'denylisted', fired: false }] })
    vi.useFakeTimers()
    const { Watcher } = await import('../src/watcher.js')
    const w = new Watcher({ owner: OWNER })

    const running = w.run()
    await vi.advanceTimersByTimeAsync(4_999)
    expect(chain.publicClient.getBlockNumber).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(1)
    expect(chain.publicClient.getBlockNumber).toHaveBeenCalledTimes(2)

    w.stop()
    await vi.advanceTimersByTimeAsync(5_000)
    await running
  })
})

describe('Watcher.scan — the lookback window', () => {
  it('starts at block 0 when the lookback reaches past the head of the chain', async () => {
    // On a young testnet the head is inside the window. Subtracting anyway
    // would ask the RPC for a negative fromBlock and fail every scan.
    chain.publicClient.getBlockNumber.mockResolvedValue(4_200n)
    const w = await makeWatcher({ lookbackBlocks: 10_000n })

    await w.scan()

    expect(chain.fetchApprovals).toHaveBeenCalledWith(OWNER, [TOKEN], 0n, 4_200n)
  })
})

describe('Watcher.scan — the revoke decision', () => {
  it('revokes an exposure whose rules fire', async () => {
    const w = await makeWatcher()
    const performed = await w.scan()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
    expect(performed).toHaveLength(1)
  })

  it('does not revoke when no rule fires', async () => {
    rules.assess.mockResolvedValue({ threat: false, fired: [], all: [{ rule: 'denylisted', fired: false }] })
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(0)
    expect(revoke.revokeApproval).not.toHaveBeenCalled()
  })

  it('skips an exposure whose allowance is already zero, without spending gas', async () => {
    // The allowance can be revoked between the log being written and this scan.
    chain.readAllowance.mockResolvedValue(0n)
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(0)
    expect(rules.assess).not.toHaveBeenCalled()
    expect(revoke.revokeApproval).not.toHaveBeenCalled()
  })

  it('never revokes the same exposure twice while the allowance is unchanged', async () => {
    // Approval logs are historical: the same (token, spender) pair reappears in
    // every scan for as long as the lookback window covers it, and the node can
    // still be serving the pre-revoke allowance. Without the handled set the
    // agent would re-revoke — and re-pay for — the same allowance forever.
    const w = await makeWatcher()
    await w.scan()
    await w.scan()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
  })

  it('REVOKES AGAIN when the same spender is re-granted after a confirmed revoke', async () => {
    // The thesis is continuous hygiene, not incident response. `handled` used
    // to be consulted before the allowance was read, so once a pair had been
    // revoked its allowance was never read again: seed → revoke → seed again in
    // one session left the agent visibly doing nothing about a live MAX
    // approval. Clearing the entry on an observed zero is what reopens it.
    const w = await makeWatcher()
    await w.scan()

    chain.readAllowance.mockResolvedValueOnce(0n) // chain confirms the revoke
    await w.scan()

    chain.readAllowance.mockResolvedValue(MAX) // the wallet approves again
    await w.scan()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)
  })

  it('keeps checking an approval whose log has aged out of the lookback window', async () => {
    // fromBlock is recomputed from the head every scan, so an old grant stops
    // appearing in the logs entirely — and an approval you forgot about is the
    // threat this product names. Falling out of the log query must not mean
    // falling out of the agent's attention.
    const w = await makeWatcher({ dryRun: true })
    await w.scan()

    chain.fetchApprovals.mockResolvedValue([]) // the grant is now older than the window
    await w.scan()

    expect(rules.assess).toHaveBeenCalledTimes(2)
  })

  it('RETRIES on the next scan when the revoke did not take', async () => {
    // The dangerous inverse of the dedupe test. If a revoke is marked handled
    // on the API's say-so, a failure leaves the allowance live and the agent
    // never looks at it again — the wallet is exposed and the log says it is
    // fine. Only a chain-confirmed zero may mark it done.
    revoke.revokeApproval.mockResolvedValueOnce({ executed: false, allowanceAfter: MAX })
    const w = await makeWatcher()

    await w.scan()
    await w.scan()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)
  })

  it('does not mark handled when the API claims success but the allowance survives', async () => {
    revoke.revokeApproval.mockResolvedValue({ executed: true, allowanceAfter: MAX })
    const w = await makeWatcher()

    await w.scan()
    await w.scan()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)
  })

  it('collapses duplicate approval logs to one exposure', async () => {
    chain.fetchApprovals.mockResolvedValue([
      { token: TOKEN, spender: SPENDER },
      { token: TOKEN, spender: SPENDER },
      { token: TOKEN, spender: SPENDER },
    ])
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(1)
  })

  it('passes an idempotency key so a retried submission cannot double-execute', async () => {
    const w = await makeWatcher()
    await w.scan()

    const call = revoke.revokeApproval.mock.calls[0]?.[0] as { idempotencyKey?: string }
    expect(call.idempotencyKey).toMatch(/^revoke-.+:.+-\d+$/)
  })

  it('touches no exposure once it has been stopped', async () => {
    // stop() can land while a scan is already in flight — from the maxRevokes
    // cap, or from a shutdown signal. It must take effect before the next
    // exposure, not after the whole batch has been revoked.
    const w = await makeWatcher()
    w.stop()

    expect(await w.scan()).toHaveLength(0)
    expect(chain.readAllowance).not.toHaveBeenCalled()
    expect(revoke.revokeApproval).not.toHaveBeenCalled()
  })
})

describe('Watcher.scan — one poisoned watchlist entry', () => {
  it('keeps evaluating the rest of the set when a token reverts on allowance()', async () => {
    // A token whose allowance() reverts used to throw straight out of scan(),
    // so every exposure after it in insertion order was never evaluated —
    // not on that cycle, and not on any later one either. One hostile token
    // could therefore switch the whole agent off silently.
    chain.fetchApprovals.mockResolvedValue([
      { token: HOSTILE, spender: SPENDER },
      { token: TOKEN, spender: SPENDER },
    ])
    chain.readAllowance
      .mockRejectedValueOnce(new Error('execution reverted'))
      .mockResolvedValue(MAX)

    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(1)
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
  })

  it('names the exposure that failed, as its own stage and not as a failed revoke', async () => {
    // No revoke was attempted, so counting it as one would overstate the
    // failure rate on the dashboard a judge reads.
    chain.readAllowance.mockRejectedValue(new Error('execution reverted'))
    const w = await makeWatcher()

    await w.scan()

    const entries = readEntries()
    expect(entries.find((e) => e.stage === 'watch.error')).toMatchObject({
      token: TOKEN,
      spender: SPENDER,
      error: 'execution reverted',
    })
    expect(entries.some((e) => e.stage === 'revoke.failed')).toBe(false)
  })

  it('a token that reverts on balanceOf() is survivable too', async () => {
    // The second read in the loop body, past the allowance guard: proof the
    // whole body is covered, not just the first call in it.
    chain.readBalance.mockRejectedValue(new Error('balanceOf reverted'))
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(0)
    expect(readEntries().find((e) => e.stage === 'watch.error')).toMatchObject({
      error: 'balanceOf reverted',
    })
  })
})

describe('Watcher.scan — what the audit trail says was at risk', () => {
  it('names an unlimited allowance MAX_UINT256 rather than printing 78 digits', async () => {
    const w = await makeWatcher()
    await w.scan()

    const detected = readEntries().find((e) => e.stage === 'threat.detected')
    expect(detected).toMatchObject({ allowance: 'MAX_UINT256', symbol: 'mUSDC' })
  })

  it('records a finite allowance as the number it actually is', async () => {
    // A capped approval is a different story after the fact — labelling it
    // MAX_UINT256 would overstate the exposure in the one record that exists
    // to justify the revoke.
    chain.readAllowance.mockResolvedValue(250_000_000n)
    const w = await makeWatcher()

    await w.scan()

    const detected = readEntries().find((e) => e.stage === 'threat.detected')
    expect(detected).toMatchObject({ allowance: '250000000', atRisk: '10000000000' })
  })
})

describe('Watcher.scan — dry run', () => {
  it('detects and reports but never executes', async () => {
    const w = await makeWatcher({ dryRun: true })

    expect(await w.scan()).toHaveLength(0)
    expect(rules.assess).toHaveBeenCalled()
    expect(revoke.revokeApproval).not.toHaveBeenCalled()
  })
})

describe('Watcher.scan — maxRevokes', () => {
  it('stops the loop once the cap is reached', async () => {
    chain.fetchApprovals.mockResolvedValue([
      { token: TOKEN, spender: SPENDER },
      { token: TOKEN, spender: '0x1111111111111111111111111111111111111111' as Address },
    ])
    const w = await makeWatcher({ maxRevokes: 1 })
    await w.scan()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
  })

  it('a failed revoke does not count toward the cap', async () => {
    revoke.revokeApproval.mockResolvedValueOnce({ executed: false, allowanceAfter: MAX })
    chain.fetchApprovals.mockResolvedValue([
      { token: TOKEN, spender: SPENDER },
      { token: TOKEN, spender: '0x1111111111111111111111111111111111111111' as Address },
    ])
    const w = await makeWatcher({ maxRevokes: 1 })
    await w.scan()

    // first failed, so the cap is still open and the second is attempted
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)
  })
})

describe('Watcher.run — surviving a bad day', () => {
  it('keeps watching after a scan throws', async () => {
    // A transient RPC failure must not kill an agent whose entire value is
    // still being there at 3am.
    chain.publicClient.getBlockNumber
      .mockRejectedValueOnce(new Error('RPC exploded'))
      .mockResolvedValue(11_443_000n)

    const w = await makeWatcher({ pollIntervalMs: 1, maxRevokes: 1 })
    await w.run()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
  })

  it('records what was thrown even when it was not an Error', async () => {
    // Rejections from a fetch stack are not always Errors: a bare string or a
    // response object would land as "undefined" in the audit trail, leaving no
    // trace of why the agent skipped a cycle.
    //
    // The stage is watch.error, not revoke.failed. The old call passed
    // `stage: 'scan'` as a DETAIL key, which the spread wrote over the real
    // stage — so the entry claimed a stage that is not in the union at all,
    // the console printed `undefined` for its label, and the dashboard drew it
    // as a failed revoke that never happened.
    chain.publicClient.getBlockNumber
      .mockRejectedValueOnce('RPC returned 503')
      .mockResolvedValue(11_443_000n)

    const w = await makeWatcher({ pollIntervalMs: 1, maxRevokes: 1 })
    await w.run()

    const failed = readEntries().find((e) => e.error !== undefined)
    expect(failed).toMatchObject({ stage: 'watch.error', error: 'RPC returned 503' })
    // A whole-scan failure names no exposure — that is what tells it apart
    // from the per-exposure watch.error the loop emits.
    expect(failed?.['token']).toBeUndefined()
  })

  it('stop() ends the loop', async () => {
    rules.assess.mockResolvedValue({ threat: false, fired: [], all: [{ rule: 'denylisted', fired: false }] })
    const w = await makeWatcher({ pollIntervalMs: 1 })
    setTimeout(() => { w.stop() }, 20)
    await w.run()

    expect(w.outcomes).toHaveLength(0)
  })
})
