import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
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
 */

const MAX = (1n << 256n) - 1n
const TOKEN = '0x4facb5fd1682c4449cad42b7590861f7ed5c88cb' as Address
const SPENDER = '0x8ebf8540ede8e40cd94825c418758d4029d8892e' as Address
const OWNER = '0x5e2e5fd3ad7fdc9b94482930db8b5f45e439bab7' as Address

const chain = vi.hoisted(() => ({
  fetchApprovals: vi.fn(),
  readAllowance: vi.fn(),
  readBalance: vi.fn(),
  tokenSymbol: vi.fn(),
  publicClient: { getBlockNumber: vi.fn() },
}))
const revoke = vi.hoisted(() => ({ revokeApproval: vi.fn() }))
const rules = vi.hoisted(() => ({ assess: vi.fn() }))

vi.mock('../src/chain.js', () => chain)
vi.mock('../src/revoke.js', () => revoke)
vi.mock('../src/rules.js', () => rules)

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

  it('never revokes the same exposure twice', async () => {
    // Approval logs are historical: the same (token, spender) pair reappears in
    // every scan for as long as the lookback window covers it. Without the
    // handled set the agent would re-revoke an already-zeroed allowance forever.
    const w = await makeWatcher()
    await w.scan()
    await w.scan()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
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

  it('stop() ends the loop', async () => {
    rules.assess.mockResolvedValue({ threat: false, fired: [], all: [{ rule: 'denylisted', fired: false }] })
    const w = await makeWatcher({ pollIntervalMs: 1 })
    setTimeout(() => { w.stop() }, 20)
    await w.run()

    expect(w.outcomes).toHaveLength(0)
  })
})
