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
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3' as Address

/**
 * The watcher's first retry gap. Mirrored here rather than exported, because a
 * test that imported the constant would pass even if the production value were
 * changed to something useless like 1ms — the number is part of the behaviour
 * under test, not an input to it.
 */
const RETRY_BACKOFF_MS = 15_000
/** Consecutive non-successes on one exposure before the agent gives up. */
const MAX_ATTEMPTS = 3

/** Chain time the Permit2 tests are anchored to, and a year past it. */
const NOW = 1_800_000_000
const FAR_FUTURE = NOW + 365 * 86_400
/** Permit2's unlimited: the amount field is packed into 160 bits, not 256. */
const MAX_UINT160 = (1n << 160n) - 1n

const chain = vi.hoisted(() => ({
  fetchApprovals: vi.fn(),
  readAllowance: vi.fn(),
  readBalance: vi.fn(),
  readChainTimeSeconds: vi.fn(),
  tokenSymbol: vi.fn(),
  publicClient: { getBlockNumber: vi.fn() },
}))
const revoke = vi.hoisted(() => ({
  revokeApproval: vi.fn(),
  revokePermit2Allowances: vi.fn(),
}))
/**
 * assess is stubbed — this suite is about the loop's judgement, not the rules
 * (test/rules.test.ts covers those). mayRevokeUnattended is NOT stubbed away:
 * it is the gate that decides whether a fired rule may be acted on unattended,
 * so it runs its real logic over whatever assessment a test hands back.
 */
const rules = vi.hoisted(() => ({
  assess: vi.fn(),
  mayRevokeUnattended: vi.fn(
    (assessment: { threat: boolean; holds: unknown[] }) =>
      assessment.threat && assessment.holds.length === 0,
  ),
}))
/**
 * Only the two network edges are replaced. permit2Status and permit2PairKey run
 * for real, so "an expired allowance is not revoked" is decided by the same
 * comparison the production path uses rather than by a stub agreeing with the
 * test.
 */
const permit2 = vi.hoisted(() => ({
  fetchPermit2Pairs: vi.fn(),
  readPermit2Allowance: vi.fn(),
}))
const keeperhub = vi.hoisted(() => ({
  KeeperHub: vi.fn(() => ({ getHeldTokens: vi.fn().mockResolvedValue([]) })),
}))

vi.mock('../src/chain.js', () => chain)
vi.mock('../src/revoke.js', () => revoke)
vi.mock('../src/rules.js', () => rules)
vi.mock('../src/keeperhub.js', () => keeperhub)
vi.mock('../src/permit2.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/permit2.js')>()),
  ...permit2,
}))

let dir: string

beforeEach(() => {
  vi.clearAllMocks()
  dir = mkdtempSync(join(tmpdir(), 'revoker-watcher-'))
  process.env['REVOKER_AUDIT_LOG'] = join(dir, 'audit.jsonl')

  chain.publicClient.getBlockNumber.mockResolvedValue(11_443_000n)
  chain.fetchApprovals.mockResolvedValue([{ token: TOKEN, spender: SPENDER }])
  chain.readAllowance.mockResolvedValue(MAX)
  chain.readBalance.mockResolvedValue(10_000_000_000n)
  chain.readChainTimeSeconds.mockResolvedValue(NOW)
  chain.tokenSymbol.mockResolvedValue('mUSDC')
  // No Permit2 exposure unless a test says so, so the ERC-20 suite below stays
  // about the ERC-20 path.
  permit2.fetchPermit2Pairs.mockResolvedValue([])
  permit2.readPermit2Allowance.mockResolvedValue({
    amount: MAX_UINT160,
    expiration: FAR_FUTURE,
    nonce: 3,
  })
  rules.assess.mockResolvedValue({
    threat: true,
    fired: [{ rule: 'denylisted', reason: 'spender is deny-listed', evidence: {} }],
    all: [{ rule: 'denylisted', fired: true }],
    holds: [],
  })
  revoke.revokeApproval.mockResolvedValue({ executed: true, allowanceAfter: 0n, txHash: '0xabc' })
  revoke.revokePermit2Allowances.mockImplementation(
    ({ pairs }: { pairs: Array<{ token: Address; spender: Address }> }) =>
      Promise.resolve({ executed: true, allowanceAfter: 0n, pairs, cleared: pairs }),
  )
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
    rules.assess.mockResolvedValue({ threat: false, fired: [], all: [{ rule: 'denylisted', fired: false }], holds: [] })
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
    rules.assess.mockResolvedValue({ threat: false, fired: [], all: [{ rule: 'denylisted', fired: false }], holds: [] })
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

  it('RETRIES immediately when the revoke was never submitted at all', async () => {
    // The dangerous inverse of the dedupe test. If a revoke is marked handled
    // on the API's say-so, a failure leaves the allowance live and the agent
    // never looks at it again — the wallet is exposed and the log says it is
    // fine. Only a chain-confirmed zero may mark it done.
    //
    // `executed: false` with no disposition is the server-side condition
    // finding the allowance already zero: nothing was submitted and no gas was
    // spent, so this costs no attempt budget and is retried on the very next
    // scan rather than being backed off.
    revoke.revokeApproval.mockResolvedValueOnce({ executed: false, allowanceAfter: MAX })
    const w = await makeWatcher()

    await w.scan()
    await w.scan()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)
  })

  it('does not mark handled when the API claims success but the allowance survives', async () => {
    // ...but it IS a spent attempt, so the retry waits out the backoff instead
    // of firing another transaction on the very next five-second scan.
    vi.useFakeTimers()
    revoke.revokeApproval.mockResolvedValue({
      executed: true,
      allowanceAfter: MAX,
      disposition: 'failed',
      error: 'allowance still non-zero after reported success',
    })
    const w = await makeWatcher()

    await w.scan()
    await w.scan()
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)

    vi.advanceTimersByTime(RETRY_BACKOFF_MS)
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

describe('Watcher.scan — a hold withholds the hammer without hiding the finding', () => {
  /** The assessment the rules return for the ERC-20 approval granted to Permit2. */
  function heldAssessment() {
    rules.assess.mockResolvedValue({
      threat: true,
      fired: [{ rule: 'unlimited-to-unverified', reason: 'unlimited to unverified', evidence: {} }],
      all: [{ rule: 'unlimited-to-unverified', fired: true }],
      holds: [
        {
          rule: 'upstream-permit2-approval',
          fired: true,
          reason: 'spender is the canonical Permit2 contract',
          evidence: { autonomousRevoke: false },
        },
      ],
    })
  }

  it('does NOT revoke the ERC-20 approval granted to Permit2 itself', async () => {
    // Revoking this one breaks every Permit2 integration for the token — every
    // Uniswap swap, every router — for a wallet whose owner is asleep and did
    // not ask. An agent that can do that quietly is not a security agent.
    heldAssessment()
    chain.fetchApprovals.mockResolvedValue([{ token: TOKEN, spender: PERMIT2 }])
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(0)
    expect(revoke.revokeApproval).not.toHaveBeenCalled()
  })

  it('still reports the threat, and says out loud why it was not acted on', async () => {
    // Withheld is not the same as unseen. Suppressing the detection would leave
    // the wallet's single widest approval invisible in the one record that
    // exists to be trusted after the fact.
    heldAssessment()
    chain.fetchApprovals.mockResolvedValue([{ token: TOKEN, spender: PERMIT2 }])
    const w = await makeWatcher()

    await w.scan()

    const entries = readEntries()
    expect(entries.find((e) => e.stage === 'threat.detected')).toMatchObject({ spender: PERMIT2 })
    const skipped = entries.find((e) => e.stage === 'revoke.skipped')
    expect(skipped).toMatchObject({ reason: 'autonomous revoke withheld by a hold' })
    expect(JSON.stringify(skipped?.['holds'])).toContain('upstream-permit2-approval')
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

/**
 * The Permit2 surface.
 *
 * The one that matters commercially: a Permit2 allowance granted by SIGNATURE
 * writes Permit2's own ledger and emits nothing on the token, so every test
 * here describes exposure the ERC-20 half of this same scan cannot see at all.
 */
describe('Watcher.scan — Permit2 exposures', () => {
  const PAIR = { token: TOKEN, spender: SPENDER }
  const PAIR_B = { token: TOKEN, spender: '0x2222222222222222222222222222222222222222' as Address }

  /** No ERC-20 exposure, so only the Permit2 half of the scan can do anything. */
  function permit2Only(pairs = [PAIR]) {
    chain.fetchApprovals.mockResolvedValue([])
    permit2.fetchPermit2Pairs.mockResolvedValue(pairs)
  }

  it('scans Permit2 over the same block window as the ERC-20 sweep', async () => {
    permit2Only()
    const w = await makeWatcher()

    await w.scan()

    expect(permit2.fetchPermit2Pairs).toHaveBeenCalledWith(OWNER, 11_438_000n, 11_443_000n)
  })

  it('revokes a live, long-lived Permit2 allowance through lockdown()', async () => {
    permit2Only()
    const w = await makeWatcher()

    const performed = await w.scan()

    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(1)
    expect(performed).toHaveLength(1)
    const call = revoke.revokePermit2Allowances.mock.calls[0]?.[0] as {
      owner: Address
      pairs: unknown[]
      idempotencyKey?: string
    }
    expect(call.owner).toBe(OWNER)
    expect(call.pairs).toEqual([PAIR])
    expect(call.idempotencyKey).toMatch(/^permit2-lockdown-.+:.+-x1-\d+$/)
  })

  it('assesses the allowance with its expiration and the CHAIN clock', async () => {
    permit2Only()
    const w = await makeWatcher()

    await w.scan()

    expect(rules.assess).toHaveBeenCalledWith(
      expect.objectContaining({
        allowance: MAX_UINT160,
        permit2: { expiration: FAR_FUTURE, nonce: 3, chainTimeSeconds: NOW },
      }),
    )
  })

  it('does NOT revoke an EXPIRED allowance, and records the reason', async () => {
    // The requirement, end to end: Permit2 reverts the transfer once chain time
    // passes the expiration, so there is nothing to take. lockdown() here would
    // burn gas zeroing a number nobody can use — and the rules are never even
    // consulted, because expiry is settled by chain state alone.
    permit2Only()
    permit2.readPermit2Allowance.mockResolvedValue({
      amount: MAX_UINT160,
      expiration: NOW - 1,
      nonce: 3,
    })
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(0)
    expect(rules.assess).not.toHaveBeenCalled()
    expect(revoke.revokePermit2Allowances).not.toHaveBeenCalled()
    expect(readEntries().find((e) => e.stage === 'threat.cleared')).toMatchObject({
      surface: 'permit2',
      reason: 'Permit2 allowance expired — a transfer against it would revert',
    })
  })

  it('revokes an allowance expiring at exactly this second, matching the contract', async () => {
    // AllowanceTransfer reverts on `block.timestamp > expiration`, so equality
    // is still live and still drainable. Rounding it off as expired would stop
    // the watcher looking at a slot that can still move money.
    permit2Only()
    permit2.readPermit2Allowance.mockResolvedValue({
      amount: MAX_UINT160,
      expiration: NOW,
      nonce: 3,
    })
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(1)
  })

  it('skips a slot whose amount is already zero, without assessing it', async () => {
    permit2Only()
    permit2.readPermit2Allowance.mockResolvedValue({ amount: 0n, expiration: FAR_FUTURE, nonce: 3 })
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(0)
    expect(rules.assess).not.toHaveBeenCalled()
  })

  it('batches every threatening slot into ONE lockdown call', async () => {
    // The structural advantage over the ERC-20 path: two exposures, one
    // transaction, one base fee. The ERC-20 loop would have sent two.
    permit2Only([PAIR, PAIR_B])
    const w = await makeWatcher()

    await w.scan()

    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(1)
    expect(
      (revoke.revokePermit2Allowances.mock.calls[0]?.[0] as { pairs: unknown[] }).pairs,
    ).toEqual([PAIR, PAIR_B])
  })

  it('does not lock down the same slot twice while the allowance is unchanged', async () => {
    permit2Only()
    const w = await makeWatcher()

    await w.scan()
    await w.scan()

    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(1)
  })

  it('LOCKS DOWN AGAIN when the same slot is re-permitted after a confirmed lockdown', async () => {
    // A signature grant can be replayed the moment a new one is signed, and a
    // slot the agent stops looking at is a slot it stops protecting.
    permit2Only()
    const w = await makeWatcher()
    await w.scan()

    permit2.readPermit2Allowance.mockResolvedValueOnce({
      amount: 0n,
      expiration: FAR_FUTURE,
      nonce: 3,
    })
    await w.scan() // the chain confirms the lockdown
    await w.scan() // ...and a new signature refills the slot

    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(2)
  })

  it('retries only the slots the chain did NOT confirm as cleared', async () => {
    // A batch that lands is not a batch that worked. Marking every pair handled
    // on the transaction's say-so would leave a surviving allowance live with
    // the log claiming it was revoked.
    vi.useFakeTimers()
    permit2Only([PAIR, PAIR_B])
    revoke.revokePermit2Allowances.mockResolvedValue({
      executed: true,
      allowanceAfter: 500n,
      pairs: [PAIR, PAIR_B],
      cleared: [PAIR],
      disposition: 'failed',
    })
    const w = await makeWatcher()

    await w.scan()
    // The uncleared slot spent an attempt, so the rebuild waits out its backoff.
    vi.advanceTimersByTime(RETRY_BACKOFF_MS)
    await w.scan()

    expect(
      (revoke.revokePermit2Allowances.mock.calls[1]?.[0] as { pairs: unknown[] }).pairs,
    ).toEqual([PAIR_B])
  })

  it('keeps a slot under watch after its only log has aged out of the window', async () => {
    // A signature grant produces exactly ONE Permit log, in the attacker's own
    // transaction. There is no second event ever. Once it ages past the sliding
    // window it is the only trace that existed, so deriving the exposure set
    // from the window alone forgets a live, drainable allowance.
    permit2Only()
    const w = await makeWatcher({ dryRun: true })
    await w.scan()

    permit2.fetchPermit2Pairs.mockResolvedValue([])
    await w.scan()

    expect(rules.assess).toHaveBeenCalledTimes(2)
  })

  it('detects and reports but never executes in a dry run', async () => {
    permit2Only()
    const w = await makeWatcher({ dryRun: true })

    expect(await w.scan()).toHaveLength(0)
    expect(revoke.revokePermit2Allowances).not.toHaveBeenCalled()
    expect(
      readEntries().find((e) => e.stage === 'revoke.skipped' && e['surface'] === 'permit2'),
    ).toMatchObject({ reason: 'dry run' })
  })

  it('does not lock down a slot no rule fired on', async () => {
    permit2Only()
    rules.assess.mockResolvedValue({
      threat: false,
      fired: [],
      all: [{ rule: 'permit2-long-lived', fired: false }],
      holds: [],
    })
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(0)
    expect(revoke.revokePermit2Allowances).not.toHaveBeenCalled()
    expect(readEntries().find((e) => e.stage === 'threat.cleared')).toMatchObject({
      surface: 'permit2',
    })
  })

  it('withholds a held Permit2 slot instead of locking it down', async () => {
    permit2Only()
    rules.assess.mockResolvedValue({
      threat: true,
      fired: [{ rule: 'permit2-long-lived', reason: 'long-lived', evidence: {} }],
      all: [{ rule: 'permit2-long-lived', fired: true }],
      holds: [{ rule: 'upstream-permit2-approval', fired: true, reason: 'held', evidence: {} }],
    })
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(0)
    expect(revoke.revokePermit2Allowances).not.toHaveBeenCalled()
    expect(
      readEntries().find((e) => e.stage === 'revoke.skipped' && e['surface'] === 'permit2'),
    ).toMatchObject({ reason: 'autonomous revoke withheld by a hold' })
  })

  it('survives one Permit2 slot that reverts, and still handles the rest', async () => {
    // The same discipline the ERC-20 loop applies: one bad slot must not switch
    // the agent off for every slot after it in insertion order.
    permit2Only([PAIR, PAIR_B])
    permit2.readPermit2Allowance
      .mockRejectedValueOnce(new Error('permit2 read reverted'))
      .mockResolvedValue({ amount: MAX_UINT160, expiration: FAR_FUTURE, nonce: 3 })
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(1)
    expect(
      (revoke.revokePermit2Allowances.mock.calls[0]?.[0] as { pairs: unknown[] }).pairs,
    ).toEqual([PAIR_B])
    expect(
      readEntries().find((e) => e.stage === 'watch.error' && e['surface'] === 'permit2'),
    ).toMatchObject({ error: 'permit2 read reverted' })
  })

  it('a broken Permit2 index does not blind the ERC-20 sweep that already succeeded', async () => {
    // Two surfaces, two failure domains. Letting the Permit2 log query throw
    // out of scan() would discard a completed ERC-20 revoke alongside it.
    permit2.fetchPermit2Pairs.mockRejectedValue('permit2 indexer 503')
    const w = await makeWatcher()

    expect(await w.scan()).toHaveLength(1)
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
    const failure = readEntries().find(
      (e) => e.stage === 'watch.error' && e['surface'] === 'permit2',
    )
    expect(failure).toMatchObject({ error: 'permit2 indexer 503' })
    expect(failure?.['token']).toBeUndefined()
  })

  it('signs no Permit2 lockdown once the ERC-20 half has hit the revoke cap', async () => {
    // stop() lands mid-scan, between the collect phase and the Permit2 write.
    // Detection on both surfaces has already happened by then and is allowed to
    // — reads change nothing — but the cap must be honoured before the lockdown
    // is signed, not discovered one transaction later.
    permit2.fetchPermit2Pairs.mockResolvedValue([PAIR])
    const w = await makeWatcher({ maxRevokes: 1 })

    await w.scan()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
    expect(revoke.revokePermit2Allowances).not.toHaveBeenCalled()
  })

  it('stops mid-batch when a Permit2 lockdown reaches the revoke cap', async () => {
    permit2Only([PAIR, PAIR_B])
    const w = await makeWatcher({ maxRevokes: 2 })

    await w.scan()

    // Both slots cleared in one call, which is the cap, so the loop stops.
    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(1)
    await w.scan()
    expect(permit2.readPermit2Allowance).toHaveBeenCalledTimes(2)
  })

  it('stops collecting slots the moment stop() lands mid-sweep', async () => {
    permit2Only([PAIR, PAIR_B])
    const w = await makeWatcher()
    permit2.readPermit2Allowance.mockImplementation(() => {
      w.stop()
      return Promise.resolve({ amount: 0n, expiration: FAR_FUTURE, nonce: 3 })
    })

    await w.scan()

    expect(permit2.readPermit2Allowance).toHaveBeenCalledTimes(1)
  })
})

/**
 * The bounded-retry ledger.
 *
 * The hazard these cover is specific and expensive: before this existed, an
 * exposure the agent could never actually clear was retried by EVERY scan,
 * forever. A token that accepts `approve(spender, 0)` and silently ignores it
 * therefore bought one new gas-spending transaction every five seconds for as
 * long as the process lived, and nothing in the audit trail ever said so —
 * every attempt looked like a healthy first attempt.
 *
 * Fake timers throughout: the behaviour under test is measured in tens of
 * seconds, and a suite that waited them out for real would be unrunnable.
 */
describe('Watcher — bounded retries and the give-up (ERC-20)', () => {
  const PAIR_KEY_DETAIL = { token: TOKEN, spender: SPENDER }

  /** A revoke that reports a hard failure — the case that spends the budget. */
  function failingRevoke(error = 'execution reported failed: reverted upstream') {
    revoke.revokeApproval.mockResolvedValue({
      executed: true,
      allowanceAfter: MAX,
      disposition: 'failed',
      error,
    })
  }

  /**
   * Scan `count` times, jumping well past each backoff so every scan really is
   * an attempt. Ten minutes rather than the exact gap, because these tests are
   * about the COUNT that triggers a give-up; the widening of the gap itself is
   * asserted on its own below.
   */
  async function burnAttempts(w: { scan: () => Promise<unknown> }, count: number) {
    for (let i = 0; i < count; i += 1) {
      await w.scan()
      vi.advanceTimersByTime(600_000)
    }
  }

  beforeEach(() => {
    vi.useFakeTimers()
    chain.fetchApprovals.mockResolvedValue([
      { token: TOKEN, spender: SPENDER, blockNumber: 11_442_000n },
    ])
  })

  it('backs off instead of firing a fresh transaction on every scan', async () => {
    failingRevoke()
    const w = await makeWatcher()

    await w.scan()
    // Six more scans at the 5s poll cadence: thirty seconds of watching, which
    // spans the 15s backoff exactly once.
    for (let i = 0; i < 6; i += 1) {
      vi.advanceTimersByTime(5_000)
      await w.scan()
    }

    // Seven scans, TWO transactions. Before the ledger this was seven — one
    // gas-spending revoke per scan, indefinitely, on an allowance that was
    // never going to move.
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)
  })

  it('retries once the backoff has elapsed, and widens it each time', async () => {
    failingRevoke()
    const w = await makeWatcher()

    await w.scan()
    vi.advanceTimersByTime(RETRY_BACKOFF_MS)
    await w.scan()
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)

    // The second gap is twice the first, so the same jump is no longer enough.
    vi.advanceTimersByTime(RETRY_BACKOFF_MS)
    await w.scan()
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)

    vi.advanceTimersByTime(RETRY_BACKOFF_MS)
    await w.scan()
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(3)
  })

  it('ABANDONS after three consecutive failures and never submits again', async () => {
    failingRevoke('execution reported failed: nothing happened')
    const w = await makeWatcher()

    await burnAttempts(w, MAX_ATTEMPTS)
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(MAX_ATTEMPTS)

    // An hour of scanning past the give-up buys not one more transaction.
    for (let i = 0; i < 20; i += 1) {
      vi.advanceTimersByTime(180_000)
      await w.scan()
    }
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(MAX_ATTEMPTS)
  })

  it('records revoke.abandoned once, with the attempt count and the last error', async () => {
    failingRevoke('execution reported failed: nothing happened')
    const w = await makeWatcher()

    await burnAttempts(w, MAX_ATTEMPTS + 4)

    const abandoned = readEntries().filter((e) => e.stage === 'revoke.abandoned')
    // Once, not once per scan: an operator needs to be told the agent stopped,
    // not reminded of it until the signal is worth nothing.
    expect(abandoned).toHaveLength(1)
    expect(abandoned[0]).toMatchObject({
      ...PAIR_KEY_DETAIL,
      attempts: MAX_ATTEMPTS,
      lastError: 'execution reported failed: nothing happened',
    })
    expect(String(abandoned[0]?.['reason'])).toContain('no further attempts')
  })

  it('falls back to the disposition, then to a plain sentence, when no error is given', async () => {
    // The audit row has to name SOMETHING: an abandoned exposure with a blank
    // reason is the silence this whole stage exists to break.
    revoke.revokeApproval.mockResolvedValue({
      executed: true,
      allowanceAfter: MAX,
      disposition: 'reverted',
    })
    const w = await makeWatcher()
    await burnAttempts(w, MAX_ATTEMPTS)
    expect(readEntries().find((e) => e.stage === 'revoke.abandoned')).toMatchObject({
      lastError: 'reverted',
    })

    vi.clearAllMocks()
    rmSync(join(dir, 'audit.jsonl'), { force: true })
    revoke.revokeApproval.mockResolvedValue({ executed: true, allowanceAfter: MAX })
    const bare = await makeWatcher()
    await burnAttempts(bare, MAX_ATTEMPTS)
    expect(readEntries().find((e) => e.stage === 'revoke.abandoned')).toMatchObject({
      lastError: 'allowance is still non-zero',
    })
  })

  it('costs an abandoned exposure nothing at all — not even a balance read', async () => {
    // The gate sits ahead of the rules on purpose. An exposure we have given up
    // on must not spend an RPC call, an explorer lookup for the verification
    // rule, or anything else on every five-second cycle for the rest of the run.
    failingRevoke()
    const w = await makeWatcher()
    await burnAttempts(w, MAX_ATTEMPTS)

    chain.readBalance.mockClear()
    rules.assess.mockClear()
    vi.advanceTimersByTime(600_000)
    await w.scan()

    expect(chain.readBalance).not.toHaveBeenCalled()
    expect(rules.assess).not.toHaveBeenCalled()
  })

  it('an observed on-chain zero releases the budget, so a later re-grant starts clean', async () => {
    failingRevoke()
    const w = await makeWatcher()
    await burnAttempts(w, MAX_ATTEMPTS)

    // The chain says the allowance is gone — whoever cleared it.
    chain.readAllowance.mockResolvedValueOnce(0n)
    vi.advanceTimersByTime(600_000)
    await w.scan()

    // ...and the same spender is granted MAX again.
    revoke.revokeApproval.mockClear()
    chain.readAllowance.mockResolvedValue(MAX)
    await w.scan()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
  })

  it('a NEW Approval log releases the budget; the same log replayed does not', async () => {
    failingRevoke()
    const w = await makeWatcher()
    await burnAttempts(w, MAX_ATTEMPTS)
    revoke.revokeApproval.mockClear()

    // The sliding window re-delivers the SAME log on every scan. If mere
    // presence reset the ledger, the give-up would never happen at all.
    vi.advanceTimersByTime(600_000)
    await w.scan()
    expect(revoke.revokeApproval).not.toHaveBeenCalled()

    // A log from a HIGHER block is the chain stating a new approval was
    // granted: the wallet is freshly exposed and deserves a fresh budget.
    chain.fetchApprovals.mockResolvedValue([
      { token: TOKEN, spender: SPENDER, blockNumber: 11_442_900n },
    ])
    await w.scan()
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
  })

  it('a revoke that worked leaves no half-spent budget behind it', async () => {
    // Two failures then a success must not leave the exposure one stumble away
    // from being abandoned the next time it is re-granted — otherwise a single
    // bad afternoon permanently lowers the bar for giving up on that spender.
    failingRevoke()
    const w = await makeWatcher()
    await burnAttempts(w, 2)

    revoke.revokeApproval.mockResolvedValue({ executed: true, allowanceAfter: 0n })
    await w.scan()
    chain.readAllowance.mockResolvedValueOnce(0n)
    await w.scan() // the chain confirms it, so the exposure is watchable again

    failingRevoke()
    revoke.revokeApproval.mockClear()
    await burnAttempts(w, MAX_ATTEMPTS)

    // A FULL three attempts were needed to reach the give-up, not one.
    expect(revoke.revokeApproval).toHaveBeenCalledTimes(MAX_ATTEMPTS)
    expect(readEntries().filter((e) => e.stage === 'revoke.abandoned')).toHaveLength(1)
  })
})

describe('Watcher — bounded retries and the give-up (Permit2)', () => {
  const PAIR = { token: TOKEN, spender: SPENDER }

  beforeEach(() => {
    vi.useFakeTimers()
    chain.fetchApprovals.mockResolvedValue([])
    permit2.fetchPermit2Pairs.mockResolvedValue([PAIR])
    revoke.revokePermit2Allowances.mockResolvedValue({
      executed: true,
      allowanceAfter: MAX_UINT160,
      pairs: [PAIR],
      cleared: [],
      disposition: 'failed',
      error: 'permit2 allowance still non-zero after reported success',
    })
  })

  async function burn(w: { scan: () => Promise<unknown> }, count: number) {
    for (let i = 0; i < count; i += 1) {
      await w.scan()
      vi.advanceTimersByTime(RETRY_BACKOFF_MS * 2 ** i)
    }
  }

  it('abandons an unclearable slot instead of locking it down forever', async () => {
    const w = await makeWatcher()
    await burn(w, MAX_ATTEMPTS)
    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(MAX_ATTEMPTS)

    for (let i = 0; i < 10; i += 1) {
      vi.advanceTimersByTime(300_000)
      await w.scan()
    }
    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(MAX_ATTEMPTS)

    const abandoned = readEntries().filter((e) => e.stage === 'revoke.abandoned')
    expect(abandoned).toHaveLength(1)
    expect(abandoned[0]).toMatchObject({ surface: 'permit2', token: TOKEN, spender: SPENDER })
  })

  it('a skipped batch spends no budget — one stale guard cannot abandon live slots', async () => {
    // The guard watches ONE slot. If that slot is zeroed elsewhere the whole
    // batch is skipped without a transaction, and charging that skip would give
    // up on the live slots queued behind it for a failure that never happened.
    revoke.revokePermit2Allowances.mockResolvedValue({
      executed: false,
      pairs: [PAIR],
      cleared: [],
    })
    const w = await makeWatcher()

    for (let i = 0; i < 6; i += 1) await w.scan()

    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(6)
    expect(readEntries().filter((e) => e.stage === 'revoke.abandoned')).toHaveLength(0)
  })

  it('an emptied slot releases the budget', async () => {
    const w = await makeWatcher()
    await burn(w, MAX_ATTEMPTS)

    // lockdown finally lands somewhere else: the slot reads zero.
    permit2.readPermit2Allowance.mockResolvedValueOnce({
      amount: 0n,
      expiration: FAR_FUTURE,
      nonce: 3,
    })
    await w.scan()

    // Re-permitted, and attempted again from a clean budget.
    revoke.revokePermit2Allowances.mockClear()
    await w.scan()
    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(1)
  })

  it('an expired slot releases the budget too', async () => {
    const w = await makeWatcher()
    await burn(w, MAX_ATTEMPTS)

    chain.readChainTimeSeconds.mockResolvedValueOnce(FAR_FUTURE + 1)
    await w.scan()

    revoke.revokePermit2Allowances.mockClear()
    await w.scan()
    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(1)
  })

  it('a re-permit (a higher nonce) releases the budget; the same grant does not', async () => {
    // Permit2 gives the watcher no log block to compare, so the "is this a NEW
    // grant?" question is answered off the slot itself: permit() increments the
    // stored nonce, and a higher one cannot be forged by a stale read.
    const w = await makeWatcher()
    await burn(w, MAX_ATTEMPTS)
    revoke.revokePermit2Allowances.mockClear()

    vi.advanceTimersByTime(600_000)
    await w.scan()
    expect(revoke.revokePermit2Allowances).not.toHaveBeenCalled()

    permit2.readPermit2Allowance.mockResolvedValue({
      amount: MAX_UINT160,
      expiration: FAR_FUTURE,
      nonce: 4,
    })
    await w.scan()
    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(1)
  })

  it('a lengthened expiration also counts as a new grant', async () => {
    // approve() on Permit2 does not touch the nonce but does rewrite the
    // expiration, so an extended one is the only signal a re-approved slot has.
    const w = await makeWatcher()
    await burn(w, MAX_ATTEMPTS)
    revoke.revokePermit2Allowances.mockClear()

    permit2.readPermit2Allowance.mockResolvedValue({
      amount: MAX_UINT160,
      expiration: FAR_FUTURE + 86_400,
      nonce: 3,
    })
    vi.advanceTimersByTime(600_000)
    await w.scan()

    expect(revoke.revokePermit2Allowances).toHaveBeenCalledTimes(1)
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
    rules.assess.mockResolvedValue({ threat: false, fired: [], all: [{ rule: 'denylisted', fired: false }], holds: [] })
    const w = await makeWatcher({ pollIntervalMs: 1 })
    setTimeout(() => { w.stop() }, 20)
    await w.run()

    expect(w.outcomes).toHaveLength(0)
  })
})

/**
 * ── The safety rails ─────────────────────────────────────────────────────────
 *
 * Everything above tests that the agent acts when it should. These test that it
 * REFUSES when it should, which is the harder half: a sentinel that revokes too
 * eagerly does not look broken, it looks busy. Two cold audits landed on the
 * same hazard from opposite ends — the top reliability risk, and the reason
 * nobody would run this on a wallet that matters.
 */
describe('Watcher — the operator allow-list', () => {
  /** N distinct spenders, so a scan can hold more than one exposure. */
  function spenders(n: number): Address[] {
    return Array.from({ length: n }, (_, i): Address => `0x${String(i + 1).padStart(40, '0')}`)
  }

  function exposures(list: readonly Address[]): void {
    chain.fetchApprovals.mockResolvedValue(list.map((spender) => ({ token: TOKEN, spender })))
  }

  it('loads data/allowlist.json by default, so an entrypoint cannot forget it', async () => {
    // index.ts and server.ts construct the watcher without ever mentioning an
    // allow-list. If the protection depended on them passing one, it would be
    // absent from every production path and present only in tests.
    const { Watcher } = await import('../src/watcher.js')
    const w = new Watcher({ owner: OWNER, kh: makeKh() })

    await w.scan()

    const passed = (rules.assess.mock.calls[0]?.[0] as { allowlist: Set<string> }).allowlist
    expect(passed.has(PERMIT2.toLowerCase())).toBe(true)
  })

  it('honours an explicitly empty allow-list instead of falling back to the file', async () => {
    // `??`, not truthiness. "Bless nothing" is a valid operator decision, and
    // silently re-adding the file's blessings would reinstate ones they removed.
    const w = await makeWatcher({ allowlist: [] })

    await w.scan()

    expect((rules.assess.mock.calls[0]?.[0] as { allowlist: Set<string> }).allowlist.size).toBe(0)
  })

  it('lower-cases what it is given, so checksum casing cannot make it miss', async () => {
    const w = await makeWatcher({ allowlist: ['0xAbCdEf0000000000000000000000000000000001'] })

    await w.scan()

    expect([
      ...(rules.assess.mock.calls[0]?.[0] as { allowlist: Set<string> }).allowlist,
    ]).toEqual(['0xabcdef0000000000000000000000000000000001'])
  })

  it('HOLDS an allow-listed spender rather than revoking it', async () => {
    // The scenario the rail exists for: young-spender fires on any contract
    // deployed in the last week, and integrating a brand-new venue at launch is
    // exactly what a trading agent does. Without this the product is most
    // dangerous to the wallets it targets.
    rules.assess.mockResolvedValue({
      threat: true,
      fired: [{ rule: 'young-spender', reason: 'deployed ~0.4 days ago', evidence: {} }],
      all: [{ rule: 'young-spender', fired: true }],
      holds: [
        {
          rule: 'operator-allowlisted',
          fired: true,
          reason: 'spender is operator-allowlisted',
          evidence: { autonomousRevoke: false },
        },
      ],
    })
    const w = await makeWatcher({ allowlist: [SPENDER] })

    expect(await w.scan()).toHaveLength(0)
    expect(revoke.revokeApproval).not.toHaveBeenCalled()

    const entries = readEntries()
    // Nothing is hidden. The threat is still detected and still on the record;
    // only the unattended signature is withheld.
    expect(entries.find((e) => e.stage === 'threat.detected')).toMatchObject({ spender: SPENDER })
    const skipped = entries.find((e) => e.stage === 'revoke.skipped')
    expect(skipped).toMatchObject({ rail: 'hold' })
    expect(JSON.stringify(skipped?.['holds'])).toContain('operator-allowlisted')
  })

  it('reports a hold even when NO threat rule fired', async () => {
    // The bug a DX audit found: holds were only reported on the path where a
    // rule fires, so an allow-listed or upstream-Permit2 exposure that tripped
    // nothing vanished from the trail entirely — the documented feature was
    // silently absent from exactly the path the demo exercises.
    rules.assess.mockResolvedValue({
      threat: false,
      fired: [],
      all: [{ rule: 'denylisted', fired: false }],
      holds: [
        {
          rule: 'operator-allowlisted',
          fired: true,
          reason: 'spender is operator-allowlisted',
          evidence: { allowlistSize: 1 },
        },
      ],
    })
    const w = await makeWatcher({ allowlist: [SPENDER] })

    await w.scan()

    const entries = readEntries()
    expect(entries.find((e) => e.stage === 'threat.cleared')).toBeDefined()
    const skipped = entries.find((e) => e.stage === 'revoke.skipped')
    expect(skipped).toMatchObject({ rail: 'hold', spender: SPENDER })
    expect(JSON.stringify(skipped?.['holds'])).toContain('operator-allowlisted')
  })

  it('reports a hold on a quiet Permit2 slot too — both surfaces agree', async () => {
    chain.fetchApprovals.mockResolvedValue([])
    permit2.fetchPermit2Pairs.mockResolvedValue([{ token: TOKEN, spender: SPENDER }])
    rules.assess.mockResolvedValue({
      threat: false,
      fired: [],
      all: [{ rule: 'permit2-long-lived', fired: false }],
      holds: [
        { rule: 'operator-allowlisted', fired: true, reason: 'blessed', evidence: {} },
      ],
    })
    const w = await makeWatcher({ allowlist: [SPENDER] })

    await w.scan()

    expect(
      readEntries().find((e) => e.stage === 'revoke.skipped' && e['surface'] === 'permit2'),
    ).toMatchObject({ rail: 'hold' })
  })

  it('says nothing extra when no hold fired', async () => {
    const w = await makeWatcher()
    await w.scan()
    expect(readEntries().filter((e) => e['rail'] === 'hold')).toHaveLength(0)
  })

  describe('the rolling revoke-rate ceiling', () => {
    it('stops the Nth revoke and keeps detecting', async () => {
      // maxRevokes ends the process; this rail does not. It refuses signatures
      // while detection, assessment and the audit trail carry on — the whole
      // difference between a safety rail and an off switch.
      //
      // Three exposures, deliberately: four would trip the correlated-failure
      // brake first and this test would be measuring the wrong rail.
      exposures(spenders(3))
      const w = await makeWatcher({ maxRevokesPerDay: 2 })

      await w.scan()

      expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)
      const entries = readEntries()
      expect(entries.filter((e) => e.stage === 'threat.detected')).toHaveLength(3)
      const refusal = entries.filter((e) => e['rail'] === 'revoke-rate-ceiling')
      // Once per scan, not once per exposure: an operator needs telling that the
      // ceiling is holding, not telling forty times in one second.
      expect(refusal).toHaveLength(1)
      expect(refusal[0]).toMatchObject({ ceiling: 2, windowHours: 24 })
    })

    it('is still exhausted on the next scan inside the window', async () => {
      vi.useFakeTimers()
      vi.setSystemTime(new Date('2026-08-08T00:00:00Z'))
      exposures(spenders(3))
      const w = await makeWatcher({ maxRevokesPerDay: 2 })

      await w.scan()
      expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)

      // Twelve hours later the third exposure is still live, still firing, and
      // still refused: the budget is a property of the window, not of the scan.
      vi.setSystemTime(new Date('2026-08-08T12:00:00Z'))
      await w.scan()

      expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)
      expect(
        readEntries().filter((e) => e['rail'] === 'revoke-rate-ceiling'),
      ).toHaveLength(2)
    })

    it('rolls forward: the budget returns once the 24h window has passed', async () => {
      // Rolling rather than per-calendar-day, so the cap cannot be doubled by
      // straddling midnight.
      vi.useFakeTimers()
      vi.setSystemTime(new Date('2026-08-08T23:59:00Z'))
      exposures(spenders(2))
      const w = await makeWatcher({ maxRevokesPerDay: 1 })

      await w.scan()
      expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)

      // Two minutes later, past midnight. A calendar-day reset would have handed
      // back the whole budget here; a rolling window does not.
      vi.setSystemTime(new Date('2026-08-09T00:01:00Z'))
      await w.scan()
      expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)

      // A full 24h after the first revoke, the budget genuinely returns.
      vi.setSystemTime(new Date('2026-08-10T00:00:00Z'))
      await w.scan()
      expect(revoke.revokeApproval).toHaveBeenCalledTimes(2)
    })

    it('trims a Permit2 batch to the remaining budget instead of walking through it', async () => {
      // One lockdown is one transaction but N revokes. Metering it as one would
      // let the batched surface stroll past a rail the ERC-20 surface obeys.
      chain.fetchApprovals.mockResolvedValue([])
      permit2.fetchPermit2Pairs.mockResolvedValue(
        spenders(3).map((spender) => ({ token: TOKEN, spender })),
      )
      const w = await makeWatcher({ maxRevokesPerDay: 2 })

      await w.scan()

      const call = revoke.revokePermit2Allowances.mock.calls[0]?.[0] as { pairs: unknown[] }
      expect(call.pairs).toHaveLength(2)
      expect(
        readEntries().find((e) => e['rail'] === 'revoke-rate-ceiling'),
      ).toMatchObject({ surface: 'permit2', withheld: 1, admitted: 2 })
    })

    it('signs no lockdown at all when the budget is already spent', async () => {
      permit2.fetchPermit2Pairs.mockResolvedValue([{ token: TOKEN, spender: SPENDER }])
      chain.fetchApprovals.mockResolvedValue([{ token: TOKEN, spender: SPENDER }])
      const w = await makeWatcher({ maxRevokesPerDay: 1 })

      await w.scan()

      // The single unit of budget went to the ERC-20 revoke; Permit2 gets none.
      expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
      expect(revoke.revokePermit2Allowances).not.toHaveBeenCalled()
      expect(
        readEntries().find(
          (e) => e['rail'] === 'revoke-rate-ceiling' && e['surface'] === 'permit2',
        ),
      ).toMatchObject({ withheld: 1 })
    })
  })

  describe('the correlated-failure brake', () => {
    it('refuses to act when most of the wallet starts firing at once', async () => {
      // Four independent spenders turning hostile between two five-second polls
      // is a claim about the world. One shared detection input misbehaving is
      // one thing going wrong. The second explanation is overwhelmingly likelier
      // and the costs are asymmetric: waiting one poll costs seconds, acting on
      // a false mass detection costs every approval the wallet depends on.
      exposures(spenders(4))
      const w = await makeWatcher()

      expect(await w.scan()).toHaveLength(0)
      expect(revoke.revokeApproval).not.toHaveBeenCalled()

      const entries = readEntries()
      // Detection is untouched. A brake that also silenced the agent would be
      // indistinguishable from blindness in the one artifact that exists to be
      // trusted after the fact.
      expect(entries.filter((e) => e.stage === 'threat.detected')).toHaveLength(4)
      expect(entries.find((e) => e['rail'] === 'correlated-failure-brake')).toMatchObject({
        newlyFiring: 4,
        evaluated: 4,
        thresholdCount: 4,
        thresholdFraction: 0.5,
      })
    })

    it('acts on the very next scan, once the same exposures confirm', async () => {
      // A one-scan delay, not a permanent refusal. A genuine mass compromise is
      // still there five seconds later; an infrastructure blip is not.
      exposures(spenders(4))
      const w = await makeWatcher()

      await w.scan()
      expect(revoke.revokeApproval).not.toHaveBeenCalled()

      await w.scan()
      expect(revoke.revokeApproval).toHaveBeenCalledTimes(4)
    })

    it('does nothing on the next scan if the exposures stopped firing', async () => {
      exposures(spenders(4))
      const w = await makeWatcher()
      await w.scan()

      // The blip cleared: the rules no longer fire on any of them.
      rules.assess.mockResolvedValue({
        threat: false,
        fired: [],
        all: [{ rule: 'denylisted', fired: false }],
        holds: [],
      })
      await w.scan()

      expect(revoke.revokeApproval).not.toHaveBeenCalled()
    })

    it('does NOT engage below the absolute floor, whatever the fraction', async () => {
      // One new drainer in a small wallet is 100% of it and is exactly the case
      // this product exists for. A fraction alone would brake it.
      exposures(spenders(3))
      const w = await makeWatcher()

      await w.scan()

      expect(revoke.revokeApproval).toHaveBeenCalledTimes(3)
      expect(readEntries().some((e) => e['rail'] === 'correlated-failure-brake')).toBe(false)
    })

    it('does NOT engage when the firing set is a small share of a busy wallet', async () => {
      // Four bad spenders among sixteen is a wallet with four bad spenders, not
      // a wallet whose detection inputs have fallen over.
      const all = spenders(16)
      exposures(all)
      const firing = new Set(all.slice(0, 4).map((s) => s.toLowerCase()))
      rules.assess.mockImplementation(({ spender }: { spender: Address }) =>
        Promise.resolve(
          firing.has(spender.toLowerCase())
            ? {
                threat: true,
                fired: [{ rule: 'denylisted', reason: 'deny-listed', evidence: {} }],
                all: [{ rule: 'denylisted', fired: true }],
                holds: [],
              }
            : { threat: false, fired: [], all: [{ rule: 'denylisted', fired: false }], holds: [] },
        ),
      )
      const w = await makeWatcher({ maxRevokesPerDay: 99 })

      await w.scan()

      expect(revoke.revokeApproval).toHaveBeenCalledTimes(4)
      expect(readEntries().some((e) => e['rail'] === 'correlated-failure-brake')).toBe(false)
    })

    it('counts both surfaces together, so a fault cannot hide by splitting itself', async () => {
      exposures(spenders(2))
      permit2.fetchPermit2Pairs.mockResolvedValue(
        spenders(2).map((spender) => ({ token: '0xfeed', spender })),
      )
      const w = await makeWatcher()

      await w.scan()

      // Two on each surface: under the floor per surface, over it across the
      // scan. A per-surface brake would have let both halves through.
      expect(revoke.revokeApproval).not.toHaveBeenCalled()
      expect(revoke.revokePermit2Allowances).not.toHaveBeenCalled()
      expect(readEntries().find((e) => e['rail'] === 'correlated-failure-brake')).toMatchObject({
        newlyFiring: 4,
        evaluated: 4,
      })
    })
  })

  it('stops signing the moment stop() lands, even mid-batch', async () => {
    // An operator shutting the agent down (server.ts closes, SIGTERM) while a
    // revoke is in flight. The remaining candidates must not be signed for: a
    // process on its way out is the last one that should be starting new
    // transactions.
    exposures(spenders(3))
    const w = await makeWatcher()
    revoke.revokeApproval.mockImplementation(() => {
      w.stop()
      return Promise.resolve({ executed: true, allowanceAfter: 0n, txHash: '0xabc' })
    })

    await w.scan()

    expect(revoke.revokeApproval).toHaveBeenCalledTimes(1)
  })

  it('a lockdown that throws does not lose the ERC-20 revokes already made', async () => {
    chain.fetchApprovals.mockResolvedValue([{ token: TOKEN, spender: SPENDER }])
    permit2.fetchPermit2Pairs.mockResolvedValue([{ token: '0xfeed' as Address, spender: SPENDER }])
    revoke.revokePermit2Allowances.mockRejectedValue(new Error('lockdown reverted in flight'))
    const w = await makeWatcher()

    const performed = await w.scan()

    expect(performed).toHaveLength(1)
    expect(
      readEntries().find((e) => e.stage === 'watch.error' && e['surface'] === 'permit2'),
    ).toMatchObject({ error: 'lockdown reverted in flight' })
  })
})
