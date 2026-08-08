import { describe, expect, it, vi, beforeEach } from 'vitest'
import type { Address } from 'viem'

// Only the chain-access primitives are mocked; the rule logic under test is
// real, as are MAX_UINT256, blocksInDays and HistoricalStateUnavailable.
vi.mock('../src/chain.js', async () => {
  const actual = await vi.importActual<typeof import('../src/chain.js')>('../src/chain.js')
  return {
    ...actual,
    hasCodeAt: vi.fn(),
    findDeploymentBlock: vi.fn(),
  }
})

const { hasCodeAt, findDeploymentBlock, HistoricalStateUnavailable, MAX_UINT256 } = await import(
  '../src/chain.js'
)
const {
  unlimitedToUnverified,
  youngSpender,
  denylisted,
  permit2LongLived,
  upstreamPermit2Approval,
  assess,
  mayRevokeUnattended,
} = await import('../src/rules.js')
import type { Permit2Facts, ThreatContext } from '../src/rules.js'
import { PERMIT2_ADDRESS, PERMIT2_MAX_AMOUNT } from '../src/permit2.js'
import type { KeeperHub } from '../src/keeperhub.js'

const TOKEN = '0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb' as Address
const SPENDER = '0x8eBf8540EdE8e40CD94825C418758d4029D8892e' as Address
const OWNER = '0x5E2e5Fd3aD7fDC9B94482930db8b5F45E439bab7' as Address
const CURRENT_BLOCK = 11_440_000n
const NOW = 1_800_000_000
const DAY = 86_400

function ctx(overrides: Partial<ThreatContext> = {}): ThreatContext {
  return {
    token: TOKEN,
    spender: SPENDER,
    owner: OWNER,
    allowance: MAX_UINT256,
    balance: 10_000_000_000n,
    currentBlock: CURRENT_BLOCK,
    kh: { isSourceVerified: vi.fn().mockResolvedValue(false) } as unknown as KeeperHub,
    denylist: new Set<string>(),
    ...overrides,
  }
}

/** A Permit2 exposure: same context, plus the facts an ERC-20 approval has none of. */
function permit2Ctx(
  facts: Partial<Permit2Facts> = {},
  overrides: Partial<ThreatContext> = {},
): ThreatContext {
  return ctx({
    allowance: PERMIT2_MAX_AMOUNT,
    permit2: { expiration: NOW + 365 * DAY, nonce: 0, chainTimeSeconds: NOW, ...facts },
    ...overrides,
  })
}

beforeEach(() => {
  vi.mocked(hasCodeAt).mockReset()
  vi.mocked(findDeploymentBlock).mockReset()
})

describe('rule: unlimited-to-unverified', () => {
  it('fires on an unlimited approval to an unverified contract', async () => {
    const verdict = await unlimitedToUnverified.evaluate(ctx())
    expect(verdict.fired).toBe(true)
    expect(verdict.evidence['sourceVerified']).toBe(false)
  })

  it('does NOT fire when the spender source is verified', async () => {
    const kh = { isSourceVerified: vi.fn().mockResolvedValue(true) } as unknown as KeeperHub
    const verdict = await unlimitedToUnverified.evaluate(ctx({ kh }))
    expect(verdict.fired).toBe(false)
  })

  it('does NOT fire on a bounded allowance, and skips the verification lookup', async () => {
    const isSourceVerified = vi.fn().mockResolvedValue(false)
    const kh = { isSourceVerified } as unknown as KeeperHub
    const verdict = await unlimitedToUnverified.evaluate(ctx({ allowance: 1_000_000n, kh }))
    expect(verdict.fired).toBe(false)
    // A bounded allowance is decided locally — no reason to spend an API call.
    expect(isSourceVerified).not.toHaveBeenCalled()
  })

  it('treats one-below-MAX as bounded, not unlimited', async () => {
    const verdict = await unlimitedToUnverified.evaluate(ctx({ allowance: MAX_UINT256 - 1n }))
    expect(verdict.fired).toBe(false)
  })

  it('uses type(uint160).max as the sentinel for a Permit2 exposure', async () => {
    // Permit2 packs the amount into 160 bits, so its unlimited is a completely
    // different number. Comparing a Permit2 amount against MAX_UINT256 can
    // never match — every unlimited Permit2 grant would score as "bounded" and
    // be cleared without a second look.
    const verdict = await unlimitedToUnverified.evaluate(permit2Ctx())

    expect(verdict.fired).toBe(true)
    expect(verdict.evidence['allowance']).toBe('MAX_UINT160')
  })

  it('does NOT treat MAX_UINT256 as unlimited on a Permit2 exposure', async () => {
    // Unreachable on chain (the field is 160 bits) and asserted anyway: the
    // sentinel must follow the surface, not be a union of both.
    const verdict = await unlimitedToUnverified.evaluate(
      permit2Ctx({}, { allowance: MAX_UINT256 }),
    )
    expect(verdict.fired).toBe(false)
  })
})

describe('rule: young-spender', () => {
  it('fires when the contract did not exist at the 7-day cutoff', async () => {
    vi.mocked(hasCodeAt).mockResolvedValue(false)
    vi.mocked(findDeploymentBlock).mockResolvedValue(CURRENT_BLOCK - 7_200n) // ~1 day

    const verdict = await youngSpender.evaluate(ctx())
    expect(verdict.fired).toBe(true)
    expect(verdict.evidence['ageDays']).toBeCloseTo(1, 1)
  })

  it('clamps the cutoff to block 0 instead of going negative on a chain younger than the window', async () => {
    // currentBlock - blocksInDays(7) would be negative on a chain with fewer
    // than ~50,400 blocks of history (e.g. a freshly spun-up testnet). The
    // clamp to 0n is what stops that underflow from being asked of the RPC.
    vi.mocked(hasCodeAt).mockResolvedValue(false)
    vi.mocked(findDeploymentBlock).mockResolvedValue(500n)

    const verdict = await youngSpender.evaluate(ctx({ currentBlock: 1_000n }))
    expect(verdict.fired).toBe(true)
    // The clamp is only observable through the query it produces — the fired
    // branch's own evidence doesn't echo the cutoff back.
    expect(hasCodeAt).toHaveBeenCalledWith(SPENDER, 0n)
  })

  it('does NOT fire for a contract that predates the window', async () => {
    vi.mocked(hasCodeAt).mockResolvedValue(true)
    const verdict = await youngSpender.evaluate(ctx())
    expect(verdict.fired).toBe(false)
    // The cheap check decides it; the binary search must not run.
    expect(findDeploymentBlock).not.toHaveBeenCalled()
  })

  it('abstains loudly when the node cannot serve historical state', async () => {
    vi.mocked(hasCodeAt).mockRejectedValue(new HistoricalStateUnavailable(1n, new Error('pruned')))

    const verdict = await youngSpender.evaluate(ctx())
    // Critically: it must NOT report the spender as safe.
    expect(verdict.fired).toBe(false)
    expect(verdict.evidence['indeterminate']).toBe(true)
    expect(verdict.reason).toContain('INDETERMINATE')
  })

  it('still reports the threat when only the exact age is unavailable', async () => {
    vi.mocked(hasCodeAt).mockResolvedValue(false)
    vi.mocked(findDeploymentBlock).mockRejectedValue(
      new HistoricalStateUnavailable(1n, new Error('pruned')),
    )

    const verdict = await youngSpender.evaluate(ctx())
    expect(verdict.fired).toBe(true)
    expect(verdict.evidence['exactAgeUnavailable']).toBe(true)
  })

  it('propagates unexpected errors instead of swallowing them', async () => {
    vi.mocked(hasCodeAt).mockRejectedValue(new Error('connection refused'))
    await expect(youngSpender.evaluate(ctx())).rejects.toThrow('connection refused')
  })

  it('propagates unexpected errors from the deployment-block search too, not just HistoricalStateUnavailable', async () => {
    // The binary search's own catch only special-cases HistoricalStateUnavailable
    // (line 149) to report a degraded-but-true verdict. Anything else — a plain
    // RPC failure — must still be rethrown (line 157), not swallowed into a
    // false "safe" or "abstained" result.
    vi.mocked(hasCodeAt).mockResolvedValue(false)
    vi.mocked(findDeploymentBlock).mockRejectedValue(new Error('rpc exploded'))

    await expect(youngSpender.evaluate(ctx())).rejects.toThrow('rpc exploded')
  })
})

describe('rule: denylisted', () => {
  it('fires on a deny-list hit', async () => {
    const verdict = await denylisted.evaluate(ctx({ denylist: new Set([SPENDER.toLowerCase()]) }))
    expect(verdict.fired).toBe(true)
  })

  it('matches case-insensitively', async () => {
    const verdict = await denylisted.evaluate(ctx({ denylist: new Set([SPENDER.toLowerCase()]) }))
    expect(verdict.fired).toBe(true)
  })

  it('does NOT fire for an address that is not listed', async () => {
    const other = '0x000000000000000000000000000000000000dEaD'.toLowerCase()
    const verdict = await denylisted.evaluate(ctx({ denylist: new Set([other]) }))
    expect(verdict.fired).toBe(false)
  })
})

describe('rule: permit2-long-lived', () => {
  it('fires on a year-long Permit2 grant to an unverified contract', async () => {
    const verdict = await permit2LongLived.evaluate(permit2Ctx())

    expect(verdict.fired).toBe(true)
    expect(verdict.evidence['daysRemaining']).toBeCloseTo(365, 0)
    expect(verdict.evidence['sourceVerified']).toBe(false)
  })

  it('does NOT fire when the long-lived spender source is verified', async () => {
    const kh = { isSourceVerified: vi.fn().mockResolvedValue(true) } as unknown as KeeperHub
    const verdict = await permit2LongLived.evaluate(permit2Ctx({}, { kh }))

    expect(verdict.fired).toBe(false)
    expect(verdict.reason).toContain('verified')
  })

  it('does NOT fire on an EXPIRED allowance — Permit2 would revert the transfer', async () => {
    // The requirement stated as a fact rather than a silence. There is nothing
    // to take, so there is nothing to revoke, and lockdown() would burn gas
    // zeroing a number nobody can use.
    const isSourceVerified = vi.fn().mockResolvedValue(false)
    const kh = { isSourceVerified } as unknown as KeeperHub
    const verdict = await permit2LongLived.evaluate(
      permit2Ctx({ expiration: NOW - 10 * DAY }, { kh }),
    )

    expect(verdict.fired).toBe(false)
    expect(verdict.reason).toContain('expired')
    expect(verdict.evidence['expiredForSeconds']).toBe(10 * DAY)
    // Expiry is decided locally from chain state; no API call is warranted.
    expect(isSourceVerified).not.toHaveBeenCalled()
  })

  it('does NOT fire on a routine 7-day grant, even to an unverified spender', async () => {
    // 30 days is what Uniswap's own interface writes for a swap approval, so
    // anything inside it is the shape of normal use.
    const verdict = await permit2LongLived.evaluate(permit2Ctx({ expiration: NOW + 7 * DAY }))

    expect(verdict.fired).toBe(false)
    expect(verdict.reason).toContain('within the 30-day norm')
  })

  it('treats exactly 30 days as inside the norm, not outside it', async () => {
    const verdict = await permit2LongLived.evaluate(permit2Ctx({ expiration: NOW + 30 * DAY }))
    expect(verdict.fired).toBe(false)
  })

  it('ABSTAINS with INDETERMINATE when chain time is unavailable', async () => {
    // Fail closed, exactly as young-spender does when the RPC cannot serve
    // historical state. Without a clock there is no reference point for "how
    // long does this last", and "not a threat" would be a claim about the chain
    // with no evidence behind it.
    const verdict = await permit2LongLived.evaluate(permit2Ctx({ chainTimeSeconds: undefined }))

    expect(verdict.fired).toBe(false)
    expect(verdict.reason).toContain('INDETERMINATE')
    expect(verdict.evidence['indeterminate']).toBe(true)
  })

  it('stays quiet on a plain ERC-20 approval, which has no expiry to reason about', async () => {
    const verdict = await permit2LongLived.evaluate(ctx())

    expect(verdict.fired).toBe(false)
    expect(verdict.evidence['permit2']).toBe(false)
  })
})

describe('hold: upstream-permit2-approval', () => {
  it('fires on the ERC-20 approval granted to Permit2 itself', async () => {
    const verdict = await upstreamPermit2Approval.evaluate(ctx({ spender: PERMIT2_ADDRESS }))

    expect(verdict.fired).toBe(true)
    expect(verdict.evidence['autonomousRevoke']).toBe(false)
    expect(verdict.evidence['permit2Address']).toBe(PERMIT2_ADDRESS)
  })

  it('matches case-insensitively, so a lower-cased log entry is still the root', async () => {
    const verdict = await upstreamPermit2Approval.evaluate(
      ctx({ spender: PERMIT2_ADDRESS.toLowerCase() as Address }),
    )
    expect(verdict.fired).toBe(true)
  })

  it('does not fire for an ordinary spender', async () => {
    const verdict = await upstreamPermit2Approval.evaluate(ctx())
    expect(verdict.fired).toBe(false)
    expect(verdict.evidence).toEqual({})
  })
})

describe('assess', () => {
  it('reports a threat when any single rule fires', async () => {
    vi.mocked(hasCodeAt).mockResolvedValue(true) // old contract, rule 2 quiet
    const kh = { isSourceVerified: vi.fn().mockResolvedValue(true) } as unknown as KeeperHub

    // Only the deny-list fires. That alone must be sufficient — requiring
    // consensus would mean ignoring a confirmed drainer because it happened
    // to be a verified, aged contract.
    const assessment = await assess(ctx({ kh, denylist: new Set([SPENDER.toLowerCase()]) }))
    expect(assessment.threat).toBe(true)
    expect(assessment.fired.map((v) => v.rule)).toEqual(['denylisted'])
    expect(mayRevokeUnattended(assessment)).toBe(true)
  })

  it('does NOT flag a benign spender: verified, aged, and not deny-listed', async () => {
    vi.mocked(hasCodeAt).mockResolvedValue(true)
    const kh = { isSourceVerified: vi.fn().mockResolvedValue(true) } as unknown as KeeperHub

    const assessment = await assess(ctx({ kh, allowance: 1_000_000n }))
    expect(assessment.threat).toBe(false)
    expect(assessment.fired).toHaveLength(0)
    expect(assessment.all).toHaveLength(4)
    expect(assessment.holds).toHaveLength(0)
    expect(mayRevokeUnattended(assessment)).toBe(false)
  })

  it('records every rule evaluated, not just the ones that fired', async () => {
    vi.mocked(hasCodeAt).mockResolvedValue(true)
    const assessment = await assess(ctx())
    expect(assessment.all.map((v) => v.rule).sort()).toEqual([
      'denylisted',
      'permit2-long-lived',
      'unlimited-to-unverified',
      'young-spender',
    ])
  })

  it('a HOLD reports the threat and withholds the autonomous revoke', async () => {
    // The whole point of the hold channel. `approve(PERMIT2, MAX)` on an
    // explorer blip looks exactly like any other unlimited-to-unverified hit —
    // and acting on it would silently disconnect the owner from every DEX that
    // routes this token. Nothing is hidden: the threat is still reported, the
    // hold is reported alongside it, and only the unattended ACTION is refused.
    vi.mocked(hasCodeAt).mockResolvedValue(true)
    const assessment = await assess(ctx({ spender: PERMIT2_ADDRESS }))

    expect(assessment.threat).toBe(true)
    expect(assessment.fired.map((v) => v.rule)).toContain('unlimited-to-unverified')
    expect(assessment.holds.map((v) => v.rule)).toEqual(['upstream-permit2-approval'])
    expect(mayRevokeUnattended(assessment)).toBe(false)
    // A hold must never be able to CREATE a threat or mask one, so it stays out
    // of both lists that decide `threat`.
    expect(assessment.all.map((v) => v.rule)).not.toContain('upstream-permit2-approval')
  })

  it('a hold that does not fire leaves the loop free to act', async () => {
    vi.mocked(hasCodeAt).mockResolvedValue(true)
    const assessment = await assess(ctx())

    expect(assessment.holds).toHaveLength(0)
    expect(mayRevokeUnattended(assessment)).toBe(true)
  })

  it('assesses a Permit2 exposure through the same call the watcher makes', async () => {
    vi.mocked(hasCodeAt).mockResolvedValue(true)
    const assessment = await assess(permit2Ctx())

    expect(assessment.threat).toBe(true)
    expect(assessment.fired.map((v) => v.rule).sort()).toEqual([
      'permit2-long-lived',
      'unlimited-to-unverified',
    ])
    expect(mayRevokeUnattended(assessment)).toBe(true)
  })
})
