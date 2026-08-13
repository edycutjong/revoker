import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import type { Address } from 'viem'
import { onAudit, type AuditEntry } from '../src/audit.js'

vi.mock('../src/chain.js', async () => {
  const actual = await vi.importActual<typeof import('../src/chain.js')>('../src/chain.js')
  return { ...actual, readAllowance: vi.fn() }
})

// Only the two edges that leave the process are replaced — the network read and
// the deployments.json lookup. PERMIT2_ADDRESS, PERMIT2_ABI_JSON,
// PERMIT2_GUARD_FUNCTION and the helper ABI all stay real, so the assertions
// below compare the actual address, the actual function name and the actual ABI
// this module puts on the wire. A wrong lockdown signature fails here, and so
// does a guard pointed back at Permit2's tuple getter.
vi.mock('../src/permit2.js', async () => {
  const actual = await vi.importActual<typeof import('../src/permit2.js')>('../src/permit2.js')
  return { ...actual, readPermit2Allowance: vi.fn(), permit2AllowanceViewAddress: vi.fn() }
})

const { readAllowance } = await import('../src/chain.js')
const {
  readPermit2Allowance,
  permit2AllowanceViewAddress,
  PERMIT2_ADDRESS,
  PERMIT2_ABI_JSON,
  PERMIT2_ALLOWANCE_VIEW_ABI_JSON,
  PERMIT2_GUARD_FUNCTION,
} = await import('../src/permit2.js')
const { revokeApproval, revokePermit2Allowances } = await import('../src/revoke.js')
import type { Permit2RevokeOutcome, RevokeOutcome } from '../src/revoke.js'
import type { KeeperHub } from '../src/keeperhub.js'

const TOKEN = '0xtoken000000000000000000000000000000000' as Address
const OWNER = '0xowner000000000000000000000000000000000' as Address
const SPENDER = '0xspender0000000000000000000000000000000' as Address
/** Where the deployed Permit2AllowanceView lives, in these tests. */
const GUARD_VIEW = '0xview00000000000000000000000000000000000' as Address

function fakeKh(overrides: Partial<KeeperHub> = {}): KeeperHub {
  return {
    checkAndExecute: vi.fn(),
    getExecutionStatus: vi.fn().mockResolvedValue({
      executionId: 'e1',
      status: 'completed',
      transactionHash: '0xhash',
      sponsored: true,
      gasUsedWei: '46482',
    }),
    ...overrides,
  } as unknown as KeeperHub
}

beforeEach(() => {
  vi.mocked(readAllowance).mockReset()
  // The helper is deployed unless a test says otherwise. Not-deployed is its own
  // scenario, asserted explicitly below, because the required behaviour there is
  // "refuse and say so" rather than "carry on without a guard".
  vi.mocked(permit2AllowanceViewAddress).mockReturnValue(GUARD_VIEW)
  process.env['REVOKER_AUDIT_LOG'] = '/dev/null'
})

describe('revokeApproval', () => {
  it('reports confirmed once the chain shows the allowance is zero', async () => {
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        executionId: 'e1',
        condition: { met: true, observedValue: '999', targetValue: '0', operator: 'gt' },
      }),
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome.executed).toBe(true)
    expect(outcome.allowanceAfter).toBe(0n)
    expect(outcome.transactionHash).toBe('0xhash')
    expect(outcome.explorerUrl).toContain('0xhash')
    expect(outcome.error).toBeUndefined()
  })

  it('reports FAILURE when the API claims success but the allowance survives', async () => {
    // This is a security property, not a nicety: an agent that reports a revoke
    // it did not achieve is worse than one that fails loudly. SECURITY.md calls
    // this out explicitly.
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        executionId: 'e1',
        condition: { met: true, observedValue: '999', targetValue: '0', operator: 'gt' },
      }),
    })
    vi.mocked(readAllowance).mockResolvedValue(500n)

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome.allowanceAfter).toBe(500n)
    expect(outcome.error).toMatch(/still non-zero/)
  })

  it('spends no gas when the allowance is already zero at execution time', async () => {
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: false,
        condition: { met: false, observedValue: '0', targetValue: '0', operator: 'gt' },
      }),
    })

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome.executed).toBe(false)
    expect(outcome.observedAllowance).toBe('0')
    // No confirmation read is needed when nothing was executed.
    expect(readAllowance).not.toHaveBeenCalled()
  })

  it('returns a failed outcome instead of throwing when KeeperHub errors', async () => {
    // The watcher loop must survive a failed revoke and retry on the next scan.
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockRejectedValue(new Error('gateway timeout')),
    })

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome.executed).toBe(false)
    expect(outcome.error).toBe('gateway timeout')
  })

  it('measures latency from detection, not from submission', async () => {
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        executionId: 'e1',
        condition: { met: true, observedValue: '9', targetValue: '0', operator: 'gt' },
      }),
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const detectedAt = Date.now() - 5_000
    const outcome = await revokeApproval({
      kh,
      token: TOKEN,
      owner: OWNER,
      spender: SPENDER,
      detectedAt,
    })

    // Detection-to-confirmed is the number we publish; it must include the time
    // spent deciding, not just the time spent submitting.
    expect(outcome.latencyMs).toBeGreaterThanOrEqual(5_000)
  })

  it('forwards the idempotency key so a retried revoke cannot double-execute', async () => {
    const checkAndExecute = vi.fn().mockResolvedValue({
      executed: true,
      executionId: 'e1',
      condition: { met: true, observedValue: '9', targetValue: '0', operator: 'gt' },
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    await revokeApproval({
      kh: fakeKh({ checkAndExecute }),
      token: TOKEN,
      owner: OWNER,
      spender: SPENDER,
      idempotencyKey: 'revoke-abc-123',
    })

    expect(checkAndExecute.mock.calls[0]![0]).toMatchObject({ idempotencyKey: 'revoke-abc-123' })
  })

  it('asks for a revoke only while the allowance is still greater than zero', async () => {
    const checkAndExecute = vi.fn().mockResolvedValue({
      executed: true,
      executionId: 'e1',
      condition: { met: true, observedValue: '9', targetValue: '0', operator: 'gt' },
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    await revokeApproval({
      kh: fakeKh({ checkAndExecute }),
      token: TOKEN,
      owner: OWNER,
      spender: SPENDER,
    })

    const arg = checkAndExecute.mock.calls[0]![0] as {
      condition: { operator: string; value: string }
      action: { functionName: string; functionArgs: unknown[] }
      check: { functionName: string }
    }
    expect(arg.check.functionName).toBe('allowance')
    expect(arg.condition).toEqual({ operator: 'gt', value: '0' })
    expect(arg.action.functionName).toBe('approve')
    expect(arg.action.functionArgs).toEqual([SPENDER, '0'])
  })

  // The block below (post-execution verification) decides whether a revoke is
  // reported as confirmed. check-and-execute's own transactionHash is
  // provisional; the /status call is the authoritative source, and every
  // field it can omit must degrade gracefully rather than crash or lie.

  it('skips the status lookup and trusts the inline hash when no executionId comes back', async () => {
    // Not every check-and-execute response yields an executionId. When none is
    // given there is nothing to poll, so the API's own hash (if any) is final.
    const getExecutionStatus = vi.fn()
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        transactionHash: '0xinline',
        condition: { met: true, observedValue: '9', targetValue: '0', operator: 'gt' },
      }),
      getExecutionStatus,
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(getExecutionStatus).not.toHaveBeenCalled()
    expect(outcome.transactionHash).toBe('0xinline')
    // sponsored/gasUsedWei only ever come from the status poll — with no poll,
    // neither key should be present on the outcome at all.
    expect(outcome).not.toHaveProperty('sponsored')
    expect(outcome).not.toHaveProperty('gasUsedWei')
  })

  it('falls back to the check-and-execute hash when the status endpoint omits its own', async () => {
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        executionId: 'e1',
        transactionHash: '0xfallback',
        condition: { met: true, observedValue: '9', targetValue: '0', operator: 'gt' },
      }),
      getExecutionStatus: vi.fn().mockResolvedValue({ executionId: 'e1', status: 'completed' }),
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome.transactionHash).toBe('0xfallback')
    expect(outcome.explorerUrl).toContain('0xfallback')
  })

  it('reports a confirmed revoke with no hash at all when neither source has one', async () => {
    // A hash-less confirmation is unusual but must not be fabricated or crash
    // the outcome — transactionHash/explorerUrl simply stay absent.
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        executionId: 'e1',
        condition: { met: true, observedValue: '9', targetValue: '0', operator: 'gt' },
      }),
      getExecutionStatus: vi.fn().mockResolvedValue({ executionId: 'e1', status: 'completed' }),
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome.executed).toBe(true)
    expect(outcome).not.toHaveProperty('transactionHash')
    expect(outcome).not.toHaveProperty('explorerUrl')
  })

  it('omits observedAllowance when check-and-execute reports no condition', async () => {
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        executionId: 'e1',
        // No `condition` key at all — an edge KeeperHub can return.
      }),
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome).not.toHaveProperty('observedAllowance')
  })

  it('drops an empty-string gasUsedWei from the status poll rather than reporting a lie', async () => {
    // Empty string is a falsy-but-defined edge distinct from "field absent" —
    // the outcome must treat it as "no gas data", not include `gasUsedWei: ''`.
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        executionId: 'e1',
        condition: { met: true, observedValue: '9', targetValue: '0', operator: 'gt' },
      }),
      getExecutionStatus: vi.fn().mockResolvedValue({
        executionId: 'e1',
        status: 'completed',
        transactionHash: '0xhash',
        gasUsedWei: '',
      }),
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome).not.toHaveProperty('gasUsedWei')
  })

  it('stringifies a non-Error rejection instead of crashing', async () => {
    // fetch/JSON layers can reject with something other than an Error (a raw
    // string, a plain object). The watcher loop must still get a usable
    // outcome.error rather than an uncaught throw.
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockRejectedValue('gateway on fire'),
    })

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome.executed).toBe(false)
    expect(outcome.error).toBe('gateway on fire')
  })
})

/**
 * Gas handling, as opposed to gas reporting.
 *
 * Two things were wrong here. The status endpoint was read exactly once, so a
 * transaction that was merely still pending — and BENCHMARK.md measures a p95
 * response of 25.17s, two-plus blocks, so that happens — was reported as a hard
 * failure. And nothing ever responded to a slow inclusion: no gas buffer, no
 * escalation, no replacement.
 *
 * These tests use fake timers, so the ladder plays out in microseconds and
 * nothing here touches a network or a clock that matters.
 */
describe('revokeApproval — terminal-state polling and fee escalation', () => {
  const CONDITION = { met: true, observedValue: '999', targetValue: '0', operator: 'gt' }

  let entries: AuditEntry[]
  let unsubscribe: () => void

  beforeEach(() => {
    entries = []
    unsubscribe = onAudit((entry) => entries.push(entry))
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
    unsubscribe()
  })

  const stagesOf = (stage: string): AuditEntry[] => entries.filter((e) => e.stage === stage)

  /** Runs the whole ladder to completion on fake timers. */
  async function drive(promise: Promise<RevokeOutcome>): Promise<RevokeOutcome> {
    await vi.advanceTimersByTimeAsync(120_000)
    return promise
  }

  function polling(statuses: unknown[]): { kh: KeeperHub; checkAndExecute: ReturnType<typeof vi.fn>; getExecutionStatus: ReturnType<typeof vi.fn> } {
    const checkAndExecute = vi
      .fn()
      .mockResolvedValue({ executed: true, executionId: 'e1', condition: CONDITION })
    const getExecutionStatus = vi.fn()
    for (const status of statuses.slice(0, -1)) getExecutionStatus.mockResolvedValueOnce(status)
    getExecutionStatus.mockResolvedValue(statuses.at(-1))
    return { kh: fakeKh({ checkAndExecute, getExecutionStatus }), checkAndExecute, getExecutionStatus }
  }

  it('polls to a terminal state instead of reading the status exactly once', async () => {
    // The false-failure bug in one test: the first two reads are non-terminal.
    const { kh, getExecutionStatus } = polling([
      { executionId: 'e1', status: 'pending' },
      { executionId: 'e1', status: 'running' },
      { executionId: 'e1', status: 'completed', transactionHash: '0xhash', gasUsedWei: '46482' },
    ])
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const outcome = await drive(revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER }))

    expect(getExecutionStatus).toHaveBeenCalledTimes(3)
    expect(outcome.disposition).toBe('confirmed')
    expect(outcome.escalations).toBe(0)
    expect(outcome.error).toBeUndefined()
  })

  it('does NOT call a still-pending execution a failure when the budget expires', async () => {
    // "Still in flight" and "failed" are different claims. Reporting the first
    // as the second is how an operator learns to ignore the alert channel.
    const { kh } = polling([{ executionId: 'e1', status: 'pending' }])
    vi.mocked(readAllowance).mockResolvedValue(500n)

    const outcome = await drive(revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER }))

    expect(outcome.disposition).toBe('pending')
    expect(outcome.error).toMatch(/not confirmed, not failed/)

    // Its OWN stage. Written as `revoke.failed` with a disposition field, this
    // was counted by the dashboard's failure tile and captioned "revoke
    // failed" — the claim ARCHITECTURE.md explicitly promises is never made.
    expect(stagesOf('revoke.failed')).toHaveLength(0)
    const entry = stagesOf('revoke.pending').at(-1)!
    expect(entry['terminal']).toBe(false)
    expect(entry['disposition']).toBe('pending')
    expect(entry['reason']).toMatch(/NOT confirmed failed/)
  })

  it('reports a MINED-but-reverted execution as reverted, quoting the revert reason', async () => {
    const { kh } = polling([
      {
        executionId: 'e1',
        status: 'completed',
        transactionHash: '0xreverted',
        error: 'Error(ERC20: approve to the zero address)',
        receipts: [{ hash: '0xreverted', blockNumber: 9, receiptStatus: '0x0', gasUsed: '21000' }],
      },
    ])
    vi.mocked(readAllowance).mockResolvedValue(500n)

    const outcome = await drive(revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER }))

    expect(outcome.disposition).toBe('reverted')
    expect(outcome.error).toMatch(/approve to the zero address/)
    // A revert is its own stage: it landed on chain and cost gas, which is not
    // what "failed" (never landed) tells an operator.
    expect(stagesOf('revoke.reverted')).toHaveLength(1)
    expect(stagesOf('revoke.failed')).toHaveLength(0)
  })

  it('falls back to a placeholder when a reverted execution carries no reason', async () => {
    const { kh } = polling([
      {
        executionId: 'e1',
        status: 'completed',
        receipts: [{ hash: '0xr', blockNumber: 9, receiptStatus: 'reverted', gasUsed: '21000' }],
      },
    ])
    vi.mocked(readAllowance).mockResolvedValue(500n)

    const outcome = await drive(revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER }))

    expect(outcome.error).toMatch(/no revert reason reported/)
  })

  it('treats a receipt with a SUCCESS status as the confirmation', async () => {
    const { kh } = polling([
      {
        executionId: 'e1',
        status: 'running', // status string lags; the receipt is the truth
        transactionHash: '0xmined',
        receipts: [{ hash: '0xmined', blockNumber: 9, receiptStatus: 'success', gasUsed: '46482' }],
      },
    ])
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const outcome = await drive(revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER }))

    expect(outcome.disposition).toBe('confirmed')
    expect(outcome.transactionHash).toBe('0xmined')
  })

  it('reports a terminal FAILED execution with the reason the API gave', async () => {
    const { kh } = polling([
      { executionId: 'e1', status: 'failed', error: 'insufficient funds for gas' },
    ])
    vi.mocked(readAllowance).mockResolvedValue(500n)

    const outcome = await drive(revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER }))

    expect(outcome.disposition).toBe('failed')
    expect(stagesOf('revoke.failed').at(-1)!['reason']).toMatch(/insufficient funds for gas/)

    // ...and the RETURNED error says the same thing as the trail. This branch
    // covers two endings and outcome.error used to be hardcoded to the other
    // one, so a hard execution failure was handed back as "reported success but
    // allowance is still non-zero" — false on its face, and POST /revoke answers
    // the workflow with this object, so the HTTP body contradicted the audit
    // trail about the same incident.
    expect(outcome.error).toContain('insufficient funds for gas')
    expect(outcome.error).not.toContain('reported success')
    expect(outcome.error).toBe(stagesOf('revoke.failed').at(-1)!['reason'])
  })

  it('treats an unrecognised terminal state as failed, never as confirmed', async () => {
    // A poll hint of 0 says "stop polling". It does NOT say "it worked", and
    // guessing "worked" is the failure mode that makes an audit trail worthless.
    const { kh } = polling([{ executionId: 'e1', status: 'quiesced', pollAfterMs: 0 }])
    vi.mocked(readAllowance).mockResolvedValue(500n)

    const outcome = await drive(revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER }))

    expect(outcome.disposition).toBe('failed')
    expect(stagesOf('revoke.failed').at(-1)!['reason']).toMatch(/execution reported quiesced/)
  })

  it('still reports a failure when the terminal response names no state at all', async () => {
    const { kh } = polling([{ executionId: 'e1', pollAfterMs: 0 }])
    vi.mocked(readAllowance).mockResolvedValue(500n)

    const outcome = await drive(revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER }))

    expect(outcome.disposition).toBe('failed')
    expect(stagesOf('revoke.failed').at(-1)!['reason']).toMatch(/a terminal failure: no reason reported/)
  })

  it('keeps polling when the status endpoint returns no state field at all', async () => {
    const { kh, getExecutionStatus } = polling([
      { executionId: 'e1' },
      { executionId: 'e1', status: 'completed', transactionHash: '0xhash' },
    ])
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const outcome = await drive(revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER }))

    expect(getExecutionStatus).toHaveBeenCalledTimes(2)
    expect(outcome.disposition).toBe('confirmed')
  })

  it('sends a gas-limit buffer on the very first submission', async () => {
    // gasLimitMultiplier was plumbed through the client and passed by nobody.
    const { kh, checkAndExecute } = polling([{ executionId: 'e1', status: 'completed' }])
    vi.mocked(readAllowance).mockResolvedValue(0n)

    await drive(revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER }))

    const arg = checkAndExecute.mock.calls[0]![0] as { action: { gasLimitMultiplier?: string } }
    expect(arg.action.gasLimitMultiplier).toBe('1.2')
  })

  it('climbs the escalation ladder under NEW idempotency keys when nothing lands', async () => {
    // The safety argument is structural, not statistical: the server-side
    // `allowance > 0` condition means the losing submission writes nothing and
    // costs nothing, so racing our own transaction is free.
    const checkAndExecute = vi
      .fn()
      .mockResolvedValueOnce({ executed: true, executionId: 'e1', condition: CONDITION })
      .mockResolvedValueOnce({ executed: true, executionId: 'e2', condition: CONDITION })
      .mockResolvedValueOnce({ executed: true, executionId: 'e3', condition: CONDITION })
    const getExecutionStatus = vi.fn().mockResolvedValue({ executionId: 'x', status: 'pending' })
    vi.mocked(readAllowance).mockResolvedValue(500n)

    const outcome = await drive(
      revokeApproval({
        kh: fakeKh({ checkAndExecute, getExecutionStatus }),
        token: TOKEN,
        owner: OWNER,
        spender: SPENDER,
        idempotencyKey: 'revoke-abc',
      }),
    )

    const submissions = checkAndExecute.mock.calls.map(
      (c) =>
        (c[0] as { action: { gasLimitMultiplier?: string }; idempotencyKey?: string }),
    )
    expect(submissions.map((s) => s.action.gasLimitMultiplier)).toEqual(['1.2', '1.5', '2.0'])
    // A replayed key would return the STUCK execution's cached response inside
    // KeeperHub's 24h window and submit nothing at all.
    expect(submissions.map((s) => s.idempotencyKey)).toEqual([
      'revoke-abc',
      'revoke-abc-esc1',
      'revoke-abc-esc2',
    ])
    expect(outcome.escalations).toBe(2)
    // ...and the poll follows the replacement execution, not the stuck one.
    expect(getExecutionStatus).toHaveBeenLastCalledWith('e3')
  })

  it('escalates without an idempotency key when the caller supplied none', async () => {
    const checkAndExecute = vi
      .fn()
      .mockResolvedValue({ executed: true, executionId: 'e1', condition: CONDITION })
    const getExecutionStatus = vi.fn().mockResolvedValue({ executionId: 'e1', status: 'pending' })
    vi.mocked(readAllowance).mockResolvedValue(500n)

    await drive(
      revokeApproval({
        kh: fakeKh({ checkAndExecute, getExecutionStatus }),
        token: TOKEN,
        owner: OWNER,
        spender: SPENDER,
      }),
    )

    expect(checkAndExecute.mock.calls[1]![0]).not.toHaveProperty('idempotencyKey')
  })

  it('keeps polling the original submission when an escalation is REJECTED', async () => {
    // Escalation is best-effort. Abandoning the poll because the bump was
    // refused would throw away a revoke that is already in flight and paid for.
    const checkAndExecute = vi
      .fn()
      .mockResolvedValueOnce({ executed: true, executionId: 'e1', condition: CONDITION })
      .mockRejectedValue(new Error('idempotency_in_progress'))
    const getExecutionStatus = vi
      .fn()
      .mockResolvedValue({ executionId: 'e1', status: 'pending' })
    vi.mocked(readAllowance).mockResolvedValue(500n)

    const outcome = await drive(
      revokeApproval({
        kh: fakeKh({ checkAndExecute, getExecutionStatus }),
        token: TOKEN,
        owner: OWNER,
        spender: SPENDER,
      }),
    )

    expect(outcome.disposition).toBe('pending')
    expect(getExecutionStatus).toHaveBeenLastCalledWith('e1')
  })

  it('stays on the original execution when the bump finds the allowance already zero', async () => {
    // `executed: false` on the resubmission means the first attempt landed
    // between our poll and our bump — there is no replacement to follow.
    const checkAndExecute = vi
      .fn()
      .mockResolvedValueOnce({ executed: true, executionId: 'e1', condition: CONDITION })
      .mockResolvedValue({ executed: false, condition: { met: false, observedValue: '0' } })
    const getExecutionStatus = vi.fn().mockResolvedValue({ executionId: 'e1', status: 'pending' })
    vi.mocked(readAllowance).mockResolvedValue(500n)

    await drive(
      revokeApproval({
        kh: fakeKh({ checkAndExecute, getExecutionStatus }),
        token: TOKEN,
        owner: OWNER,
        spender: SPENDER,
      }),
    )

    expect(getExecutionStatus).toHaveBeenLastCalledWith('e1')
  })

  it('paces polling on the API poll-interval hint rather than its own cadence', async () => {
    const getExecutionStatus = vi
      .fn()
      .mockResolvedValue({ executionId: 'e1', status: 'pending', pollAfterMs: 3_000 })
    const kh = fakeKh({
      checkAndExecute: vi
        .fn()
        .mockResolvedValue({ executed: true, executionId: 'e1', condition: CONDITION }),
      getExecutionStatus,
    })
    vi.mocked(readAllowance).mockResolvedValue(500n)

    const promise = revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })
    await vi.advanceTimersByTimeAsync(2_999)
    expect(getExecutionStatus).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(getExecutionStatus).toHaveBeenCalledTimes(2)

    await drive(promise)
  })

  it('records gasPriceWei alongside gasUsedWei on a confirmed revoke', async () => {
    // "What did the defense cost?" needs both halves; only one was recorded.
    const { kh } = polling([
      {
        executionId: 'e1',
        status: 'completed',
        transactionHash: '0xhash',
        sponsored: true,
        gasUsedWei: '46482',
        gasPriceWei: '1500000007',
      },
    ])
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const outcome = await drive(revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER }))

    expect(outcome.gasPriceWei).toBe('1500000007')
    const confirmed = stagesOf('revoke.confirmed').at(-1)!
    expect(confirmed['gasPriceWei']).toBe('1500000007')
    expect(confirmed['gasUsedWei']).toBe('46482')
    expect(confirmed['escalations']).toBe(0)
  })
})

/**
 * ── The Permit2 revoke ───────────────────────────────────────────────────────
 *
 * Same execution machinery, a different primitive: `lockdown(TokenSpenderPair[])`
 * zeroes many slots in one transaction where `approve(spender, 0)` zeroes one.
 *
 * What these tests are actually pinning is that batching did not buy speed by
 * spending the project's core claim: the allowance read and the write are still
 * ONE server-side check-and-execute, so there is still no window between
 * deciding and acting.
 */
describe('revokePermit2Allowances — lockdown() through check-and-execute', () => {
  const CONDITION = { met: true, observedValue: '999', targetValue: '0', operator: 'gt' }
  const PAIR_A = { token: TOKEN, spender: SPENDER }
  const PAIR_B = {
    token: '0xtokenB00000000000000000000000000000000' as Address,
    spender: '0xspenderB000000000000000000000000000000' as Address,
  }

  let entries: AuditEntry[]
  let unsubscribe: () => void

  beforeEach(() => {
    vi.mocked(readPermit2Allowance).mockReset()
    entries = []
    unsubscribe = onAudit((entry) => entries.push(entry))
  })

  afterEach(() => {
    unsubscribe()
  })

  const stagesOf = (stage: string): AuditEntry[] => entries.filter((e) => e.stage === stage)

  /** Every slot reads back at `amount`, which is what "did the lockdown land" means. */
  function slotsAt(amount: bigint): void {
    vi.mocked(readPermit2Allowance).mockResolvedValue({
      amount,
      expiration: 1_900_000_000,
      nonce: 4,
    })
  }

  function fakePermit2Kh(overrides: Partial<KeeperHub> = {}): KeeperHub {
    return fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        executionId: 'e1',
        condition: CONDITION,
      }),
      ...overrides,
    })
  }

  it('guards the write with a server-side allowance read — the TOCTOU property, unchanged', async () => {
    const checkAndExecute = vi
      .fn()
      .mockResolvedValue({ executed: true, executionId: 'e1', condition: CONDITION })
    slotsAt(0n)

    await revokePermit2Allowances({
      kh: fakePermit2Kh({ checkAndExecute }),
      owner: OWNER,
      pairs: [PAIR_A, PAIR_B],
    })

    const arg = checkAndExecute.mock.calls[0]![0] as {
      check: { contractAddress: string; functionName: string; functionArgs: unknown[]; abi: unknown }
      condition: { operator: string; value: string }
      action: { contractAddress: string; functionName: string; functionArgs: unknown[]; abi: unknown }
    }

    // The check reads the on-chain helper, NOT Permit2's own getter — and that
    // is the whole fix. `Permit2.allowance` returns (uint160,uint48,uint48), and
    // check-and-execute's condition schema is only {operator, value}: no output
    // index, no tuple path. Guarding on the tuple gives the evaluator nothing to
    // compare, so it reports observedValue undefined, scores `gt 0` false, and
    // SKIPS the write while logging a clean skip. Proved on Sepolia against a
    // real armed grant. If this assertion is ever "corrected" back to
    // PERMIT2_ADDRESS/'allowance', the Permit2 revoke silently stops working.
    expect(arg.check.contractAddress).toBe(GUARD_VIEW)
    expect(arg.check.contractAddress).not.toBe(PERMIT2_ADDRESS)
    expect(arg.check.functionName).toBe(PERMIT2_GUARD_FUNCTION)
    expect(arg.check.functionName).toBe('liveAmountOf')
    expect(arg.check.functionArgs).toEqual([OWNER, PAIR_A.token, PAIR_A.spender])
    expect(arg.check.abi).toBe(PERMIT2_ALLOWANCE_VIEW_ABI_JSON)
    expect(arg.condition).toEqual({ operator: 'gt', value: '0' })

    // ...and the guard is still INSIDE the same check-and-execute as the write.
    // One call, one server-side operation: that is the TOCTOU property, and
    // splitting the read out into a separate request would end it.
    expect(checkAndExecute.mock.calls[0]![0]).toHaveProperty('check')
    expect(checkAndExecute.mock.calls[0]![0]).toHaveProperty('action')

    // ONE lockdown call carrying BOTH pairs. This is the batching advantage the
    // ERC-20 path cannot have: two exposures, one base fee, one transaction.
    expect(checkAndExecute).toHaveBeenCalledTimes(1)
    expect(arg.action.contractAddress).toBe(PERMIT2_ADDRESS)
    expect(arg.action.functionName).toBe('lockdown')
    expect(arg.action.functionArgs).toEqual([
      [
        { token: PAIR_A.token, spender: PAIR_A.spender },
        { token: PAIR_B.token, spender: PAIR_B.spender },
      ],
    ])
    expect(arg.action.abi).toBe(PERMIT2_ABI_JSON)
  })

  it('reports confirmed once every slot in the batch reads zero', async () => {
    slotsAt(0n)

    const outcome = await revokePermit2Allowances({
      kh: fakePermit2Kh(),
      owner: OWNER,
      pairs: [PAIR_A, PAIR_B],
    })

    expect(outcome.executed).toBe(true)
    expect(outcome.disposition).toBe('confirmed')
    expect(outcome.allowanceAfter).toBe(0n)
    expect(outcome.cleared).toEqual([PAIR_A, PAIR_B])
    expect(outcome.transactionHash).toBe('0xhash')
    expect(outcome.explorerUrl).toContain('0xhash')
    expect(stagesOf('revoke.confirmed').at(-1)).toMatchObject({ pairs: 2, cleared: 2 })
  })

  it('confirms each slot against the CHAIN, not against "the transaction succeeded"', async () => {
    // A batch that lands is not the same statement as a batch that worked. Only
    // the slots the chain reports as zero are marked cleared, so the watcher
    // retries exactly the remainder rather than the whole batch or none of it.
    vi.mocked(readPermit2Allowance)
      .mockResolvedValueOnce({ amount: 0n, expiration: 1_900_000_000, nonce: 4 })
      .mockResolvedValue({ amount: 500n, expiration: 1_900_000_000, nonce: 4 })

    const outcome = await revokePermit2Allowances({
      kh: fakePermit2Kh(),
      owner: OWNER,
      pairs: [PAIR_A, PAIR_B],
    })

    expect(outcome.cleared).toEqual([PAIR_A])
    expect(outcome.allowanceAfter).toBe(500n)
    expect(outcome.disposition).toBe('failed')
    expect(outcome.error).toMatch(/still non-zero/)
    expect(stagesOf('revoke.failed').at(-1)!['reason']).toMatch(/still non-zero/)
  })

  it('submits nothing at all for an empty batch', async () => {
    // lockdown over an empty array emits nothing and still pays for a
    // transaction, so an empty batch must never reach KeeperHub.
    const checkAndExecute = vi.fn()

    const outcome = await revokePermit2Allowances({
      kh: fakeKh({ checkAndExecute }),
      owner: OWNER,
      pairs: [],
    })

    expect(checkAndExecute).not.toHaveBeenCalled()
    expect(outcome.executed).toBe(false)
    expect(outcome.pairs).toEqual([])
    expect(outcome.cleared).toEqual([])
    expect(stagesOf('revoke.skipped').at(-1)!['reason']).toBe('empty batch')
  })

  it('spends no gas when the guard slot is already zero at execution time', async () => {
    // Someone else got there first. The batch is skipped whole rather than
    // partially applied, and the watcher rebuilds it from live reads next scan —
    // a delay, never a silent drop.
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: false,
        condition: { met: false, observedValue: '0', targetValue: '0', operator: 'gt' },
      }),
    })

    const outcome = await revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A, PAIR_B] })

    expect(outcome.executed).toBe(false)
    expect(outcome.observedAllowance).toBe('0')
    expect(outcome.cleared).toEqual([])
    // No confirmation read is warranted when nothing was executed.
    expect(readPermit2Allowance).not.toHaveBeenCalled()
    // The wording names BOTH ways the guard can read zero, because liveAmountOf
    // folds the expiry check in: revoked by someone else, or expired since
    // detection. Claiming only the first would misreport the second.
    expect(stagesOf('revoke.skipped').at(-1)!['reason']).toMatch(/guard reads zero at execution time/)
    expect(stagesOf('revoke.skipped').at(-1)!['reason']).toMatch(/expired/)
  })

  it('records which contract and function the guard actually read', async () => {
    // The bug this replaced was invisible in the submit log: the guard looked
    // fine and evaluated nothing. `guardVia` is what makes the next one visible.
    slotsAt(0n)

    await revokePermit2Allowances({ kh: fakePermit2Kh(), owner: OWNER, pairs: [PAIR_A] })

    expect(stagesOf('revoke.submit').at(-1)!['guardVia']).toBe(`${GUARD_VIEW}.liveAmountOf`)
  })

  it('FAILS LOUDLY and submits nothing when the guard helper is not deployed', async () => {
    // The requirement that outranks landing the revoke. The only alternative to
    // a guarded lockdown is an unguarded one, and an unguarded write hands back
    // the exact TOCTOU window this project exists to close. A revoke that does
    // not happen is a bug an operator can see; a revoke that happens without a
    // guard is a silent downgrade of the security claim.
    const checkAndExecute = vi.fn()
    vi.mocked(permit2AllowanceViewAddress).mockImplementation(() => {
      throw new Error('deployments.json records no Permit2AllowanceView address for network "sepolia"')
    })

    const outcome = await revokePermit2Allowances({
      kh: fakeKh({ checkAndExecute }),
      owner: OWNER,
      pairs: [PAIR_A, PAIR_B],
    })

    expect(checkAndExecute).not.toHaveBeenCalled()
    expect(outcome.executed).toBe(false)
    expect(outcome.disposition).toBe('failed')
    expect(outcome.cleared).toEqual([])
    // The batch is reported back in full, so the watcher marks nothing handled
    // and retries every pair once a human deploys the helper.
    expect(outcome.pairs).toEqual([PAIR_A, PAIR_B])
    expect(outcome.error).toMatch(/no Permit2AllowanceView address/)

    const failed = stagesOf('revoke.failed').at(-1)!
    expect(failed['reason']).toMatch(/refusing to submit an unguarded lockdown/)
    expect(failed['terminal']).toBe(true)
    expect(failed['pairs']).toBe(2)
  })

  it('reports a non-Error thrown by the helper lookup without losing it', async () => {
    const checkAndExecute = vi.fn()
    vi.mocked(permit2AllowanceViewAddress).mockImplementation(() => {
      // A bare string, deliberately: this asserts the message survives when
      // whatever failed underneath did not throw an Error.
      // eslint-disable-next-line @typescript-eslint/only-throw-error
      throw 'deployments.json unreadable'
    })

    const outcome = await revokePermit2Allowances({
      kh: fakeKh({ checkAndExecute }),
      owner: OWNER,
      pairs: [PAIR_A],
    })

    expect(checkAndExecute).not.toHaveBeenCalled()
    expect(outcome.error).toBe('deployments.json unreadable')
    expect(outcome.disposition).toBe('failed')
  })

  it('says nothing about a missing helper for an empty batch', async () => {
    // Emptiness is checked first: there is no revoke to refuse, so an undeployed
    // helper is not an error worth raising on a scan that found no exposure.
    vi.mocked(permit2AllowanceViewAddress).mockImplementation(() => {
      throw new Error('not deployed')
    })

    const outcome = await revokePermit2Allowances({ kh: fakeKh(), owner: OWNER, pairs: [] })

    expect(outcome.disposition).toBeUndefined()
    expect(stagesOf('revoke.skipped').at(-1)!['reason']).toBe('empty batch')
  })

  it('omits observedAllowance from a skip that carried no condition', async () => {
    const kh = fakeKh({ checkAndExecute: vi.fn().mockResolvedValue({ executed: false }) })

    const outcome = await revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A] })

    expect(outcome).not.toHaveProperty('observedAllowance')
  })

  it('returns a failed outcome instead of throwing when KeeperHub errors', async () => {
    // The watcher loop must survive a failed batch and retry on the next scan.
    const kh = fakeKh({ checkAndExecute: vi.fn().mockRejectedValue(new Error('gateway timeout')) })

    const outcome = await revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A] })

    expect(outcome.executed).toBe(false)
    expect(outcome.disposition).toBe('failed')
    expect(outcome.error).toBe('gateway timeout')
    expect(stagesOf('revoke.failed').at(-1)).toMatchObject({ action: 'permit2-lockdown', pairs: 1 })
  })

  it('records a non-Error rejection instead of writing "undefined" to the trail', async () => {
    // Rejections off a fetch stack are not always Errors. A bare string would
    // otherwise erase the only record of why the batch never went out.
    const kh = fakeKh({ checkAndExecute: vi.fn().mockRejectedValue('gateway exploded') })

    const outcome = await revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A] })

    expect(outcome.error).toBe('gateway exploded')
    expect(stagesOf('revoke.failed').at(-1)!['error']).toBe('gateway exploded')
  })

  it('skips the status poll and keeps the inline hash when no executionId comes back', async () => {
    const getExecutionStatus = vi.fn()
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        transactionHash: '0xinline',
        condition: CONDITION,
      }),
      getExecutionStatus,
    })
    slotsAt(0n)

    const outcome = await revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A] })

    expect(getExecutionStatus).not.toHaveBeenCalled()
    expect(outcome.transactionHash).toBe('0xinline')
    expect(outcome).not.toHaveProperty('sponsored')
    expect(outcome).not.toHaveProperty('gasUsedWei')
    expect(outcome).not.toHaveProperty('escalations')
  })

  it('reports a confirmed lockdown with no hash and no condition at all', async () => {
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({ executed: true, executionId: 'e1' }),
      getExecutionStatus: vi
        .fn()
        .mockResolvedValue({ executionId: 'e1', status: 'completed', gasUsedWei: '', gasPriceWei: '' }),
    })
    slotsAt(0n)

    const outcome = await revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A] })

    expect(outcome.disposition).toBe('confirmed')
    expect(outcome).not.toHaveProperty('transactionHash')
    expect(outcome).not.toHaveProperty('observedAllowance')
    // Empty strings are "no gas data", not values worth reporting.
    expect(outcome).not.toHaveProperty('gasUsedWei')
    expect(outcome).not.toHaveProperty('gasPriceWei')
  })
})

describe('revokePermit2Allowances — the escalation ladder, reused verbatim', () => {
  const CONDITION = { met: true, observedValue: '999', targetValue: '0', operator: 'gt' }
  const PAIR_A = { token: TOKEN, spender: SPENDER }

  let entries: AuditEntry[]
  let unsubscribe: () => void

  beforeEach(() => {
    vi.mocked(readPermit2Allowance).mockResolvedValue({
      amount: 500n,
      expiration: 1_900_000_000,
      nonce: 4,
    })
    entries = []
    unsubscribe = onAudit((entry) => entries.push(entry))
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
    unsubscribe()
  })

  const stagesOf = (stage: string): AuditEntry[] => entries.filter((e) => e.stage === stage)

  async function drive(promise: Promise<Permit2RevokeOutcome>): Promise<Permit2RevokeOutcome> {
    await vi.advanceTimersByTimeAsync(120_000)
    return promise
  }

  it('climbs the same rungs under NEW idempotency keys when nothing lands', async () => {
    // Racing our own lockdown is free for exactly the reason it is free on the
    // ERC-20 path: the losing submission finds the guard slot at zero, the
    // server-side condition fails, and it writes nothing.
    const checkAndExecute = vi
      .fn()
      .mockResolvedValueOnce({ executed: true, executionId: 'e1', condition: CONDITION })
      .mockResolvedValueOnce({ executed: true, executionId: 'e2', condition: CONDITION })
      .mockResolvedValueOnce({ executed: true, executionId: 'e3', condition: CONDITION })
    const getExecutionStatus = vi.fn().mockResolvedValue({ executionId: 'x', status: 'pending' })

    const outcome = await drive(
      revokePermit2Allowances({
        kh: fakeKh({ checkAndExecute, getExecutionStatus }),
        owner: OWNER,
        pairs: [PAIR_A],
        idempotencyKey: 'permit2-abc',
      }),
    )

    const submissions = checkAndExecute.mock.calls.map(
      (c) => c[0] as { action: { gasLimitMultiplier?: string }; idempotencyKey?: string },
    )
    expect(submissions.map((s) => s.action.gasLimitMultiplier)).toEqual(['1.2', '1.5', '2.0'])
    expect(submissions.map((s) => s.idempotencyKey)).toEqual([
      'permit2-abc',
      'permit2-abc-esc1',
      'permit2-abc-esc2',
    ])

    // Still pending is NOT failed: the transaction may yet land, and the watcher
    // leaves the slots unhandled and retries. Same stage, same reasoning as the
    // ERC-20 path — and no `revoke.failed` row anywhere for the tile to count.
    expect(outcome.disposition).toBe('pending')
    expect(outcome.escalations).toBe(2)
    expect(stagesOf('revoke.failed')).toHaveLength(0)
    expect(stagesOf('revoke.pending').at(-1)).toMatchObject({
      terminal: false,
      disposition: 'pending',
    })
  })

  it('escalates without an idempotency key when the caller gave none', async () => {
    const checkAndExecute = vi
      .fn()
      .mockResolvedValue({ executed: true, executionId: 'e1', condition: CONDITION })
    const getExecutionStatus = vi.fn().mockResolvedValue({ executionId: 'e1', status: 'pending' })

    await drive(
      revokePermit2Allowances({
        kh: fakeKh({ checkAndExecute, getExecutionStatus }),
        owner: OWNER,
        pairs: [PAIR_A],
      }),
    )

    expect(checkAndExecute.mock.calls.every((c) => (c[0] as { idempotencyKey?: string }).idempotencyKey === undefined)).toBe(true)
  })

  it('reports a MINED-but-reverted lockdown as reverted, quoting the reason', async () => {
    const kh = fakeKh({
      checkAndExecute: vi
        .fn()
        .mockResolvedValue({ executed: true, executionId: 'e1', condition: CONDITION }),
      getExecutionStatus: vi.fn().mockResolvedValue({
        executionId: 'e1',
        status: 'completed',
        transactionHash: '0xreverted',
        error: 'Error(ExcessiveInvalidation())',
        sponsored: true,
        gasUsedWei: '52000',
        gasPriceWei: '1500000007',
        receipts: [{ hash: '0xreverted', blockNumber: 9, receiptStatus: '0x0', gasUsed: '52000' }],
      }),
    })

    const outcome = await drive(
      revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A] }),
    )

    expect(outcome.disposition).toBe('reverted')
    expect(outcome.error).toMatch(/ExcessiveInvalidation/)
    expect(outcome.sponsored).toBe(true)
    expect(outcome.gasPriceWei).toBe('1500000007')
    // Landed on chain and cost gas — which is not what "failed" (never landed)
    // tells an operator.
    expect(stagesOf('revoke.reverted')).toHaveLength(1)
    expect(stagesOf('revoke.failed')).toHaveLength(0)
  })
})

/**
 * ── Publishing KeeperHub's executionId ───────────────────────────────────────
 *
 * A transaction hash proves that a revoke landed. It does not prove HOW: read
 * from the explorer alone, the write is a relayer address calling `approve`, and
 * "executed via KeeperHub" is left as an inference. The executionId is the
 * missing half — it addresses KeeperHub's own record of the submission, so the
 * guarded check-and-execute behind the hash can be looked up rather than
 * assumed.
 *
 * The audit trail is the only place that record can be joined to the chain, so
 * every stage that names a transaction names the execution too, on both revoke
 * paths. These tests exist because the field is easy to add to the happy path
 * and easy to forget on the four endings nobody demos.
 */
describe('the audit trail names the KeeperHub execution, not just the transaction', () => {
  const CONDITION = { met: true, observedValue: '999', targetValue: '0', operator: 'gt' }
  const PAIR_A = { token: TOKEN, spender: SPENDER }

  let entries: AuditEntry[]
  let unsubscribe: () => void

  beforeEach(() => {
    entries = []
    unsubscribe = onAudit((entry) => entries.push(entry))
  })

  afterEach(() => unsubscribe())

  const stagesOf = (stage: string): AuditEntry[] => entries.filter((e) => e.stage === stage)
  const lastOf = (stage: string): AuditEntry => stagesOf(stage).at(-1)!

  /** An execution that reaches `status` immediately, so no fake clock is needed. */
  function landsWith(status: Record<string, unknown>): KeeperHub {
    return fakeKh({
      checkAndExecute: vi
        .fn()
        .mockResolvedValue({ executed: true, executionId: 'exec-77', condition: CONDITION }),
      getExecutionStatus: vi.fn().mockResolvedValue({ executionId: 'exec-77', ...status }),
    })
  }

  describe('ERC-20 approve(spender, 0)', () => {
    it('records the executionId on the submit and on the confirmation', async () => {
      const kh = landsWith({ status: 'completed', transactionHash: '0xhash', sponsored: true })
      vi.mocked(readAllowance).mockResolvedValue(0n)

      const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

      expect(outcome.executionId).toBe('exec-77')
      // The submit record is written after the call returns precisely so it can
      // carry this; written before, it could only restate our own arguments.
      expect(lastOf('revoke.submit')['executionId']).toBe('exec-77')
      expect(lastOf('revoke.confirmed')).toMatchObject({
        executionId: 'exec-77',
        txHash: '0xhash',
      })
    })

    it('records it on a reverted execution', async () => {
      const kh = landsWith({
        status: 'completed',
        transactionHash: '0xreverted',
        error: 'Error(ERC20: approve to the zero address)',
        receipts: [{ hash: '0xreverted', blockNumber: 9, receiptStatus: '0x0', gasUsed: '21000' }],
      })
      vi.mocked(readAllowance).mockResolvedValue(500n)

      const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

      expect(outcome.disposition).toBe('reverted')
      expect(lastOf('revoke.reverted')['executionId']).toBe('exec-77')
    })

    it('records it when the execution reports success and the allowance survives', async () => {
      const kh = landsWith({ status: 'completed', transactionHash: '0xhash' })
      vi.mocked(readAllowance).mockResolvedValue(500n)

      await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

      expect(lastOf('revoke.failed')['executionId']).toBe('exec-77')
    })

    it('records it when the poll blows up after the execution was accepted', async () => {
      // The distinction this buys an operator: "we submitted exec-77 and then
      // lost contact with it" is a live transaction to go and look up, whereas a
      // bare error is an incident with nothing to chase.
      const kh = landsWith({ status: 'completed', transactionHash: '0xhash' })
      vi.mocked(readAllowance).mockRejectedValue(new Error('rpc exploded'))

      const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

      expect(outcome.disposition).toBe('failed')
      expect(outcome.executionId).toBe('exec-77')
      expect(lastOf('revoke.failed')).toMatchObject({
        executionId: 'exec-77',
        error: 'rpc exploded',
      })
    })

    it('claims no executionId when the submission never reached KeeperHub', async () => {
      // An id we never received must not be invented, and the outcome must not
      // carry an empty key that reads like one.
      const kh = fakeKh({ checkAndExecute: vi.fn().mockRejectedValue(new Error('gateway timeout')) })

      const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

      expect(outcome).not.toHaveProperty('executionId')
      expect(lastOf('revoke.failed')['executionId']).toBeUndefined()
    })

    it('claims no executionId when check-and-execute returns none', async () => {
      const kh = fakeKh({
        checkAndExecute: vi
          .fn()
          .mockResolvedValue({ executed: true, transactionHash: '0xinline', condition: CONDITION }),
      })
      vi.mocked(readAllowance).mockResolvedValue(0n)

      const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

      expect(outcome.transactionHash).toBe('0xinline')
      expect(outcome).not.toHaveProperty('executionId')
    })

    it('names the execution that LANDED, not the one that was replaced', async () => {
      // Each rung is a separate KeeperHub record. Publishing the original id
      // after an escalation would point a reader at a submission that decided
      // nothing, and it would disagree with the transaction we published.
      vi.useFakeTimers()
      try {
        const checkAndExecute = vi
          .fn()
          .mockResolvedValueOnce({ executed: true, executionId: 'e1', condition: CONDITION })
          .mockResolvedValueOnce({ executed: true, executionId: 'e2', condition: CONDITION })
          .mockResolvedValue({ executed: true, executionId: 'e3', condition: CONDITION })
        const getExecutionStatus = vi
          .fn()
          .mockResolvedValue({ executionId: 'x', status: 'pending' })
        vi.mocked(readAllowance).mockResolvedValue(500n)

        const promise = revokeApproval({
          kh: fakeKh({ checkAndExecute, getExecutionStatus }),
          token: TOKEN,
          owner: OWNER,
          spender: SPENDER,
        })
        await vi.advanceTimersByTimeAsync(120_000)
        const outcome = await promise

        expect(outcome.escalations).toBe(2)
        expect(outcome.executionId).toBe('e3')
        expect(lastOf('revoke.pending')['executionId']).toBe('e3')

        // Three submissions, chained: each rung says which execution it was sent
        // to overtake, so the three KeeperHub records are joinable to one revoke.
        expect(
          stagesOf('revoke.submit').map((e) => [e['executionId'], e['replaces']]),
        ).toEqual([
          ['e1', undefined],
          ['e2', 'e1'],
          ['e3', 'e2'],
        ])
      } finally {
        vi.useRealTimers()
      }
    })
  })

  describe('Permit2 lockdown()', () => {
    beforeEach(() => {
      vi.mocked(readPermit2Allowance).mockReset()
    })

    it('records the executionId on the submit and on the confirmation', async () => {
      const kh = landsWith({ status: 'completed', transactionHash: '0xlock', sponsored: true })
      vi.mocked(readPermit2Allowance).mockResolvedValue({
        amount: 0n,
        expiration: 1_900_000_000,
        nonce: 4,
      })

      const outcome = await revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A] })

      expect(outcome.disposition).toBe('confirmed')
      expect(outcome.executionId).toBe('exec-77')
      expect(lastOf('revoke.submit')).toMatchObject({
        executionId: 'exec-77',
        action: 'permit2-lockdown',
      })
      expect(lastOf('revoke.confirmed')).toMatchObject({
        executionId: 'exec-77',
        txHash: '0xlock',
      })
    })

    it('records it when the batch reports success and a slot survives', async () => {
      const kh = landsWith({ status: 'completed', transactionHash: '0xlock' })
      vi.mocked(readPermit2Allowance).mockResolvedValue({
        amount: 500n,
        expiration: 1_900_000_000,
        nonce: 4,
      })

      await revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A] })

      expect(lastOf('revoke.failed')['executionId']).toBe('exec-77')
    })

    it('records it when the confirmation read blows up after acceptance', async () => {
      const kh = landsWith({ status: 'completed', transactionHash: '0xlock' })
      vi.mocked(readPermit2Allowance).mockRejectedValue(new Error('rpc exploded'))

      const outcome = await revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A] })

      expect(outcome.executionId).toBe('exec-77')
      expect(lastOf('revoke.failed')).toMatchObject({
        executionId: 'exec-77',
        action: 'permit2-lockdown',
      })
    })

    it('claims no executionId when the lockdown never reached KeeperHub', async () => {
      const kh = fakeKh({ checkAndExecute: vi.fn().mockRejectedValue(new Error('gateway timeout')) })

      const outcome = await revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A] })

      expect(outcome).not.toHaveProperty('executionId')
      expect(lastOf('revoke.failed')['executionId']).toBeUndefined()
    })

    it('claims no executionId when check-and-execute returns none', async () => {
      const kh = fakeKh({
        checkAndExecute: vi
          .fn()
          .mockResolvedValue({ executed: true, transactionHash: '0xinline', condition: CONDITION }),
      })
      vi.mocked(readPermit2Allowance).mockResolvedValue({
        amount: 0n,
        expiration: 1_900_000_000,
        nonce: 4,
      })

      const outcome = await revokePermit2Allowances({ kh, owner: OWNER, pairs: [PAIR_A] })

      expect(outcome.transactionHash).toBe('0xinline')
      expect(outcome).not.toHaveProperty('executionId')
    })

    it('names the execution that LANDED, not the one that was replaced', async () => {
      vi.useFakeTimers()
      try {
        const checkAndExecute = vi
          .fn()
          .mockResolvedValueOnce({ executed: true, executionId: 'e1', condition: CONDITION })
          .mockResolvedValueOnce({ executed: true, executionId: 'e2', condition: CONDITION })
          .mockResolvedValue({ executed: true, executionId: 'e3', condition: CONDITION })
        const getExecutionStatus = vi
          .fn()
          .mockResolvedValue({ executionId: 'x', status: 'pending' })
        vi.mocked(readPermit2Allowance).mockResolvedValue({
          amount: 500n,
          expiration: 1_900_000_000,
          nonce: 4,
        })

        const promise = revokePermit2Allowances({
          kh: fakeKh({ checkAndExecute, getExecutionStatus }),
          owner: OWNER,
          pairs: [PAIR_A],
        })
        await vi.advanceTimersByTimeAsync(120_000)
        const outcome = await promise

        expect(outcome.executionId).toBe('e3')
        expect(lastOf('revoke.pending')['executionId']).toBe('e3')
        expect(
          stagesOf('revoke.submit').map((e) => [e['executionId'], e['replaces']]),
        ).toEqual([
          ['e1', undefined],
          ['e2', 'e1'],
          ['e3', 'e2'],
        ])
      } finally {
        vi.useRealTimers()
      }
    })
  })
})
