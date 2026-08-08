import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import type { Address } from 'viem'
import { onAudit, type AuditEntry } from '../src/audit.js'

vi.mock('../src/chain.js', async () => {
  const actual = await vi.importActual<typeof import('../src/chain.js')>('../src/chain.js')
  return { ...actual, readAllowance: vi.fn() }
})

const { readAllowance } = await import('../src/chain.js')
const { revokeApproval } = await import('../src/revoke.js')
import type { RevokeOutcome } from '../src/revoke.js'
import type { KeeperHub } from '../src/keeperhub.js'

const TOKEN = '0xtoken000000000000000000000000000000000' as Address
const OWNER = '0xowner000000000000000000000000000000000' as Address
const SPENDER = '0xspender0000000000000000000000000000000' as Address

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

    const entry = stagesOf('revoke.failed').at(-1)!
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
