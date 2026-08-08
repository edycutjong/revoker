import type { Address } from 'viem'
import { audit } from './audit.js'
import { readAllowance } from './chain.js'
import { explorerTxUrl, sleep, type ExecutionStatus, type KeeperHub } from './keeperhub.js'

/**
 * The revoke action.
 *
 * The whole design decision lives here: the allowance re-read and the
 * `approve(spender, 0)` are one server-side operation via check-and-execute,
 * not a read followed by a write. A read-then-write agent has a window between
 * deciding and acting, and that window is precisely what a drainer watching the
 * mempool needs. Closing it is the difference between a security agent and a
 * script that usually wins.
 */

const ALLOWANCE_ABI = [
  {
    inputs: [
      { name: 'owner', type: 'address' },
      { name: 'spender', type: 'address' },
    ],
    name: 'allowance',
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
]

const APPROVE_ABI = [
  {
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'value', type: 'uint256' },
    ],
    name: 'approve',
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
]

/**
 * ── Gas handling: the escalation ladder ──────────────────────────────────────
 *
 * What KeeperHub actually lets us control. The direct-execution API takes no
 * `gasPrice`, no `maxFeePerGas` and no `maxPriorityFeePerGas` on
 * check-and-execute; its docs state that "gas pricing (base fee, priority fee)
 * is handled automatically", and the only fee-adjacent field on the wire is
 * `gasLimitMultiplier`. So we do not get to name a tip. What we DO get is that
 * every fresh submission is re-priced by KeeperHub's oracle against the base
 * fee that is current *at that moment* — which, if our first attempt is stuck
 * behind a fee spike, is by definition above the price that stranded it.
 * Resubmitting IS the fee bump this API exposes.
 *
 *   rung 0   t=0s     first submission,   gasLimitMultiplier 1.2
 *   rung 1   t=24s    resubmit,           gasLimitMultiplier 1.5
 *   rung 2   t=48s    resubmit,           gasLimitMultiplier 2.0
 *   give up  t=75s    report "pending", explicitly NOT "failed"
 *
 * 24s is two Sepolia/mainnet blocks and sits right on our measured p95 response
 * of 25.17s (BENCHMARK.md): past it, "slow" has become "stuck". The widening
 * gas limit rides along so that a shifting fee market cannot turn a late
 * inclusion into an out-of-gas revert as well.
 *
 * Racing our own transaction is free here rather than reckless, and that is a
 * property of the design, not luck: the server-side `allowance > 0` condition
 * means whichever submission loses the race observes a zero allowance, skips
 * the write entirely, and costs nothing. Each rung must carry a NEW idempotency
 * key — replaying the original would return the stuck execution's cached
 * response inside KeeperHub's 24h window instead of submitting anything.
 */
const FIRST_GAS_LIMIT_MULTIPLIER = '1.2'
const ESCALATION_RUNGS = ['1.5', '2.0'] as const
/** ~2 blocks. Past this the transaction is not slow, it is stranded. */
const ESCALATE_AFTER_MS = 24_000
/** Total time we will wait for a landing before reporting "still pending". */
const LANDING_BUDGET_MS = 75_000
/** Poll cadence while the transaction could still land inside our p95. */
const POLL_FAST_MS = 1_000
/** ...and after, so one revoke cannot eat the 60 req/min the watcher shares. */
const POLL_SLOW_MS = 5_000

/** Direct-execution status values meaning "done, and it worked". */
const DONE_STATES = new Set(['completed', 'success', 'confirmed'])
/** ...and "done, and it did not". */
const FAILED_STATES = new Set(['failed', 'error', 'cancelled'])

/**
 * How the execution ended, from KeeperHub's point of view.
 *
 * `pending` is the one that matters: it means our budget expired while the
 * execution was still non-terminal. That is not a failure — the transaction may
 * yet land — and reporting it as one is exactly the false alarm this module
 * used to raise by reading the status endpoint exactly once.
 */
export type RevokeDisposition = 'confirmed' | 'reverted' | 'failed' | 'pending'

export interface RevokeOutcome {
  executed: boolean
  transactionHash?: string
  explorerUrl?: string
  /** Detect-to-confirmed latency in milliseconds. The headline number. */
  latencyMs: number
  observedAllowance?: string
  allowanceAfter?: bigint
  sponsored?: boolean
  gasUsedWei?: string
  /** Effective price per unit of gas the execution actually paid. */
  gasPriceWei?: string
  /** How many rungs of the ladder the landing needed. 0 = landed on the first try. */
  escalations?: number
  disposition?: RevokeDisposition
  error?: string
}

/**
 * Receipt status is a string on the wire and its spelling varies by chain
 * adapter. Treat only the known-good spellings as success: mistaking a revert
 * for a confirmation is the one mistake this agent must never make.
 */
function receiptSucceeded(receiptStatus: string): boolean {
  return ['success', 'succeeded', '1', '0x1'].includes(receiptStatus.toLowerCase())
}

/**
 * Terminal disposition, or undefined while the execution is still in flight.
 *
 * A receipt is the strongest evidence available: it means the transaction was
 * MINED, and `receiptStatus` then says whether it did what we asked. Only when
 * there is no receipt do we fall back to the status string.
 */
function classify(status: ExecutionStatus): Exclude<RevokeDisposition, 'pending'> | undefined {
  const receipts = status.receipts ?? []
  if (receipts.length > 0) {
    return receipts.every((r) => receiptSucceeded(r.receiptStatus)) ? 'confirmed' : 'reverted'
  }

  const state = (status.status ?? '').toLowerCase()
  if (FAILED_STATES.has(state)) return 'failed'
  if (DONE_STATES.has(state)) return 'confirmed'

  // A poll hint of 0 is the API telling us it is done. Trust it to stop
  // polling, but an unrecognised terminal state with no receipt is a failure,
  // not a success we get to claim.
  if (status.pollAfterMs === 0) return 'failed'
  return undefined
}

/** Honour the API's own pacing hint; otherwise poll fast, then back off. */
function pollDelayMs(elapsedMs: number, hintMs: number | undefined): number {
  return hintMs ?? (elapsedMs < ESCALATE_AFTER_MS ? POLL_FAST_MS : POLL_SLOW_MS)
}

interface Landing {
  disposition: RevokeDisposition
  status: ExecutionStatus
  escalations: number
}

/**
 * Poll an execution to a terminal state, escalating along the ladder above if
 * it does not get there in time.
 *
 * Before this existed the status endpoint was read exactly once, and a
 * transaction that was merely still pending was reported as a hard failure.
 */
async function awaitLanding(
  kh: KeeperHub,
  executionId: string,
  escalate: (rung: number, gasLimitMultiplier: string) => Promise<string | undefined>,
): Promise<Landing> {
  const startedAt = Date.now()
  let current = executionId
  let escalations = 0
  let escalateAt = startedAt + ESCALATE_AFTER_MS

  for (;;) {
    const status = await kh.getExecutionStatus(current)

    const disposition = classify(status)
    if (disposition) return { disposition, status, escalations }

    const now = Date.now()
    if (now - startedAt >= LANDING_BUDGET_MS) {
      return { disposition: 'pending', status, escalations }
    }

    const nextRung = ESCALATION_RUNGS[escalations]
    if (now >= escalateAt && nextRung !== undefined) {
      escalations += 1
      escalateAt = now + ESCALATE_AFTER_MS
      try {
        const replacement = await escalate(escalations, nextRung)
        // No replacement id means the resubmission's `allowance > 0` condition
        // was already false — i.e. the original landed while we were asking.
        // Keep polling the original, which is about to report terminal.
        if (replacement !== undefined) current = replacement
      } catch {
        // Escalation is best-effort. If KeeperHub rejects the extra submission
        // the original is still in flight, and abandoning the poll over it
        // would throw away the revoke we already paid for.
      }
    }

    await sleep(pollDelayMs(now - startedAt, status.pollAfterMs))
  }
}

export async function revokeApproval(input: {
  kh: KeeperHub
  token: Address
  owner: Address
  spender: Address
  /** Deduplicates retries of the same logical revoke within KeeperHub's 24h window. */
  idempotencyKey?: string
  detectedAt?: number
}): Promise<RevokeOutcome> {
  const { kh, token, owner, spender } = input
  const startedAt = input.detectedAt ?? Date.now()

  const submit = (gasLimitMultiplier: string, idempotencyKey?: string) =>
    kh.checkAndExecute({
      check: {
        contractAddress: token,
        functionName: 'allowance',
        functionArgs: [owner, spender],
        abi: ALLOWANCE_ABI,
      },
      // Only revoke if there is still something to revoke. If another actor
      // already zeroed it, the condition fails and no gas is spent.
      condition: { operator: 'gt', value: '0' },
      action: {
        contractAddress: token,
        functionName: 'approve',
        functionArgs: [spender, '0'],
        abi: APPROVE_ABI,
        gasLimitMultiplier,
      },
      ...(idempotencyKey ? { idempotencyKey } : {}),
    })

  audit('revoke.submit', {
    token,
    owner,
    spender,
    method: 'check-and-execute',
    gasLimitMultiplier: FIRST_GAS_LIMIT_MULTIPLIER,
  })

  try {
    const result = await submit(FIRST_GAS_LIMIT_MULTIPLIER, input.idempotencyKey)

    if (!result.executed) {
      const latencyMs = Date.now() - startedAt
      audit('revoke.skipped', {
        token,
        spender,
        reason: 'allowance already zero at execution time',
        observed: result.condition?.observedValue,
        latencyMs,
      })
      return { executed: false, latencyMs, observedAllowance: result.condition?.observedValue }
    }

    // check-and-execute returns before the hash is attached; the execution
    // record is the authoritative source for it.
    let hash = result.transactionHash
    let sponsored: boolean | undefined
    let gasUsedWei: string | undefined
    let gasPriceWei: string | undefined
    let landing: Landing | undefined

    if (result.executionId) {
      landing = await awaitLanding(kh, result.executionId, async (rung, gasLimitMultiplier) => {
        audit('revoke.submit', {
          token,
          owner,
          spender,
          method: 'check-and-execute',
          escalation: rung,
          gasLimitMultiplier,
          reason: `no terminal state after ${ESCALATE_AFTER_MS / 1_000}s (~2 blocks) — resubmitting at the current base fee`,
        })
        const bumped = await submit(
          gasLimitMultiplier,
          input.idempotencyKey ? `${input.idempotencyKey}-esc${rung}` : undefined,
        )
        return bumped.executionId
      })
      hash = landing.status.transactionHash ?? hash
      sponsored = landing.status.sponsored
      gasUsedWei = landing.status.gasUsedWei
      gasPriceWei = landing.status.gasPriceWei
    }

    // Confirm against the chain rather than trusting the execution report.
    const allowanceAfter = await readAllowance(token, owner, spender)
    const latencyMs = Date.now() - startedAt

    const outcome: RevokeOutcome = {
      executed: true,
      latencyMs,
      allowanceAfter,
      ...(hash ? { transactionHash: hash, explorerUrl: explorerTxUrl(hash) } : {}),
      ...(result.condition ? { observedAllowance: result.condition.observedValue } : {}),
      ...(sponsored !== undefined ? { sponsored } : {}),
      ...(gasUsedWei ? { gasUsedWei } : {}),
      ...(gasPriceWei ? { gasPriceWei } : {}),
      ...(landing ? { escalations: landing.escalations } : {}),
    }

    // The chain outranks the execution record: if the allowance is gone it is
    // gone, whichever rung of the ladder actually landed.
    if (allowanceAfter === 0n) {
      outcome.disposition = 'confirmed'
      audit('revoke.confirmed', {
        token,
        spender,
        txHash: hash,
        explorerUrl: outcome.explorerUrl,
        latencyMs,
        sponsored,
        gasUsedWei,
        gasPriceWei,
        escalations: landing?.escalations,
        allowanceAfter: '0',
      })
    } else if (landing?.disposition === 'reverted') {
      // Mined, and it failed on chain. Distinct from never landing at all, and
      // the only case where a revert reason exists to report.
      const reason = landing.status.error ?? 'no revert reason reported'
      outcome.disposition = 'reverted'
      outcome.error = `revoke reverted on chain: ${reason}`
      audit('revoke.reverted', {
        token,
        spender,
        txHash: hash,
        reason,
        gasUsedWei,
        gasPriceWei,
        escalations: landing.escalations,
        allowanceAfter: allowanceAfter.toString(),
        latencyMs,
      })
    } else if (landing?.disposition === 'pending') {
      // NOT a failure, and the audit entry has to say so out loud: the budget
      // expired while the execution was still in flight, so the transaction may
      // still land. The watcher leaves the exposure unhandled and retries next
      // scan, which is correct either way.
      outcome.disposition = 'pending'
      outcome.error = 'still pending at poll timeout — not confirmed, not failed'
      audit('revoke.failed', {
        token,
        spender,
        txHash: hash,
        terminal: false,
        disposition: 'pending',
        reason: `execution had not reached a terminal state after ${LANDING_BUDGET_MS / 1_000}s and ${ESCALATION_RUNGS.length} fee escalations — still pending, NOT confirmed failed; it may still land`,
        escalations: landing.escalations,
        allowanceAfter: allowanceAfter.toString(),
        latencyMs,
      })
    } else {
      // Either the execution reported a hard failure, or it reported success
      // and the allowance survived anyway. Both are failures; report which.
      const reason =
        landing?.disposition === 'failed'
          ? `execution reported ${landing.status.status || 'a terminal failure'}: ${landing.status.error ?? 'no reason reported'}`
          : 'execution reported success but allowance is still non-zero'
      outcome.disposition = 'failed'
      outcome.error = 'allowance still non-zero after reported success'
      audit('revoke.failed', {
        token,
        spender,
        txHash: hash,
        terminal: true,
        reason,
        allowanceAfter: allowanceAfter.toString(),
        latencyMs,
      })
    }

    return outcome
  } catch (error) {
    const latencyMs = Date.now() - startedAt
    const message = error instanceof Error ? error.message : String(error)
    audit('revoke.failed', { token, spender, terminal: true, error: message, latencyMs })
    return { executed: false, latencyMs, disposition: 'failed', error: message }
  }
}
