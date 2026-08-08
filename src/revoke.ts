import type { Address } from 'viem'
import { audit } from './audit.js'
import { readAllowance } from './chain.js'
import { explorerTxUrl, sleep, type ExecutionStatus, type KeeperHub } from './keeperhub.js'
import {
  PERMIT2_ABI_JSON,
  PERMIT2_ADDRESS,
  PERMIT2_ALLOWANCE_VIEW_ABI_JSON,
  PERMIT2_GUARD_FUNCTION,
  permit2AllowanceViewAddress,
  readPermit2Allowance,
  type Permit2Pair,
} from './permit2.js'

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
 * ── Gas handling: the escalation ladder, and what it is NOT ──────────────────
 *
 * What KeeperHub actually lets us control. The direct-execution API takes no
 * `gasPrice`, no `maxFeePerGas` and no `maxPriorityFeePerGas` on
 * check-and-execute; its docs state that "gas pricing (base fee, priority fee)
 * is handled automatically", and the only fee-adjacent field on the wire is
 * `gasLimitMultiplier`. That is not an oversight on our side of the wire: the
 * live MCP schema for `execute_contract_call` DOES carry a `priority_fee_gwei`
 * ("bypasses the chain's default min/max priority-fee clamp") and the schema
 * for `execute_check_and_execute` does not. The guarded path — the only one
 * this module is willing to use, because it is the one without a TOCTOU window
 * — is precisely the path with no tip control.
 *
 *   rung 0   t=0s     first submission,   gasLimitMultiplier 1.2
 *   rung 1   t=30s    resubmit,           gasLimitMultiplier 1.5
 *   rung 2   t=60s    resubmit,           gasLimitMultiplier 2.0
 *   give up  t=75s    report "pending", explicitly NOT "failed"
 *
 * ── The nonce question, answered honestly ────────────────────────────────────
 *
 * This ladder used to be described as "the resubmission IS the fee bump". That
 * claim only holds if KeeperHub REPLACES the stranded transaction at the same
 * nonce. If a resubmission is allocated a fresh nonce instead, rung 1 queues
 * *behind* rung 0 and structurally cannot be mined first, so it bumps nothing.
 *
 * KeeperHub does not document which of the two it does. The entire published
 * corpus says one thing about nonces — an FAQ sentence listing "transaction
 * retries, nonce management" among its production features — and the
 * direct-execution API reference does not mention a nonce at all: no request
 * field, no response field, nothing on the status endpoint. The live MCP
 * schemas agree; there is no way for a caller to name a nonce or to ask which
 * one an execution used. Each rung here is a separate check-and-execute under a
 * distinct idempotency key, so it is a separate execution record, and nothing
 * in the API states that KeeperHub folds those into one nonce slot.
 *
 * So this is NOT claimed to be a guaranteed fee bump. What the ladder provably
 * buys, with no assumption about nonce handling at all:
 *
 *   1. A WIDER GAS LIMIT on each retry (1.2 -> 1.5 -> 2.0), so a fee market
 *      that moves under a late inclusion cannot also turn it into an
 *      out-of-gas revert.
 *   2. A SECOND GUARDED ATTEMPT re-priced by KeeperHub's oracle against the
 *      base fee current at that moment. If the first attempt is stranded and
 *      the retry does get an independent nonce, this is the attempt that can
 *      land on its own.
 *   3. A LOSER THAT COSTS NOTHING, whenever the winner lands first: the
 *      server-side `allowance > 0` condition is evaluated before signing, so a
 *      rung submitted after the allowance is already zero performs no write and
 *      spends no gas. (Two rungs whose conditions are both evaluated while the
 *      allowance is still non-zero do both submit; the second is then a no-op
 *      `approve(spender, 0)` that still pays its base gas. That is the honest
 *      worst case, and it is bounded by the two rungs above.)
 *
 * 30s is two and a half Sepolia/mainnet blocks and sits ABOVE the slowest
 * healthy response we have measured — p95 25.17s, max 26.55s over 25 live
 * cycles (BENCHMARK.md). The previous 24s sat below both, so more than 5% of
 * perfectly healthy executions tripped the ladder and paid for a rung they
 * never needed. Past 30s, "slow" has genuinely become "stuck".
 *
 * Each rung must carry a NEW idempotency key — replaying the original would
 * return the stuck execution's cached response inside KeeperHub's 24h window
 * instead of submitting anything.
 */
const FIRST_GAS_LIMIT_MULTIPLIER = '1.2'
const ESCALATION_RUNGS = ['1.5', '2.0'] as const
/** ~2.5 blocks, and above the 26.55s slowest healthy landing we have measured. */
const ESCALATE_AFTER_MS = 30_000
/** Total time we will wait for a landing before reporting "still pending". */
const LANDING_BUDGET_MS = 75_000
/** Poll cadence while the transaction could still land inside the first rung. */
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
 * ── The four endings, worded once ────────────────────────────────────────────
 *
 * Both revoke paths (ERC-20 `approve(spender, 0)` and Permit2 `lockdown`) have
 * to classify the same four outcomes, and the wording of those verdicts is the
 * audit trail. Two independently written copies would eventually disagree about
 * what "confirmed" means, which is the one judgement in this module that must
 * never be made twice.
 */
const PENDING_ERROR = 'still pending at poll timeout — not confirmed, not failed'

function pendingReason(escalations: number): string {
  return `execution had not reached a terminal state after ${LANDING_BUDGET_MS / 1_000}s and ${escalations} fee escalations — still pending, NOT confirmed failed; it may still land`
}

/** A mined-but-reverted execution: the only case where a revert reason exists. */
function revertReason(status: ExecutionStatus): string {
  return status.error ?? 'no revert reason reported'
}

/**
 * Either the execution reported a hard failure, or it reported success and the
 * allowance survived anyway. Both are failures; this says which.
 */
function failureReason(landing: Landing | undefined): string {
  return landing?.disposition === 'failed'
    ? `execution reported ${landing.status.status || 'a terminal failure'}: ${landing.status.error ?? 'no reason reported'}`
    : 'execution reported success but allowance is still non-zero'
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
          reason: `no terminal state after ${ESCALATE_AFTER_MS / 1_000}s (~2.5 blocks, above our measured max) — resubmitting at the current base fee, on a wider gas limit`,
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
      const reason = revertReason(landing.status)
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
      outcome.error = PENDING_ERROR
      // Its own stage, not `revoke.failed` with a disposition field nobody
      // reads. Written as a failure, the dashboard counted it in the failure
      // tile and captioned the row "revoke failed" — contradicting, on the one
      // screen a judge looks at, the guarantee that a pending execution is
      // never reported as failed.
      audit('revoke.pending', {
        token,
        spender,
        txHash: hash,
        terminal: false,
        disposition: 'pending',
        reason: pendingReason(ESCALATION_RUNGS.length),
        escalations: landing.escalations,
        allowanceAfter: allowanceAfter.toString(),
        latencyMs,
      })
    } else {
      // Either the execution reported a hard failure, or it reported success
      // and the allowance survived anyway. Both are failures; report which.
      const reason = failureReason(landing)
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

/**
 * ── The Permit2 revoke: lockdown() through the same check-and-execute ────────
 *
 * `lockdown(TokenSpenderPair[])` zeroes the `amount` on any number of
 * (token, spender) slots in ONE transaction. That is a real structural
 * advantage over the ERC-20 path, which needs one `approve(spender, 0)`
 * transaction per exposure and pays a base fee for each: a wallet with eight
 * poisoned Permit2 grants is eight transactions and eight chances to be
 * front-run on the ERC-20 model, and one transaction here.
 *
 * The guard is the part that matters, and it is deliberately identical in kind
 * to the ERC-20 path — the TOCTOU-free property is the project's core claim and
 * a second, looser write path would quietly retire it. The allowance read and
 * the lockdown are one server-side operation: KeeperHub re-reads the live
 * exposure and only then submits, so there is no window between deciding and
 * acting for a drainer watching the mempool.
 *
 * Two honest consequences of batching a single-slot guard:
 *
 *   1. The condition can only watch ONE slot. It watches the first pair in the
 *      batch. If that slot is zeroed by someone else between our read and
 *      KeeperHub's, the whole batch is skipped rather than partially applied —
 *      no gas is spent and the watcher rebuilds the batch from live reads on
 *      the next scan, so the remaining pairs are picked up seconds later. A
 *      skipped batch is a delay, never a silent drop.
 *   2. `lockdown` on an already-zero slot is a no-op write, not a revert. That
 *      is what makes the escalation ladder above safe to reuse verbatim: a
 *      resubmission that loses the race finds the guard slot at zero, the
 *      condition fails, and nothing is submitted at all.
 *
 * ── Why the guard does NOT read Permit2.allowance ────────────────────────────
 *
 * This used to point the check straight at Permit2's own
 * `allowance(owner, token, spender)` and assume the condition would be compared
 * against the first of its three return values. It is not, and a live Sepolia
 * run is what proved it: an armed, unlimited, correctly-detected grant produced
 *
 *     revoke.skipped method=permit2-lockdown pairs=1
 *       reason=guard slot already zero at execution time observed=undefined
 *
 * and the slot was still armed afterwards, re-read from a public RPC.
 *
 * The cause is the API's condition schema, not this call site. KeeperHub's
 * `check-and-execute` condition is exactly `{operator, value}` — there is no
 * output index, no tuple path, no member selector anywhere in it. Permit2's
 * getter returns THREE values `(uint160 amount, uint48 expiration, uint48
 * nonce)`, so the evaluator has no scalar to compare, reports `observedValue:
 * undefined`, scores `gt 0` as false, and skips the write. A guard that silently
 * declines to fire and logs a tidy success is the worst possible shape for this
 * failure, which is exactly why it took a real transaction to find.
 *
 * The fix keeps the property and changes only WHAT is read: a minimal, ownerless,
 * immutable on-chain view (contracts/src/Permit2AllowanceView.sol) flattens the
 * tuple to a single `uint160`, and the guard reads that. The action is still
 * `Permit2.lockdown(...)` at the canonical address, and both still sit inside the
 * SAME check-and-execute — so the read and the write remain one atomic
 * server-side operation and the TOCTOU claim is untouched. The helper is a pure
 * pass-through that reads canonical Permit2 at call time, so it cannot go stale
 * or disagree with the slot the action zeroes.
 *
 * `condition.observedValue` is still recorded on the outcome and in the audit
 * trail. That field is what made this diagnosable — an `undefined` there is the
 * signature of a guard reading a shape the API cannot evaluate — so it stays.
 */
export interface Permit2RevokeOutcome extends RevokeOutcome {
  /** Every slot the lockdown call was asked to zero. */
  pairs: Permit2Pair[]
  /**
   * The slots the chain confirms are now zero. The watcher marks only these
   * handled, so a partially-applied batch is retried for exactly the remainder.
   */
  cleared: Permit2Pair[]
}

export async function revokePermit2Allowances(input: {
  kh: KeeperHub
  owner: Address
  pairs: readonly Permit2Pair[]
  /** Deduplicates retries of the same logical batch within KeeperHub's 24h window. */
  idempotencyKey?: string
  detectedAt?: number
}): Promise<Permit2RevokeOutcome> {
  const { kh, owner } = input
  const pairs = [...input.pairs]
  const startedAt = input.detectedAt ?? Date.now()

  // The guard slot. An empty batch has none, and submitting a lockdown over an
  // empty array would spend gas emitting nothing at all.
  const guard = pairs[0]
  if (guard === undefined) {
    const latencyMs = Date.now() - startedAt
    audit('revoke.skipped', { method: 'permit2-lockdown', reason: 'empty batch', latencyMs })
    return { executed: false, latencyMs, pairs: [], cleared: [] }
  }

  // Resolve the guard helper BEFORE anything is submitted, and fail loudly if it
  // is not deployed. There is deliberately no fallback: the only other way to
  // reach lockdown from here is an unguarded write, and shipping the revoke
  // without its check-and-execute condition would trade away the exact property
  // this module exists to provide. A revoke that does not happen is a bug an
  // operator can see and fix; a revoke that happens without a guard is the
  // TOCTOU window back, silently.
  let guardAddress: Address
  try {
    guardAddress = permit2AllowanceViewAddress()
  } catch (error) {
    const latencyMs = Date.now() - startedAt
    const message = error instanceof Error ? error.message : String(error)
    audit('revoke.failed', {
      owner,
      action: 'permit2-lockdown',
      pairs: pairs.length,
      terminal: true,
      reason: 'Permit2 guard helper is not deployed — refusing to submit an unguarded lockdown',
      error: message,
      latencyMs,
    })
    return { executed: false, latencyMs, pairs, cleared: [], disposition: 'failed', error: message }
  }

  const submit = (gasLimitMultiplier: string, idempotencyKey?: string) =>
    kh.checkAndExecute({
      check: {
        // The helper, NOT Permit2 itself — see the note above. Permit2's
        // allowance() returns a 3-tuple and this API's condition schema has no
        // way to select a member from it, so guarding on it evaluates nothing
        // and skips the write while logging a success.
        contractAddress: guardAddress,
        functionName: PERMIT2_GUARD_FUNCTION,
        functionArgs: [owner, guard.token, guard.spender],
        abi: PERMIT2_ALLOWANCE_VIEW_ABI_JSON,
      },
      condition: { operator: 'gt', value: '0' },
      action: {
        contractAddress: PERMIT2_ADDRESS,
        functionName: 'lockdown',
        // One argument: the TokenSpenderPair[]. Passed as objects rather than
        // positional arrays because the ABI names both components, which is the
        // form every encoder accepts for a named tuple.
        functionArgs: [pairs.map((pair) => ({ token: pair.token, spender: pair.spender }))],
        abi: PERMIT2_ABI_JSON,
        gasLimitMultiplier,
      },
      ...(idempotencyKey ? { idempotencyKey } : {}),
    })

  audit('revoke.submit', {
    owner,
    method: 'check-and-execute',
    action: 'permit2-lockdown',
    pairs: pairs.length,
    guard: `${guard.token}:${guard.spender}`,
    // Which contract and function the server-side condition actually reads.
    // Recorded because the last bug here was invisible in the submit log: the
    // guard looked right and evaluated nothing.
    guardVia: `${guardAddress}.${PERMIT2_GUARD_FUNCTION}`,
    gasLimitMultiplier: FIRST_GAS_LIMIT_MULTIPLIER,
  })

  try {
    const result = await submit(FIRST_GAS_LIMIT_MULTIPLIER, input.idempotencyKey)

    if (!result.executed) {
      const latencyMs = Date.now() - startedAt
      audit('revoke.skipped', {
        method: 'permit2-lockdown',
        pairs: pairs.length,
        // Zero now means one of TWO things, and the wording says so rather than
        // implying only the first: the slot was revoked by someone else, or it
        // expired between detection and execution. `liveAmountOf` folds the
        // expiry check in, so an expired grant reads zero and correctly costs
        // no gas. `observed` distinguishes them after the fact — and an
        // `undefined` there means the guard evaluated nothing at all, which is
        // the bug this path was rebuilt to make impossible.
        reason:
          'guard reads zero at execution time (revoked elsewhere, or expired) — ' +
          'batch rebuilt on the next scan',
        observed: result.condition?.observedValue,
        latencyMs,
      })
      return {
        executed: false,
        latencyMs,
        pairs,
        cleared: [],
        ...(result.condition ? { observedAllowance: result.condition.observedValue } : {}),
      }
    }

    let hash = result.transactionHash
    let sponsored: boolean | undefined
    let gasUsedWei: string | undefined
    let gasPriceWei: string | undefined
    let landing: Landing | undefined

    if (result.executionId) {
      landing = await awaitLanding(kh, result.executionId, async (rung, gasLimitMultiplier) => {
        audit('revoke.submit', {
          owner,
          method: 'check-and-execute',
          action: 'permit2-lockdown',
          pairs: pairs.length,
          escalation: rung,
          gasLimitMultiplier,
          reason: `no terminal state after ${ESCALATE_AFTER_MS / 1_000}s (~2.5 blocks, above our measured max) — resubmitting at the current base fee, on a wider gas limit`,
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

    // Confirm every slot against the chain rather than trusting the execution
    // report — per slot, because a batch can land partially in principle and
    // "the transaction succeeded" is not the same statement as "this allowance
    // is gone".
    const observed = await Promise.all(
      pairs.map(async (pair) => ({
        pair,
        state: await readPermit2Allowance(owner, pair.token, pair.spender),
      })),
    )
    const cleared = observed.filter((entry) => entry.state.amount === 0n).map((e) => e.pair)
    const remaining = observed.reduce((sum, entry) => sum + entry.state.amount, 0n)
    const latencyMs = Date.now() - startedAt

    const outcome: Permit2RevokeOutcome = {
      executed: true,
      latencyMs,
      allowanceAfter: remaining,
      pairs,
      cleared,
      ...(hash ? { transactionHash: hash, explorerUrl: explorerTxUrl(hash) } : {}),
      ...(result.condition ? { observedAllowance: result.condition.observedValue } : {}),
      ...(sponsored !== undefined ? { sponsored } : {}),
      ...(gasUsedWei ? { gasUsedWei } : {}),
      ...(gasPriceWei ? { gasPriceWei } : {}),
      ...(landing ? { escalations: landing.escalations } : {}),
    }

    const detail = {
      owner,
      action: 'permit2-lockdown',
      txHash: hash,
      pairs: pairs.length,
      cleared: cleared.length,
      latencyMs,
    }

    // The chain outranks the execution record, exactly as in revokeApproval:
    // every slot at zero is a confirmed revoke whichever rung landed it.
    if (remaining === 0n) {
      outcome.disposition = 'confirmed'
      audit('revoke.confirmed', {
        ...detail,
        explorerUrl: outcome.explorerUrl,
        sponsored,
        gasUsedWei,
        gasPriceWei,
        escalations: landing?.escalations,
        allowanceAfter: '0',
      })
    } else if (landing?.disposition === 'reverted') {
      const reason = revertReason(landing.status)
      outcome.disposition = 'reverted'
      outcome.error = `permit2 lockdown reverted on chain: ${reason}`
      audit('revoke.reverted', {
        ...detail,
        reason,
        gasUsedWei,
        gasPriceWei,
        escalations: landing.escalations,
        allowanceAfter: remaining.toString(),
      })
    } else if (landing?.disposition === 'pending') {
      outcome.disposition = 'pending'
      outcome.error = PENDING_ERROR
      // Same stage, same reasoning as the ERC-20 path above: pending is not a
      // failure, and the audit trail is where that has to be said.
      audit('revoke.pending', {
        ...detail,
        terminal: false,
        disposition: 'pending',
        reason: pendingReason(ESCALATION_RUNGS.length),
        escalations: landing.escalations,
        allowanceAfter: remaining.toString(),
      })
    } else {
      outcome.disposition = 'failed'
      outcome.error = 'permit2 allowance still non-zero after reported success'
      audit('revoke.failed', {
        ...detail,
        terminal: true,
        reason: failureReason(landing),
        allowanceAfter: remaining.toString(),
      })
    }

    return outcome
  } catch (error) {
    const latencyMs = Date.now() - startedAt
    const message = error instanceof Error ? error.message : String(error)
    audit('revoke.failed', {
      owner,
      action: 'permit2-lockdown',
      pairs: pairs.length,
      terminal: true,
      error: message,
      latencyMs,
    })
    return { executed: false, latencyMs, pairs, cleared: [], disposition: 'failed', error: message }
  }
}
