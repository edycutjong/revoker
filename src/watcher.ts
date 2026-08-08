import type { Address } from 'viem'
import { audit } from './audit.js'
import {
  fetchApprovals,
  publicClient,
  readAllowance,
  readBalance,
  readChainTimeSeconds,
  tokenSymbol,
} from './chain.js'
import { config, loadAllowlist } from './config.js'
import { KeeperHub } from './keeperhub.js'
import {
  fetchPermit2Pairs,
  permit2PairKey,
  permit2Status,
  readPermit2Allowance,
  type Permit2Allowance,
  type Permit2Pair,
} from './permit2.js'
import { assess, mayRevokeUnattended } from './rules.js'
import { revokeApproval, revokePermit2Allowances, type RevokeOutcome } from './revoke.js'

/**
 * The autonomous loop: watch → detect → revoke, unattended.
 *
 * Each scan discovers live exposure from real Approval logs, evaluates the
 * threat rules against current chain state, and — when a rule fires —
 * autonomously revokes. No human in the loop, because the entire premise is
 * that the human is asleep.
 *
 * Two surfaces, scanned every cycle, because approval risk lives on two:
 *
 *   ERC-20  — `Approval` logs on the watched tokens, revoked one
 *             `approve(spender, 0)` at a time.
 *   Permit2 — Permit2's own allowance ledger, discovered from Permit2's own
 *             events, revoked as ONE batched `lockdown()`.
 *
 * They are kept structurally separate rather than merged into one exposure list
 * because almost nothing about them is the same: different log source,
 * different unlimited sentinel, different revoke primitive, and only one of
 * them expires. A merged list would have needed a discriminant at every step
 * and would have made the batching impossible.
 *
 * ── Detection is separated from execution, on purpose ────────────────────────
 *
 * Each scan runs in two phases. COLLECT evaluates every exposure on both
 * surfaces and writes the full audit trail — threats detected, exposures
 * cleared, holds reported — without signing anything. Only then does EXECUTE
 * run, behind three rails that can each refuse it:
 *
 *   holds                     per-exposure; the operator's allow-list and the
 *                             upstream Permit2 approval (rules.ts)
 *   correlated-failure brake  whole-scan; a mass simultaneous firing is far more
 *                             likely to be broken infrastructure than a mass
 *                             simultaneous compromise
 *   revoke-rate ceiling       rolling 24h; a hard cap on blast radius whatever
 *                             the rules believe
 *
 * The loop used to revoke inline, mid-iteration, which made the middle rail
 * impossible to express: by the time the scan knew how many exposures had
 * fired, it had already revoked the first of them. Collecting first costs one
 * extra round of assessment latency before the FIRST revoke of a multi-exposure
 * scan and nothing at all for the last; a brake that can only be applied after
 * the damage is not a brake.
 */

export interface WatcherOptions {
  owner: Address
  kh?: KeeperHub
  denylist?: Iterable<string>
  /**
   * Tokens to watch. Merged with whatever KeeperHub reports the wallet holding.
   * Required because no public RPC serves address-less log queries — see
   * fetchApprovals for the full reasoning.
   */
  tokens?: Iterable<string>
  /** How far back to look on first scan. */
  lookbackBlocks?: bigint
  /**
   * Spenders the operator has explicitly blessed — their own routers, pools and
   * settlement contracts. Never revoked unattended; reported as a hold instead,
   * so the exposure stays visible and a human can still act on it.
   *
   * Defaults to data/allowlist.json plus REVOKER_ALLOWLIST, so an entrypoint
   * that knows nothing about allow-listing still gets the protection. Pass an
   * explicit empty iterable to run with no blessings at all.
   */
  allowlist?: Iterable<string>
  pollIntervalMs?: number
  /**
   * Stop the PROCESS after this many revokes. A harness affordance — the
   * benchmark uses it to bound a run — not a safety rail, and deliberately not
   * promoted into one: it is terminal. An agent that stops watching is not a
   * safer agent, it is an absent one.
   *
   * The rail is maxRevokesPerDay below, which refuses further signatures while
   * continuing to detect, report and audit. Unset means run forever.
   */
  maxRevokes?: number
  /**
   * Hard ceiling on autonomous revokes per rolling 24 hours. Defaults to
   * config.maxRevokesPerDay (REVOKER_MAX_REVOKES_PER_DAY, 12). On breach the
   * loop refuses to sign, says so loudly in the trail, and keeps scanning.
   */
  maxRevokesPerDay?: number
  /** Report but do not execute. */
  dryRun?: boolean
}

export interface ExposureKey {
  token: Address
  spender: Address
}

function key(exposure: ExposureKey): string {
  return `${exposure.token.toLowerCase()}:${exposure.spender.toLowerCase()}`
}

/** Rejections off a fetch/RPC stack are not always Errors. */
function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/**
 * The default cadence, exported so the /verify health endpoint can measure
 * "when did the last scan happen?" against the interval the watcher was
 * actually given rather than against a second copy of the number that is free
 * to drift away from it.
 */
export const DEFAULT_POLL_INTERVAL_MS = 5_000

/**
 * ── Bounded retries: the agent has to be able to give up ─────────────────────
 *
 * `handled` is set only on an OBSERVED on-chain zero, which is the right rule —
 * but on its own it also means an exposure the agent can never actually clear
 * is retried by every single scan, forever, with no attempt counter, no backoff
 * and nothing in the trail that ever says "this is stuck".
 *
 * The concrete hazard is not theoretical. A token whose `approve()` accepts the
 * call and silently ignores it (a paused, blocklisting or otherwise
 * non-standard ERC-20) reports success, leaves the allowance where it was, and
 * therefore produced one NEW gas-spending transaction every pollIntervalMs for
 * as long as the process lived. A genuinely stranded execution did the same. In
 * both cases every individual attempt looked like a healthy first attempt, so
 * the failure was invisible in exactly the artifact that exists to make failure
 * visible.
 *
 * So: a bounded number of consecutive non-successes per exposure, spaced by an
 * exponential backoff, and then the exposure is ABANDONED — recorded once, with
 * the attempt count and the last error — and not attempted again until the
 * chain says something new about it.
 */
const MAX_REVOKE_ATTEMPTS = 3

/**
 * First gap between attempts on one exposure, doubling per attempt (15s, 30s).
 *
 * Deliberately several poll intervals wide: a retry that fires on the very next
 * scan is the unbounded behaviour again with a counter bolted on, and the
 * failure modes worth waiting out (a fee spike, a rate limit, an upstream blip)
 * do not clear inside five seconds.
 */
const RETRY_BACKOFF_BASE_MS = 15_000

interface RetryRecord {
  /** Consecutive non-successes against the grant identified by `witness`. */
  attempts: number
  nextAttemptAt: number
  abandoned: boolean
  lastError: string
  /** The grant those attempts were spent on. See `ready`. */
  witness: bigint
}

/**
 * Per-exposure attempt budget, shared verbatim by the ERC-20 and Permit2 paths.
 *
 * One implementation rather than two because the give-up rule is a safety
 * property: two copies would eventually disagree about how many attempts is
 * enough, and the surface that drifted looser is the one that would keep
 * burning gas.
 */
class RetryLedger {
  private readonly records = new Map<string, RetryRecord>()

  /**
   * May this exposure be attempted right now?
   *
   * `witness` is a number that moves forward only when the CHAIN records a NEW
   * grant on the slot. A witness above the one a budget was spent against means
   * this is a different grant, so the budget starts over — a re-granted
   * approval must never inherit the give-up of the one before it, or the agent
   * would permanently stop defending a wallet that has just been re-exposed.
   */
  ready(id: string, witness: bigint, now: number): boolean {
    const record = this.records.get(id)
    if (record === undefined) return true
    if (witness > record.witness) {
      this.records.delete(id)
      return true
    }
    if (record.abandoned) return false
    return now >= record.nextAttemptAt
  }

  /** The chain settled it: a confirmed zero, an expiry, or an empty slot. */
  clear(id: string): void {
    this.records.delete(id)
  }

  /**
   * Record one non-success. Returns the record ONLY on the attempt that crosses
   * the give-up line, so `revoke.abandoned` is emitted exactly once per grant
   * rather than on every scan that then declines to retry.
   */
  fail(id: string, witness: bigint, now: number, error: string): RetryRecord | undefined {
    const attempts = (this.records.get(id)?.attempts ?? 0) + 1
    const abandoned = attempts >= MAX_REVOKE_ATTEMPTS
    const record: RetryRecord = {
      attempts,
      abandoned,
      lastError: error,
      witness,
      nextAttemptAt: now + RETRY_BACKOFF_BASE_MS * 2 ** (attempts - 1),
    }
    this.records.set(id, record)
    return abandoned ? record : undefined
  }
}

/** The rolling window the revoke ceiling is measured over. */
const REVOKE_WINDOW_MS = 24 * 60 * 60 * 1_000

/**
 * The revoke ceiling, as a rolling-window budget.
 *
 * Rolling rather than per-calendar-day because a daily reset is a cliff an
 * attacker can straddle: spend the budget at 23:59, spend it again at 00:01,
 * and the "daily" cap authorised twice its number in two minutes.
 *
 * It meters SUBMITTED revokes, not successful ones. A revoke that reverts still
 * signed a transaction, still spent gas, and still counts against a rail whose
 * job is to bound how much this process may do to the wallet.
 */
class RevokeBudget {
  private readonly submitted: number[] = []

  constructor(private readonly ceiling: number) {}

  /** How many more autonomous revokes are permitted right now. */
  remaining(now: number): number {
    while (this.submitted.length > 0 && now - this.submitted[0]! >= REVOKE_WINDOW_MS) {
      this.submitted.shift()
    }
    return this.ceiling - this.submitted.length
  }

  spend(now: number, count = 1): void {
    for (let i = 0; i < count; i += 1) this.submitted.push(now)
  }

  get limit(): number {
    return this.ceiling
  }
}

/**
 * ── The correlated-failure brake ─────────────────────────────────────────────
 *
 * Even with every rule abstaining correctly on a failed lookup, there is a
 * class of fault this loop cannot enumerate in advance: some shared input —
 * an explorer that starts answering wrongly rather than not at all, a deny-list
 * feed that ships a bad update, an RPC serving another chain's state — flips
 * many exposures from quiet to threatening in the same instant.
 *
 * The prior matters here. For N unrelated (token, spender) grants to become
 * genuinely hostile between two five-second polls, an attacker must have
 * compromised N independent counterparties simultaneously. For the same N to
 * light up because one shared input misbehaved requires one thing to go wrong.
 * At N of any size the second explanation is overwhelmingly likelier, and the
 * cost of being wrong is asymmetric: waiting one poll interval to act costs
 * seconds, while acting on a false mass detection costs the wallet every
 * approval it depends on, irreversibly.
 *
 * So: above the threshold, the scan signs nothing, says so loudly, and the NEXT
 * scan decides. A genuine mass compromise is still there five seconds later and
 * is acted on then — the same exposures are no longer "newly" firing, so the
 * brake opens. An infrastructure blip has cleared and there was never anything
 * to revoke.
 */

/**
 * Below this many newly-firing exposures the brake never engages.
 *
 * An absolute floor, because a fraction alone is nonsense at small N: one new
 * drainer in a two-approval wallet is 50% of it and is exactly the case this
 * product exists for. Three is the largest number that is still plausibly one
 * incident with one attacker; four independent grants turning hostile between
 * two polls is a claim about the world that deserves a second look. The demo
 * wallet holds two exposures and therefore can never trip this.
 */
const CORRELATED_FAILURE_MIN = 4

/**
 * ...and it must also be at least this share of everything the rules looked at
 * this scan.
 *
 * Both conditions, not either. The floor alone would brake a busy wallet that
 * legitimately found four bad spenders among sixty; the fraction alone would
 * brake the two-exposure case above. Together they describe the only shape that
 * is actually suspicious: most of what we can see changed its answer at once.
 * A half is the point where "several exposures fired" becomes "the population
 * fired".
 */
const CORRELATED_FAILURE_FRACTION = 0.5

/**
 * A single monotonic number identifying the CURRENT Permit2 grant on a slot.
 *
 * The ERC-20 path gets its witness for free — the Approval log carries a block
 * number, and a higher one is a new grant. Permit2 has no such handle here:
 * fetchPermit2Pairs returns pairs, not logs, precisely so that nothing
 * downstream can act on a log value. So the witness is read off the slot
 * itself. `permit()` increments the stored nonce and both `permit()` and
 * `approve()` write a fresh expiration, so packing the nonce above the 48-bit
 * expiration makes either a re-permit or a lengthened approval strictly greater
 * than what the give-up was recorded against.
 *
 * The one re-grant it does NOT see is an `approve()` that rewrites the same
 * slot at the same or an earlier expiry; that slot stays abandoned until the
 * chain shows a zero. That is the conservative direction — no transaction —
 * rather than the expensive one, which is the correct way for this particular
 * blind spot to fail.
 */
function permit2GrantWitness(allowance: Permit2Allowance): bigint {
  return (BigInt(allowance.nonce) << 48n) | BigInt(allowance.expiration)
}

/** One exposure the collect phase decided is a revoke candidate. */
interface Erc20Candidate {
  id: string
  exposure: ExposureKey
  witness: bigint
  /** When the rules fired, captured in COLLECT so the reported latency is honest. */
  detectedAt: number
}

interface Permit2Candidate {
  id: string
  pair: Permit2Pair
  witness: bigint
}

/**
 * What one surface's collect phase produced.
 *
 * `evaluated` is the denominator the correlated-failure brake divides by: the
 * number of live exposures the rules actually ran against this scan. Exposures
 * the chain says are already zero, or that are inside a retry backoff, are not
 * counted — the rules did not look at them, so they say nothing about whether
 * the ones that did look are behaving strangely.
 */
interface Collected<T> {
  candidates: T[]
  evaluated: number
}

export class Watcher {
  private readonly kh: KeeperHub
  private readonly denylist: Set<string>
  private readonly allowlist: Set<string>
  private readonly owner: Address
  private readonly pollIntervalMs: number
  private readonly lookbackBlocks: bigint
  private readonly dryRun: boolean
  private readonly maxRevokes: number | undefined

  /** Exposures already actioned, so a slow confirmation isn't revoked twice. */
  private readonly handled = new Set<string>()

  /**
   * Every (token, spender) pair this process has ever seen in a log.
   *
   * `fromBlock` is recomputed from the head on every scan, so the log query is
   * a ~16.6h sliding window (5_000 blocks at 12s). Deriving the exposure set
   * from that query alone meant an approval simply dropped out of the agent's
   * attention once its Approval event aged past the window — and "the approval
   * you forgot about" is the exact threat this product claims to cover. Keeping
   * the pairs means their live allowance is re-read every scan forever,
   * regardless of how old the grant is.
   *
   * In-memory on purpose. A JSONL cursor on disk would also close the
   * cold-start gap, at the cost of a file format, its corruption cases and its
   * own tests; the honest boundary today is that a RESTART still only rebuilds
   * the set from the last window, so an approval older than that is invisible
   * until the process sees another log for it. Everything within one run — the
   * demo, the benchmark, an unattended overnight watch — is covered.
   */
  private readonly tracked = new Map<string, ExposureKey>()

  /**
   * The same idea for Permit2 slots, and for a sharper reason.
   *
   * A Permit2 grant made by SIGNATURE produces exactly one `Permit` log, in the
   * attacker's own transaction. There is no second event, no token-side
   * `Approval`, and nothing that re-announces the grant later. Once that single
   * log ages out of the sliding window it is the only trace there ever was, so
   * a watcher that derives its exposure set from the window alone forgets the
   * grant while it is still live and still drainable.
   */
  private readonly trackedPermit2 = new Map<string, Permit2Pair>()
  private readonly handledPermit2 = new Set<string>()

  /** Attempt budgets, one ledger per surface. See RetryLedger. */
  private readonly retries = new RetryLedger()
  private readonly retriesPermit2 = new RetryLedger()

  /**
   * The highest Approval-log block seen per ERC-20 exposure — the witness that
   * tells an abandoned exposure apart from a freshly re-granted one.
   *
   * It has to be a HIGH-WATER MARK rather than "was a log present this scan?",
   * because the sliding window re-delivers the same log on every single scan:
   * resetting on presence would defeat the give-up entirely and hand back the
   * unbounded retry loop under a new name.
   */
  private readonly lastApprovalBlock = new Map<string, bigint>()

  /** The rolling 24h autonomous-revoke ceiling. See RevokeBudget. */
  private readonly budget: RevokeBudget

  /**
   * The revoke candidates the PREVIOUS scan produced, across both surfaces.
   *
   * The brake's memory. An exposure that was a candidate last scan and is one
   * again has been confirmed by two independent rounds of chain reads, so it is
   * no longer "newly" firing and no longer counts toward the trip. This is what
   * makes the brake a one-scan delay rather than a permanent refusal.
   */
  private previousCandidates = new Set<string>()

  private readonly configuredTokens: Address[]
  private revokeCount = 0
  private stopped = false

  readonly outcomes: RevokeOutcome[] = []

  constructor(options: WatcherOptions) {
    this.owner = options.owner
    this.kh = options.kh ?? new KeeperHub()
    this.configuredTokens = [...(options.tokens ?? [])] as Address[]
    this.denylist = new Set([...(options.denylist ?? [])].map((a) => a.toLowerCase()))
    // `??`, not a truthiness check: an explicitly empty allow-list is a valid
    // operator decision ("bless nothing"), and falling back to the file there
    // would silently re-add blessings they removed.
    this.allowlist = new Set(
      [...(options.allowlist ?? loadAllowlist())].map((a) => a.toLowerCase()),
    )
    this.pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS
    this.lookbackBlocks = options.lookbackBlocks ?? 5_000n
    this.dryRun = options.dryRun ?? false
    this.maxRevokes = options.maxRevokes
    this.budget = new RevokeBudget(options.maxRevokesPerDay ?? config.maxRevokesPerDay)
  }

  stop(): void {
    this.stopped = true
  }

  /** Configured watchlist plus anything KeeperHub reports the wallet holding. */
  private async resolveTokens(): Promise<Address[]> {
    const held = await this.kh.getHeldTokens()
    const merged = new Map<string, Address>()
    for (const token of [...this.configuredTokens, ...(held as Address[])]) {
      merged.set(token.toLowerCase(), token)
    }
    return [...merged.values()]
  }

  async scan(): Promise<RevokeOutcome[]> {
    const currentBlock = await publicClient.getBlockNumber()
    const fromBlock = currentBlock > this.lookbackBlocks ? currentBlock - this.lookbackBlocks : 0n

    // ── PHASE 1: COLLECT ────────────────────────────────────────────────────
    // Every exposure on both surfaces is read, assessed and audited. Nothing is
    // signed. The full detection record therefore exists before any rail can
    // refuse — an agent that is refusing to act must still be able to say what
    // it saw, or the refusal is indistinguishable from blindness.
    const erc20 = await this.collectErc20(fromBlock, currentBlock)

    // A failure on one surface must not blind the other. The Permit2 scan makes
    // its own RPC calls (three log queries plus a block read), and letting one
    // of them throw out of scan() would mean an unreachable Permit2 index also
    // stopped the ERC-20 sweep that had just finished successfully.
    let permit2: Collected<Permit2Candidate> = { candidates: [], evaluated: 0 }
    try {
      permit2 = await this.collectPermit2(fromBlock, currentBlock)
    } catch (error) {
      audit('watch.error', { surface: 'permit2', error: describeError(error) })
    }

    // ── PHASE 2: GATE ───────────────────────────────────────────────────────
    if (!this.correlationGateOpen(erc20, permit2)) return []

    // ── PHASE 3: EXECUTE ────────────────────────────────────────────────────
    const performed = await this.executeErc20(erc20.candidates)
    try {
      performed.push(...(await this.executePermit2(permit2.candidates)))
    } catch (error) {
      audit('watch.error', { surface: 'permit2', error: describeError(error) })
    }
    return performed
  }

  /**
   * Whole-scan brake. See CORRELATED_FAILURE_MIN / _FRACTION for the reasoning
   * and the thresholds.
   *
   * Called once per scan with BOTH surfaces' candidates, because the shared
   * inputs it exists to defend against — the ABI endpoint, the deny-list, the
   * RPC — are shared across both. A brake that ran per surface would let a
   * fault that halved its blast radius across the two slip under each half's
   * threshold.
   */
  private correlationGateOpen(
    erc20: Collected<Erc20Candidate>,
    permit2: Collected<Permit2Candidate>,
  ): boolean {
    const ids = [...erc20.candidates.map((c) => c.id), ...permit2.candidates.map((c) => c.id)]
    const newlyFiring = ids.filter((id) => !this.previousCandidates.has(id))

    // Recorded BEFORE the decision, and unconditionally. This is what turns the
    // brake into a one-scan delay: whatever fired now is no longer new next
    // time, so a genuine mass compromise is acted on at the very next poll
    // rather than being refused forever.
    this.previousCandidates = new Set(ids)

    const evaluated = erc20.evaluated + permit2.evaluated
    const tripped =
      newlyFiring.length >= CORRELATED_FAILURE_MIN &&
      newlyFiring.length >= evaluated * CORRELATED_FAILURE_FRACTION
    if (!tripped) return true

    audit('revoke.skipped', {
      rail: 'correlated-failure-brake',
      reason:
        `${newlyFiring.length} of ${evaluated} evaluated exposures began firing in this single scan — ` +
        'that shape is far likelier to be a shared detection input failing than a simultaneous ' +
        'compromise of that many independent spenders. NO revoke was signed this scan. The next ' +
        'scan re-reads all of them: any that still fire are confirmed and will be acted on then.',
      newlyFiring: newlyFiring.length,
      evaluated,
      thresholdCount: CORRELATED_FAILURE_MIN,
      thresholdFraction: CORRELATED_FAILURE_FRACTION,
      exposures: ids,
    })
    return false
  }

  /**
   * The ERC-20 collect phase: read, assess, audit — and decide nothing.
   *
   * Returns the exposures that a revoke would be signed for, in the order they
   * were found, so execution order is unchanged from when this loop revoked
   * inline.
   */
  private async collectErc20(
    fromBlock: bigint,
    currentBlock: bigint,
  ): Promise<Collected<Erc20Candidate>> {
    const tokens = await this.resolveTokens()
    const approvals = await fetchApprovals(this.owner, tokens, fromBlock, currentBlock)

    // Collapse the log history to the distinct (token, spender) pairs it
    // mentions, and remember them for good. The event value is historical; only
    // the live allowance decides.
    for (const approval of approvals) {
      const id = key(approval)
      this.tracked.set(id, { token: approval.token, spender: approval.spender })

      // A log from a block we have not seen before is the chain stating that a
      // NEW approval was granted on this pair. That is the one thing, short of
      // an observed zero, that should hand an abandoned exposure a fresh
      // attempt budget: the wallet has just been re-exposed, and a sentinel
      // that stays given-up through a re-grant is not defending anything.
      const seen = this.lastApprovalBlock.get(id) ?? -1n
      if (approval.blockNumber > seen) {
        this.lastApprovalBlock.set(id, approval.blockNumber)
      }
    }

    audit('watch.scan', {
      block: currentBlock,
      fromBlock,
      tokensWatched: tokens.length,
      approvalEvents: approvals.length,
      distinctExposures: this.tracked.size,
    })

    const candidates: Erc20Candidate[] = []
    let evaluated = 0

    for (const exposure of this.tracked.values()) {
      if (this.stopped) break

      // One hostile or non-standard token must not blind the agent. Without
      // this guard a token that reverts on allowance() or balanceOf() threw
      // straight out of scan(), so every exposure after it in insertion order
      // was never evaluated again — on this cycle or any future one.
      try {
        const id = key(exposure)

        // Read BEFORE consulting `handled`, never after. Checking `handled`
        // first meant a pair that had once been revoked was never read again,
        // so a freshly re-granted MAX approval to the same spender was
        // invisible for the life of the process — the opposite of continuous
        // hygiene.
        const allowance = await readAllowance(exposure.token, this.owner, exposure.spender)
        if (allowance === 0n) {
          // The chain confirms the revoke stuck, which is the one fact that
          // makes the dedupe entry unnecessary. Dropping it here is what lets a
          // later re-grant be treated as a fresh exposure.
          //
          // Deliberately not keyed on the allowance VALUE: the common re-grant
          // is the same MAX_UINT256 the wallet just had, so "value changed"
          // would miss precisely the case that matters, and a stale RPC read
          // would forge a re-grant out of nothing. An observed zero is a
          // positive fact about the chain rather than an inference from one.
          //
          // The attempt budget is released on the same fact and for the same
          // reason: an allowance the chain says is gone is not an exposure this
          // agent gave up on, so a later re-grant starts from a clean slate.
          this.handled.delete(id)
          this.retries.clear(id)
          continue
        }

        // Non-zero and already actioned: a confirmation that has not landed in
        // this node's view yet. Waiting is correct — re-revoking would burn gas
        // on an allowance that is already gone.
        //
        // The cost of that wait is the one remaining hole: a re-grant that
        // lands in the gap between the revoke and the first scan that sees a
        // zero looks identical to this stale read, and is missed until a zero
        // is finally observed. Closing it properly needs the Approval log's
        // block number compared against the revoke's, not a bigger allowance
        // heuristic — the heuristic would trade a rare miss for routine
        // double-revokes on a lagging RPC pool.
        if (this.handled.has(id)) continue

        // The attempt budget, checked BEFORE the rules are evaluated. An
        // exposure that is backing off — or one the agent has given up on —
        // must cost nothing at all on this cycle: not a balance read, not an
        // explorer lookup for the source-verification rule, and above all not
        // another transaction. Cheap silence is the entire point of the gate.
        const witness = this.lastApprovalBlock.get(id) ?? 0n
        if (!this.retries.ready(id, witness, Date.now())) continue

        const balance = await readBalance(exposure.token, this.owner)
        const assessment = await assess({
          token: exposure.token,
          spender: exposure.spender,
          owner: this.owner,
          allowance,
          balance,
          currentBlock,
          kh: this.kh,
          denylist: this.denylist,
          allowlist: this.allowlist,
        })
        evaluated += 1

        if (!assessment.threat) {
          audit('threat.cleared', {
            token: exposure.token,
            spender: exposure.spender,
            allowance,
            checked: assessment.all.map((v) => v.rule),
          })
          // A hold is a finding in its own right and does not need a threat rule
          // to have fired first. Reporting it only on the threat path meant an
          // allow-listed or upstream-Permit2 exposure that tripped no rule
          // vanished from the trail entirely — the one surface where the
          // withheld-action guarantee is supposed to be visible was silent in
          // exactly the case the guarantee covers.
          this.reportHolds(assessment, { token: exposure.token, spender: exposure.spender })
          continue
        }

        const symbol = await tokenSymbol(exposure.token)
        const detectedAt = Date.now()
        audit('threat.detected', {
          token: exposure.token,
          symbol,
          spender: exposure.spender,
          allowance: allowance === (1n << 256n) - 1n ? 'MAX_UINT256' : allowance,
          atRisk: balance,
          rules: assessment.fired.map((v) => ({ rule: v.rule, reason: v.reason, ...v.evidence })),
        })

        // A hold means the finding is real and the hammer is too big to swing
        // unattended — an ERC-20 approval granted to Permit2 itself, whose
        // revocation would break every Permit2 integration for this token for a
        // wallet whose owner never asked, or a spender the operator has
        // explicitly blessed. Reported in full, with the reason, and left for a
        // human. See rules.ts → ALL_HOLDS.
        if (!mayRevokeUnattended(assessment)) {
          this.reportHolds(assessment, { token: exposure.token, spender: exposure.spender })
          continue
        }

        if (this.dryRun) {
          audit('revoke.skipped', { token: exposure.token, spender: exposure.spender, reason: 'dry run' })
          continue
        }

        candidates.push({ id, exposure, witness, detectedAt })
      } catch (error) {
        audit('watch.error', {
          token: exposure.token,
          spender: exposure.spender,
          error: describeError(error),
        })
        continue
      }
    }

    return { candidates, evaluated }
  }

  /**
   * The ERC-20 execute phase: sign, one candidate at a time, under the ceiling.
   */
  private async executeErc20(candidates: readonly Erc20Candidate[]): Promise<RevokeOutcome[]> {
    const performed: RevokeOutcome[] = []
    let announced = false

    for (const { id, exposure, witness, detectedAt } of candidates) {
      if (this.stopped) break

      if (this.budget.remaining(Date.now()) <= 0) {
        // Once per scan, not once per exposure: an operator needs to be told the
        // ceiling is holding, not told it forty times in one second.
        if (!announced) {
          this.announceCeiling({ token: exposure.token, spender: exposure.spender })
          announced = true
        }
        // `continue`, not `break`, and no this.stop(): the ceiling refuses
        // signatures, it does not end the watch. Detection, reporting and the
        // audit trail carry on, which is the difference between a safety rail
        // and an off switch.
        continue
      }
      this.budget.spend(Date.now())

      const outcome = await revokeApproval({
        kh: this.kh,
        token: exposure.token,
        owner: this.owner,
        spender: exposure.spender,
        detectedAt,
        idempotencyKey: `revoke-${id}-${detectedAt}`,
      })

      // Only mark handled once the chain agrees the allowance is gone, so a
      // failed revoke gets retried rather than silently dropped — but now
      // against a bounded, backed-off budget rather than forever.
      if (outcome.executed && outcome.allowanceAfter === 0n) {
        this.handled.add(id)
        this.retries.clear(id)
        this.revokeCount += 1
      } else {
        this.noteRevokeFailure(this.retries, id, witness, outcome, {
          token: exposure.token,
          spender: exposure.spender,
        })
      }

      performed.push(outcome)
      this.outcomes.push(outcome)

      if (this.maxRevokes !== undefined && this.revokeCount >= this.maxRevokes) {
        this.stop()
        break
      }
    }

    return performed
  }

  /**
   * Every hold that fired, on one audit line, whether or not a threat rule also
   * fired. The single place holds reach the trail, so the two surfaces and the
   * two paths cannot drift into disagreeing about whether they are reported.
   */
  private reportHolds(
    assessment: { holds: Array<{ rule: string; reason: string; evidence: Record<string, unknown> }> },
    detail: Record<string, unknown>,
  ): void {
    if (assessment.holds.length === 0) return
    audit('revoke.skipped', {
      ...detail,
      rail: 'hold',
      reason: 'autonomous revoke withheld by a hold',
      holds: assessment.holds.map((v) => ({ rule: v.rule, reason: v.reason, ...v.evidence })),
    })
  }

  /** The ceiling engaged. Said once per scan per surface, with the numbers. */
  private announceCeiling(detail: Record<string, unknown>): void {
    audit('revoke.skipped', {
      ...detail,
      rail: 'revoke-rate-ceiling',
      reason:
        `the rolling 24h autonomous revoke ceiling of ${this.budget.limit} is exhausted — ` +
        'no further revoke will be SIGNED until the window rolls forward. Detection, assessment ' +
        'and reporting continue, and a human can still revoke through the MCP revoke_approval ' +
        'tool with confirm: true.',
      ceiling: this.budget.limit,
      windowHours: REVOKE_WINDOW_MS / 3_600_000,
    })
  }

  /**
   * Charge one non-success against an exposure's budget, and announce the
   * give-up if this attempt was the one that crossed the line.
   *
   * `revoke.abandoned` is emitted exactly once per grant, not on every
   * subsequent scan that declines to retry — an operator needs to be told that
   * the agent stopped, once, not reminded of it every five seconds until the
   * signal is worth nothing.
   */
  private noteRevokeFailure(
    ledger: RetryLedger,
    id: string,
    witness: bigint,
    outcome: RevokeOutcome,
    detail: Record<string, unknown>,
  ): void {
    // A revoke that was never submitted is not an attempt. `executed: false`
    // with no disposition is the server-side condition reporting the allowance
    // was already zero: no transaction, no gas, and the next scan reads that
    // zero and releases the budget on its own. Charging it would be actively
    // harmful on the Permit2 path, where one stale GUARD slot skips the whole
    // batch — three such scans would abandon the live slots queued behind it.
    if (!outcome.executed && outcome.disposition === undefined) return

    const lastError = outcome.error ?? outcome.disposition ?? 'allowance is still non-zero'
    const record = ledger.fail(id, witness, Date.now(), lastError)
    if (record === undefined) return

    audit('revoke.abandoned', {
      ...detail,
      attempts: record.attempts,
      lastError,
      reason:
        `${record.attempts} consecutive revoke attempts failed to clear this allowance — ` +
        'no further attempts until the chain shows a zero or records a new grant',
    })
  }

  /**
   * The Permit2 collect phase.
   *
   * Structurally the same shape as the ERC-20 loop above with one deliberate
   * difference: threatening slots are COLLECTED, not revoked one at a time.
   * `lockdown()` zeroes any number of them in a single transaction, so a wallet
   * with six poisoned Permit2 grants pays one base fee here where the ERC-20
   * path would pay six.
   */
  private async collectPermit2(
    fromBlock: bigint,
    currentBlock: bigint,
  ): Promise<Collected<Permit2Candidate>> {
    if (this.stopped) return { candidates: [], evaluated: 0 }

    const discovered = await fetchPermit2Pairs(this.owner, fromBlock, currentBlock)
    for (const pair of discovered) {
      this.trackedPermit2.set(permit2PairKey(pair), pair)
    }

    // Chain time, read once per scan. Every expiry decision below is made
    // against the chain's clock rather than this host's — see
    // readChainTimeSeconds for why a drifted local clock would fail open.
    const chainTimeSeconds = await readChainTimeSeconds()

    audit('watch.scan', {
      surface: 'permit2',
      block: currentBlock,
      fromBlock,
      permit2Events: discovered.length,
      distinctExposures: this.trackedPermit2.size,
      chainTimeSeconds,
    })

    /**
     * The batch, keyed by slot, carrying the grant each pair was read at.
     *
     * The witness is captured HERE rather than re-read after the lockdown so
     * the attempt is charged against the grant it was actually checked against
     * — a re-read afterwards would charge the failure to whatever the slot
     * happens to hold by then, which on a partially-landed batch is a different
     * grant from the one that was attempted.
     */
    const batched = new Map<string, Permit2Candidate>()
    let evaluated = 0

    for (const pair of this.trackedPermit2.values()) {
      if (this.stopped) break

      try {
        const id = permit2PairKey(pair)
        const allowance = await readPermit2Allowance(this.owner, pair.token, pair.spender)
        const status = permit2Status(allowance, chainTimeSeconds)

        if (status === 'empty') {
          // Zero amount: a lockdown landed, or nothing was ever granted here.
          // Dropping the dedupe entry is what lets a later re-permit of the
          // same slot be treated as a fresh exposure rather than as one we
          // already handled — the identical reasoning as the ERC-20 path, and
          // it releases the attempt budget for the identical reason.
          this.handledPermit2.delete(id)
          this.retriesPermit2.clear(id)
          continue
        }

        if (status === 'expired') {
          // Not a threat, and stated as a fact rather than a silence. Permit2
          // reverts the transfer once chain time passes the expiration, so
          // there is nothing to take and lockdown() would spend gas zeroing a
          // number nobody can use.
          this.handledPermit2.delete(id)
          this.retriesPermit2.clear(id)
          audit('threat.cleared', {
            surface: 'permit2',
            token: pair.token,
            spender: pair.spender,
            reason: 'Permit2 allowance expired — a transfer against it would revert',
            amount: allowance.amount,
            expiration: allowance.expiration,
            chainTimeSeconds,
          })
          continue
        }

        if (this.handledPermit2.has(id)) continue

        // Same gate, same reason, same ledger implementation as the ERC-20 path
        // — a batched revoke primitive does not make an unclearable slot any
        // cheaper to keep retrying.
        const witness = permit2GrantWitness(allowance)
        if (!this.retriesPermit2.ready(id, witness, Date.now())) continue

        const balance = await readBalance(pair.token, this.owner)
        const assessment = await assess({
          token: pair.token,
          spender: pair.spender,
          owner: this.owner,
          allowance: allowance.amount,
          balance,
          currentBlock,
          kh: this.kh,
          denylist: this.denylist,
          allowlist: this.allowlist,
          permit2: {
            expiration: allowance.expiration,
            nonce: allowance.nonce,
            chainTimeSeconds,
          },
        })
        evaluated += 1

        if (!assessment.threat) {
          audit('threat.cleared', {
            surface: 'permit2',
            token: pair.token,
            spender: pair.spender,
            allowance: allowance.amount,
            expiration: allowance.expiration,
            checked: assessment.all.map((v) => v.rule),
          })
          // Same reason as the ERC-20 path: a hold that fired without any threat
          // rule firing is still a finding, and dropping it here made the
          // allow-list invisible in exactly the case it is designed for.
          this.reportHolds(assessment, {
            surface: 'permit2',
            token: pair.token,
            spender: pair.spender,
          })
          continue
        }

        const symbol = await tokenSymbol(pair.token)
        audit('threat.detected', {
          surface: 'permit2',
          token: pair.token,
          symbol,
          spender: pair.spender,
          allowance: allowance.amount,
          expiration: allowance.expiration,
          atRisk: balance,
          rules: assessment.fired.map((v) => ({ rule: v.rule, reason: v.reason, ...v.evidence })),
        })

        if (!mayRevokeUnattended(assessment)) {
          this.reportHolds(assessment, {
            surface: 'permit2',
            token: pair.token,
            spender: pair.spender,
          })
          continue
        }

        if (this.dryRun) {
          audit('revoke.skipped', {
            surface: 'permit2',
            token: pair.token,
            spender: pair.spender,
            reason: 'dry run',
          })
          continue
        }

        batched.set(id, { id, pair, witness })
      } catch (error) {
        audit('watch.error', {
          surface: 'permit2',
          token: pair.token,
          spender: pair.spender,
          error: describeError(error),
        })
        continue
      }
    }

    return { candidates: [...batched.values()], evaluated }
  }

  /**
   * The Permit2 execute phase: one `lockdown()` over the whole batch.
   *
   * The ceiling TRIMS the batch rather than refusing it outright. A lockdown of
   * six slots is one transaction but six revokes, and metering it as one would
   * let the batched surface walk straight through a rail the ERC-20 surface
   * obeys — the exact drift the shared RetryLedger exists to prevent, one level
   * up. The slots that do not fit are simply not in this transaction; they are
   * still tracked, still reported, and are the first candidates next scan.
   */
  private async executePermit2(candidates: readonly Permit2Candidate[]): Promise<RevokeOutcome[]> {
    if (this.stopped) return []

    // The guard slot doubles as the emptiness check: no threatening slot means
    // no transaction, and lockdown over an empty array would emit nothing while
    // still paying for a transaction.
    const first = candidates[0]
    if (first === undefined) return []

    const now = Date.now()
    const room = this.budget.remaining(now)
    if (room <= 0) {
      this.announceCeiling({
        surface: 'permit2',
        withheld: candidates.length,
        token: first.pair.token,
        spender: first.pair.spender,
      })
      return []
    }

    const admitted = candidates.slice(0, room)
    if (admitted.length < candidates.length) {
      this.announceCeiling({
        surface: 'permit2',
        withheld: candidates.length - admitted.length,
        admitted: admitted.length,
      })
    }
    this.budget.spend(now, admitted.length)

    const batch = admitted.map((entry) => entry.pair)
    const guard = batch[0]!
    const detectedAt = Date.now()
    const outcome = await revokePermit2Allowances({
      kh: this.kh,
      owner: this.owner,
      pairs: batch,
      detectedAt,
      idempotencyKey: `permit2-lockdown-${permit2PairKey(guard)}-x${batch.length}-${detectedAt}`,
    })

    // Only slots the chain confirms are zero are marked handled, so a batch
    // that landed partially is retried for exactly the remainder next scan —
    // and every slot the batch did NOT clear is charged one attempt, so the
    // remainder cannot be retried indefinitely either. Walking the batch rather
    // than only `outcome.cleared` is what makes the second half true: the
    // uncleared slots are precisely the ones the old code never looked at.
    const cleared = new Set(outcome.cleared.map(permit2PairKey))
    for (const { id, pair, witness } of admitted) {
      if (cleared.has(id)) {
        this.handledPermit2.add(id)
        this.retriesPermit2.clear(id)
        continue
      }
      this.noteRevokeFailure(this.retriesPermit2, id, witness, outcome, {
        surface: 'permit2',
        token: pair.token,
        spender: pair.spender,
      })
    }
    this.revokeCount += outcome.cleared.length
    this.outcomes.push(outcome)

    if (this.maxRevokes !== undefined && this.revokeCount >= this.maxRevokes) {
      this.stop()
    }

    return [outcome]
  }

  /** Run until stopped, or until maxRevokes is reached. */
  async run(): Promise<void> {
    audit('watch.start', {
      owner: this.owner,
      pollIntervalMs: this.pollIntervalMs,
      denylistSize: this.denylist.size,
      dryRun: this.dryRun,
    })

    while (!this.stopped) {
      try {
        await this.scan()
      } catch (error) {
        // A transient RPC or API failure must not kill an agent whose whole job
        // is to still be watching at 3am.
        //
        // Its own stage, not `revoke.failed` with a `stage: 'scan'` detail: no
        // revoke was ever attempted here, and the old form both clobbered the
        // canonical stage (see audit.ts) and inflated the failure count the
        // dashboard shows. A whole-scan failure carries no token/spender, which
        // is what distinguishes it from the per-exposure watch.error above.
        audit('watch.error', { error: describeError(error) })
      }
      if (this.stopped) break
      await new Promise((resolve) => setTimeout(resolve, this.pollIntervalMs))
    }
  }
}
