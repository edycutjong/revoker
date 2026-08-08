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
import { KeeperHub } from './keeperhub.js'
import {
  fetchPermit2Pairs,
  permit2PairKey,
  permit2Status,
  readPermit2Allowance,
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
  pollIntervalMs?: number
  /** Stop after this many revokes. Used by the benchmark; unset means run forever. */
  maxRevokes?: number
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

export class Watcher {
  private readonly kh: KeeperHub
  private readonly denylist: Set<string>
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
  private readonly configuredTokens: Address[]
  private revokeCount = 0
  private stopped = false

  readonly outcomes: RevokeOutcome[] = []

  constructor(options: WatcherOptions) {
    this.owner = options.owner
    this.kh = options.kh ?? new KeeperHub()
    this.configuredTokens = [...(options.tokens ?? [])] as Address[]
    this.denylist = new Set([...(options.denylist ?? [])].map((a) => a.toLowerCase()))
    this.pollIntervalMs = options.pollIntervalMs ?? 5_000
    this.lookbackBlocks = options.lookbackBlocks ?? 5_000n
    this.dryRun = options.dryRun ?? false
    this.maxRevokes = options.maxRevokes
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

    const tokens = await this.resolveTokens()
    const approvals = await fetchApprovals(this.owner, tokens, fromBlock, currentBlock)

    // Collapse the log history to the distinct (token, spender) pairs it
    // mentions, and remember them for good. The event value is historical; only
    // the live allowance decides.
    for (const approval of approvals) {
      this.tracked.set(key(approval), { token: approval.token, spender: approval.spender })
    }

    audit('watch.scan', {
      block: currentBlock,
      fromBlock,
      tokensWatched: tokens.length,
      approvalEvents: approvals.length,
      distinctExposures: this.tracked.size,
    })

    const performed: RevokeOutcome[] = []

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
          this.handled.delete(id)
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
        })

        if (!assessment.threat) {
          audit('threat.cleared', {
            token: exposure.token,
            spender: exposure.spender,
            allowance,
            checked: assessment.all.map((v) => v.rule),
          })
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
        // unattended — today, an ERC-20 approval granted to Permit2 itself,
        // whose revocation would break every Permit2 integration for this token
        // for a wallet whose owner never asked. Reported in full, with the
        // reason, and left for a human. See rules.ts → upstreamPermit2Approval.
        if (!mayRevokeUnattended(assessment)) {
          audit('revoke.skipped', {
            token: exposure.token,
            spender: exposure.spender,
            reason: 'autonomous revoke withheld by a hold',
            holds: assessment.holds.map((v) => ({ rule: v.rule, reason: v.reason, ...v.evidence })),
          })
          continue
        }

        if (this.dryRun) {
          audit('revoke.skipped', { token: exposure.token, spender: exposure.spender, reason: 'dry run' })
          continue
        }

        const outcome = await revokeApproval({
          kh: this.kh,
          token: exposure.token,
          owner: this.owner,
          spender: exposure.spender,
          detectedAt,
          idempotencyKey: `revoke-${id}-${detectedAt}`,
        })

        // Only mark handled once the chain agrees the allowance is gone, so a
        // failed revoke gets retried on the next scan rather than silently
        // dropped.
        if (outcome.executed && outcome.allowanceAfter === 0n) {
          this.handled.add(id)
          this.revokeCount += 1
        }

        performed.push(outcome)
        this.outcomes.push(outcome)

        if (this.maxRevokes !== undefined && this.revokeCount >= this.maxRevokes) {
          this.stop()
          break
        }
      } catch (error) {
        audit('watch.error', {
          token: exposure.token,
          spender: exposure.spender,
          error: describeError(error),
        })
        continue
      }
    }

    // A failure on one surface must not blind the other. The Permit2 scan makes
    // its own RPC calls (three log queries plus a block read), and letting one
    // of them throw out of scan() would mean an unreachable Permit2 index also
    // stopped the ERC-20 sweep that had just finished successfully.
    try {
      performed.push(...(await this.scanPermit2(fromBlock, currentBlock)))
    } catch (error) {
      audit('watch.error', { surface: 'permit2', error: describeError(error) })
    }

    return performed
  }

  /**
   * The Permit2 half of a scan.
   *
   * Structurally the same shape as the ERC-20 loop above with one deliberate
   * difference: threatening slots are COLLECTED, not revoked one at a time.
   * `lockdown()` zeroes any number of them in a single transaction, so a wallet
   * with six poisoned Permit2 grants pays one base fee here where the ERC-20
   * path would pay six.
   */
  private async scanPermit2(fromBlock: bigint, currentBlock: bigint): Promise<RevokeOutcome[]> {
    if (this.stopped) return []

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

    const batch: Permit2Pair[] = []

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
          // already handled — the identical reasoning as the ERC-20 path.
          this.handledPermit2.delete(id)
          continue
        }

        if (status === 'expired') {
          // Not a threat, and stated as a fact rather than a silence. Permit2
          // reverts the transfer once chain time passes the expiration, so
          // there is nothing to take and lockdown() would spend gas zeroing a
          // number nobody can use.
          this.handledPermit2.delete(id)
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
          permit2: {
            expiration: allowance.expiration,
            nonce: allowance.nonce,
            chainTimeSeconds,
          },
        })

        if (!assessment.threat) {
          audit('threat.cleared', {
            surface: 'permit2',
            token: pair.token,
            spender: pair.spender,
            allowance: allowance.amount,
            expiration: allowance.expiration,
            checked: assessment.all.map((v) => v.rule),
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
          audit('revoke.skipped', {
            surface: 'permit2',
            token: pair.token,
            spender: pair.spender,
            reason: 'autonomous revoke withheld by a hold',
            holds: assessment.holds.map((v) => ({ rule: v.rule, reason: v.reason, ...v.evidence })),
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

        batch.push(pair)
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

    // The guard slot doubles as the emptiness check: no threatening slot means
    // no transaction, and lockdown over an empty array would emit nothing while
    // still paying for a transaction.
    const guard = batch[0]
    if (guard === undefined) return []

    const detectedAt = Date.now()
    const outcome = await revokePermit2Allowances({
      kh: this.kh,
      owner: this.owner,
      pairs: batch,
      detectedAt,
      idempotencyKey: `permit2-lockdown-${permit2PairKey(guard)}-x${batch.length}-${detectedAt}`,
    })

    // Only slots the chain confirms are zero are marked handled, so a batch
    // that landed partially is retried for exactly the remainder next scan.
    for (const pair of outcome.cleared) {
      this.handledPermit2.add(permit2PairKey(pair))
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
