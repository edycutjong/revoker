import type { Address } from 'viem'
import { audit } from './audit.js'
import { fetchApprovals, publicClient, readAllowance, readBalance, tokenSymbol } from './chain.js'
import { KeeperHub } from './keeperhub.js'
import { assess } from './rules.js'
import { revokeApproval, type RevokeOutcome } from './revoke.js'

/**
 * The autonomous loop: watch → detect → revoke, unattended.
 *
 * Each scan discovers live exposure from real Approval logs, evaluates the
 * threat rules against current chain state, and — when a rule fires —
 * autonomously revokes. No human in the loop, because the entire premise is
 * that the human is asleep.
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
    // mentions. The event value is historical; only the live allowance decides.
    const exposures = new Map<string, ExposureKey>()
    for (const approval of approvals) {
      exposures.set(key(approval), { token: approval.token, spender: approval.spender })
    }

    audit('watch.scan', {
      block: currentBlock,
      fromBlock,
      tokensWatched: tokens.length,
      approvalEvents: approvals.length,
      distinctExposures: exposures.size,
    })

    const performed: RevokeOutcome[] = []

    for (const exposure of exposures.values()) {
      if (this.stopped) break
      if (this.handled.has(key(exposure))) continue

      const allowance = await readAllowance(exposure.token, this.owner, exposure.spender)
      if (allowance === 0n) continue

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
        idempotencyKey: `revoke-${key(exposure)}-${detectedAt}`,
      })

      // Only mark handled once the chain agrees the allowance is gone, so a
      // failed revoke gets retried on the next scan rather than silently
      // dropped.
      if (outcome.executed && outcome.allowanceAfter === 0n) {
        this.handled.add(key(exposure))
        this.revokeCount += 1
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
        audit('revoke.failed', {
          stage: 'scan',
          error: error instanceof Error ? error.message : String(error),
        })
      }
      if (this.stopped) break
      await new Promise((resolve) => setTimeout(resolve, this.pollIntervalMs))
    }
  }
}
