import type { Address } from 'viem'
import {
  HistoricalStateUnavailable,
  MAX_UINT256,
  blocksInDays,
  findDeploymentBlock,
  hasCodeAt,
} from './chain.js'
import type { KeeperHub } from './keeperhub.js'

/**
 * Three concrete, auditable threat rules.
 *
 * Deliberately NOT an ML "maliciousness score". Every rule states a fact about
 * chain state that anyone can independently check, and every firing carries the
 * evidence that produced it. An agent that moves funds on an opaque classifier
 * is not auditable, and "the model said so" is not a defence when it is wrong.
 *
 * The tradeoff is stated plainly: a sophisticated spender that is verified,
 * aged, and absent from the deny-list will not trip any of these. That case is
 * out of scope, not silently mishandled.
 */

export interface ThreatContext {
  token: Address
  spender: Address
  owner: Address
  allowance: bigint
  balance: bigint
  currentBlock: bigint
  kh: KeeperHub
  denylist: ReadonlySet<string>
}

export interface RuleVerdict {
  rule: string
  fired: boolean
  reason: string
  evidence: Record<string, unknown>
}

export interface ThreatRule {
  id: string
  description: string
  evaluate(ctx: ThreatContext): Promise<RuleVerdict>
}

/** Age below which a spender contract is considered untrusted. */
export const YOUNG_SPENDER_DAYS = 7

/**
 * Rule 1 — unlimited approval to a contract whose source nobody can read.
 *
 * Unlimited allowance is the difference between "they can take what I agreed
 * to" and "they can take everything, forever". Combined with unverified source
 * it means the holder has no way to know what they granted.
 */
export const unlimitedToUnverified: ThreatRule = {
  id: 'unlimited-to-unverified',
  description: 'Unlimited (MAX_UINT256) approval granted to a contract with unverified source',
  async evaluate(ctx): Promise<RuleVerdict> {
    const isUnlimited = ctx.allowance === MAX_UINT256
    if (!isUnlimited) {
      return {
        rule: this.id,
        fired: false,
        reason: 'allowance is bounded',
        evidence: { allowance: ctx.allowance.toString() },
      }
    }

    const verified = await ctx.kh.isSourceVerified(ctx.spender)
    return {
      rule: this.id,
      fired: !verified,
      reason: verified
        ? 'unlimited, but spender source is verified'
        : 'unlimited approval to an unverified contract',
      evidence: { allowance: 'MAX_UINT256', sourceVerified: verified },
    }
  },
}

/**
 * Rule 2 — the spender contract is newer than YOUNG_SPENDER_DAYS.
 *
 * Drainer contracts are typically deployed shortly before use. A long-lived
 * contract has had time to be scrutinised; one deployed this week has not.
 */
export const youngSpender: ThreatRule = {
  id: 'young-spender',
  description: `Spender contract deployed less than ${YOUNG_SPENDER_DAYS} days ago`,
  async evaluate(ctx): Promise<RuleVerdict> {
    const depth = blocksInDays(YOUNG_SPENDER_DAYS)
    const cutoff = ctx.currentBlock > depth ? ctx.currentBlock - depth : 0n

    // One cheap call decides the rule: if code already existed at the cutoff,
    // the contract predates the window and cannot be young.
    let existedAtCutoff: boolean
    try {
      existedAtCutoff = await hasCodeAt(ctx.spender, cutoff)
    } catch (error) {
      if (error instanceof HistoricalStateUnavailable) {
        // Report inability to evaluate rather than reporting safety. An
        // archive RPC (ARCHIVE_RPC_URL) restores this rule; without one it
        // abstains loudly and the other two rules still stand.
        return {
          rule: this.id,
          fired: false,
          reason: 'INDETERMINATE — RPC does not serve historical state; rule abstained',
          evidence: {
            indeterminate: true,
            cutoffBlock: cutoff.toString(),
            remedy: 'point SEPOLIA_RPC_URL at an archive node to enable this rule',
          },
        }
      }
      throw error
    }

    if (existedAtCutoff) {
      return {
        rule: this.id,
        fired: false,
        reason: `spender predates the ${YOUNG_SPENDER_DAYS}-day window`,
        evidence: { cutoffBlock: cutoff.toString() },
      }
    }

    // The rule has already fired at this point — the contract did not exist at
    // the cutoff. The binary search only sharpens the reported age, so if the
    // node gives out partway we still report the threat, just less precisely.
    try {
      const deployedAt = await findDeploymentBlock(ctx.spender, cutoff, ctx.currentBlock)
      const ageBlocks = ctx.currentBlock - deployedAt
      const ageDays = (Number(ageBlocks) * 12) / 86_400

      return {
        rule: this.id,
        fired: true,
        reason: `spender deployed ~${ageDays.toFixed(2)} days ago`,
        evidence: {
          deploymentBlock: deployedAt.toString(),
          ageBlocks: ageBlocks.toString(),
          ageDays: Number(ageDays.toFixed(3)),
        },
      }
    } catch (error) {
      if (error instanceof HistoricalStateUnavailable) {
        return {
          rule: this.id,
          fired: true,
          reason: `spender is newer than ${YOUNG_SPENDER_DAYS} days (exact age unavailable)`,
          evidence: { cutoffBlock: cutoff.toString(), exactAgeUnavailable: true },
        }
      }
      throw error
    }
  },
}

/**
 * Rule 3 — the spender is on a known-bad list.
 *
 * The least clever rule and often the most useful: once an address is a
 * confirmed drainer, no further inference is needed.
 */
export const denylisted: ThreatRule = {
  id: 'denylisted',
  description: 'Spender appears on the community deny-list',
  // Purely local — no await needed, but the interface is async so every rule
  // can be evaluated uniformly in parallel.
  evaluate(ctx): Promise<RuleVerdict> {
    const hit = ctx.denylist.has(ctx.spender.toLowerCase())
    return Promise.resolve({
      rule: this.id,
      fired: hit,
      reason: hit ? 'spender is deny-listed' : 'spender not deny-listed',
      evidence: { denylistSize: ctx.denylist.size },
    })
  },
}

export const ALL_RULES: readonly ThreatRule[] = [unlimitedToUnverified, youngSpender, denylisted]

export interface ThreatAssessment {
  threat: boolean
  fired: RuleVerdict[]
  all: RuleVerdict[]
}

/**
 * Any rule firing is sufficient. These are independent signals of different
 * kinds, not weighted contributions to a score — requiring consensus between
 * them would mean ignoring a confirmed deny-list hit because the contract
 * happened to be verified.
 */
export async function assess(ctx: ThreatContext, rules = ALL_RULES): Promise<ThreatAssessment> {
  const all = await Promise.all(rules.map((rule) => rule.evaluate(ctx)))
  const fired = all.filter((verdict) => verdict.fired)
  return { threat: fired.length > 0, fired, all }
}
