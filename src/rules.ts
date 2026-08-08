import type { Address } from 'viem'
import {
  HistoricalStateUnavailable,
  MAX_UINT256,
  blocksInDays,
  findDeploymentBlock,
  hasCodeAt,
} from './chain.js'
import type { KeeperHub } from './keeperhub.js'
import { PERMIT2_ADDRESS, PERMIT2_MAX_AMOUNT, isPermit2 } from './permit2.js'

/**
 * Four concrete, auditable threat rules and two holds.
 *
 * Deliberately NOT an ML "maliciousness score". Every rule states a fact about
 * chain state that anyone can independently check, and every firing carries the
 * evidence that produced it. An agent that moves funds on an opaque classifier
 * is not auditable, and "the model said so" is not a defence when it is wrong.
 *
 * The tradeoff is stated plainly: a sophisticated spender that is verified,
 * aged, and absent from the deny-list will not trip any of these. That case is
 * out of scope, not silently mishandled.
 *
 * ── The invariant every rule here obeys ──────────────────────────────────────
 *
 * A rule may fire only on a fact it OBSERVED. A lookup that failed is not a
 * fact, and the failure of a detection input must never be convertible into a
 * verdict — in either direction. So there are exactly three outcomes, not two:
 *
 *   fired: true                     an observed fact says this is a threat
 *   fired: false                    an observed fact says it is not
 *   fired: false, indeterminate     nothing was observed; the rule abstained
 *
 * The third is not a shade of the second. It is reported with the remedy that
 * would restore the rule, and no path may report the spender safe on the
 * strength of it. See `indeterminate()` and `verificationOrAbstain()` below —
 * and see keeperhub.ts → sourceVerification for what happened when this
 * distinction was missing from the one type that needed it.
 */

/**
 * The extra facts a Permit2 exposure carries that an ERC-20 approval does not.
 *
 * Present only when the exposure came from Permit2's own allowance ledger. Its
 * absence is what tells every rule below "this is a plain ERC-20 approval" —
 * modelled as an optional member rather than a second context type so the
 * existing rules keep working on both without a discriminant switch each.
 */
export interface Permit2Facts {
  /** Unix seconds. Permit2 refuses the transfer once chain time passes it. */
  expiration: number
  nonce: number
  /**
   * Latest block timestamp, in Unix seconds — NOT the host clock.
   *
   * Optional because it is a separate RPC read that can fail on its own. When
   * it is missing the lifetime rule has no reference point, and the only
   * honest answer is INDETERMINATE. Defaulting it to `Date.now()` would let a
   * drifted or unreachable clock silently decide that a live grant had expired.
   */
  chainTimeSeconds?: number
}

export interface ThreatContext {
  token: Address
  spender: Address
  owner: Address
  /**
   * The live allowance. For a Permit2 exposure this is the uint160 `amount`
   * from Permit2's ledger, so the two paths share every rule that only needs a
   * magnitude.
   */
  allowance: bigint
  balance: bigint
  currentBlock: bigint
  kh: KeeperHub
  denylist: ReadonlySet<string>
  /**
   * Spenders the operator has explicitly blessed — their own routers, pools and
   * settlement contracts. Never a reason to suppress a rule: an allow-listed
   * spender is evaluated exactly like any other and, if it is a threat, it is
   * reported as one. It is a reason to withhold the unattended TRANSACTION, via
   * the hold channel. See operatorAllowlisted.
   *
   * Optional so a read-only caller that has no operator context (a script
   * checking one pair) does not have to invent one; absent means "no blessings",
   * which can only ever make the agent more willing to act, never less. Every
   * path that can actually sign supplies it — see watcher.ts and mcp.ts.
   */
  allowlist?: ReadonlySet<string>
  /** Set only for Permit2 exposures. See Permit2Facts. */
  permit2?: Permit2Facts
}

/**
 * "Unlimited" is a different number on each surface: `type(uint256).max` for an
 * ERC-20 allowance, `type(uint160).max` for Permit2's packed amount. Comparing
 * a Permit2 amount against MAX_UINT256 can never match, which would score every
 * unlimited Permit2 grant as bounded and clear it.
 */
function unlimitedSentinel(ctx: ThreatContext): { value: bigint; label: string } {
  return ctx.permit2
    ? { value: PERMIT2_MAX_AMOUNT, label: 'MAX_UINT160' }
    : { value: MAX_UINT256, label: 'MAX_UINT256' }
}

export interface RuleVerdict {
  rule: string
  fired: boolean
  reason: string
  evidence: Record<string, unknown>
}

/**
 * The verdict a rule returns when it could not establish the fact it needs.
 *
 * `fired: false` here does NOT mean "safe" and is never allowed to read as
 * such: the evidence carries `indeterminate: true` and the remedy that would
 * restore the rule, and the reason is prefixed INDETERMINATE so it survives
 * being skimmed in a log. Extracted into one function because there are now
 * four places that abstain and the discipline is the property being defended —
 * a fifth that quietly omitted `indeterminate` would be indistinguishable, in
 * the audit trail, from a rule that looked and found nothing.
 */
function indeterminate(
  rule: string,
  reason: string,
  remedy: string,
  evidence: Record<string, unknown> = {},
): RuleVerdict {
  return {
    rule,
    fired: false,
    reason: `INDETERMINATE — ${reason}; rule abstained`,
    evidence: { ...evidence, indeterminate: true, remedy },
  }
}

/**
 * The source-verification lookup, with the one answer that must never be acted
 * on separated out.
 *
 * `'unknown'` means the ABI endpoint did not answer. Both rules that consult
 * verification abstain on it, because the alternative — the behaviour this
 * codebase actually shipped — is that a single explorer outage makes
 * `fired: !verified` true for every unlimited approval in the wallet at the same
 * instant, and an unattended agent revokes all of them. Detection inputs fail;
 * a rule that converts a failed input into a firing verdict converts an outage
 * into an attack.
 */
async function verificationOrAbstain(
  ctx: ThreatContext,
  ruleId: string,
  evidence: Record<string, unknown>,
): Promise<{ verified: boolean } | { abstained: RuleVerdict }> {
  const verification = await ctx.kh.sourceVerification(ctx.spender)
  if (verification === 'unknown') {
    return {
      abstained: indeterminate(
        ruleId,
        'source verification lookup failed — the explorer did not answer',
        'retry once the KeeperHub ABI endpoint / block explorer is reachable; ' +
          'this rule needs a POSITIVE answer either way and will not fire on a failed lookup',
        { ...evidence, sourceVerification: verification },
      ),
    }
  }
  return { verified: verification === 'verified' }
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
    const sentinel = unlimitedSentinel(ctx)
    if (ctx.allowance !== sentinel.value) {
      return {
        rule: this.id,
        fired: false,
        reason: 'allowance is bounded',
        evidence: { allowance: ctx.allowance.toString() },
      }
    }

    const lookup = await verificationOrAbstain(ctx, this.id, { allowance: sentinel.label })
    if ('abstained' in lookup) return lookup.abstained

    return {
      rule: this.id,
      fired: !lookup.verified,
      reason: lookup.verified
        ? 'unlimited, but spender source is verified'
        : 'unlimited approval to an unverified contract',
      evidence: {
        allowance: sentinel.label,
        sourceVerified: lookup.verified,
        sourceVerification: lookup.verified ? 'verified' : 'unverified',
      },
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
        // archive RPC (point SEPOLIA_RPC_URL at one) restores this rule; without one it
        // abstains loudly and the other two rules still stand.
        return indeterminate(
          this.id,
          'RPC does not serve historical state',
          'point SEPOLIA_RPC_URL at an archive node to enable this rule',
          { cutoffBlock: cutoff.toString() },
        )
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

/**
 * Beyond this, a Permit2 grant has stopped behaving like a session and started
 * behaving like an ERC-20 approval with extra steps.
 *
 * 30 days is not a taste call: it is the expiration Uniswap's own interface
 * writes for a routine swap approval, so it is the ceiling of normal. A grant
 * that outlives it was either deliberately widened or signed blind.
 */
export const PERMIT2_LONG_LIVED_DAYS = 30
const PERMIT2_LONG_LIVED_SECONDS = PERMIT2_LONG_LIVED_DAYS * 24 * 60 * 60

/**
 * Rule 4 — a Permit2 allowance that outlives the session it pretends to be,
 * held by a spender nobody can read the source of.
 *
 * This is the rule the ERC-20 path cannot express, because ERC-20 approvals
 * have no expiry: every one of them is already forever. Permit2 added a clock
 * precisely so grants would die on their own, which makes a grant that opts out
 * of the clock a statement of intent worth acting on.
 *
 * The inverse matters just as much and is stated as a checkable fact rather
 * than a silence: an EXPIRED Permit2 allowance is not a threat. Permit2 reverts
 * the transfer, so there is nothing to revoke and `lockdown()` would burn gas
 * to change a number nobody can use. That verdict is reported, not assumed.
 */
export const permit2LongLived: ThreatRule = {
  id: 'permit2-long-lived',
  description: `Permit2 allowance valid for more than ${PERMIT2_LONG_LIVED_DAYS} days, held by a contract with unverified source`,
  async evaluate(ctx): Promise<RuleVerdict> {
    const facts = ctx.permit2
    if (!facts) {
      return {
        rule: this.id,
        fired: false,
        reason: 'not a Permit2 exposure',
        evidence: { permit2: false },
      }
    }

    const { chainTimeSeconds } = facts
    if (chainTimeSeconds === undefined) {
      // Fail closed, exactly as young-spender does when the RPC cannot serve
      // historical state. Without chain time there is no reference point for
      // "how long does this last", and answering "not a threat" would be a
      // claim about the chain we have no evidence for.
      return indeterminate(
        this.id,
        'chain timestamp unavailable — lifetime could not be measured',
        'the latest block timestamp is required to compare against expiration',
        { expiration: facts.expiration },
      )
    }

    // Matches AllowanceTransfer exactly: it reverts on
    // `block.timestamp > allowed.expiration`, so equality is still live.
    if (chainTimeSeconds > facts.expiration) {
      return {
        rule: this.id,
        fired: false,
        reason: 'Permit2 allowance has expired — the transfer would revert',
        evidence: {
          expiration: facts.expiration,
          chainTimeSeconds,
          expiredForSeconds: chainTimeSeconds - facts.expiration,
        },
      }
    }

    const secondsRemaining = facts.expiration - chainTimeSeconds
    if (secondsRemaining <= PERMIT2_LONG_LIVED_SECONDS) {
      return {
        rule: this.id,
        fired: false,
        reason: `Permit2 allowance expires in ${(secondsRemaining / 86_400).toFixed(2)} days, within the ${PERMIT2_LONG_LIVED_DAYS}-day norm`,
        evidence: { expiration: facts.expiration, secondsRemaining },
      }
    }

    const lookup = await verificationOrAbstain(ctx, this.id, {
      expiration: facts.expiration,
      chainTimeSeconds,
      secondsRemaining,
    })
    if ('abstained' in lookup) return lookup.abstained

    return {
      rule: this.id,
      fired: !lookup.verified,
      reason: lookup.verified
        ? 'long-lived Permit2 allowance, but spender source is verified'
        : `Permit2 allowance valid for another ${(secondsRemaining / 86_400).toFixed(2)} days on an unverified contract`,
      evidence: {
        expiration: facts.expiration,
        chainTimeSeconds,
        secondsRemaining,
        daysRemaining: Number((secondsRemaining / 86_400).toFixed(3)),
        nonce: facts.nonce,
        sourceVerified: lookup.verified,
        sourceVerification: lookup.verified ? 'verified' : 'unverified',
      },
    }
  },
}

export const ALL_RULES: readonly ThreatRule[] = [
  unlimitedToUnverified,
  youngSpender,
  denylisted,
  permit2LongLived,
]

/**
 * A hold states a fact that is worth reporting and that must NOT be acted on
 * unattended. Same shape as a threat rule so the evidence discipline is
 * identical; different list so it can never contribute to `threat` and can
 * never authorise a transaction on its own.
 */
export type HoldRule = ThreatRule

/**
 * Hold 1 — the ERC-20 approval granted TO Permit2 itself.
 *
 * This is the upstream root of every Permit2 allowance for that token: Permit2
 * can only move what the token contract has approved it to move, so
 * `approve(PERMIT2, x)` is the single grant that enables the entire downstream
 * ledger. Revoking it kills every Permit2 allowance for the token at once,
 * including ones the owner still wants.
 *
 * THE TRADEOFF, stated plainly, because this is the one place Revoker
 * deliberately does less than it could:
 *
 *   Downstream (`lockdown()`) is a scalpel. It zeroes exactly the (token,
 *   spender) slots that fired, costs one transaction, and nothing else in the
 *   wallet notices.
 *
 *   Upstream (`approve(PERMIT2, 0)`) is an amputation. It breaks Uniswap,
 *   every router, and every dapp that routes that token through Permit2 —
 *   silently, at the next swap, for a wallet whose owner is asleep and did not
 *   ask for it. It is also the ONE approval most likely to be both unlimited
 *   and long-forgotten, which is precisely what makes an automated agent likely
 *   to reach for it: `unlimited-to-unverified` would fire on it the moment an
 *   explorer lookup blips and reports Permit2's source as unverified.
 *
 * So it is reported with its own identity, never revoked autonomously, and
 * offered to a human through the MCP surface where `confirm: true` is a person
 * saying yes. An agent that can quietly disconnect its owner from every DEX on
 * the chain is not a security agent.
 */
export const upstreamPermit2Approval: HoldRule = {
  id: 'upstream-permit2-approval',
  description:
    'ERC-20 approval granted to Permit2 itself — the enabling grant behind every Permit2 allowance for this token',
  evaluate(ctx): Promise<RuleVerdict> {
    const hit = isPermit2(ctx.spender)
    return Promise.resolve({
      rule: this.id,
      fired: hit,
      reason: hit
        ? 'spender is the canonical Permit2 contract — revoking this breaks every Permit2 integration for this token, so it is reported and left for a human'
        : 'spender is not Permit2',
      evidence: hit
        ? {
            permit2Address: PERMIT2_ADDRESS,
            allowance: ctx.allowance.toString(),
            autonomousRevoke: false,
            remedy:
              'downstream Permit2 allowances are revoked surgically via lockdown(); revoke this one by hand through the MCP revoke_approval tool with confirm: true',
          }
        : {},
    })
  },
}

/**
 * Hold 2 — the spender is on the operator's own allow-list.
 *
 * The mirror image of the deny-list, and it exists because of what the rules
 * actually key on. `young-spender` fires on any contract deployed in the last
 * seven days; integrating a brand-new venue at launch is the single most normal
 * thing a trading agent does. `unlimited-to-unverified` fires on any unlimited
 * approval whose spender the explorer has not indexed yet — which is every
 * router, for the first hours of its life. Both are correct rules and both
 * describe a genuine risk, and both of them, pointed at an agent wallet's own
 * infrastructure, describe the wallet working as intended.
 *
 * So an operator may state, in advance and in writing, which spenders their
 * strategy depends on. That statement does NOT suppress detection: the rules
 * still run, the exposure is still reported, the evidence is still on the
 * record, and it is still offerable to a human through the MCP surface. It
 * withholds exactly one thing — the unattended signature.
 *
 * Reported through the SAME hold channel as upstreamPermit2Approval rather than
 * as a filter earlier in the pipeline, because a suppressed exposure and an
 * absent exposure look identical in a log, and the difference between them is
 * the entire safety argument.
 *
 * The tradeoff stated plainly: an operator who allow-lists a spender that later
 * turns hostile has opted that spender out of autonomous protection. That is a
 * decision they made explicitly, with the address in front of them, which is a
 * categorically better failure than an agent that quietly decided the same
 * thing on their behalf.
 */
export const operatorAllowlisted: HoldRule = {
  id: 'operator-allowlisted',
  description:
    'Spender is on the operator-maintained allow-list — detected and reported, never revoked unattended',
  evaluate(ctx): Promise<RuleVerdict> {
    const allowlist = ctx.allowlist
    const hit = allowlist !== undefined && allowlist.has(ctx.spender.toLowerCase())
    return Promise.resolve({
      rule: this.id,
      fired: hit,
      reason: hit
        ? 'spender is operator-allowlisted — the exposure is real and is reported, but the unattended loop will not sign a revoke for it'
        : 'spender is not operator-allowlisted',
      evidence: hit
        ? {
            allowlistSize: allowlist.size,
            allowance: ctx.allowance.toString(),
            autonomousRevoke: false,
            remedy:
              'remove the address from data/allowlist.json (or REVOKER_ALLOWLIST) to let the agent act on it, ' +
              'or revoke it now by hand through the MCP revoke_approval tool with confirm: true',
          }
        : { allowlistSize: allowlist?.size ?? 0 },
    })
  },
}

export const ALL_HOLDS: readonly HoldRule[] = [upstreamPermit2Approval, operatorAllowlisted]

export interface ThreatAssessment {
  threat: boolean
  fired: RuleVerdict[]
  all: RuleVerdict[]
  /**
   * Holds that fired. Non-empty means the agent found something real and is
   * refusing to act on it unattended — reported, never hidden. Kept out of
   * `fired`/`all` so a hold can neither create a threat nor mask one.
   */
  holds: RuleVerdict[]
}

/**
 * Any rule firing is sufficient. These are independent signals of different
 * kinds, not weighted contributions to a score — requiring consensus between
 * them would mean ignoring a confirmed deny-list hit because the contract
 * happened to be verified.
 */
export async function assess(
  ctx: ThreatContext,
  rules = ALL_RULES,
  holdRules = ALL_HOLDS,
): Promise<ThreatAssessment> {
  const [all, holdVerdicts] = await Promise.all([
    Promise.all(rules.map((rule) => rule.evaluate(ctx))),
    Promise.all(holdRules.map((rule) => rule.evaluate(ctx))),
  ])
  const fired = all.filter((verdict) => verdict.fired)
  return { threat: fired.length > 0, fired, all, holds: holdVerdicts.filter((v) => v.fired) }
}

/**
 * The single gate the autonomous loop asks. A threat with a hold on it is still
 * a threat — it is reported, it appears in the audit trail, and a human can act
 * on it — but nothing unattended may sign for it.
 */
export function mayRevokeUnattended(assessment: ThreatAssessment): boolean {
  return assessment.threat && assessment.holds.length === 0
}
