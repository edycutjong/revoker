import { readFileSync } from 'node:fs'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import type { Address } from 'viem'
import {
  MAX_UINT256,
  fetchApprovals,
  publicClient,
  readAllowance,
  readBalance,
  readChainTimeSeconds,
  tokenSymbol,
} from './chain.js'
import { config } from './config.js'
import { KeeperHub, type SimulationResult } from './keeperhub.js'
import {
  PERMIT2_ABI_JSON,
  PERMIT2_ADDRESS,
  PERMIT2_MAX_AMOUNT,
  fetchPermit2Pairs,
  isPermit2,
  permit2Status,
  readPermit2Allowance,
  type Permit2Allowance,
} from './permit2.js'
import { revokeApproval, revokePermit2Allowances, type RevokeOutcome } from './revoke.js'
import {
  ALL_HOLDS,
  ALL_RULES,
  assess,
  mayRevokeUnattended,
  type RuleVerdict,
  type ThreatAssessment,
} from './rules.js'
import type { ExposureKey } from './watcher.js'

/**
 * MCP surface — Revoker's threat intelligence, answerable by an agent.
 *
 * Read this before assuming what it is for, because there are two things called
 * "MCP in a security agent" and this project ships one and refuses the other.
 *
 * REFUSED: a model in the decision path. The autonomous loop (watcher.ts) sees
 * no model and gains none here. It decides with three deterministic rules over
 * chain state, so the same inputs always produce the same revoke, and the reason
 * survives being read back a month later. A transaction that moves someone's
 * money cannot be justified by "the model thought so", and a loop whose output
 * depends on sampling temperature is not reproducible enough to defend.
 *
 * SHIPPED, and this file: a query surface over the same facts. The owner — or
 * the assistant sitting next to them — asks "what am I exposed to right now, and
 * why?", and gets the exposures, the rules that fired, and the evidence behind
 * each one. Three of the four tools are pure reads and cannot change chain state
 * at all. The fourth can, which is exactly why `confirm: true` exists: an agent
 * may propose a revoke, but a human authorises it.
 *
 * The separation is structural, not a convention: nothing in watcher.ts imports
 * this module, and no tool here can reach the loop's decision.
 *
 *   pnpm mcp    speak MCP over stdio
 */

function readJson<T>(file: string, fallback: T): T {
  try {
    return JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8')) as T
  } catch {
    return fallback
  }
}

/** Reported on initialize. Read from package.json so it cannot drift from the release. */
const VERSION = readJson<{ version: string }>('../package.json', { version: '0.0.0' }).version

/**
 * The same window watcher.ts scans by default, so both surfaces agree about what
 * counts as a live approval rather than the dashboard and the agent disagreeing.
 */
const LOOKBACK_BLOCKS = 5_000n

const APPROVE_ABI: unknown[] = [
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

/** Everything the tools read from. Injected, so a test never needs credentials. */
export interface McpContext {
  owner: Address
  kh: KeeperHub
  /** Tokens to look for Approval logs on — see fetchApprovals for why this is explicit. */
  tokens: readonly Address[]
  denylist: ReadonlySet<string>
  lookbackBlocks: bigint
}

/**
 * Which allowance ledger an exposure lives in.
 *
 * Not cosmetic: the two are revoked by different contracts with different
 * primitives, so a caller that cannot tell them apart cannot act on either.
 */
export type AllowanceStandard = 'erc20' | 'permit2'

export interface Exposure extends ExposureKey {
  standard: AllowanceStandard
  symbol: string
  /** Decimal strings: an unlimited allowance is 78 digits and JSON has no bigint. */
  allowance: string
  unlimited: boolean
  /**
   * What the spender could actually take on the next block — min(allowance,
   * balance), not the raw balance. An unlimited approval over an empty wallet is
   * a real risk but not a present loss, and reporting the allowance as the
   * exposure would make every idle approval look like a five-alarm fire.
   */
  atRisk: string
  /** Permit2 only. Unix seconds; Permit2 refuses the transfer past this. */
  expiresAt?: number
  /**
   * Permit2 only. Reported rather than filtered out: an expired grant is not a
   * threat, and being able to SEE that Revoker knows the difference is the
   * point. A surface that silently dropped them would be indistinguishable from
   * one that never looked.
   */
  expired?: boolean
  /** Permit2 only. Negative once expired. */
  secondsRemaining?: number
  /**
   * ERC-20 only, and the reason this field exists: this approval is the one
   * granted TO Permit2 itself — the upstream root that enables every Permit2
   * allowance for this token. Flagged distinctly because revoking it is a far
   * bigger hammer than revoking any ordinary spender. See rules.ts →
   * upstreamPermit2Approval for the full tradeoff.
   */
  upstreamPermit2?: boolean
}

export interface ExposureExplanation extends Exposure {
  owner: Address
  blockNumber: string
  threat: boolean
  /** Rules that fired, each carrying the chain facts that produced it. */
  fired: RuleVerdict[]
  /** Every rule evaluated — a rule that stayed quiet is part of the answer. */
  all: RuleVerdict[]
  /**
   * Holds that fired: findings the autonomous loop deliberately will NOT act
   * on. Non-empty means a human has to decide.
   */
  holds: RuleVerdict[]
  /** False when a hold fired. The loop's own gate, reported verbatim. */
  autonomousRevoke: boolean
  /** What each rule id means, so the reader does not need the source open. */
  catalogue: Array<{ id: string; description: string }>
}

export interface SimulationReport extends SimulationResult {
  token: Address
  spender: Address
  /** Always false. simulate() encodes, estimates and eth_calls — it never broadcasts. */
  broadcast: false
}

export type RevokeDecision =
  | { authorised: false; reason: string }
  | { authorised: true; outcome: RevokeOutcome }

const CONFIRMATION_REQUIRED =
  'Refused: revoke_approval writes on-chain and will not run on a model request alone. ' +
  'Show the caller what explain_exposure and simulate_revoke returned, get an explicit human ' +
  'yes, then call again with confirm: true.'

/** The production wiring: the watched wallet, its watchlist, and the deny-list. */
export function defaultContext(): McpContext {
  const watchlist = readJson<Record<string, Array<{ address: string }> | undefined>>(
    '../data/watchlist.json',
    {},
  )
  const denylist = readJson<{ addresses?: Array<{ address: string }> }>('../data/denylist.json', {})

  return {
    owner: config.walletAddress,
    kh: new KeeperHub(),
    tokens: (watchlist[String(config.chainId)] ?? []).map((entry) => entry.address as Address),
    denylist: new Set((denylist.addresses ?? []).map((entry) => entry.address.toLowerCase())),
    lookbackBlocks: LOOKBACK_BLOCKS,
  }
}

function toExposure(
  token: Address,
  spender: Address,
  symbol: string,
  allowance: bigint,
  balance: bigint,
): Exposure {
  return {
    token,
    spender,
    standard: 'erc20',
    symbol,
    allowance: allowance.toString(),
    unlimited: allowance === MAX_UINT256,
    atRisk: (allowance < balance ? allowance : balance).toString(),
    // Only ever true, never false: an absent flag reads as "ordinary spender",
    // and a `false` on every one of them would bury the one that matters.
    ...(isPermit2(spender) ? { upstreamPermit2: true } : {}),
  }
}

/**
 * The Permit2 equivalent. The unlimited sentinel is `type(uint160).max`, not
 * `type(uint256).max` — comparing against the wrong one would report every
 * unlimited Permit2 grant as bounded.
 */
function toPermit2Exposure(
  token: Address,
  spender: Address,
  symbol: string,
  allowance: Permit2Allowance,
  balance: bigint,
  chainTimeSeconds: number,
): Exposure {
  const { amount } = allowance
  return {
    token,
    spender,
    standard: 'permit2',
    symbol,
    allowance: amount.toString(),
    unlimited: amount === PERMIT2_MAX_AMOUNT,
    // An expired grant can take nothing, whatever the amount says.
    atRisk:
      permit2Status(allowance, chainTimeSeconds) === 'expired'
        ? '0'
        : (amount < balance ? amount : balance).toString(),
    expiresAt: allowance.expiration,
    expired: chainTimeSeconds > allowance.expiration,
    secondsRemaining: allowance.expiration - chainTimeSeconds,
  }
}

/**
 * Every live (token, spender) approval the watched wallet has granted.
 *
 * This is the read-only half of what Watcher.scan does, built from the same
 * chain.ts primitives so the two cannot drift. It deliberately stops where the
 * watcher continues: no assessment is run and no revoke can follow from here.
 */
export async function listExposures(ctx: McpContext): Promise<Exposure[]> {
  const currentBlock = await publicClient.getBlockNumber()
  const fromBlock = currentBlock > ctx.lookbackBlocks ? currentBlock - ctx.lookbackBlocks : 0n

  const tokens = new Map<string, Address>()
  for (const token of [...ctx.tokens, ...((await ctx.kh.getHeldTokens()) as Address[])]) {
    tokens.set(token.toLowerCase(), token)
  }

  const approvals = await fetchApprovals(ctx.owner, [...tokens.values()], fromBlock, currentBlock)

  // Approval logs are history; only the live allowance says whether the exposure
  // still exists. Collapse the log stream to the distinct pairs it mentions.
  const pairs = new Map<string, ExposureKey>()
  for (const approval of approvals) {
    const key = `${approval.token.toLowerCase()}:${approval.spender.toLowerCase()}`
    pairs.set(key, { token: approval.token, spender: approval.spender })
  }

  const exposures: Exposure[] = []
  for (const pair of pairs.values()) {
    const allowance = await readAllowance(pair.token, ctx.owner, pair.spender)
    // A zeroed allowance is a revoke that already happened, not an exposure.
    if (allowance === 0n) continue

    const balance = await readBalance(pair.token, ctx.owner)
    const symbol = await tokenSymbol(pair.token)
    exposures.push(toExposure(pair.token, pair.spender, symbol, allowance, balance))
  }

  // Permit2's ledger, discovered from Permit2's own logs. Not a variation on
  // the query above: the token is a topic here rather than the emitting
  // address, and a signature-based grant leaves no trace on the token at all —
  // so a surface that only ran the loop above would report "no exposures" for a
  // wallet with a live, drainable Permit2 allowance.
  const permit2Pairs = await fetchPermit2Pairs(ctx.owner, fromBlock, currentBlock)
  if (permit2Pairs.length > 0) {
    const chainTimeSeconds = await readChainTimeSeconds()
    for (const pair of permit2Pairs) {
      const allowance = await readPermit2Allowance(ctx.owner, pair.token, pair.spender)
      // Zero amount is a lockdown that already landed. Expired slots ARE
      // reported — see Exposure.expired.
      if (permit2Status(allowance, chainTimeSeconds) === 'empty') continue

      const balance = await readBalance(pair.token, ctx.owner)
      const symbol = await tokenSymbol(pair.token)
      exposures.push(
        toPermit2Exposure(pair.token, pair.spender, symbol, allowance, balance, chainTimeSeconds),
      )
    }
  }

  return exposures
}

/**
 * The threat assessment for one pair, with its evidence.
 *
 * Runs the real rules.ts assessment — the same call the watcher makes before it
 * decides to revoke — so what an investigator is shown here is what the agent
 * would act on, not a parallel explanation written to sound convincing.
 *
 * Works on any pair, including one that never appears in list_exposures, so a
 * spender someone is merely suspicious of can be checked before it is granted.
 */
export async function explainExposure(
  ctx: McpContext,
  token: Address,
  spender: Address,
  via: AllowanceStandard = 'erc20',
): Promise<ExposureExplanation> {
  const currentBlock = await publicClient.getBlockNumber()
  const balance = await readBalance(token, ctx.owner)
  const symbol = await tokenSymbol(token)

  const { exposure, assessment } =
    via === 'permit2'
      ? await explainPermit2(ctx, token, spender, symbol, balance, currentBlock)
      : await explainErc20(ctx, token, spender, symbol, balance, currentBlock)

  return {
    ...exposure,
    owner: ctx.owner,
    blockNumber: currentBlock.toString(),
    threat: assessment.threat,
    fired: assessment.fired,
    all: assessment.all,
    holds: assessment.holds,
    autonomousRevoke: mayRevokeUnattended(assessment),
    catalogue: [...ALL_RULES, ...ALL_HOLDS].map((rule) => ({
      id: rule.id,
      description: rule.description,
    })),
  }
}

async function explainErc20(
  ctx: McpContext,
  token: Address,
  spender: Address,
  symbol: string,
  balance: bigint,
  currentBlock: bigint,
): Promise<{ exposure: Exposure; assessment: ThreatAssessment }> {
  const allowance = await readAllowance(token, ctx.owner, spender)
  const assessment = await assess({
    token,
    spender,
    owner: ctx.owner,
    allowance,
    balance,
    currentBlock,
    kh: ctx.kh,
    denylist: ctx.denylist,
  })
  return { exposure: toExposure(token, spender, symbol, allowance, balance), assessment }
}

async function explainPermit2(
  ctx: McpContext,
  token: Address,
  spender: Address,
  symbol: string,
  balance: bigint,
  currentBlock: bigint,
): Promise<{ exposure: Exposure; assessment: ThreatAssessment }> {
  const allowance = await readPermit2Allowance(ctx.owner, token, spender)

  // A failed block read must not become a silent "not expired". Passing
  // undefined through makes permit2-long-lived report INDETERMINATE, which is
  // the one answer that is true when the clock cannot be established. See
  // rules.ts → Permit2Facts.chainTimeSeconds.
  const chainTimeSeconds = await readChainTimeSeconds().catch(() => undefined)

  const assessment = await assess({
    token,
    spender,
    owner: ctx.owner,
    allowance: allowance.amount,
    balance,
    currentBlock,
    kh: ctx.kh,
    denylist: ctx.denylist,
    permit2: {
      expiration: allowance.expiration,
      nonce: allowance.nonce,
      ...(chainTimeSeconds === undefined ? {} : { chainTimeSeconds }),
    },
  })

  // Without chain time the derived expiry fields would be fiction, so the
  // exposure is reported without them rather than with invented ones.
  const exposure: Exposure =
    chainTimeSeconds === undefined
      ? {
          token,
          spender,
          standard: 'permit2',
          symbol,
          allowance: allowance.amount.toString(),
          unlimited: allowance.amount === PERMIT2_MAX_AMOUNT,
          atRisk: (allowance.amount < balance ? allowance.amount : balance).toString(),
          expiresAt: allowance.expiration,
        }
      : toPermit2Exposure(token, spender, symbol, allowance, balance, chainTimeSeconds)

  return { exposure, assessment }
}

/**
 * Dry-run the revoke through KeeperHub.
 *
 * Sends the identical approve(spender, 0) call the live revoke sends, with
 * simulate set: KeeperHub validates, encodes, estimates gas and eth_calls it
 * against current state, then throws the result away. Whether it would revert is
 * knowable before anyone spends gas or commits to anything.
 */
export async function simulateRevoke(
  ctx: McpContext,
  token: Address,
  spender: Address,
  via: AllowanceStandard = 'erc20',
): Promise<SimulationReport> {
  const result = await (via === 'permit2'
    ? // The Permit2 revoke is a lockdown over a one-element pair array — the
      // same call the batched autonomous path sends, with a batch of one.
      ctx.kh.simulate({
        contractAddress: PERMIT2_ADDRESS,
        functionName: 'lockdown',
        functionArgs: [[{ token, spender }]],
        abi: PERMIT2_ABI_JSON,
      })
    : ctx.kh.simulate({
        contractAddress: token,
        functionName: 'approve',
        functionArgs: [spender, '0'],
        abi: APPROVE_ABI,
      }))
  return { ...result, token, spender, broadcast: false }
}

/**
 * The write, behind an explicit human confirmation.
 *
 * Executes through revoke.ts, so a human-initiated revoke takes the same
 * check-and-execute path as an autonomous one and lands in the same audit trail.
 * There is no second, looser code path for the interactive case.
 */
export async function revokeExposure(
  ctx: McpContext,
  token: Address,
  spender: Address,
  confirm: boolean | undefined,
  via: AllowanceStandard = 'erc20',
): Promise<RevokeDecision> {
  // Anything other than a literal true refuses. A missing argument and a
  // deliberate false are the same answer, and treating either as consent is how
  // an agent ends up signing for a human who never said yes.
  if (confirm !== true) return { authorised: false, reason: CONFIRMATION_REQUIRED }

  // Prefixed so the audit trail records which surface asked. Within KeeperHub's
  // dedupe window a retried tool call cannot double-execute.
  const idempotencyKey = `mcp-revoke-${token.toLowerCase()}:${spender.toLowerCase()}-${Date.now()}`

  // This is also the only route to revoking the ERC-20 approval granted to
  // Permit2 itself: the autonomous loop holds that one back (rules.ts →
  // upstreamPermit2Approval), so it can only ever be cleared by a human saying
  // yes here.
  const outcome = await (via === 'permit2'
    ? revokePermit2Allowances({
        kh: ctx.kh,
        owner: ctx.owner,
        pairs: [{ token, spender }],
        idempotencyKey,
      })
    : revokeApproval({ kh: ctx.kh, token, owner: ctx.owner, spender, idempotencyKey }))
  return { authorised: true, outcome }
}

/** JSON has no bigint, and an unserialisable allowance would throw mid-response. */
function bigintSafe(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value
}

function textResult(payload: unknown, isError = false): CallToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, bigintSafe, 2) }],
    ...(isError ? { isError: true } : {}),
  }
}

const addressArg = z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'must be a 0x-prefixed 20-byte address')

/**
 * Which ledger the pair lives in. Defaulted rather than required so every
 * existing caller keeps working, and described in full because an LLM picking
 * the wrong one would read an empty slot and report "no exposure" about a live
 * one.
 */
const viaArg = z
  .enum(['erc20', 'permit2'])
  .optional()
  .describe(
    "Which allowance ledger: 'erc20' (default) for the token's own allowance mapping, or " +
      "'permit2' for the allowance held inside the Permit2 contract. Permit2 allowances are " +
      'granted by signature and emit NO event on the token, so they are invisible to an ERC-20 ' +
      'approval scan — if list_exposures showed the pair with standard "permit2", use permit2 here.',
  )

const exposureArgs = {
  token: addressArg.describe('ERC-20 token contract the allowance was granted on'),
  spender: addressArg.describe('Address that holds the allowance'),
  via: viaArg,
}

export function createMcpServer(ctx: McpContext): McpServer {
  const server = new McpServer(
    { name: 'revoker', version: VERSION, title: 'Revoker — approval exposure sentinel' },
    {
      instructions:
        'Revoker autonomously revokes dangerous approvals on two surfaces: ERC-20 allowances ' +
        '(approve(spender, 0)) and Permit2 allowances (lockdown(), batched). That loop is ' +
        'deterministic and runs without any model; these tools are the investigation surface ' +
        'over the same data, for a human asking what they are exposed to. Read freely. ' +
        'revoke_approval writes on-chain and refuses without confirm: true, and that flag ' +
        'represents a human decision, never your own inference that a revoke is warranted.',
    },
  )

  server.registerTool(
    'list_exposures',
    {
      title: 'List live approval exposures (ERC-20 and Permit2)',
      description:
        'Every live (token, spender) approval the watched wallet has granted, with the allowance ' +
        'and the amount actually at risk right now. Covers BOTH ledgers and labels each entry ' +
        'with `standard`: "erc20" for the token\'s own allowance mapping, and "permit2" for ' +
        'allowances held inside the Permit2 contract, which are granted by signature and emit no ' +
        'event on the token at all. Permit2 entries also carry expiresAt / expired / ' +
        'secondsRemaining — an expired one is listed but is not a threat, since the transfer ' +
        'would revert. An ERC-20 entry marked upstreamPermit2 is the approval granted to Permit2 ' +
        'itself: the root that enables every Permit2 allowance for that token, and the one the ' +
        'autonomous loop refuses to revoke on its own. Read-only. Pairs whose allowance is ' +
        'already zero are omitted: they are history, not exposure.',
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async () => textResult(await listExposures(ctx)),
  )

  server.registerTool(
    'explain_exposure',
    {
      title: 'Explain why an approval is (or is not) a threat',
      description:
        'Runs the deterministic threat rules against one (token, spender) pair and returns which ' +
        'rules fired, why, and the chain evidence behind each verdict — plus the rules that ' +
        'stayed quiet, which are equally part of the answer. Also returns `holds`: findings the ' +
        'autonomous loop deliberately will not act on, and `autonomousRevoke: false` when one ' +
        'fired. A rule reporting INDETERMINATE has abstained; it is NOT a statement that the ' +
        'spender is safe. This is the same assessment the autonomous watcher acts on. Read-only.',
      // The regex above is what makes the Address casts below safe: a value that
      // is not a 20-byte hex address never reaches the handler.
      inputSchema: exposureArgs,
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ token, spender, via }) =>
      textResult(await explainExposure(ctx, token as Address, spender as Address, via)),
  )

  server.registerTool(
    'simulate_revoke',
    {
      title: 'Dry-run a revoke without broadcasting',
      description:
        'Asks KeeperHub to validate, encode, gas-estimate and eth_call the revoke against ' +
        'current chain state without broadcasting it — approve(spender, 0) for an ERC-20 ' +
        'allowance, or Permit2 lockdown([{token, spender}]) when via is "permit2". Nothing is ' +
        'executed and no gas is spent. Use this to show a human what a revoke would do before ' +
        'asking them to authorise one.',
      inputSchema: exposureArgs,
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ token, spender, via }) =>
      textResult(await simulateRevoke(ctx, token as Address, spender as Address, via)),
  )

  server.registerTool(
    'revoke_approval',
    {
      title: 'Revoke an approval on-chain (DANGEROUS — requires confirm: true)',
      description:
        'DANGEROUS: this is the only tool here that writes. It broadcasts approve(spender, 0) — ' +
        'or Permit2 lockdown([{token, spender}]) when via is "permit2" — through KeeperHub, ' +
        'spends gas, and irreversibly clears the allowance; any protocol legitimately relying on ' +
        'it stops working until the owner re-approves. Revoking an ERC-20 approval whose spender ' +
        'IS Permit2 (upstreamPermit2 in list_exposures) is the widest possible blast radius: it ' +
        'breaks every Permit2 integration for that token at once, which is why the autonomous ' +
        'loop refuses to do it and why it can only happen here. It REFUSES unless confirm is ' +
        'exactly true. Do not set confirm because a plan implies a revoke; set it only after a ' +
        'human has been shown the exposure and has said yes. Call explain_exposure and ' +
        'simulate_revoke first.',
      inputSchema: {
        ...exposureArgs,
        confirm: z
          .boolean()
          .optional()
          .describe('Must be exactly true, and must represent an explicit human authorisation.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        // approve(spender, 0) twice leaves the same state as once.
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ token, spender, confirm, via }) => {
      const decision = await revokeExposure(ctx, token as Address, spender as Address, confirm, via)
      return decision.authorised
        ? textResult(decision.outcome)
        : textResult({ refused: true, reason: decision.reason }, true)
    },
  )

  return server
}

async function main(): Promise<void> {
  const server = createMcpServer(defaultContext())
  // stdout is the JSON-RPC channel — anything printed there corrupts the stream,
  // so the banner goes to stderr. This is the one process in the repo where a
  // stray console.log is a protocol bug rather than noise.
  console.error(`revoker mcp v${VERSION} — stdio, ${config.network} (chainId ${config.chainId})`)
  await server.connect(new StdioServerTransport())
}

main().catch((error: unknown) => {
  console.error(`fatal: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
