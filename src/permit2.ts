import { readFileSync } from 'node:fs'
import { parseAbiItem, type Address } from 'viem'
import { publicClient } from './chain.js'
import { config } from './config.js'

/**
 * Permit2 — the approval surface an ERC-20 `Approval` log cannot see.
 *
 * Why this module exists at all. Permit2 keeps its own allowance ledger:
 * `allowance[owner][token][spender] -> (uint160 amount, uint48 expiration,
 * uint48 nonce)`. A signature-based grant (`permit`) writes that slot without
 * the token contract being touched, so the token emits NOTHING — no
 * `Approval(owner, spender, value)`, no state change in the token's own
 * allowance mapping. An approval watcher built only on ERC-20 `Approval` logs,
 * which is every automated revoker we could find including this one until now,
 * is structurally blind to it. Permit/Permit2 abuse accounted for 38% of losses
 * in 2025 incidents over $1M — the single largest slice of modern approval
 * risk. That blind spot is not a corner case; it is where the money went.
 *
 * The detection consequence, and the reason this is not a two-line addition to
 * chain.ts: Permit2's events are emitted FROM THE PERMIT2 CONTRACT, not from
 * the token. `fetchApprovals` filters logs by `address: tokens[]`; here the
 * address filter is the single canonical Permit2 deployment and the TOKEN is a
 * field in the log. Same shape, inverted.
 *
 * Every signature below is transcribed from Uniswap's canonical
 * `permit2/src/interfaces/IAllowanceTransfer.sol`. Nothing here is inferred
 * from a block explorer or from memory.
 */

/**
 * Permit2 is deployed at the same address on every chain (deterministic
 * deployment, salt 0), which is why this is a constant and not a per-chain
 * config entry. Deliberately NOT in config.ts: it is not configurable, and
 * making it look configurable would invite someone to point the lockdown call
 * at an arbitrary contract.
 */
export const PERMIT2_ADDRESS = '0x000000000022D473030F116dDEE9F6B43aC78BA3' as Address

/** True when `address` is the canonical Permit2 deployment. */
export function isPermit2(address: string): boolean {
  return address.toLowerCase() === PERMIT2_ADDRESS.toLowerCase()
}

/**
 * The "unlimited" sentinel on Permit2 is `type(uint160).max`, not
 * `type(uint256).max` — the amount field is packed into 160 bits. Comparing a
 * Permit2 amount against MAX_UINT256 would never match, so every unlimited
 * Permit2 grant would be scored as "bounded" and quietly cleared.
 */
export const PERMIT2_MAX_AMOUNT = (1n << 160n) - 1n

/**
 * `type(uint48).max` — the expiration written for "no expiry". As a Unix
 * timestamp that is roughly 8.9 million years out, so anything at or near it is
 * a permanent grant wearing an expiry field.
 */
export const PERMIT2_MAX_EXPIRATION = Number((1n << 48n) - 1n)

/**
 * The slice of IAllowanceTransfer this agent uses. Two entries, both verbatim:
 * the allowance getter it reads exposures from, and the revoke primitive.
 *
 * `lockdown` is the interesting one. It takes an ARRAY of (token, spender)
 * pairs and zeroes all of them in one transaction — so where the ERC-20 path
 * needs one `approve(spender, 0)` transaction per exposure, Permit2 needs one
 * transaction per scan no matter how many exposures fired.
 */
export const PERMIT2_ABI = [
  {
    inputs: [
      { name: 'user', type: 'address' },
      { name: 'token', type: 'address' },
      { name: 'spender', type: 'address' },
    ],
    name: 'allowance',
    outputs: [
      { name: 'amount', type: 'uint160' },
      { name: 'expiration', type: 'uint48' },
      { name: 'nonce', type: 'uint48' },
    ],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      {
        name: 'approvals',
        type: 'tuple[]',
        components: [
          { name: 'token', type: 'address' },
          { name: 'spender', type: 'address' },
        ],
      },
    ],
    name: 'lockdown',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
] as const

/**
 * The same ABI in the shape KeeperHub's wire format wants: a plain array it can
 * JSON-stringify. Derived from PERMIT2_ABI rather than written out twice, so
 * the ABI viem reads with and the ABI KeeperHub executes with cannot diverge.
 */
export const PERMIT2_ABI_JSON: unknown[] = [...PERMIT2_ABI]

/**
 * ── The guard helper, and why the revoke cannot read Permit2 directly ────────
 *
 * The Permit2 revoke runs through KeeperHub's `check-and-execute`, which reads a
 * contract value, compares it, and only then submits the write — one server-side
 * operation, which is what removes the TOCTOU window this project exists to
 * close. Its condition schema is exactly `{operator, value}`: no output index,
 * no tuple path, no member selector (KeeperHub direct-execution API reference,
 * "Check and Execute" → Condition Operators).
 *
 * `PERMIT2_ABI`'s `allowance` returns THREE values. Guarding on it therefore
 * does not merely read the wrong member — there is no scalar for the evaluator
 * to compare at all, so it reports `observedValue: undefined`, scores `gt 0` as
 * false, and skips the write. That failure is silent and reads like success:
 * observed on Sepolia against a real armed, unlimited, correctly-detected grant,
 * the run logged `revoke.skipped ... reason=guard slot already zero at execution
 * time observed=undefined` and left the slot fully armed.
 *
 * So a minimal on-chain view flattens the tuple to one `uint160` and the guard
 * reads THAT, while the action still calls canonical Permit2's `lockdown`. The
 * read and the write stay inside the same check-and-execute — only which view
 * function is read changed, never when. See contracts/src/Permit2AllowanceView.sol.
 */
const DEPLOYMENTS_PATH = new URL('../deployments.json', import.meta.url)

/** The key this helper's address is recorded under in deployments.json. */
export const PERMIT2_ALLOWANCE_VIEW_NAME = 'Permit2AllowanceView'

/**
 * The helper function the guard reads.
 *
 * `liveAmountOf`, not `amountOf`: an allowance whose expiration has passed is
 * not an exposure — Permit2 reverts any transfer against it — so a lockdown
 * there would spend gas zeroing a number nobody can use. The watcher already
 * refuses to batch expired slots; guarding on the liveness-folding read makes
 * the server-side re-read agree with that instead of being laxer than it.
 */
export const PERMIT2_GUARD_FUNCTION = 'liveAmountOf'

/**
 * The helper's interface. Both functions are sent so the ABI KeeperHub executes
 * with is the contract's real shape, not a one-entry excerpt of it that a future
 * `functionName` change would silently invalidate.
 */
export const PERMIT2_ALLOWANCE_VIEW_ABI = [
  {
    inputs: [
      { name: 'owner', type: 'address' },
      { name: 'token', type: 'address' },
      { name: 'spender', type: 'address' },
    ],
    name: 'amountOf',
    outputs: [{ name: '', type: 'uint160' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [
      { name: 'owner', type: 'address' },
      { name: 'token', type: 'address' },
      { name: 'spender', type: 'address' },
    ],
    name: 'liveAmountOf',
    outputs: [{ name: '', type: 'uint160' }],
    stateMutability: 'view',
    type: 'function',
  },
] as const

/** The same ABI in the plain-array shape KeeperHub's wire format wants. */
export const PERMIT2_ALLOWANCE_VIEW_ABI_JSON: unknown[] = [...PERMIT2_ALLOWANCE_VIEW_ABI]

interface DeploymentsFile {
  [network: string]:
    | { contracts?: Record<string, { address?: string } | undefined> | undefined }
    | undefined
}

/** What an operator has to do about it, said the same way wherever it is raised. */
export const PERMIT2_VIEW_MISSING_HINT =
  `The Permit2 revoke guard reads ${PERMIT2_ALLOWANCE_VIEW_NAME}.${PERMIT2_GUARD_FUNCTION}(), ` +
  'because Permit2\'s own allowance() returns a 3-tuple and check-and-execute cannot ' +
  'select a member from it. Deploy the helper with `pnpm deploy:view` and re-run. ' +
  'Submitting the lockdown without it would be an UNGUARDED write.'

/**
 * The deployed helper's address, resolved fresh from deployments.json.
 *
 * Deliberately a function called at revoke time rather than a module constant.
 * Two reasons, both load-bearing: a missing entry must take down ONLY the
 * Permit2 revoke path — resolving at import time would throw while the module
 * graph loads and blind the ERC-20 watcher too — and an operator who deploys
 * the helper gets it picked up without restarting the agent.
 *
 * It throws rather than returning undefined so that no caller can accidentally
 * treat "not deployed" as "guard not needed". A guardless lockdown would land,
 * and would trade away the single property this project sells.
 */
export function permit2AllowanceViewAddress(): Address {
  let deployments: DeploymentsFile
  try {
    deployments = JSON.parse(readFileSync(DEPLOYMENTS_PATH, 'utf8')) as DeploymentsFile
  } catch (error) {
    throw new Error(
      `Could not read deployments.json (${error instanceof Error ? error.message : String(error)}). ` +
        PERMIT2_VIEW_MISSING_HINT,
      { cause: error },
    )
  }

  const address = deployments[config.network]?.contracts?.[PERMIT2_ALLOWANCE_VIEW_NAME]?.address
  if (address === undefined) {
    throw new Error(
      `deployments.json records no ${PERMIT2_ALLOWANCE_VIEW_NAME} address for network ` +
        `"${config.network}". ${PERMIT2_VIEW_MISSING_HINT}`,
    )
  }

  // A typo'd address is the quiet version of the same catastrophe: the call
  // would revert or, worse, hit an unrelated contract, and a guard that cannot
  // return a number is a guard that never fires.
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(
      `deployments.json records ${PERMIT2_ALLOWANCE_VIEW_NAME} as "${address}", ` +
        `which is not a valid address. ${PERMIT2_VIEW_MISSING_HINT}`,
    )
  }

  return address as Address
}

/**
 * Permit2's own events. All three are emitted by the Permit2 contract.
 *
 *  - `Approval` — someone called `approve()` on Permit2 directly.
 *  - `Permit`   — a SIGNATURE was redeemed. This is the one the ERC-20 path
 *                 can never see, and the one that matters: the victim signed
 *                 an off-chain message and the grant appeared on chain in the
 *                 attacker's transaction, with no wallet approval prompt that
 *                 named an allowance.
 *  - `Lockdown` — a revoke. Collected for the same reason the ERC-20 path
 *                 keeps `approve(x, 0)` logs: a pair that was locked down can
 *                 be re-permitted, and a pair we stop tracking is a pair we
 *                 stop protecting.
 *
 * Note the indexed layout differs from ERC-20's Approval: Permit2 indexes
 * owner, token AND spender, so the token is a topic here rather than the log's
 * emitting address.
 */
export const PERMIT2_APPROVAL_EVENT = parseAbiItem(
  'event Approval(address indexed owner, address indexed token, address indexed spender, uint160 amount, uint48 expiration)',
)

export const PERMIT2_PERMIT_EVENT = parseAbiItem(
  'event Permit(address indexed owner, address indexed token, address indexed spender, uint160 amount, uint48 expiration, uint48 nonce)',
)

export const PERMIT2_LOCKDOWN_EVENT = parseAbiItem(
  'event Lockdown(address indexed owner, address token, address spender)',
)

/** One (token, spender) slot in Permit2's allowance ledger. */
export interface Permit2Pair {
  token: Address
  spender: Address
}

export interface Permit2Allowance {
  /** uint160. `PERMIT2_MAX_AMOUNT` is Permit2's unlimited. */
  amount: bigint
  /** Unix seconds. Permit2 refuses a transfer once `block.timestamp` passes it. */
  expiration: number
  nonce: number
}

export function permit2PairKey(pair: Permit2Pair): string {
  return `${pair.token.toLowerCase()}:${pair.spender.toLowerCase()}`
}

/**
 * Every (token, spender) slot this owner has touched on Permit2 since
 * `fromBlock`.
 *
 * Three queries rather than one because the three events do not share an
 * indexed layout — `Lockdown` indexes only `owner`, so it cannot ride the same
 * topic filter as `Approval`/`Permit`. Splitting them keeps the `owner` filter
 * server-side on all three, which is what stops this from downloading every
 * Permit2 log on the chain.
 *
 * Like `fetchApprovals`, this returns PAIRS, not amounts: the log records what
 * was granted at the time, and only the live allowance says what is still
 * there. Nothing downstream is allowed to act on a log value.
 */
export async function fetchPermit2Pairs(
  owner: Address,
  fromBlock: bigint,
  toBlock: bigint,
): Promise<Permit2Pair[]> {
  const range = { address: PERMIT2_ADDRESS, args: { owner }, fromBlock, toBlock }

  const [approvals, permits, lockdowns] = await Promise.all([
    publicClient.getLogs({ ...range, event: PERMIT2_APPROVAL_EVENT }),
    publicClient.getLogs({ ...range, event: PERMIT2_PERMIT_EVENT }),
    publicClient.getLogs({ ...range, event: PERMIT2_LOCKDOWN_EVENT }),
  ])

  const pairs = new Map<string, Permit2Pair>()
  for (const log of [...approvals, ...permits, ...lockdowns]) {
    const { token, spender } = log.args
    // A log missing either field is a decode that did not produce what the
    // signature promises. Dropping it is the same discipline fetchApprovals
    // applies: a half-read log would fabricate an exposure the agent then acts
    // on.
    if (token === undefined || spender === undefined) continue
    pairs.set(permit2PairKey({ token, spender }), { token, spender })
  }
  return [...pairs.values()]
}

/**
 * The live Permit2 allowance. The authoritative value at this instant, and the
 * only number any decision here is allowed to use.
 */
export async function readPermit2Allowance(
  owner: Address,
  token: Address,
  spender: Address,
): Promise<Permit2Allowance> {
  const [amount, expiration, nonce] = await publicClient.readContract({
    address: PERMIT2_ADDRESS,
    abi: PERMIT2_ABI,
    functionName: 'allowance',
    args: [owner, token, spender],
  })
  return { amount, expiration, nonce }
}

/**
 * `empty`   — nothing granted, or a lockdown already landed.
 * `expired` — granted, but Permit2 will refuse the transfer.
 * `live`    — the spender can move tokens on the next block.
 */
export type Permit2Status = 'empty' | 'expired' | 'live'

/**
 * Classify one slot against chain time.
 *
 * The comparison is strictly greater-than because that is exactly what
 * AllowanceTransfer does — `if (block.timestamp > allowed.expiration) revert
 * AllowanceExpired(...)`. Using `>=` here would declare an allowance dead one
 * second before the contract does, and "dead" means we stop watching it.
 *
 * Note that a stored expiration of 0 is not "never expires": Permit2 rewrites a
 * zero expiration to `block.timestamp` at grant time, so a zero can only appear
 * on a slot that was never written, where `amount` is 0 as well and this
 * returns `empty` before the comparison is reached.
 */
export function permit2Status(
  allowance: Permit2Allowance,
  chainTimeSeconds: number,
): Permit2Status {
  if (allowance.amount === 0n) return 'empty'
  if (chainTimeSeconds > allowance.expiration) return 'expired'
  return 'live'
}
