import { parseAbiItem, type Address } from 'viem'
import { publicClient } from './chain.js'

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
