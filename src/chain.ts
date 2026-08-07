import { createPublicClient, http, parseAbiItem, erc20Abi, type Address, type Log } from 'viem'
import { sepolia } from 'viem/chains'
import { config } from './config.js'

/**
 * Read-side chain access.
 *
 * Reads go straight to an RPC because the watcher polls continuously and a
 * round trip through an execution API would add latency to the one number that
 * matters (detect-to-revoke). Writes never come through here — KeeperHub is the
 * execution layer, and it re-reads state server-side inside check-and-execute
 * anyway, so nothing we read here is trusted for the actual revoke decision.
 */
export const publicClient = createPublicClient({
  chain: sepolia,
  transport: http(config.rpcUrl),
})

export const APPROVAL_EVENT = parseAbiItem(
  'event Approval(address indexed owner, address indexed spender, uint256 value)',
)

export const MAX_UINT256 = (1n << 256n) - 1n

/** Sepolia targets 12s blocks. Used to convert an age in days to a block depth. */
const SECONDS_PER_BLOCK = 12n

export function blocksInDays(days: number): bigint {
  return (BigInt(Math.round(days * 24 * 60 * 60)) / SECONDS_PER_BLOCK)
}

export interface ApprovalEvent {
  token: Address
  owner: Address
  spender: Address
  value: bigint
  blockNumber: bigint
  txHash: `0x${string}`
}

/**
 * Every Approval this wallet has granted on `tokens` since `fromBlock`.
 *
 * Scoped to an explicit token set rather than scanning all ERC-20 logs. That
 * is not a design preference — no public RPC will serve an address-less
 * `eth_getLogs` over a useful block range (publicnode requires an address
 * filter; 1rpc caps the range at 50 blocks), and KeeperHub's balances endpoint
 * only knows a curated token registry, so it cannot discover arbitrary tokens
 * either.
 *
 * Production would resolve the token set from an indexer. The watchlist is the
 * honest MVP boundary: Revoker protects the tokens it is told to watch, and
 * says so, rather than implying coverage it does not have.
 */
export async function fetchApprovals(
  owner: Address,
  tokens: readonly Address[],
  fromBlock: bigint,
  toBlock: bigint,
): Promise<ApprovalEvent[]> {
  if (tokens.length === 0) return []

  const logs = await publicClient.getLogs({
    address: tokens as Address[],
    event: APPROVAL_EVENT,
    args: { owner },
    fromBlock,
    toBlock,
  })

  return logs.flatMap((log: Log & { args?: { spender?: Address; value?: bigint } }) => {
    const spender = log.args?.spender
    const value = log.args?.value
    if (!spender || value === undefined || log.blockNumber === null || !log.transactionHash) {
      return []
    }
    return [{
      token: log.address,
      owner,
      spender,
      value,
      blockNumber: log.blockNumber,
      txHash: log.transactionHash,
    }]
  })
}

/** Live allowance. The authoritative value at this instant. */
export async function readAllowance(
  token: Address,
  owner: Address,
  spender: Address,
): Promise<bigint> {
  return publicClient.readContract({
    address: token,
    abi: erc20Abi,
    functionName: 'allowance',
    args: [owner, spender],
  })
}

export async function readBalance(token: Address, owner: Address): Promise<bigint> {
  return publicClient.readContract({
    address: token,
    abi: erc20Abi,
    functionName: 'balanceOf',
    args: [owner],
  })
}

export async function tokenSymbol(token: Address): Promise<string> {
  try {
    return await publicClient.readContract({ address: token, abi: erc20Abi, functionName: 'symbol' })
  } catch {
    return token.slice(0, 10)
  }
}

/**
 * Raised when the node cannot answer a historical-state query.
 *
 * Non-archive RPCs prune old state, so `eth_getCode` at a block from last week
 * is simply unanswerable. That is a different thing from "the contract did not
 * exist", and conflating the two would silently turn a threat rule into a
 * rubber stamp.
 */
export class HistoricalStateUnavailable extends Error {
  constructor(readonly blockNumber: bigint, cause: unknown) {
    super(`historical state unavailable at block ${blockNumber}`)
    this.name = 'HistoricalStateUnavailable'
    this.cause = cause
  }
}

/** True when `address` has contract code at the given block. */
export async function hasCodeAt(address: Address, blockNumber?: bigint): Promise<boolean> {
  try {
    const code = await publicClient.getCode({ address, ...(blockNumber ? { blockNumber } : {}) })
    return code !== undefined && code !== '0x'
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    if (blockNumber !== undefined && /historical state|missing trie node|not available|pruned/i.test(message)) {
      throw new HistoricalStateUnavailable(blockNumber, error)
    }
    throw error
  }
}

/**
 * Deployment block, found by binary search over `eth_getCode`.
 *
 * Only called once a cheaper check has already established the contract is
 * young, so this runs on the rare path and never in the hot loop. Keyless by
 * design — an explorer API would mean another credential to provision.
 */
export async function findDeploymentBlock(
  address: Address,
  earliest: bigint,
  latest: bigint,
): Promise<bigint> {
  let low = earliest
  let high = latest
  while (low < high) {
    const mid = (low + high) / 2n
    if (await hasCodeAt(address, mid)) high = mid
    else low = mid + 1n
  }
  return low
}
