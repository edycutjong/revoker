import { describe, expect, it, vi, beforeEach } from 'vitest'
import type { Address } from 'viem'
import { erc20Abi } from 'viem'

/**
 * chain.ts builds a module-level `publicClient` once, at import time, from
 * `createPublicClient`. The only way to control what it returns without
 * touching a real RPC is to replace `createPublicClient` itself — everything
 * else (parseAbiItem, erc20Abi, sepolia) stays real so APPROVAL_EVENT and the
 * ABI references used in assertions below are the exact objects chain.ts
 * actually sends over the wire.
 */
const client = vi.hoisted(() => ({
  getLogs: vi.fn(),
  readContract: vi.fn(),
  getCode: vi.fn(),
}))

vi.mock('viem', async (importOriginal) => {
  const actual = await importOriginal<typeof import('viem')>()
  return {
    ...actual,
    createPublicClient: vi.fn(() => client),
  }
})

const {
  blocksInDays,
  fetchApprovals,
  readAllowance,
  readBalance,
  tokenSymbol,
  HistoricalStateUnavailable,
  hasCodeAt,
  findDeploymentBlock,
  APPROVAL_EVENT,
} = await import('../src/chain.js')

const TOKEN = '0x4facb5fd1682c4449cad42b7590861f7ed5c88cb' as Address
const OWNER = '0x5e2e5fd3ad7fdc9b94482930db8b5f45e439bab7' as Address
const SPENDER = '0x8ebf8540ede8e40cd94825c418758d4029d8892e' as Address
const TX_HASH = '0x1111111111111111111111111111111111111111111111111111111111111111' as `0x${string}`

beforeEach(() => {
  vi.clearAllMocks()
})

describe('blocksInDays', () => {
  it('converts a day count into a Sepolia block depth (12s blocks)', () => {
    expect(blocksInDays(30)).toBe(216_000n) // 30 * 86400 / 12, divides exactly
  })

  it('truncates toward zero when the block depth is not exact', () => {
    // 13 seconds / 12s-per-block does not divide evenly; bigint division
    // truncates rather than rounds, so this must come out to 1, not 2.
    expect(blocksInDays(13 / 86400)).toBe(1n)
  })
})

describe('fetchApprovals', () => {
  it('short-circuits on an empty watchlist without calling the RPC', async () => {
    const result = await fetchApprovals(OWNER, [], 0n, 100n)

    expect(result).toEqual([])
    expect(client.getLogs).not.toHaveBeenCalled()
  })

  it('scopes the log query to the given tokens, owner, and block range', async () => {
    client.getLogs.mockResolvedValue([])
    await fetchApprovals(OWNER, [TOKEN], 10n, 20n)

    expect(client.getLogs).toHaveBeenCalledWith({
      address: [TOKEN],
      event: APPROVAL_EVENT, // must be the real parsed ABI event, not a stand-in
      args: { owner: OWNER },
      fromBlock: 10n,
      toBlock: 20n,
    })
  })

  it('maps a well-formed log to an ApprovalEvent and drops anything incomplete', async () => {
    // A single batch mixing one valid log with every way a log can be
    // incomplete (missing spender/value, unmined blockNumber, unmined tx
    // hash). Only the valid one may survive — silently keeping a partial log
    // would fabricate exposure data the watcher would act on.
    client.getLogs.mockResolvedValue([
      { address: TOKEN, args: { spender: SPENDER, value: 500n }, blockNumber: 42n, transactionHash: TX_HASH },
      { address: TOKEN, args: { value: 500n }, blockNumber: 42n, transactionHash: TX_HASH }, // no spender
      { address: TOKEN, args: { spender: SPENDER }, blockNumber: 42n, transactionHash: TX_HASH }, // no value
      { address: TOKEN, args: { spender: SPENDER, value: 500n }, blockNumber: null, transactionHash: TX_HASH }, // pending block
      { address: TOKEN, args: { spender: SPENDER, value: 500n }, blockNumber: 42n, transactionHash: null }, // pending tx
    ] as never)

    const result = await fetchApprovals(OWNER, [TOKEN], 0n, 100n)

    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({
      token: TOKEN,
      owner: OWNER,
      spender: SPENDER,
      value: 500n,
      blockNumber: 42n,
      txHash: TX_HASH,
    })
  })

  it('keeps a log whose value is legitimately zero', () => {
    // args.value === 0n must not be confused with "missing" — an explicit
    // approve(spender, 0) is exactly the event a revoke produces and must
    // still be recorded as history.
    const value = { args: { spender: SPENDER, value: 0n }, blockNumber: 1n, transactionHash: TX_HASH, address: TOKEN }
    client.getLogs.mockResolvedValue([value] as never)

    return fetchApprovals(OWNER, [TOKEN], 0n, 100n).then((result) => {
      expect(result).toHaveLength(1)
      expect(result[0]!.value).toBe(0n)
    })
  })
})

describe('readAllowance / readBalance', () => {
  it('reads allowance(owner, spender) through the real erc20Abi', async () => {
    client.readContract.mockResolvedValue(123n)
    const result = await readAllowance(TOKEN, OWNER, SPENDER)

    expect(result).toBe(123n)
    expect(client.readContract).toHaveBeenCalledWith({
      address: TOKEN,
      abi: erc20Abi,
      functionName: 'allowance',
      args: [OWNER, SPENDER],
    })
  })

  it('reads balanceOf(owner) through the real erc20Abi', async () => {
    client.readContract.mockResolvedValue(999n)
    const result = await readBalance(TOKEN, OWNER)

    expect(result).toBe(999n)
    expect(client.readContract).toHaveBeenCalledWith({
      address: TOKEN,
      abi: erc20Abi,
      functionName: 'balanceOf',
      args: [OWNER],
    })
  })
})

describe('tokenSymbol', () => {
  it('returns the on-chain symbol when the call succeeds', async () => {
    client.readContract.mockResolvedValue('USDC')
    expect(await tokenSymbol(TOKEN)).toBe('USDC')
  })

  it('falls back to a truncated address when symbol() reverts (non-standard token)', async () => {
    // Not every ERC-20 implements symbol() correctly (some proxies revert).
    // The watcher must still have something human-readable to log, not throw.
    client.readContract.mockRejectedValue(new Error('execution reverted'))
    expect(await tokenSymbol(TOKEN)).toBe(TOKEN.slice(0, 10))
  })
})

describe('HistoricalStateUnavailable', () => {
  it('carries the block number and original cause, distinct from a plain Error', () => {
    const cause = new Error('missing trie node abc123')
    const err = new HistoricalStateUnavailable(9_000_000n, cause)

    expect(err).toBeInstanceOf(Error)
    expect(err.name).toBe('HistoricalStateUnavailable')
    expect(err.blockNumber).toBe(9_000_000n)
    expect(err.cause).toBe(cause)
    expect(err.message).toContain('9000000')
  })
})

describe('hasCodeAt', () => {
  it('is true when the address has bytecode at the given block', async () => {
    client.getCode.mockResolvedValue('0x6080604052')
    expect(await hasCodeAt(TOKEN, 100n)).toBe(true)
    expect(client.getCode).toHaveBeenCalledWith({ address: TOKEN, blockNumber: 100n })
  })

  it('is false when the RPC returns the empty-code sentinel "0x"', async () => {
    client.getCode.mockResolvedValue('0x')
    expect(await hasCodeAt(TOKEN, 100n)).toBe(false)
  })

  it('is false when the RPC returns undefined (address never had code)', async () => {
    client.getCode.mockResolvedValue(undefined)
    expect(await hasCodeAt(TOKEN, 100n)).toBe(false)
  })

  it('omits blockNumber from the RPC call when reading current state', async () => {
    client.getCode.mockResolvedValue('0x1234')
    await hasCodeAt(TOKEN)
    expect(client.getCode).toHaveBeenCalledWith({ address: TOKEN })
  })

  it('sends block 0 rather than silently reading current state (0n is falsy)', async () => {
    // Regression guard. This was built with `...(blockNumber ? {blockNumber} : {})`,
    // and 0n is falsy — so asking about block 0 dropped the field and quietly
    // answered about CURRENT state instead. No error, just the wrong question.
    //
    // It is reachable: findDeploymentBlock probes (low + high) / 2n, which is 0n
    // as soon as the search narrows to the first block. A module whose purpose is
    // keeping "did not exist then" distinct from "cannot tell" must not answer
    // about a different block than the one it was asked about.
    client.getCode.mockResolvedValue('0xdeadbeef')
    await hasCodeAt(TOKEN, 0n)

    expect(client.getCode).toHaveBeenCalledWith({ address: TOKEN, blockNumber: 0n })
  })

  it('wraps a pruned-state error as HistoricalStateUnavailable when a block was requested', async () => {
    client.getCode.mockRejectedValue(new Error('missing trie node 0xabc (archive node required)'))

    await expect(hasCodeAt(TOKEN, 100n)).rejects.toBeInstanceOf(HistoricalStateUnavailable)
  })

  it('matches the pruned-state phrases case-insensitively, including a plain-string throw', async () => {
    // getCode can reject with something that is not an Error instance (e.g. a
    // raw string from a transport). The message-extraction ternary must still
    // work, and the regex must not be case-sensitive.
    client.getCode.mockRejectedValue('STATE NOT AVAILABLE for this block')

    const error = await hasCodeAt(TOKEN, 100n).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(HistoricalStateUnavailable)
    expect((error as InstanceType<typeof HistoricalStateUnavailable>).cause).toBe(
      'STATE NOT AVAILABLE for this block',
    )
  })

  it('does NOT wrap an unrelated error even when a block was requested', async () => {
    // A rate limit or network blip is not "state unavailable" — conflating
    // the two would make findDeploymentBlock give up on transient failures
    // instead of retrying, or worse, would mask real pruning as a retryable
    // failure.
    const original = new Error('502 Bad Gateway')
    client.getCode.mockRejectedValue(original)

    await expect(hasCodeAt(TOKEN, 100n)).rejects.toBe(original)
  })

  it('rethrows the raw error as-is when no block was requested (current state has no "unavailable" concept)', async () => {
    const original = new Error('missing trie node — should not matter here')
    client.getCode.mockRejectedValue(original)

    await expect(hasCodeAt(TOKEN)).rejects.toBe(original)
  })
})

describe('findDeploymentBlock — binary search for deployment age', () => {
  /** Simulates an archive node that has code at every block >= deployedAt. */
  function archiveWithDeployBlock(deployedAt: bigint): void {
    client.getCode.mockImplementation(({ blockNumber }: { blockNumber?: bigint }) => {
      const at = blockNumber ?? deployedAt // "current state" reads always see the deployed contract
      return Promise.resolve(at >= deployedAt ? '0x6080' : '0x')
    })
  }

  it('finds the exact block for a contract deployed mid-range', async () => {
    archiveWithDeployBlock(1_005n)
    expect(await findDeploymentBlock(TOKEN, 1_000n, 1_010n)).toBe(1_005n)
  })

  it('deployed exactly at the lower cutoff: every block in range has code', async () => {
    archiveWithDeployBlock(1_000n)
    expect(await findDeploymentBlock(TOKEN, 1_000n, 1_010n)).toBe(1_000n)
  })

  it('deployed exactly at the upper cutoff: only the last block has code', async () => {
    archiveWithDeployBlock(1_010n)
    expect(await findDeploymentBlock(TOKEN, 1_000n, 1_010n)).toBe(1_010n)
  })

  it('never deployed within the window: the search converges to the upper bound', async () => {
    // hasCodeAt is false everywhere in range. The function has no "not found"
    // signal — it returns `latest` — which is only safe because, per its own
    // doc comment, callers only reach this after a cheaper check already
    // proved the contract is young (i.e. exists now). This test pins that
    // documented contract rather than silently assuming it.
    client.getCode.mockResolvedValue('0x')
    expect(await findDeploymentBlock(TOKEN, 1_000n, 1_010n)).toBe(1_010n)
  })

  it('returns immediately, with no RPC calls, for a single-block window', async () => {
    expect(await findDeploymentBlock(TOKEN, 5_000n, 5_000n)).toBe(5_000n)
    expect(client.getCode).not.toHaveBeenCalled()
  })

  it('propagates HistoricalStateUnavailable when the archive node cannot answer mid-search', async () => {
    // The critical safety property: an unanswerable query must abort the
    // search, not be treated as "no code here, keep searching" — that would
    // let a pruned RPC report a false deployment age and undercut a
    // young-contract threat rule.
    client.getCode.mockRejectedValue(new Error('missing trie node during search'))

    await expect(findDeploymentBlock(TOKEN, 1_000n, 1_010n)).rejects.toBeInstanceOf(
      HistoricalStateUnavailable,
    )
  })
})
