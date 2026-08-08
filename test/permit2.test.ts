import { describe, expect, it, vi, beforeEach } from 'vitest'
import type { Address } from 'viem'

/**
 * The Permit2 detection layer.
 *
 * Same seam as test/chain.test.ts, and for the same reason: permit2.ts uses the
 * module-level viem client that chain.ts builds at import time, so the only way
 * to control it without a real RPC is to replace `createPublicClient` itself.
 * `parseAbiItem` stays real, which is the point — the event objects asserted
 * below are the exact objects sent over the wire, so a typo in a Permit2 event
 * signature would fail here rather than silently return zero logs against a
 * live node.
 */
const client = vi.hoisted(() => ({
  getLogs: vi.fn(),
  readContract: vi.fn(),
}))

vi.mock('viem', async (importOriginal) => {
  const actual = await importOriginal<typeof import('viem')>()
  return { ...actual, createPublicClient: vi.fn(() => client) }
})

const {
  PERMIT2_ADDRESS,
  PERMIT2_ABI,
  PERMIT2_ABI_JSON,
  PERMIT2_APPROVAL_EVENT,
  PERMIT2_PERMIT_EVENT,
  PERMIT2_LOCKDOWN_EVENT,
  PERMIT2_MAX_AMOUNT,
  PERMIT2_MAX_EXPIRATION,
  fetchPermit2Pairs,
  isPermit2,
  permit2PairKey,
  permit2Status,
  readPermit2Allowance,
} = await import('../src/permit2.js')

const TOKEN = '0x4facb5fd1682c4449cad42b7590861f7ed5c88cb' as Address
const OTHER_TOKEN = '0x1111111111111111111111111111111111111111' as Address
const OWNER = '0x5e2e5fd3ad7fdc9b94482930db8b5f45e439bab7' as Address
const SPENDER = '0x8ebf8540ede8e40cd94825c418758d4029d8892e' as Address

beforeEach(() => {
  vi.clearAllMocks()
  client.getLogs.mockResolvedValue([])
})

describe('the canonical deployment', () => {
  it('is the same address on every chain, and is recognised case-insensitively', () => {
    // Permit2 is deployed deterministically, which is why this is a constant
    // and not a per-chain config entry. A wrong address here would point
    // lockdown() at nothing.
    expect(PERMIT2_ADDRESS).toBe('0x000000000022D473030F116dDEE9F6B43aC78BA3')
    expect(isPermit2(PERMIT2_ADDRESS.toLowerCase())).toBe(true)
    expect(isPermit2(PERMIT2_ADDRESS)).toBe(true)
    expect(isPermit2(SPENDER)).toBe(false)
  })

  it('uses type(uint160).max as its unlimited sentinel, not type(uint256).max', () => {
    // The amount field is packed into 160 bits. Comparing a Permit2 amount
    // against MAX_UINT256 can never match, so every unlimited Permit2 grant
    // would be scored "bounded" and quietly cleared.
    expect(PERMIT2_MAX_AMOUNT).toBe(1461501637330902918203684832716283019655932542975n)
    expect(PERMIT2_MAX_AMOUNT).not.toBe((1n << 256n) - 1n)
    expect(PERMIT2_MAX_EXPIRATION).toBe(281_474_976_710_655)
  })
})

describe('the ABI, transcribed from IAllowanceTransfer.sol', () => {
  it('declares allowance() with all THREE return values', () => {
    // Truncating the outputs to a single uint160 would make the decode simpler
    // and would be inventing a function that does not exist.
    const allowance = PERMIT2_ABI.find((entry) => entry.name === 'allowance')
    expect(allowance?.inputs.map((i) => i.type)).toEqual(['address', 'address', 'address'])
    expect(allowance?.outputs.map((o) => `${o.type} ${o.name}`)).toEqual([
      'uint160 amount',
      'uint48 expiration',
      'uint48 nonce',
    ])
  })

  it('declares lockdown() as taking an ARRAY of (token, spender) pairs', () => {
    // The array is the whole advantage: one transaction clears N slots where
    // the ERC-20 path needs N transactions.
    const lockdown = PERMIT2_ABI.find((entry) => entry.name === 'lockdown')
    const arg = lockdown?.inputs[0]
    expect(arg?.type).toBe('tuple[]')
    expect(arg && 'components' in arg ? arg.components.map((c) => c.name) : []).toEqual([
      'token',
      'spender',
    ])
    expect(lockdown?.stateMutability).toBe('nonpayable')
  })

  it('exposes the same ABI in the plain-array form KeeperHub is sent', () => {
    // Derived, never written twice: the ABI viem reads with and the ABI
    // KeeperHub executes with must not be able to diverge.
    expect(PERMIT2_ABI_JSON).toEqual([...PERMIT2_ABI])
  })
})

describe('fetchPermit2Pairs — discovery from Permit2s own logs', () => {
  it('queries the PERMIT2 contract for all three of its events, filtered by owner', async () => {
    await fetchPermit2Pairs(OWNER, 10n, 20n)

    // The inversion that makes this a separate module: fetchApprovals filters
    // by `address: tokens[]` and reads the token off the log; here the address
    // filter is Permit2 itself and the token is a topic.
    const range = { address: PERMIT2_ADDRESS, args: { owner: OWNER }, fromBlock: 10n, toBlock: 20n }
    expect(client.getLogs).toHaveBeenCalledTimes(3)
    expect(client.getLogs).toHaveBeenCalledWith({ ...range, event: PERMIT2_APPROVAL_EVENT })
    expect(client.getLogs).toHaveBeenCalledWith({ ...range, event: PERMIT2_PERMIT_EVENT })
    expect(client.getLogs).toHaveBeenCalledWith({ ...range, event: PERMIT2_LOCKDOWN_EVENT })
  })

  it('discovers a slot granted by SIGNATURE, which leaves no ERC-20 Approval anywhere', async () => {
    // This is the gap the whole module exists for. `permit()` writes Permit2's
    // ledger inside the attacker's transaction; the token contract emits
    // nothing, so an ERC-20 approval scan reports the wallet as clean.
    client.getLogs.mockImplementation(({ event }: { event: { name: string } }) =>
      Promise.resolve(
        event.name === 'Permit'
          ? [{ args: { owner: OWNER, token: TOKEN, spender: SPENDER } }]
          : [],
      ),
    )

    expect(await fetchPermit2Pairs(OWNER, 0n, 100n)).toEqual([{ token: TOKEN, spender: SPENDER }])
  })

  it('collapses the three event streams into distinct pairs', async () => {
    // A slot that was approved, then permitted, then locked down appears three
    // times. It is one exposure, and it is still tracked after the lockdown:
    // the slot can be re-permitted, and a pair we stop tracking is a pair we
    // stop protecting.
    client.getLogs.mockImplementation(({ event }: { event: { name: string } }) =>
      Promise.resolve(
        event.name === 'Lockdown'
          ? [{ args: { owner: OWNER, token: OTHER_TOKEN, spender: SPENDER } }]
          : [{ args: { owner: OWNER, token: TOKEN, spender: SPENDER } }],
      ),
    )

    expect(await fetchPermit2Pairs(OWNER, 0n, 100n)).toEqual([
      { token: TOKEN, spender: SPENDER },
      { token: OTHER_TOKEN, spender: SPENDER },
    ])
  })

  it('drops a log missing either half of the pair rather than fabricating an exposure', async () => {
    // A half-decoded log would invent a (token, spender) slot the agent then
    // reads, assesses and potentially sends a transaction about.
    client.getLogs.mockImplementation(({ event }: { event: { name: string } }) =>
      Promise.resolve(
        event.name === 'Approval'
          ? [
              { args: { owner: OWNER, token: TOKEN, spender: SPENDER } },
              { args: { owner: OWNER, spender: SPENDER } },
              { args: { owner: OWNER, token: TOKEN } },
            ]
          : [],
      ),
    )

    expect(await fetchPermit2Pairs(OWNER, 0n, 100n)).toEqual([{ token: TOKEN, spender: SPENDER }])
  })

  it('keys pairs case-insensitively so a checksummed and a lower-cased log are one slot', () => {
    expect(permit2PairKey({ token: TOKEN.toUpperCase() as Address, spender: SPENDER })).toBe(
      permit2PairKey({ token: TOKEN, spender: SPENDER.toUpperCase() as Address }),
    )
  })
})

describe('readPermit2Allowance', () => {
  it('reads allowance(owner, token, spender) off the Permit2 contract, not the token', async () => {
    client.readContract.mockResolvedValue([500n, 1_800_000_000, 7])

    expect(await readPermit2Allowance(OWNER, TOKEN, SPENDER)).toEqual({
      amount: 500n,
      expiration: 1_800_000_000,
      nonce: 7,
    })
    expect(client.readContract).toHaveBeenCalledWith({
      address: PERMIT2_ADDRESS,
      abi: PERMIT2_ABI,
      // Argument order is (user, token, spender) — NOT (owner, spender) as on
      // an ERC-20. Getting it wrong reads a different slot and returns zero.
      functionName: 'allowance',
      args: [OWNER, TOKEN, SPENDER],
    })
  })
})

describe('permit2Status — live, expired, or nothing there', () => {
  const NOW = 1_800_000_000

  it('calls a zero amount empty: a lockdown landed, or nothing was granted', () => {
    // lockdown() zeroes `amount` and leaves expiration and nonce in place, so
    // amount is the only field that says whether the slot is spent.
    expect(permit2Status({ amount: 0n, expiration: PERMIT2_MAX_EXPIRATION, nonce: 3 }, NOW)).toBe(
      'empty',
    )
  })

  it('calls a past expiration expired', () => {
    expect(permit2Status({ amount: 500n, expiration: NOW - 1, nonce: 3 }, NOW)).toBe('expired')
  })

  it('treats an expiration of exactly now as STILL LIVE, matching the contract', () => {
    // AllowanceTransfer reverts on `block.timestamp > allowed.expiration`, so
    // equality is valid. Using >= here would declare an allowance dead a second
    // before the contract does — and "dead" means the watcher stops looking.
    expect(permit2Status({ amount: 500n, expiration: NOW, nonce: 3 }, NOW)).toBe('live')
  })

  it('calls a future expiration live', () => {
    expect(permit2Status({ amount: 1n, expiration: NOW + 1, nonce: 0 }, NOW)).toBe('live')
  })

  it('checks the amount before the clock, so a zeroed slot is never called expired', () => {
    // A never-written slot reads as all zeroes. Permit2 rewrites a zero
    // expiration to block.timestamp at grant time, so a stored zero can only
    // mean "never written" — and reporting that as an expired grant would put
    // a phantom exposure in every report.
    expect(permit2Status({ amount: 0n, expiration: 0, nonce: 0 }, NOW)).toBe('empty')
  })
})
