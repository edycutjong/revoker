import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { permit2LongLived } from '../src/rules.js'
import type { KeeperHub as KeeperHubClient } from '../src/keeperhub.js'

/**
 * scripts/seed-permit2.ts calls `main().catch(...)` at module top level, so
 * importing it runs the whole seed. Every edge that would leave this process is
 * replaced: node:fs (deployments.json), config, the chain reads, the Permit2
 * reads, and the KeeperHub client that would otherwise send two REAL Sepolia
 * transactions from the org's Turnkey wallet.
 *
 * The chain mocks are backed by a mutable `state` object and KeeperHub's
 * writeContract APPLIES the write to it, so this is a small simulated chain
 * rather than a sequence of canned answers. That is what makes the idempotency
 * claim testable at all: run 2 reads back exactly what run 1 wrote, and the
 * assertion "zero transactions" means something.
 */

const OWNER = '0x5e2e5fd3ad7fdc9b94482930db8b5f45e439bab7'
const TOKEN = '0x4facb5fd1682c4449cad42b7590861f7ed5c88cb'
const SPENDER = '0x8ebf8540ede8e40cd94825c418758d4029d8892e'
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3'

const MAX_UINT256 = (1n << 256n) - 1n
const MAX_UINT160 = (1n << 160n) - 1n

/** 2026-08-08T00:00:00Z. Fixed so the derived expiration is an exact string. */
const CHAIN_TIME = 1_786_147_200
/** CHAIN_TIME + 365 days — must match EXPIRATION_DAYS in seed-permit2.ts. */
const EXPIRATION = 1_817_683_200
const EXPIRATION_ISO = '2027-08-08T00:00:00.000Z'
const THIRTY_DAYS = 30 * 86_400

const state = vi.hoisted(() => ({
  chainTime: 0,
  permit2HasCode: true,
  /** ERC-20 allowance token -> Permit2. */
  upstream: 0n,
  /** Permit2's own allowance slot for (owner, token, spender). */
  amount: 0n,
  expiration: 0,
  nonce: 0,
  executions: 0,
  /** Set to drop the transactionHash off the status response. */
  withholdHash: false,
}))

const fsState = vi.hoisted(() => ({ deployments: '' }))
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    readFileSync: (path: Parameters<typeof actual.readFileSync>[0], enc?: BufferEncoding) => {
      if (String(path).includes('deployments.json')) return fsState.deployments
      return actual.readFileSync(path, enc)
    },
  }
})

vi.mock('../src/config.js', () => ({
  config: {
    walletAddress: OWNER,
    chainId: 11155111,
    rpcUrl: 'https://ethereum-sepolia-rpc.publicnode.com',
  },
  explorerTxUrl: (hash: string) => `https://sepolia.etherscan.io/tx/${hash}`,
}))

const chain = vi.hoisted(() => ({
  hasCodeAt: vi.fn<(address: string) => Promise<boolean>>(),
  readAllowance: vi.fn<(token: string, owner: string, spender: string) => Promise<bigint>>(),
  readChainTimeSeconds: vi.fn<() => Promise<number>>(),
}))
vi.mock('../src/chain.js', () => ({
  MAX_UINT256: (1n << 256n) - 1n,
  hasCodeAt: chain.hasCodeAt,
  readAllowance: chain.readAllowance,
  readChainTimeSeconds: chain.readChainTimeSeconds,
}))

/**
 * Only the live read is replaced. The constants (PERMIT2_ADDRESS,
 * PERMIT2_MAX_AMOUNT) stay REAL — a test that mocked the unlimited sentinel
 * could not catch the script sending the wrong one, which is the single most
 * important thing these assertions exist to check.
 */
const permit2 = vi.hoisted(() => ({
  readPermit2Allowance:
    vi.fn<
      (
        owner: string,
        token: string,
        spender: string,
      ) => Promise<{ amount: bigint; expiration: number; nonce: number }>
    >(),
}))
vi.mock('../src/permit2.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/permit2.js')>()
  return { ...actual, readPermit2Allowance: permit2.readPermit2Allowance }
})

interface WriteInput {
  contractAddress: string
  functionName: string
  functionArgs: string[]
  abi: unknown[]
}

const kh = vi.hoisted(() => {
  const writeContract = vi.fn<(input: WriteInput) => Promise<{ executionId: string }>>()
  const getExecutionStatus = vi.fn<(id: string) => Promise<{ transactionHash?: string }>>()
  const constructed: number[] = []
  class KeeperHub {
    writeContract = writeContract
    getExecutionStatus = getExecutionStatus
    constructor() {
      constructed.push(1)
    }
  }
  return { KeeperHub, writeContract, getExecutionStatus, constructed }
})
vi.mock('../src/keeperhub.js', () => ({ KeeperHub: kh.KeeperHub }))

function deploymentsFile(contracts: Record<string, { address: string }>): string {
  return JSON.stringify({ sepolia: { contracts } }, null, 2)
}

const FIXTURES = { MockUSDC: { address: TOKEN }, RoachMotelSpender: { address: SPENDER } }

function logged(): string {
  return vi.mocked(console.log).mock.calls.map((args) => args.join(' ')).join('\n')
}

function errored(): string {
  return vi.mocked(console.error).mock.calls.map((args) => args.join(' ')).join('\n')
}

/** The nth write the script submitted, 1-based. */
function write(n: number): WriteInput {
  const call = kh.writeContract.mock.calls[n - 1]
  expect(call, `expected at least ${n} KeeperHub write(s)`).toBeDefined()
  return call![0]
}

async function settle(): Promise<void> {
  for (let i = 0; i < 3; i++) await new Promise<void>((resolve) => setImmediate(resolve))
}

async function runSeed(): Promise<void> {
  await import('../scripts/seed-permit2.js')
  await settle()
}

let originalArgv: string[]

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()
  kh.constructed.length = 0

  fsState.deployments = deploymentsFile({ ...FIXTURES })

  // Default world: fixtures deployed, Permit2 live, and NOTHING armed yet — the
  // state the real chain is in today. Every test moves one thing off this.
  Object.assign(state, {
    chainTime: CHAIN_TIME,
    permit2HasCode: true,
    upstream: 0n,
    amount: 0n,
    expiration: 0,
    nonce: 0,
    executions: 0,
    withholdHash: false,
  })

  chain.hasCodeAt.mockImplementation(() => Promise.resolve(state.permit2HasCode))
  chain.readChainTimeSeconds.mockImplementation(() => Promise.resolve(state.chainTime))
  chain.readAllowance.mockImplementation(() => Promise.resolve(state.upstream))
  permit2.readPermit2Allowance.mockImplementation(() =>
    Promise.resolve({ amount: state.amount, expiration: state.expiration, nonce: state.nonce }),
  )

  kh.writeContract.mockImplementation((input) => {
    state.executions += 1
    if (input.contractAddress.toLowerCase() === PERMIT2.toLowerCase()) {
      state.amount = BigInt(input.functionArgs[2]!)
      state.expiration = Number(input.functionArgs[3])
      state.nonce += 1
    } else {
      state.upstream = BigInt(input.functionArgs[1]!)
    }
    return Promise.resolve({ executionId: `exec-${state.executions}` })
  })
  kh.getExecutionStatus.mockImplementation((id) =>
    Promise.resolve(state.withholdHash ? {} : { transactionHash: `0xtx-${id}` }),
  )

  originalArgv = process.argv
  process.argv = ['node', 'scripts/seed-permit2.ts']
  process.exitCode = undefined
  vi.spyOn(console, 'log').mockImplementation(() => undefined)
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
})

afterEach(() => {
  process.argv = originalArgv
  process.exitCode = undefined
  vi.restoreAllMocks()
})

describe('seed-permit2.ts — the two transactions', () => {
  it('sends the upstream ERC-20 approval and then the Permit2 grant, in that order', async () => {
    await runSeed()

    expect(kh.constructed).toHaveLength(1)
    expect(kh.writeContract).toHaveBeenCalledTimes(2)

    // 1. MockUSDC.approve(PERMIT2, MAX_UINT256) — the enabling grant.
    expect(write(1)).toEqual({
      contractAddress: TOKEN,
      functionName: 'approve',
      functionArgs: [PERMIT2, MAX_UINT256.toString()],
      abi: expect.anything(),
    })

    // 2. Permit2.approve(token, spender, MAX_UINT160, expiration) — the exposure.
    expect(write(2)).toEqual({
      contractAddress: PERMIT2,
      functionName: 'approve',
      functionArgs: [TOKEN, SPENDER, MAX_UINT160.toString(), String(EXPIRATION)],
      abi: expect.anything(),
    })

    expect(process.exitCode).toBeUndefined()
  })

  it('sends MAX_UINT160 as the Permit2 amount and never MAX_UINT256', async () => {
    // The whole reason PERMIT2_MAX_AMOUNT exists. A uint256 max is out of range
    // for Permit2's uint160 amount field; an encoder that truncated it instead
    // of rejecting it would write a value every unlimited check scores as
    // bounded, and the fixture would arm nothing detectable.
    await runSeed()

    const amount = write(2).functionArgs[2]
    expect(amount).toBe('1461501637330902918203684832716283019655932542975')
    expect(amount).toBe(MAX_UINT160.toString())
    expect(amount).not.toBe(MAX_UINT256.toString())
    expect(BigInt(amount!) < 1n << 160n).toBe(true)
  })

  it('declares the Permit2 approve ABI as uint160/uint48, matching IAllowanceTransfer', async () => {
    // KeeperHub encodes from the ABI we hand it. A uint256 amount here would
    // encode a different call than Permit2 implements and revert on chain.
    await runSeed()

    expect(write(2).abi).toEqual([
      {
        inputs: [
          { name: 'token', type: 'address' },
          { name: 'spender', type: 'address' },
          { name: 'amount', type: 'uint160' },
          { name: 'expiration', type: 'uint48' },
        ],
        name: 'approve',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
      },
    ])
  })

  it('derives the expiration from chain time, not the host clock', async () => {
    // A host clock is allowed to be wrong; block.timestamp is what Permit2 and
    // the rule both compare against.
    state.chainTime = CHAIN_TIME - 10 * 86_400

    await runSeed()

    expect(write(2).functionArgs[3]).toBe(String(CHAIN_TIME - 10 * 86_400 + 365 * 86_400))
  })

  it('reports both transactions with an explorer link', async () => {
    await runSeed()

    expect(logged()).toContain('https://sepolia.etherscan.io/tx/0xtx-exec-1')
    expect(logged()).toContain('https://sepolia.etherscan.io/tx/0xtx-exec-2')
    expect(logged()).toContain('approved MAX_UINT256 -> Permit2')
    expect(logged()).toContain(`granted MAX_UINT160 to ${SPENDER}, expiring ${EXPIRATION_ISO}`)
  })
})

describe('seed-permit2.ts — the expiration trips permit2-long-lived', () => {
  it('produces a grant the REAL rule fires on', async () => {
    await runSeed()

    const expiration = Number(write(2).functionArgs[3])
    const verdict = await permit2LongLived.evaluate({
      token: TOKEN,
      spender: SPENDER,
      owner: OWNER,
      allowance: MAX_UINT160,
      balance: 10_000_000_000n,
      currentBlock: 0n,
      // The spender is an unverified throwaway deploy, which is the second half
      // of the rule's condition.
      kh: { isSourceVerified: () => Promise.resolve(false) } as unknown as KeeperHubClient,
      denylist: new Set<string>(),
      permit2: { expiration, nonce: 0, chainTimeSeconds: CHAIN_TIME },
    })

    expect(verdict.fired).toBe(true)
    expect(verdict.evidence['secondsRemaining']).toBe(365 * 86_400)
    expect(expiration - CHAIN_TIME).toBeGreaterThan(THIRTY_DAYS)
  })

  it('leaves 335 days of headroom over the 30-day threshold', async () => {
    // Stated as a number so shrinking EXPIRATION_DAYS toward the threshold is a
    // deliberate edit rather than an accident that quietly stops arming.
    await runSeed()

    const remaining = Number(write(2).functionArgs[3]) - CHAIN_TIME
    expect((remaining - THIRTY_DAYS) / 86_400).toBe(335)
  })
})

describe('seed-permit2.ts — idempotency', () => {
  it('a second run against the state the first run left sends ZERO transactions', async () => {
    await runSeed()
    expect(state.executions).toBe(2)

    kh.writeContract.mockClear()
    kh.getExecutionStatus.mockClear()
    kh.constructed.length = 0
    vi.resetModules()

    await runSeed()

    expect(kh.writeContract).not.toHaveBeenCalled()
    expect(kh.getExecutionStatus).not.toHaveBeenCalled()
    expect(state.executions).toBe(2) // unchanged: nothing was submitted
    expect(state.nonce).toBe(1) // the grant was not rewritten
    expect(logged()).toContain('upstream ERC-20 approval to Permit2 already unlimited — skipping')
    expect(logged()).toContain('Permit2 allowance already armed — MAX_UINT160, 365.00 days left')
    expect(process.exitCode).toBeUndefined()
  })

  it('skips only the upstream approval when the Permit2 slot was locked down', async () => {
    // What the chain looks like right after Revoker does its job: lockdown()
    // zeroes `amount` and leaves `expiration` and `nonce` where they were. The
    // demo has to be replayable from exactly here.
    state.upstream = MAX_UINT256
    state.amount = 0n
    state.expiration = EXPIRATION
    state.nonce = 7

    await runSeed()

    expect(kh.writeContract).toHaveBeenCalledTimes(1)
    expect(write(1).contractAddress).toBe(PERMIT2)
    expect(logged()).toContain('upstream ERC-20 approval to Permit2 already unlimited — skipping')
    expect(logged()).toContain(
      'slot amount is not MAX_UINT160 — never granted, bounded, or already locked down',
    )
  })

  it('re-arms an unlimited grant whose remaining lifetime has fallen under the threshold', async () => {
    // Not armed, despite the amount being right: a grant with 10 days left does
    // not trip permit2-long-lived, so leaving it would produce a green seed and
    // a silent watcher.
    state.upstream = MAX_UINT256
    state.amount = MAX_UINT160
    state.expiration = CHAIN_TIME + 10 * 86_400

    await runSeed()

    expect(kh.writeContract).toHaveBeenCalledTimes(1)
    expect(write(1).functionArgs[3]).toBe(String(EXPIRATION))
    expect(logged()).toContain('slot is unlimited but expires inside the 30-day window')
  })

  it('re-approves upstream when the allowance is non-zero but bounded', async () => {
    // "Non-zero" is not the bar. A bounded upstream allowance is spent down by
    // every transfer that flows through Permit2, so the fixture would decay.
    state.upstream = 1_000_000n

    await runSeed()

    expect(write(1)).toEqual({
      contractAddress: TOKEN,
      functionName: 'approve',
      functionArgs: [PERMIT2, MAX_UINT256.toString()],
      abi: expect.anything(),
    })
    expect(logged()).toContain('approving Permit2 on MockUSDC (was 1000000)')
  })

  it('--rearm regrants the Permit2 slot but does not resend the upstream approval', async () => {
    // --rearm forces the step it names, as --redeploy does in seed.ts. Forcing
    // the upstream approval too would only burn gas writing MAX over MAX.
    state.upstream = MAX_UINT256
    state.amount = MAX_UINT160
    state.expiration = EXPIRATION
    process.argv = ['node', 'scripts/seed-permit2.ts', '--rearm']

    await runSeed()

    expect(kh.writeContract).toHaveBeenCalledTimes(1)
    expect(write(1).contractAddress).toBe(PERMIT2)
    expect(logged()).toContain('--rearm given; regranting regardless of the current slot')
  })
})

describe('seed-permit2.ts — the final report', () => {
  it('prints the armed slot, a human-readable expiry and a pasteable eth_call', async () => {
    await runSeed()

    const out = logged()
    expect(out).toContain('THREAT ARMED — Permit2')
    expect(out).toContain('upstream   MAX_UINT256 (unlimited)')
    expect(out).toContain('amount     MAX_UINT160 (Permit2 unlimited)')
    expect(out).toContain(`expiration ${EXPIRATION}  (${EXPIRATION_ISO})`)
    expect(out).toContain('lifetime   365.00 days remaining')
    expect(out).toContain('nonce      1')
    expect(out).toContain(`cast call ${PERMIT2} \\`)
    expect(out).toContain('"allowance(address,address,address)(uint160,uint48,uint48)" \\')
    expect(out).toContain(`${OWNER} ${TOKEN} ${SPENDER} \\`)
    expect(out).toContain('--rpc-url https://ethereum-sepolia-rpc.publicnode.com')
    expect(out).toContain(`kh read ${PERMIT2} "allowance(address,address,address)"`)
    expect(out).toContain('--chain 11155111')
    expect(out).toContain('permit2-long-lived will fire: 365.00 days remaining > 30-day threshold')
    expect(out).toContain('Run `pnpm watch -- --once`')
  })

  it('prints raw values, not the unlimited labels, when the chain disagrees', async () => {
    // The report reads the slot back rather than echoing what was submitted, so
    // a write that did not take shows up as a number here.
    kh.writeContract.mockResolvedValue({ executionId: 'exec-noop' })

    await runSeed()

    expect(logged()).toContain('upstream   0  (ERC-20 approve -> Permit2)')
    expect(logged()).toContain('amount     0')
    expect(process.exitCode).toBe(1)
  })
})

describe('seed-permit2.ts — failures', () => {
  it('refuses to arm when Permit2 has no code at the canonical address', async () => {
    // A CALL to a codeless address succeeds and does nothing, so without this
    // check the script would report an armed fixture that does not exist.
    state.permit2HasCode = false

    await runSeed()

    expect(kh.writeContract).not.toHaveBeenCalled()
    expect(errored()).toContain(`No contract code at ${PERMIT2} on chainId 11155111`)
    expect(process.exitCode).toBe(1)
  })

  it('points at `pnpm seed` when deployments.json records no fixture', async () => {
    fsState.deployments = deploymentsFile({})

    await runSeed()

    expect(errored()).toContain('deployments.json records no MockUSDC address — run `pnpm seed` first')
    expect(process.exitCode).toBe(1)
  })

  it('fails when an execution completes without a transaction hash', async () => {
    state.withholdHash = true

    await runSeed()

    expect(errored()).toContain('ERC-20 approve returned execution exec-1 with no transaction hash')
    expect(process.exitCode).toBe(1)
  })

  it('fails when the upstream approval is still zero at the end of the run', async () => {
    // Detectable but unexploitable: Permit2 could not move a single token.
    kh.writeContract.mockImplementation((input) => {
      state.executions += 1
      if (input.contractAddress.toLowerCase() === PERMIT2.toLowerCase()) {
        state.amount = BigInt(input.functionArgs[2]!)
        state.expiration = Number(input.functionArgs[3])
      }
      return Promise.resolve({ executionId: `exec-${state.executions}` })
    })

    await runSeed()

    expect(errored()).toContain('the ERC-20 approval to Permit2 is still zero')
    expect(process.exitCode).toBe(1)
  })

  it('fails when the Permit2 amount landed short of MAX_UINT160', async () => {
    kh.writeContract.mockImplementation((input) => {
      state.executions += 1
      if (input.contractAddress.toLowerCase() === PERMIT2.toLowerCase()) {
        state.amount = 1_000n // a truncating encoder, or a partially-spent slot
        state.expiration = Number(input.functionArgs[3])
      } else {
        state.upstream = BigInt(input.functionArgs[1]!)
      }
      return Promise.resolve({ executionId: `exec-${state.executions}` })
    })

    await runSeed()

    expect(errored()).toContain('the Permit2 amount is 1000, not MAX_UINT160')
    expect(process.exitCode).toBe(1)
  })

  it('fails when the landed expiration would not trip permit2-long-lived', async () => {
    kh.writeContract.mockImplementation((input) => {
      state.executions += 1
      if (input.contractAddress.toLowerCase() === PERMIT2.toLowerCase()) {
        state.amount = BigInt(input.functionArgs[2]!)
        state.expiration = state.chainTime + 5 * 86_400 // a chain that clamped it
      } else {
        state.upstream = BigInt(input.functionArgs[1]!)
      }
      return Promise.resolve({ executionId: `exec-${state.executions}` })
    })

    await runSeed()

    expect(errored()).toContain(
      'the Permit2 allowance has 5.00 days left, which does not exceed the 30-day permit2-long-lived threshold',
    )
    expect(process.exitCode).toBe(1)
  })

  it('stringifies a non-Error rejection into the failure line', async () => {
    chain.readChainTimeSeconds.mockRejectedValue('RPC returned a bare string, not an Error')

    await runSeed()

    expect(errored()).toContain('Permit2 seed failed: RPC returned a bare string, not an Error')
    expect(process.exitCode).toBe(1)
  })
})
