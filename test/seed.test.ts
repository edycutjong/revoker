import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'

/**
 * scripts/seed.ts calls `main().catch(...)` at module top level: importing it
 * runs the whole seed. Everything that would leave this process is replaced —
 * viem's wallet client, KeeperHub, the chain reads, and node:fs.
 *
 * node:fs is partially mocked so only the two files seed.ts touches are
 * intercepted: deployments.json (served from `fsState`, so each test starts
 * from whatever prior state it wants) and the forge artifacts under
 * contracts/out/. writeFileSync is captured into `fsState.writes` and never
 * forwarded to the real implementation — the real deployments.json records live
 * Sepolia addresses and a test that rewrote it would silently break the demo.
 */

const addr = vi.hoisted(() => ({
  victim: '0x5e2e5fd3ad7fdc9b94482930db8b5f45e439bab7',
  deployer: '0xdead00000000000000000000000000000000beef',
  token: '0x4facb5fd1682c4449cad42b7590861f7ed5c88cb',
  spender: '0x8ebf8540ede8e40cd94825c418758d4029d8892e',
  freshToken: '0xaaaa000000000000000000000000000000000001',
  freshSpender: '0xbbbb000000000000000000000000000000000002',
}))

const TX = {
  deployToken: '0xd001',
  deploySpender: '0xd002',
  mint: '0xm001',
  approve: '0xa001',
} as const

const MAX_UINT256 = (1n << 256n) - 1n
const MINT_AMOUNT = 10_000_000_000n // must match seed.ts — 10,000 mUSDC at 6 decimals

const fsState = vi.hoisted(() => ({
  deployments: '',
  artifactMissing: false,
  writes: [] as { path: string; data: string }[],
}))
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    readFileSync: (path: Parameters<typeof actual.readFileSync>[0], enc?: BufferEncoding) => {
      const p = String(path)
      if (p.includes('deployments.json')) return fsState.deployments
      if (p.includes('/contracts/out/')) {
        if (fsState.artifactMissing) {
          throw Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT' })
        }
        return JSON.stringify({ abi: [{ name: 'mint' }], bytecode: { object: '0x6080604052' } })
      }
      return actual.readFileSync(path, enc)
    },
    writeFileSync: (path: Parameters<typeof actual.writeFileSync>[0], data: unknown) => {
      fsState.writes.push({ path: String(path), data: String(data) })
    },
  }
})

const wallet = vi.hoisted(() => ({
  deployContract: vi.fn<(args: { abi: unknown[]; bytecode: string; args: unknown[] }) => Promise<string>>(),
  writeContract: vi.fn<(args: {
    address: string
    abi: unknown[]
    functionName: string
    args: [string, bigint]
  }) => Promise<string>>(),
}))
vi.mock('viem', async (importOriginal) => {
  const actual = await importOriginal<typeof import('viem')>()
  return {
    ...actual,
    createWalletClient: vi.fn(() => wallet),
    http: vi.fn((url?: string) => ({ url })),
  }
})
vi.mock('viem/accounts', () => ({
  privateKeyToAccount: vi.fn(() => ({ address: addr.deployer })),
}))

vi.mock('../src/config.js', () => ({
  config: {
    deployerPrivateKey: `0x${'11'.repeat(32)}`,
    rpcUrl: 'http://rpc.invalid',
    walletAddress: addr.victim,
  },
}))

const chain = vi.hoisted(() => ({
  hasCodeAt: vi.fn<(address: string) => Promise<boolean>>(),
  readAllowance: vi.fn<(token: string, owner: string, spender: string) => Promise<bigint>>(),
  readBalance: vi.fn<(token: string, owner: string) => Promise<bigint>>(),
  waitForTransactionReceipt: vi.fn<(args: { hash: string }) => Promise<{ contractAddress?: string }>>(),
}))
vi.mock('../src/chain.js', () => ({
  MAX_UINT256: (1n << 256n) - 1n,
  publicClient: { waitForTransactionReceipt: chain.waitForTransactionReceipt },
  readAllowance: chain.readAllowance,
  readBalance: chain.readBalance,
  hasCodeAt: chain.hasCodeAt,
}))

const kh = vi.hoisted(() => {
  const writeContract = vi.fn<(input: {
    contractAddress: string
    functionName: string
    functionArgs: unknown[]
    abi: unknown[]
  }) => Promise<{ executionId: string }>>()
  const getExecutionStatus = vi.fn<(id: string) => Promise<{ transactionHash: string }>>()
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

interface ContractRecord {
  address: string
  deployTx: string
  note: string
}
interface Deployments {
  sepolia: {
    chainId: number
    explorer: string
    contracts: Record<string, ContractRecord>
    watchedWallet: { address: string; note: string }
  }
}

const RECORDED: Record<string, ContractRecord> = {
  MockUSDC: {
    address: addr.token,
    deployTx: '0xoldtokentx',
    note: '6-decimal ERC-20 demo fixture. Open mint.',
  },
  RoachMotelSpender: {
    address: addr.spender,
    deployTx: '0xoldspendertx',
    note: 'Demonstration drain target. Owner-gated; inert once its approval is revoked.',
  },
}

function deploymentsFile(contracts: Record<string, ContractRecord>): string {
  const data: Deployments = {
    sepolia: {
      chainId: 11155111,
      explorer: 'https://sepolia.etherscan.io',
      contracts,
      watchedWallet: { address: addr.victim, note: 'Org Turnkey smart account.' },
    },
  }
  return JSON.stringify(data, null, 2)
}

/** The payload writeDeployments would have put on disk, parsed back. */
function lastWrite(): Deployments {
  const write = fsState.writes.at(-1)
  expect(write, 'seed.ts never wrote deployments.json').toBeDefined()
  return JSON.parse(write!.data) as Deployments
}

function logged(): string {
  return vi.mocked(console.log).mock.calls.map((args) => args.join(' ')).join('\n')
}

function errored(): string {
  return vi.mocked(console.error).mock.calls.map((args) => args.join(' ')).join('\n')
}

/**
 * main() is a long await chain. A macrotask tick drains the entire microtask
 * queue — including the continuations each await schedules — so this is enough
 * for a run whose every dependency resolves synchronously.
 */
async function settle(): Promise<void> {
  for (let i = 0; i < 3; i++) await new Promise<void>((resolve) => setImmediate(resolve))
}

async function runSeed(): Promise<void> {
  await import('../scripts/seed.js')
  await settle()
}

let originalArgv: string[]

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()
  kh.constructed.length = 0

  fsState.deployments = deploymentsFile({ ...RECORDED })
  fsState.artifactMissing = false
  fsState.writes.length = 0

  // Default world: both fixtures live on chain, victim funded, approval armed.
  // Every test below moves exactly one thing off this baseline.
  chain.hasCodeAt.mockResolvedValue(true)
  chain.readBalance.mockResolvedValue(MINT_AMOUNT)
  chain.readAllowance.mockResolvedValue(MAX_UINT256)

  wallet.deployContract
    .mockResolvedValueOnce(TX.deployToken)
    .mockResolvedValueOnce(TX.deploySpender)
  wallet.writeContract.mockResolvedValue(TX.mint)
  chain.waitForTransactionReceipt.mockImplementation(({ hash }) => {
    const byHash: Record<string, { contractAddress?: string }> = {
      [TX.deployToken]: { contractAddress: addr.freshToken },
      [TX.deploySpender]: { contractAddress: addr.freshSpender },
    }
    return Promise.resolve(byHash[hash] ?? {})
  })

  kh.writeContract.mockResolvedValue({ executionId: 'exec-1' })
  kh.getExecutionStatus.mockResolvedValue({ transactionHash: TX.approve })

  originalArgv = process.argv
  process.argv = ['node', 'scripts/seed.ts']
  process.exitCode = undefined
  vi.spyOn(console, 'log').mockImplementation(() => undefined)
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
})

afterEach(() => {
  process.argv = originalArgv
  process.exitCode = undefined
  vi.restoreAllMocks()
})

describe('seed.ts — contract deployment', () => {
  it('reuses recorded contracts that still have code on chain', async () => {
    await runSeed()

    expect(wallet.deployContract).not.toHaveBeenCalled()
    expect(chain.hasCodeAt).toHaveBeenCalledWith(addr.token)
    expect(chain.hasCodeAt).toHaveBeenCalledWith(addr.spender)
    expect(logged()).toContain(`reusing ${addr.token}`)
    expect(lastWrite().sepolia.contracts).toEqual(RECORDED)
  })

  it('deploys from scratch when deployments.json records no contracts', async () => {
    // No recorded address means hasCodeAt is never asked — there is nothing to
    // ask about — and the note falls back to '' rather than undefined.
    fsState.deployments = deploymentsFile({})

    await runSeed()

    expect(chain.hasCodeAt).not.toHaveBeenCalled()
    expect(wallet.deployContract).toHaveBeenCalledTimes(2)
    expect(lastWrite().sepolia.contracts).toEqual({
      MockUSDC: { address: addr.freshToken, deployTx: TX.deployToken, note: '' },
      RoachMotelSpender: { address: addr.freshSpender, deployTx: TX.deploySpender, note: '' },
    })
    expect(logged()).toContain(`deployed ${addr.freshToken}`)
  })

  it('redeploys a recorded address that has no code on chain', async () => {
    // A recorded address that the chain no longer knows about (wrong network,
    // wiped testnet) must not be reused — reusing it would arm an approval
    // against nothing and report success.
    chain.hasCodeAt.mockResolvedValue(false)

    await runSeed()

    expect(wallet.deployContract).toHaveBeenCalledTimes(2)
    expect(lastWrite().sepolia.contracts['MockUSDC']).toEqual({
      address: addr.freshToken,
      deployTx: TX.deployToken,
      note: RECORDED['MockUSDC']!.note, // the human-written note survives a redeploy
    })
  })

  it('--redeploy forces fresh deployments even when the recorded ones are live', async () => {
    process.argv = ['node', 'scripts/seed.ts', '--redeploy']

    await runSeed()

    expect(wallet.deployContract).toHaveBeenCalledTimes(2)
    expect(lastWrite().sepolia.contracts['RoachMotelSpender']).toEqual({
      address: addr.freshSpender,
      deployTx: TX.deploySpender,
      note: RECORDED['RoachMotelSpender']!.note,
    })
  })

  it('passes the compiled artifact bytecode to deployContract', async () => {
    fsState.deployments = deploymentsFile({})

    await runSeed()

    expect(wallet.deployContract).toHaveBeenCalledWith({
      abi: [{ name: 'mint' }],
      bytecode: '0x6080604052',
      args: [],
    })
  })

  it('fails with the forge hint when the build artifact is missing', async () => {
    fsState.artifactMissing = true
    chain.hasCodeAt.mockResolvedValue(false)

    await runSeed()

    expect(errored()).toContain('Missing build artifact for MockUSDC. Run: cd contracts && forge build')
    expect(process.exitCode).toBe(1)
    expect(fsState.writes).toHaveLength(0)
  })

  it('fails when a deployment receipt carries no contract address', async () => {
    fsState.deployments = deploymentsFile({})
    chain.waitForTransactionReceipt.mockResolvedValue({})

    await runSeed()

    expect(errored()).toContain('MockUSDC deployment produced no address')
    expect(process.exitCode).toBe(1)
    expect(fsState.writes).toHaveLength(0)
  })

  it('writes deployments.json back as 2-space JSON with a trailing newline, preserving the rest of the file', async () => {
    fsState.deployments = deploymentsFile({})

    await runSeed()

    const write = fsState.writes.at(-1)!
    expect(write.path).toContain('deployments.json')
    expect(write.data.endsWith('}\n')).toBe(true)
    expect(write.data).toContain('\n  "sepolia": {')
    expect(lastWrite().sepolia.chainId).toBe(11155111)
    expect(lastWrite().sepolia.watchedWallet.address).toBe(addr.victim)
  })
})

describe('seed.ts — funding the victim', () => {
  it('mints exactly the shortfall when the victim is underfunded', async () => {
    chain.readBalance.mockResolvedValueOnce(4_000_000_000n)

    await runSeed()

    expect(wallet.writeContract).toHaveBeenCalledWith({
      address: addr.token,
      abi: expect.anything(),
      functionName: 'mint',
      args: [addr.victim, 6_000_000_000n],
    })
    expect(chain.waitForTransactionReceipt).toHaveBeenCalledWith({ hash: TX.mint })
    expect(logged()).toContain('minted   6000.00 mUSDC to victim')
  })

  it('does not mint when the victim already holds the full amount', async () => {
    await runSeed()

    expect(wallet.writeContract).not.toHaveBeenCalled()
    expect(logged()).toContain('victim already holds 10000.00 mUSDC')
  })
})

describe('seed.ts — arming the approval', () => {
  it('approves MAX_UINT256 through KeeperHub when the allowance is short', async () => {
    // The approval MUST go through KeeperHub, not the deployer wallet: only the
    // Turnkey account can grant an allowance that Revoker is then able to clear.
    chain.readAllowance.mockResolvedValueOnce(0n)

    await runSeed()

    expect(kh.constructed).toHaveLength(1)
    expect(kh.writeContract).toHaveBeenCalledWith({
      contractAddress: addr.token,
      functionName: 'approve',
      functionArgs: [addr.spender, MAX_UINT256.toString()],
      abi: expect.anything(),
    })
    expect(kh.getExecutionStatus).toHaveBeenCalledWith('exec-1')
    expect(logged()).toContain(`approved MAX_UINT256 -> ${addr.spender}`)
    expect(logged()).toContain(TX.approve)
    expect(logged()).toContain('allowance MAX_UINT256 (unlimited)')
  })

  it('does not re-approve when the unlimited approval is already live', async () => {
    await runSeed()

    expect(kh.constructed).toHaveLength(0)
    expect(kh.writeContract).not.toHaveBeenCalled()
    expect(logged()).toContain('unlimited approval already live')
    expect(logged()).toContain('Run `pnpm watch -- --once`')
  })

  it('fails loudly when the approval is still not live at the end of the run', async () => {
    // Everything "succeeded" but the chain disagrees. Exiting 0 here would hand
    // the demo a threat that was never armed.
    chain.readAllowance.mockResolvedValue(0n)

    await runSeed()

    expect(errored()).toContain('Seed failed: Seed finished but the unlimited approval is not live')
    expect(process.exitCode).toBe(1)
    expect(logged()).toContain('allowance 0') // raw value printed, not the MAX label
  })

  it('stringifies a non-Error rejection into the failure line', async () => {
    chain.readBalance.mockRejectedValue('RPC returned a bare string, not an Error')

    await runSeed()

    expect(errored()).toContain('Seed failed: RPC returned a bare string, not an Error')
    expect(process.exitCode).toBe(1)
  })
})

describe('seed.ts — idempotency', () => {
  it('a second run redeploys nothing, mints nothing and re-approves nothing', async () => {
    // The docblock's central claim, tested against a simulated chain that
    // actually remembers what the first run did. Run 1 starts from an empty
    // deployments.json and a broke victim; run 2 reads back exactly what run 1
    // wrote and must be a no-op on chain.
    const state = {
      balance: 0n,
      allowance: 0n,
      code: new Set<string>(),
      deploys: 0,
    }
    chain.hasCodeAt.mockImplementation((address) => Promise.resolve(state.code.has(address)))
    chain.readBalance.mockImplementation(() => Promise.resolve(state.balance))
    chain.readAllowance.mockImplementation(() => Promise.resolve(state.allowance))
    wallet.deployContract.mockReset()
    wallet.deployContract.mockImplementation(() => {
      state.deploys += 1
      return Promise.resolve(`0xdeploy${state.deploys}`)
    })
    chain.waitForTransactionReceipt.mockImplementation(({ hash }) => {
      if (!hash.startsWith('0xdeploy')) return Promise.resolve({})
      const address = `0xc0de${hash.slice(-1)}`
      state.code.add(address)
      return Promise.resolve({ contractAddress: address })
    })
    wallet.writeContract.mockImplementation(({ args }) => {
      state.balance += args[1]
      return Promise.resolve(TX.mint)
    })
    kh.writeContract.mockImplementation(() => {
      state.allowance = MAX_UINT256
      return Promise.resolve({ executionId: 'exec-1' })
    })
    fsState.deployments = deploymentsFile({})

    await runSeed()

    expect(state.deploys).toBe(2)
    expect(state.balance).toBe(MINT_AMOUNT)
    expect(state.allowance).toBe(MAX_UINT256)
    const afterFirstRun = fsState.writes.at(-1)!.data

    // Run 2 sees the world run 1 left behind.
    fsState.deployments = afterFirstRun
    fsState.writes.length = 0
    wallet.deployContract.mockClear()
    wallet.writeContract.mockClear()
    kh.writeContract.mockClear()
    vi.resetModules()

    await runSeed()

    expect(wallet.deployContract).not.toHaveBeenCalled() // no redeploy
    expect(wallet.writeContract).not.toHaveBeenCalled() // no double-mint
    expect(kh.writeContract).not.toHaveBeenCalled() // approval already at MAX
    expect(state.balance).toBe(MINT_AMOUNT)
    expect(process.exitCode).toBeUndefined()
    // Same chain state in, same file out — the run left nothing to diff.
    expect(fsState.writes.at(-1)!.data).toBe(afterFirstRun)
  })
})
