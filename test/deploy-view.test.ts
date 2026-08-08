import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'

/**
 * scripts/deploy-view.ts calls `main().catch(...)` at module top level, so
 * importing it runs the whole deploy. Every edge that would leave this process
 * is replaced — viem's wallet client, the chain reads, and node:fs.
 *
 * writeFileSync is captured and never forwarded: the real deployments.json
 * records live Sepolia addresses, and a test that rewrote it would silently
 * break the demo. Same discipline as test/seed.test.ts.
 *
 * What these tests are really pinning is that the script cannot report success
 * over a helper that is wrong. Deploying a contract is the easy half; the three
 * verification steps (it delegates to canonical Permit2, the agent can resolve
 * it, and its flattened read equals Permit2's own amount) are the half that
 * would have caught the original bug, so each has a failing case here.
 */

const addr = vi.hoisted(() => ({
  deployer: '0xdead00000000000000000000000000000000beef',
  owner: '0x5e2e5fd3ad7fdc9b94482930db8b5f45e439bab7',
  token: '0x4facb5fd1682c4449cad42b7590861f7ed5c88cb',
  spender: '0x8ebf8540ede8e40cd94825c418758d4029d8892e',
  recordedView: '0x1111000000000000000000000000000000000011',
  freshView: '0x2222000000000000000000000000000000000022',
}))

const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3'
const DEPLOY_TX = '0xd00d'
const MAX_UINT160 = (1n << 160n) - 1n

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
        return JSON.stringify({ abi: [{ name: 'amountOf' }], bytecode: { object: '0x6080604052' } })
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
}))
vi.mock('viem', async (importOriginal) => {
  const actual = await importOriginal<typeof import('viem')>()
  return { ...actual, createWalletClient: vi.fn(() => wallet), http: vi.fn((url?: string) => ({ url })) }
})
vi.mock('viem/accounts', () => ({ privateKeyToAccount: vi.fn(() => ({ address: addr.deployer })) }))

vi.mock('../src/config.js', () => ({
  config: {
    deployerPrivateKey: `0x${'11'.repeat(32)}`,
    rpcUrl: 'http://rpc.invalid',
    walletAddress: addr.owner,
    chainId: 11155111,
    network: 'sepolia',
  },
  explorerTxUrl: (hash: string) => `https://sepolia.etherscan.io/tx/${hash}`,
}))

const chain = vi.hoisted(() => ({
  hasCodeAt: vi.fn<(address: string) => Promise<boolean>>(),
  waitForTransactionReceipt: vi.fn<(args: { hash: string }) => Promise<{ contractAddress?: string }>>(),
  readContract: vi.fn<(args: { address: string; functionName: string; args?: unknown[] }) => Promise<unknown>>(),
}))
vi.mock('../src/chain.js', () => ({
  hasCodeAt: chain.hasCodeAt,
  publicClient: {
    waitForTransactionReceipt: chain.waitForTransactionReceipt,
    readContract: chain.readContract,
  },
}))

/**
 * Only the two live edges are replaced. The constants and the ABI stay REAL, so
 * a typo in the helper's function names or in PERMIT2_ADDRESS fails here rather
 * than against a live node.
 */
const permit2 = vi.hoisted(() => ({
  permit2AllowanceViewAddress: vi.fn<() => string>(),
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
  return {
    ...actual,
    permit2AllowanceViewAddress: permit2.permit2AllowanceViewAddress,
    readPermit2Allowance: permit2.readPermit2Allowance,
  }
})

interface ContractRecord {
  address: string
  deployTx?: string
  note?: string
}

const FIXTURES: Record<string, ContractRecord> = {
  MockUSDC: { address: addr.token, deployTx: '0xoldtoken', note: 'token' },
  RoachMotelSpender: { address: addr.spender, deployTx: '0xoldspender', note: 'spender' },
}

function deploymentsFile(contracts?: Record<string, ContractRecord>, network = 'sepolia'): string {
  return JSON.stringify({
    [network]: {
      chainId: 11155111,
      ...(contracts === undefined ? {} : { contracts }),
    },
  })
}

function lastWrite(): Record<string, { contracts: Record<string, ContractRecord> }> {
  const write = fsState.writes.at(-1)
  expect(write, 'deploy-view.ts never wrote deployments.json').toBeDefined()
  return JSON.parse(write!.data) as Record<string, { contracts: Record<string, ContractRecord> }>
}

function logged(): string {
  return vi.mocked(console.log).mock.calls.map((args) => args.join(' ')).join('\n')
}

function errored(): string {
  return vi.mocked(console.error).mock.calls.map((args) => args.join(' ')).join('\n')
}

/** A macrotask tick drains the microtask queue the await chain schedules. */
async function settle(): Promise<void> {
  for (let i = 0; i < 3; i++) await new Promise<void>((resolve) => setImmediate(resolve))
}

async function runDeploy(): Promise<void> {
  await import('../scripts/deploy-view.js')
  await settle()
}

let originalArgv: string[]

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()

  fsState.deployments = deploymentsFile({ ...FIXTURES })
  fsState.artifactMissing = false
  fsState.writes.length = 0

  // Default world: Permit2 is live, nothing recorded yet, the deploy lands, and
  // every verification agrees. Each test moves exactly one thing off this.
  chain.hasCodeAt.mockResolvedValue(true)
  wallet.deployContract.mockResolvedValue(DEPLOY_TX)
  chain.waitForTransactionReceipt.mockResolvedValue({ contractAddress: addr.freshView })
  chain.readContract.mockImplementation(({ functionName }) => {
    if (functionName === 'PERMIT2') return Promise.resolve(PERMIT2)
    return Promise.resolve(MAX_UINT160)
  })
  permit2.permit2AllowanceViewAddress.mockReturnValue(addr.freshView)
  permit2.readPermit2Allowance.mockResolvedValue({
    amount: MAX_UINT160,
    expiration: 1_817_728_584,
    nonce: 0,
  })

  originalArgv = process.argv
  process.argv = ['node', 'scripts/deploy-view.ts']
  process.exitCode = undefined
  vi.spyOn(console, 'log').mockImplementation(() => undefined)
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
})

afterEach(() => {
  process.argv = originalArgv
  process.exitCode = undefined
  vi.restoreAllMocks()
})

describe('deploy-view.ts — deploying the guard helper', () => {
  it('deploys and records the address, deploy tx and note', async () => {
    await runDeploy()

    expect(wallet.deployContract).toHaveBeenCalledTimes(1)
    const record = lastWrite()['sepolia']!.contracts['Permit2AllowanceView']!
    expect(record.address).toBe(addr.freshView)
    expect(record.deployTx).toBe(DEPLOY_TX)
    // The note is what a future reader finds instead of this commit message.
    expect(record.note).toMatch(/cannot select a tuple member/)
    expect(logged()).toContain(`deployed ${addr.freshView}`)
    expect(logged()).toContain(`tx/${DEPLOY_TX}`)
    expect(process.exitCode).toBeUndefined()
  })

  it('leaves the existing fixture records untouched', async () => {
    // The helper is recorded ALONGSIDE the demo fixtures, not instead of them.
    await runDeploy()

    const contracts = lastWrite()['sepolia']!.contracts
    expect(contracts['MockUSDC']).toEqual(FIXTURES['MockUSDC'])
    expect(contracts['RoachMotelSpender']).toEqual(FIXTURES['RoachMotelSpender'])
  })

  it('reuses a recorded helper that still has code, sending nothing', async () => {
    fsState.deployments = deploymentsFile({ ...FIXTURES, Permit2AllowanceView: { address: addr.recordedView } })
    permit2.permit2AllowanceViewAddress.mockReturnValue(addr.recordedView)

    await runDeploy()

    expect(wallet.deployContract).not.toHaveBeenCalled()
    expect(fsState.writes).toHaveLength(0)
    expect(logged()).toContain(`reusing ${addr.recordedView}`)
  })

  it('redeploys a recorded address the chain no longer knows about', async () => {
    // A wiped testnet or a wrong-network record. Reusing it would leave the
    // guard pointed at nothing, and every read against it would revert.
    fsState.deployments = deploymentsFile({ ...FIXTURES, Permit2AllowanceView: { address: addr.recordedView } })
    chain.hasCodeAt.mockImplementation((address) => Promise.resolve(address !== addr.recordedView))

    await runDeploy()

    expect(wallet.deployContract).toHaveBeenCalledTimes(1)
    expect(lastWrite()['sepolia']!.contracts['Permit2AllowanceView']!.address).toBe(addr.freshView)
  })

  it('redeploys on --redeploy even when the recorded helper is live', async () => {
    fsState.deployments = deploymentsFile({ ...FIXTURES, Permit2AllowanceView: { address: addr.recordedView } })
    process.argv = ['node', 'scripts/deploy-view.ts', '--redeploy']

    await runDeploy()

    expect(wallet.deployContract).toHaveBeenCalledTimes(1)
  })

  it('creates the contracts map when deployments.json has none', async () => {
    fsState.deployments = deploymentsFile(undefined)

    await runDeploy()

    expect(lastWrite()['sepolia']!.contracts['Permit2AllowanceView']!.address).toBe(addr.freshView)
  })
})

describe('deploy-view.ts — refusing to deploy something useless', () => {
  it('stops when Permit2 is not deployed on this chain', async () => {
    // A CALL to a codeless address returns empty data rather than reverting, so
    // the helper would be recorded and every read against it would fail on
    // decode. Cheaper to refuse than to debug later.
    chain.hasCodeAt.mockImplementation((address) => Promise.resolve(address !== PERMIT2))

    await runDeploy()

    expect(wallet.deployContract).not.toHaveBeenCalled()
    expect(errored()).toContain('Permit2 is not deployed on this chain')
    expect(process.exitCode).toBe(1)
  })

  it('stops when deployments.json has no section for the configured network', async () => {
    fsState.deployments = deploymentsFile({ ...FIXTURES }, 'mainnet')

    await runDeploy()

    expect(errored()).toContain('no "sepolia" section')
    expect(process.exitCode).toBe(1)
  })

  it('points at forge build when the artifact is missing', async () => {
    fsState.artifactMissing = true

    await runDeploy()

    expect(errored()).toContain('Run: cd contracts && forge build')
    expect(process.exitCode).toBe(1)
  })

  it('stops when the deployment receipt carries no contract address', async () => {
    chain.waitForTransactionReceipt.mockResolvedValue({})

    await runDeploy()

    expect(errored()).toContain('deployment produced no contract address')
    expect(fsState.writes).toHaveLength(0)
    expect(process.exitCode).toBe(1)
  })

  it('reports a non-Error rejection without swallowing it', async () => {
    chain.hasCodeAt.mockRejectedValue('rpc exploded')

    await runDeploy()

    expect(errored()).toContain('rpc exploded')
    expect(process.exitCode).toBe(1)
  })
})

describe('deploy-view.ts — verifying what was deployed', () => {
  it('reads PERMIT2() back off the deployed helper', async () => {
    await runDeploy()

    expect(chain.readContract).toHaveBeenCalledWith(
      expect.objectContaining({ address: addr.freshView, functionName: 'PERMIT2' }),
    )
    expect(logged()).toContain('delegates to canonical Permit2')
  })

  it('refuses a helper that delegates somewhere other than canonical Permit2', async () => {
    // Bytecode at an address is not evidence of WHICH bytecode. A helper reading
    // an attacker's contract would report a live allowance the lockdown cannot
    // zero, and bait a revoke on every scan forever.
    chain.readContract.mockImplementation(({ functionName }) => {
      if (functionName === 'PERMIT2') return Promise.resolve(addr.spender)
      return Promise.resolve(MAX_UINT160)
    })

    await runDeploy()

    expect(errored()).toContain('not canonical Permit2')
    expect(process.exitCode).toBe(1)
  })

  it('refuses when deployments.json does not resolve to what was just deployed', async () => {
    // The deploy succeeding and the AGENT being able to find the address are two
    // different claims. This is the second one, checked the way revoke.ts checks it.
    permit2.permit2AllowanceViewAddress.mockReturnValue(addr.recordedView)

    await runDeploy()

    expect(errored()).toContain(`resolves to ${addr.recordedView}`)
    expect(process.exitCode).toBe(1)
  })

  it('cross-checks the flattened read against Permit2 own amount member', async () => {
    await runDeploy()

    expect(chain.readContract).toHaveBeenCalledWith(
      expect.objectContaining({
        functionName: 'amountOf',
        args: [addr.owner, addr.token, addr.spender],
      }),
    )
    expect(chain.readContract).toHaveBeenCalledWith(
      expect.objectContaining({ functionName: 'liveAmountOf' }),
    )
    expect(logged()).toContain('CROSS-CHECK against the seeded slot')
    expect(process.exitCode).toBeUndefined()
  })

  it('refuses when the helper disagrees with Permit2 about the same slot', async () => {
    // The one check that would have caught the original bug class: a guard whose
    // number is not the number the action zeroes.
    permit2.readPermit2Allowance.mockResolvedValue({ amount: 42n, expiration: 1, nonce: 0 })

    await runDeploy()

    expect(errored()).toContain('do not use it')
    expect(process.exitCode).toBe(1)
  })

  it('skips the cross-check loudly when the fixtures are not seeded', async () => {
    fsState.deployments = deploymentsFile({})

    await runDeploy()

    expect(permit2.readPermit2Allowance).not.toHaveBeenCalled()
    expect(logged()).toContain('fixtures not seeded')
    // The placeholders keep the printed cast command copy-pasteable-shaped
    // rather than embedding the word "undefined".
    expect(logged()).toContain('<token>')
    expect(logged()).toContain('<spender>')
    expect(process.exitCode).toBeUndefined()
  })

  it('prints a credential-free way to check the deployment by hand', async () => {
    await runDeploy()

    expect(logged()).toContain(`cast call ${addr.freshView} "PERMIT2()(address)"`)
    expect(logged()).toContain('liveAmountOf(address,address,address)(uint160)')
  })
})
