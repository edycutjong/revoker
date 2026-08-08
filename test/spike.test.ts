import { describe, expect, it, vi, beforeEach, afterEach, type Mock } from 'vitest'

/**
 * scripts/spike.ts calls `main().catch(...)` at module top level: importing it
 * for real resolves live credentials, POSTs a funded transfer to KeeperHub and
 * broadcasts a transaction. ../src/keeperhub.js is mocked so the five surfaces
 * the spike exercises answer from fixtures, ../src/config.js is mocked so its
 * getters don't demand real KH_* env vars, and global fetch is stubbed so the
 * independent JSON-RPC verification never leaves the process.
 *
 * The point of the spike is that it does NOT trust KeeperHub's own claim that a
 * transaction landed, so these tests pin that separation: which surface was
 * called with what, and what the RPC is asked to confirm.
 */

/** The signer KeeperHub reports — same address as the config, different case. */
const SIGNER = '0xABCdef0123456789ABCdef0123456789abCDEF01'
const HASH = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'

interface TransferInput {
  recipientAddress: string
  amount: string
  simulate?: boolean
  idempotencyKey?: string
}

const khMock = vi.hoisted(() => {
  const getWallet = vi.fn()
  const getChains = vi.fn()
  const transfer = vi.fn()
  const getExecutionStatus = vi.fn()
  const explorerTxUrl = vi.fn()
  class KeeperHub {
    getWallet = getWallet
    getChains = getChains
    transfer = transfer
    getExecutionStatus = getExecutionStatus
  }
  return { KeeperHub, getWallet, getChains, transfer, getExecutionStatus, explorerTxUrl }
})
vi.mock('../src/keeperhub.js', () => ({
  KeeperHub: khMock.KeeperHub,
  explorerTxUrl: khMock.explorerTxUrl,
}))

const configMock = {
  walletAddress: '0xabcdef0123456789abcdef0123456789abcdef01',
  network: 'sepolia',
  chainId: 11155111,
  rpcUrl: 'https://rpc.test/sepolia',
}
vi.mock('../src/config.js', () => ({ config: configMock }))

/** What the stubbed public RPC answers. */
const rpcState = {
  /** Consumed one per eth_getBalance call; the last entry sticks. */
  balances: [] as string[],
  receipt: null as unknown,
  errors: {} as Record<string, string>,
}

interface RpcCall {
  url: string
  method: string
  params: unknown[]
}
const rpcCalls: RpcCall[] = []

/** Narrowed to what the spike's rpc() helper actually sends: a URL and a JSON body. */
interface FetchInit {
  method?: string
  headers?: Record<string, string>
  body?: string
}
type FetchStub = (url: string, init?: FetchInit) => Promise<Response>

let fetchMock: Mock<FetchStub>
let logSpy: Mock<(...args: unknown[]) => void>
let errorSpy: Mock<(...args: unknown[]) => void>

function rpcResult(method: string): unknown {
  if (method !== 'eth_getBalance') return rpcState.receipt
  return rpcState.balances.length > 1 ? rpcState.balances.shift() : rpcState.balances[0]
}

/** Everything the spike printed, one line per console.log call. */
function logged(): string {
  return logSpy.mock.calls.map((call) => String(call[0])).join('\n')
}

function reported(): string {
  return errorSpy.mock.calls.map((call) => String(call[0])).join('\n')
}

/**
 * main()'s promise is never exported, so the only observable end of the run is
 * the success line or the top-level catch. Polling with real timers (rather
 * than draining microtasks) also lets the stubbed Response bodies resolve.
 */
async function runSpike(): Promise<void> {
  await import('../scripts/spike.js')
  await vi.waitFor(
    () => {
      expect(logged().includes('Spike passed') || reported() !== '').toBe(true)
    },
    { interval: 1, timeout: 5_000 },
  )
}

beforeEach(() => {
  vi.resetModules()

  rpcState.balances = ['0x2386f26fc10000']
  rpcState.receipt = { status: '0x1', blockNumber: '0x10d4f', gasUsed: '0x5208' }
  rpcState.errors = {}
  rpcCalls.length = 0

  khMock.getWallet.mockReset().mockResolvedValue({ hasWallet: true, walletAddress: SIGNER })
  khMock.getChains
    .mockReset()
    .mockResolvedValue([
      { chainId: 11155111, name: 'Ethereum Sepolia', explorerUrl: 'https://sepolia.etherscan.io' },
      { chainId: 84532, name: 'Base Sepolia', explorerUrl: 'https://sepolia.basescan.org' },
    ])
  khMock.transfer
    .mockReset()
    .mockResolvedValueOnce({ success: true, status: 'simulated', gasEstimate: '21000' })
    .mockResolvedValue({ executionId: 'exec-spike-1', status: 'completed', transactionHash: HASH })
  khMock.getExecutionStatus.mockReset().mockResolvedValue({
    executionId: 'exec-spike-1',
    status: 'completed',
    sponsored: false,
    gasUsedWei: '21000',
    gasPriceWei: '1500000000',
    retryCount: 0,
  })
  khMock.explorerTxUrl
    .mockReset()
    .mockImplementation((hash: string) => `https://sepolia.etherscan.io/tx/${hash}`)

  fetchMock = vi.fn<FetchStub>((url, init) => {
    const call = JSON.parse(String(init?.body)) as { method: string; params: unknown[] }
    rpcCalls.push({ url, method: call.method, params: call.params })
    const message = rpcState.errors[call.method]
    const payload = message
      ? { jsonrpc: '2.0', id: 1, error: { message } }
      : { jsonrpc: '2.0', id: 1, result: rpcResult(call.method) }
    return Promise.resolve(new Response(JSON.stringify(payload)))
  })
  vi.stubGlobal('fetch', fetchMock)

  process.exitCode = undefined
  logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined) as unknown as typeof logSpy
  errorSpy = vi
    .spyOn(console, 'error')
    .mockImplementation(() => undefined) as unknown as typeof errorSpy
})

afterEach(() => {
  process.exitCode = undefined
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('scripts/spike.ts — the five KeeperHub surfaces', () => {
  it('resolves the signer, the chain, a dry run, the real transfer and its audit record', async () => {
    await runSpike()

    expect(khMock.getWallet).toHaveBeenCalledTimes(1)
    expect(khMock.getChains).toHaveBeenCalledTimes(1)
    expect(khMock.transfer).toHaveBeenCalledTimes(2)
    expect(khMock.getExecutionStatus).toHaveBeenCalledWith('exec-spike-1')
    expect(reported()).toBe('')
    expect(process.exitCode).toBeUndefined()
  })

  it('accepts a signer that matches the configured address in a different case', async () => {
    // KeeperHub returns a checksummed address; KH_WALLET_ADDRESS is commonly
    // pasted lowercase. Comparing them raw would fail a correct configuration.
    await runSpike()

    expect(SIGNER).not.toBe(configMock.walletAddress)
    expect(logged()).toContain('configured address matches the signer KeeperHub controls')
  })

  it('dry-runs the transfer before broadcasting the real one', async () => {
    await runSpike()

    const [dry, real] = khMock.transfer.mock.calls.map((call) => call[0] as TransferInput)
    expect(dry?.simulate).toBe(true)
    expect(dry?.idempotencyKey).toBeUndefined()
    expect(real?.simulate).toBeUndefined()
    expect(real?.recipientAddress).toBe(configMock.walletAddress)
    expect(real?.amount).toBe('0.0001')
  })

  it('sends a per-day idempotency key so a re-run replays instead of paying twice', async () => {
    await runSpike()

    const real = khMock.transfer.mock.calls[1]?.[0] as TransferInput
    expect(real.idempotencyKey).toBe(`revoker-spike-${new Date().toISOString().slice(0, 10)}`)
  })

  it('reports the explorer link for the hash KeeperHub actually returned', async () => {
    await runSpike()

    expect(khMock.explorerTxUrl).toHaveBeenCalledWith(HASH)
    expect(logged()).toContain(`https://sepolia.etherscan.io/tx/${HASH}`)
  })

  it('prints the receipts carried on the audit record', async () => {
    khMock.getExecutionStatus.mockResolvedValue({
      executionId: 'exec-spike-1',
      status: 'completed',
      sponsored: false,
      receipts: [{ hash: HASH, blockNumber: 68943, receiptStatus: 'success', gasUsed: '21000' }],
    })

    await runSpike()

    expect(logged()).toContain('receipt   : block 68943, success')
  })
})

describe('scripts/spike.ts — preconditions it refuses to run without', () => {
  it('stops when the org has no Turnkey wallet', async () => {
    khMock.getWallet.mockResolvedValue({ hasWallet: false })

    await runSpike()

    expect(reported()).toContain('Org has no Turnkey wallet')
    expect(khMock.transfer).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(1)
  })

  it('stops when the wallet record carries no address', async () => {
    khMock.getWallet.mockResolvedValue({ hasWallet: true, walletAddress: undefined })

    await runSpike()

    expect(reported()).toContain('Org has no Turnkey wallet')
    expect(khMock.transfer).not.toHaveBeenCalled()
  })

  it('stops when the configured address is not the wallet KeeperHub signs for', async () => {
    // Signing for someone else's address is impossible, so this has to fail
    // loudly rather than send a transfer that can never do what was asked.
    khMock.getWallet.mockResolvedValue({
      hasWallet: true,
      walletAddress: '0x9999999999999999999999999999999999999999',
    })

    await runSpike()

    expect(reported()).toContain('does not match the org wallet')
    expect(khMock.transfer).not.toHaveBeenCalled()
  })

  it('stops when the target chain is not among the supported ones', async () => {
    khMock.getChains.mockResolvedValue([
      { chainId: 84532, name: 'Base Sepolia', explorerUrl: 'https://sepolia.basescan.org' },
    ])

    await runSpike()

    expect(reported()).toContain('chainId 11155111 not supported by KeeperHub')
    expect(khMock.transfer).not.toHaveBeenCalled()
  })

  it('logs the matched chain when the network is supported', async () => {
    await runSpike()

    expect(logged()).toContain('Ethereum Sepolia (11155111) — https://sepolia.etherscan.io')
  })
})

describe('scripts/spike.ts — independent on-chain verification', () => {
  it('asks the configured RPC to confirm the hash the API claimed', async () => {
    await runSpike()

    expect(rpcCalls.map((call) => call.method)).toEqual([
      'eth_getBalance',
      'eth_getTransactionReceipt',
      'eth_getBalance',
    ])
    expect(rpcCalls.every((call) => call.url === configMock.rpcUrl)).toBe(true)
    // The verification is only worth anything if it looks up the hash the API
    // returned, not one the spike already knew.
    expect(rpcCalls[1]?.params).toEqual([HASH])
    expect(rpcCalls[0]?.params).toEqual([configMock.walletAddress, 'latest'])
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBe('POST')
  })

  it('stops before the audit record when KeeperHub reports no transaction hash', async () => {
    khMock.transfer
      .mockReset()
      .mockResolvedValueOnce({ success: true, status: 'simulated' })
      .mockResolvedValue({ executionId: 'exec-spike-1', status: 'completed' })

    await runSpike()

    expect(reported()).toContain('completion without a transaction hash')
    expect(khMock.getExecutionStatus).not.toHaveBeenCalled()
  })

  it('fails when the transaction is not on-chain at all', async () => {
    rpcState.receipt = null

    await runSpike()

    expect(reported()).toContain(`Transaction ${HASH} not found on-chain via ${configMock.rpcUrl}`)
    expect(process.exitCode).toBe(1)
  })

  it('fails when the receipt says the transaction reverted', async () => {
    // A mined transaction is not a successful one — status 0x0 is a revert, and
    // KeeperHub still reports it as completed.
    rpcState.receipt = { status: '0x0', blockNumber: '0x10d4f', gasUsed: '0x5208' }

    await runSpike()

    expect(logged()).toContain('on-chain status : FAILED')
    expect(reported()).toContain('Transaction reverted on-chain')
  })

  it('reports the balance delta measured across the transaction', async () => {
    rpcState.balances = ['0x64', '0x5a']

    await runSpike()

    expect(logged()).toContain('balance delta   : -10 wei')
  })

  it('notes sponsored gas when the signer paid nothing', async () => {
    khMock.getExecutionStatus.mockResolvedValue({
      executionId: 'exec-spike-1',
      status: 'completed',
      sponsored: true,
    })

    await runSpike()

    expect(logged()).toContain('gas was sponsored by KeeperHub')
  })

  it('does not claim sponsorship when the balance moved', async () => {
    khMock.getExecutionStatus.mockResolvedValue({
      executionId: 'exec-spike-1',
      status: 'completed',
      sponsored: true,
    })
    rpcState.balances = ['0x64', '0x5a']

    await runSpike()

    expect(logged()).not.toContain('gas was sponsored by KeeperHub')
  })

  it('does not claim sponsorship when KeeperHub did not sponsor', async () => {
    // sponsored is false and the balance is unchanged — an unchanged balance
    // alone must not be read as sponsorship.
    await runSpike()

    expect(logged()).not.toContain('gas was sponsored by KeeperHub')
  })
})

describe('scripts/spike.ts — failure reporting', () => {
  it('surfaces a JSON-RPC error as RPC <method>: <message>', async () => {
    rpcState.errors = { eth_getBalance: 'exceeded quota' }

    await runSpike()

    expect(reported()).toContain('Spike failed: RPC eth_getBalance: exceeded quota')
    expect(process.exitCode).toBe(1)
  })

  it('surfaces a JSON-RPC error raised by the verification step', async () => {
    rpcState.errors = { eth_getTransactionReceipt: 'unknown block' }

    await runSpike()

    expect(reported()).toContain('Spike failed: RPC eth_getTransactionReceipt: unknown block')
  })

  it('stringifies a non-Error rejection into the failure line', async () => {
    khMock.getWallet.mockRejectedValue('KeeperHub returned something that was not an Error')

    await runSpike()

    expect(reported()).toContain(
      'Spike failed: KeeperHub returned something that was not an Error',
    )
    expect(process.exitCode).toBe(1)
  })
})
