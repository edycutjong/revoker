import { describe, expect, it, vi, beforeEach, afterEach, type Mock } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import type { Address } from 'viem'
import type { KeeperHub } from '../src/keeperhub.js'
import type { McpContext } from '../src/mcp.js'

/**
 * The MCP surface is the one place an LLM touches Revoker, so the tests that
 * matter are the ones about what it is NOT allowed to do: revoke without an
 * explicit human confirmation, and reach chain state through a path the
 * deterministic loop does not also use.
 *
 * chain.ts is mocked at its network edges only — rules.ts runs for real, because
 * "explain_exposure returns the rules that actually fired, with their evidence"
 * is untestable against a stubbed assess(). revoke.ts is mocked so the decision
 * to write can be observed without one being made. The transport is in-memory:
 * no stdio is opened, no socket, no credentials.
 */

const MAX = (1n << 256n) - 1n
const TOKEN = '0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb' as Address
const SPENDER = '0x8eBf8540EdE8e40CD94825C418758d4029D8892e' as Address
const OWNER = '0x5E2e5Fd3aD7fDC9B94482930db8b5F45E439bab7' as Address
const HEAD = 11_443_000n

const chainMocks = vi.hoisted(() => ({
  fetchApprovals: vi.fn(),
  readAllowance: vi.fn(),
  readBalance: vi.fn(),
  tokenSymbol: vi.fn(),
  hasCodeAt: vi.fn(),
  findDeploymentBlock: vi.fn(),
  getBlockNumber: vi.fn(),
}))
vi.mock('../src/chain.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/chain.js')>()
  return {
    ...actual,
    ...chainMocks,
    publicClient: { getBlockNumber: chainMocks.getBlockNumber },
  }
})

const revokeMock = vi.hoisted(() => ({ revokeApproval: vi.fn() }))
vi.mock('../src/revoke.js', () => revokeMock)

const keeperhubMock = vi.hoisted(() => ({ constructed: vi.fn() }))
vi.mock('../src/keeperhub.js', () => ({
  KeeperHub: class {
    getHeldTokens = vi.fn().mockResolvedValue([])
    isSourceVerified = vi.fn().mockResolvedValue(true)
    simulate = vi.fn()
    constructor() {
      keeperhubMock.constructed()
    }
  },
}))

vi.mock('../src/config.js', () => ({
  config: {
    walletAddress: OWNER,
    chainId: 11155111,
    network: 'sepolia',
    rpcUrl: 'http://127.0.0.1:1',
    explorerBase: 'https://sepolia.etherscan.io',
  },
  explorerTxUrl: (hash: string) => `https://sepolia.etherscan.io/tx/${hash}`,
}))

/** Seeded with valid content: src/mcp.ts reads package.json at module load. */
const fsState = vi.hoisted((): { pkg?: string; watchlist?: string; denylist?: string } => ({
  pkg: '{"version":"9.9.9"}',
  watchlist: JSON.stringify({ '11155111': [{ address: '0xTokenFromTheWatchlist' }] }),
  denylist: JSON.stringify({ addresses: [{ address: '0xDeadBeefSpender' }] }),
}))
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  const missing = (name: string): never => {
    throw Object.assign(new Error(`ENOENT: no such file, open ${name}`), { code: 'ENOENT' })
  }
  return {
    ...actual,
    readFileSync: (path: Parameters<typeof actual.readFileSync>[0], enc?: BufferEncoding) => {
      const p = String(path)
      if (p.endsWith('package.json')) return fsState.pkg ?? missing(p)
      if (p.endsWith('watchlist.json')) return fsState.watchlist ?? missing(p)
      if (p.endsWith('denylist.json')) return fsState.denylist ?? missing(p)
      return actual.readFileSync(path, enc)
    },
  }
})

/**
 * StdioServerTransport would seize this process's stdin/stdout. A minimal
 * Transport is enough for Protocol.connect, and `failWith` lets the entrypoint's
 * failure path be forced without a real pipe.
 */
const stdioState = vi.hoisted((): { started: Mock; failWith?: Error } => ({
  started: vi.fn(),
}))
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: class {
    onclose?: () => void
    onerror?: (error: Error) => void
    onmessage?: (message: unknown) => void
    start(): Promise<void> {
      stdioState.started()
      return stdioState.failWith === undefined
        ? Promise.resolve()
        : Promise.reject(stdioState.failWith)
    }
    close(): Promise<void> {
      return Promise.resolve()
    }
    send(): Promise<void> {
      return Promise.resolve()
    }
  },
}))

// Spied before the import below, because src/mcp.ts prints its banner to stderr
// as it starts — the module is an entrypoint and runs main() on load.
const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined)

const mcp = await import('../src/mcp.js')

async function flushMicrotasks(): Promise<void> {
  for (let i = 0; i < 5; i++) await Promise.resolve()
}

/** Only the surface the tools actually touch. */
function makeKh(overrides: Record<string, unknown> = {}) {
  return {
    getHeldTokens: vi.fn().mockResolvedValue([]),
    isSourceVerified: vi.fn().mockResolvedValue(true),
    simulate: vi.fn().mockResolvedValue({
      success: true,
      status: 'simulated',
      from: OWNER,
      to: TOKEN,
      value: '0',
      gasEstimate: '46021',
      simulatedReturnValue: true,
      wouldRevert: false,
    }),
    ...overrides,
  }
}

function makeCtx(overrides: Partial<McpContext> = {}): McpContext {
  return {
    owner: OWNER,
    kh: makeKh() as unknown as KeeperHub,
    tokens: [TOKEN],
    denylist: new Set<string>(),
    lookbackBlocks: 5_000n,
    ...overrides,
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  consoleError.mockImplementation(() => undefined)

  fsState.pkg = '{"version":"9.9.9"}'
  fsState.watchlist = JSON.stringify({ '11155111': [{ address: '0xTokenFromTheWatchlist' }] })
  fsState.denylist = JSON.stringify({ addresses: [{ address: '0xDeadBeefSpender' }] })
  stdioState.failWith = undefined

  chainMocks.getBlockNumber.mockResolvedValue(HEAD)
  chainMocks.fetchApprovals.mockResolvedValue([{ token: TOKEN, spender: SPENDER }])
  chainMocks.readAllowance.mockResolvedValue(MAX)
  chainMocks.readBalance.mockResolvedValue(10_000_000_000n)
  chainMocks.tokenSymbol.mockResolvedValue('mUSDC')
  // Aged contract by default, so young-spender stays quiet unless a test says so.
  chainMocks.hasCodeAt.mockResolvedValue(true)
  revokeMock.revokeApproval.mockResolvedValue({
    executed: true,
    latencyMs: 812,
    allowanceAfter: 0n,
    transactionHash: '0xabc',
  })
})

afterEach(() => {
  process.exitCode = undefined
})

describe('defaultContext — the production wiring', () => {
  it('watches the configured wallet with the same lookback the autonomous loop uses', () => {
    const ctx = mcp.defaultContext()

    expect(ctx.owner).toBe(OWNER)
    // A different window here than in watcher.ts would mean the dashboard and
    // the agent disagreeing about which approvals are still live.
    expect(ctx.lookbackBlocks).toBe(5_000n)
    expect(keeperhubMock.constructed).toHaveBeenCalledTimes(1)
  })

  it('loads the watchlist for the configured chain and lower-cases the deny-list', () => {
    const ctx = mcp.defaultContext()

    expect(ctx.tokens).toEqual(['0xTokenFromTheWatchlist'])
    // rules.ts matches deny-list entries lower-cased; storing them as written
    // would silently never match.
    expect([...ctx.denylist]).toEqual(['0xdeadbeefspender'])
  })

  it('degrades to empty lists when the data files are missing', () => {
    fsState.watchlist = undefined
    fsState.denylist = undefined

    const ctx = mcp.defaultContext()

    expect(ctx.tokens).toEqual([])
    expect([...ctx.denylist]).toEqual([])
  })

  it('degrades to empty lists when the files parse but hold nothing for this chain', () => {
    fsState.watchlist = JSON.stringify({ '1': [{ address: '0xMainnetToken' }] })
    fsState.denylist = JSON.stringify({ updated: '2026-08-08' })

    const ctx = mcp.defaultContext()

    expect(ctx.tokens).toEqual([])
    expect([...ctx.denylist]).toEqual([])
  })
})

describe('list_exposures', () => {
  it('reports the live exposure with its allowance and what is actually at risk', async () => {
    const exposures = await mcp.listExposures(makeCtx())

    expect(exposures).toEqual([
      {
        token: TOKEN,
        spender: SPENDER,
        symbol: 'mUSDC',
        allowance: MAX.toString(),
        unlimited: true,
        // Unlimited allowance, finite balance: the balance is the exposure.
        atRisk: '10000000000',
      },
    ])
  })

  it('caps at-risk at the allowance when the allowance is smaller than the balance', async () => {
    // Reporting the whole balance for a 250 USDC approval would overstate every
    // capped approval in the wallet.
    chainMocks.readAllowance.mockResolvedValue(250_000_000n)

    const [exposure] = await mcp.listExposures(makeCtx())

    expect(exposure).toMatchObject({ allowance: '250000000', unlimited: false, atRisk: '250000000' })
  })

  it('omits a pair whose allowance is already zero', async () => {
    // Approval logs are permanent; a revoked approval keeps appearing in them.
    chainMocks.readAllowance.mockResolvedValue(0n)

    expect(await mcp.listExposures(makeCtx())).toEqual([])
    expect(chainMocks.readBalance).not.toHaveBeenCalled()
  })

  it('collapses repeated approval logs for the same pair into one exposure', async () => {
    chainMocks.fetchApprovals.mockResolvedValue([
      { token: TOKEN, spender: SPENDER },
      { token: TOKEN.toLowerCase() as Address, spender: SPENDER.toLowerCase() as Address },
      { token: TOKEN, spender: SPENDER },
    ])

    expect(await mcp.listExposures(makeCtx())).toHaveLength(1)
  })

  it('merges the watchlist with what KeeperHub reports the wallet holding, without duplicates', async () => {
    const held = '0x1111111111111111111111111111111111111111'
    const kh = makeKh({ getHeldTokens: vi.fn().mockResolvedValue([TOKEN.toLowerCase(), held]) })

    await mcp.listExposures(makeCtx({ kh: kh as unknown as KeeperHub }))

    expect(chainMocks.fetchApprovals).toHaveBeenCalledWith(
      OWNER,
      [TOKEN.toLowerCase(), held],
      HEAD - 5_000n,
      HEAD,
    )
  })

  it('starts at block 0 when the lookback reaches past the head of the chain', async () => {
    chainMocks.getBlockNumber.mockResolvedValue(4_200n)

    await mcp.listExposures(makeCtx({ lookbackBlocks: 10_000n }))

    expect(chainMocks.fetchApprovals).toHaveBeenCalledWith(OWNER, [TOKEN], 0n, 4_200n)
  })

  it('is a pure read: nothing is assessed and nothing is revoked', async () => {
    await mcp.listExposures(makeCtx())

    expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
  })
})

describe('explain_exposure — the evidence, not a summary of it', () => {
  it('returns every rule that fired, each with the chain fact behind it', async () => {
    const kh = makeKh({ isSourceVerified: vi.fn().mockResolvedValue(false) })
    chainMocks.hasCodeAt.mockResolvedValue(false)
    chainMocks.findDeploymentBlock.mockResolvedValue(HEAD - 7_200n) // ~1 day old

    const explanation = await mcp.explainExposure(
      makeCtx({
        kh: kh as unknown as KeeperHub,
        denylist: new Set([SPENDER.toLowerCase()]),
      }),
      TOKEN,
      SPENDER,
    )

    expect(explanation.threat).toBe(true)
    expect(explanation.fired.map((v) => v.rule).sort()).toEqual([
      'denylisted',
      'unlimited-to-unverified',
      'young-spender',
    ])

    // The evidence is the point of the surface: an investigator has to be able
    // to re-derive the verdict, not take "malicious: true" on faith.
    const unlimited = explanation.fired.find((v) => v.rule === 'unlimited-to-unverified')
    expect(unlimited?.evidence).toEqual({ allowance: 'MAX_UINT256', sourceVerified: false })

    const young = explanation.fired.find((v) => v.rule === 'young-spender')
    expect(young?.evidence['ageDays']).toBeCloseTo(1, 1)
    expect(young?.reason).toContain('deployed')

    expect(explanation.fired.find((v) => v.rule === 'denylisted')?.evidence).toEqual({
      denylistSize: 1,
    })
  })

  it('reports the rules that stayed quiet too, and calls a benign spender benign', async () => {
    chainMocks.readAllowance.mockResolvedValue(250_000_000n)

    const explanation = await mcp.explainExposure(makeCtx(), TOKEN, SPENDER)

    expect(explanation.threat).toBe(false)
    expect(explanation.fired).toEqual([])
    // A rule that did not fire is part of the answer — "we checked three things
    // and none of them tripped" is a different statement from "no threat found".
    expect(explanation.all.map((v) => v.rule).sort()).toEqual([
      'denylisted',
      'unlimited-to-unverified',
      'young-spender',
    ])
    expect(explanation.all.every((v) => typeof v.reason === 'string')).toBe(true)
  })

  it('carries the rule catalogue so the reader does not need the source open', async () => {
    const explanation = await mcp.explainExposure(makeCtx(), TOKEN, SPENDER)

    expect(explanation.catalogue.map((r) => r.id).sort()).toEqual([
      'denylisted',
      'unlimited-to-unverified',
      'young-spender',
    ])
    expect(explanation.catalogue.every((r) => r.description.length > 0)).toBe(true)
  })

  it('answers for a pair that never appears in the approval logs', async () => {
    // Checking a spender before granting it anything is the useful case, and it
    // must not depend on log discovery having found the pair first.
    const other = '0x2222222222222222222222222222222222222222' as Address

    const explanation = await mcp.explainExposure(makeCtx(), TOKEN, other)

    expect(explanation.spender).toBe(other)
    expect(explanation.owner).toBe(OWNER)
    expect(explanation.blockNumber).toBe(HEAD.toString())
    expect(chainMocks.fetchApprovals).not.toHaveBeenCalled()
  })

  it('is a pure read: nothing is revoked', async () => {
    await mcp.explainExposure(makeCtx(), TOKEN, SPENDER)

    expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
  })
})

describe('simulate_revoke — KeeperHub simulate() on a real path', () => {
  it('dry-runs the exact call the live revoke would send', async () => {
    const kh = makeKh()

    const report = await mcp.simulateRevoke(makeCtx({ kh: kh as unknown as KeeperHub }), TOKEN, SPENDER)

    expect(kh.simulate).toHaveBeenCalledWith({
      contractAddress: TOKEN,
      functionName: 'approve',
      functionArgs: [SPENDER, '0'],
      abi: expect.arrayContaining([expect.objectContaining({ name: 'approve' })]),
    })
    expect(report).toMatchObject({
      status: 'simulated',
      wouldRevert: false,
      gasEstimate: '46021',
      token: TOKEN,
      spender: SPENDER,
      broadcast: false,
    })
  })

  it('surfaces a revert prediction instead of hiding it behind success', async () => {
    const kh = makeKh({
      simulate: vi.fn().mockResolvedValue({
        success: false,
        status: 'simulated',
        from: OWNER,
        to: TOKEN,
        value: '0',
        gasEstimate: '0',
        simulatedReturnValue: null,
        wouldRevert: true,
      }),
    })

    const report = await mcp.simulateRevoke(makeCtx({ kh: kh as unknown as KeeperHub }), TOKEN, SPENDER)

    expect(report.wouldRevert).toBe(true)
    expect(report.broadcast).toBe(false)
  })

  it('executes nothing: no write is submitted and no execution is polled', async () => {
    const checkAndExecute = vi.fn()
    const writeContract = vi.fn()
    const kh = makeKh({ checkAndExecute, writeContract })

    await mcp.simulateRevoke(makeCtx({ kh: kh as unknown as KeeperHub }), TOKEN, SPENDER)

    // The whole promise of a dry run: the two methods that can move chain state
    // are never reached, and neither is the revoke path itself.
    expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
    expect(checkAndExecute).not.toHaveBeenCalled()
    expect(writeContract).not.toHaveBeenCalled()
  })
})

describe('revoke_approval — the confirmation gate', () => {
  it('REFUSES when confirm is omitted, and submits nothing', async () => {
    const decision = await mcp.revokeExposure(makeCtx(), TOKEN, SPENDER, undefined)

    expect(decision.authorised).toBe(false)
    expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
  })

  it('REFUSES an explicit confirm: false rather than treating it as "not specified"', async () => {
    const decision = await mcp.revokeExposure(makeCtx(), TOKEN, SPENDER, false)

    expect(decision.authorised).toBe(false)
    expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
  })

  it('tells the caller exactly what is missing, so the model can go and get it', async () => {
    const decision = await mcp.revokeExposure(makeCtx(), TOKEN, SPENDER, undefined)

    expect(decision.authorised === false && decision.reason).toContain('confirm: true')
    expect(decision.authorised === false && decision.reason).toMatch(/human/i)
  })

  it('executes on confirm: true, through the same revoke path the loop uses', async () => {
    const ctx = makeCtx()

    const decision = await mcp.revokeExposure(ctx, TOKEN, SPENDER, true)

    expect(decision.authorised).toBe(true)
    expect(decision.authorised === true && decision.outcome.executed).toBe(true)
    expect(revokeMock.revokeApproval).toHaveBeenCalledTimes(1)

    const call = revokeMock.revokeApproval.mock.calls[0]?.[0] as {
      owner: Address
      kh: unknown
      idempotencyKey?: string
    }
    expect(call.owner).toBe(OWNER)
    expect(call.kh).toBe(ctx.kh)
    // Prefixed so the audit trail records which surface asked, and keyed so a
    // retried tool call cannot double-execute.
    expect(call.idempotencyKey).toMatch(/^mcp-revoke-0x[0-9a-f]{40}:0x[0-9a-f]{40}-\d+$/)
  })
})

describe('the MCP server itself, over an in-memory transport', () => {
  async function connect(ctx = makeCtx()) {
    const server = mcp.createMcpServer(ctx)
    const client = new Client({ name: 'test-investigator', version: '0.0.0' })
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
    return { client, server }
  }

  /** The text block of a tool result. Typed loosely: callTool's result union
   *  includes a legacy shape that carries no `content` at all. */
  function textOf(result: unknown): string {
    const { content } = result as { content?: Array<{ type: string; text: string }> }
    return content?.[0]?.text ?? ''
  }

  it('advertises exactly the four tools, and marks only one of them destructive', async () => {
    const { client, server } = await connect()

    const { tools } = await client.listTools()
    expect(tools.map((t) => t.name).sort()).toEqual([
      'explain_exposure',
      'list_exposures',
      'revoke_approval',
      'simulate_revoke',
    ])

    const reads = tools.filter((t) => t.name !== 'revoke_approval')
    expect(reads.every((t) => t.annotations?.readOnlyHint === true)).toBe(true)

    const write = tools.find((t) => t.name === 'revoke_approval')
    expect(write?.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true })
    // A model reading the description must not be able to miss what this does.
    expect(write?.description).toMatch(/DANGEROUS/)
    expect(write?.description).toMatch(/confirm/)

    await server.close()
  })

  it('answers list_exposures with the live exposure', async () => {
    const { client, server } = await connect()

    const result = await client.callTool({ name: 'list_exposures', arguments: {} })
    expect(JSON.parse(textOf(result))).toEqual([
      expect.objectContaining({ token: TOKEN, spender: SPENDER, unlimited: true }),
    ])

    await server.close()
  })

  it('answers explain_exposure with the fired rules', async () => {
    const { client, server } = await connect(makeCtx({ denylist: new Set([SPENDER.toLowerCase()]) }))

    const result = await client.callTool({
      name: 'explain_exposure',
      arguments: { token: TOKEN, spender: SPENDER },
    })
    const explanation = JSON.parse(textOf(result)) as { threat: boolean; fired: Array<{ rule: string }> }

    expect(explanation.threat).toBe(true)
    expect(explanation.fired.map((v) => v.rule)).toContain('denylisted')

    await server.close()
  })

  it('answers simulate_revoke without broadcasting', async () => {
    const { client, server } = await connect()

    const result = await client.callTool({
      name: 'simulate_revoke',
      arguments: { token: TOKEN, spender: SPENDER },
    })

    expect(JSON.parse(textOf(result))).toMatchObject({ status: 'simulated', broadcast: false })
    expect(revokeMock.revokeApproval).not.toHaveBeenCalled()

    await server.close()
  })

  it('REFUSES revoke_approval called without confirm, as a tool error', async () => {
    const { client, server } = await connect()

    const result = await client.callTool({
      name: 'revoke_approval',
      arguments: { token: TOKEN, spender: SPENDER },
    })

    expect(result.isError).toBe(true)
    expect(JSON.parse(textOf(result))).toMatchObject({ refused: true })
    expect(revokeMock.revokeApproval).not.toHaveBeenCalled()

    await server.close()
  })

  it('executes revoke_approval on confirm: true and reports the outcome as JSON', async () => {
    const { client, server } = await connect()

    const result = await client.callTool({
      name: 'revoke_approval',
      arguments: { token: TOKEN, spender: SPENDER, confirm: true },
    })

    expect(result.isError).toBeFalsy()
    // allowanceAfter comes back from revoke.ts as a bigint; JSON has none, and an
    // unserialisable field would throw mid-response instead of answering.
    expect(JSON.parse(textOf(result))).toMatchObject({
      executed: true,
      allowanceAfter: '0',
      transactionHash: '0xabc',
    })
    expect(revokeMock.revokeApproval).toHaveBeenCalledTimes(1)

    await server.close()
  })

  it('rejects a malformed address before any chain call is made', async () => {
    const { client, server } = await connect()

    const result = await client.callTool({
      name: 'explain_exposure',
      arguments: { token: 'not-an-address', spender: SPENDER },
    })

    expect(result.isError).toBe(true)
    expect(chainMocks.readAllowance).not.toHaveBeenCalled()

    await server.close()
  })
})

describe('the stdio entrypoint', () => {
  it('connects over stdio on start, and keeps stdout clear for the protocol', async () => {
    vi.resetModules()

    await import('../src/mcp.js')
    await flushMicrotasks()

    expect(stdioState.started).toHaveBeenCalledTimes(1)
    // stdout is the JSON-RPC channel; the banner has to go to stderr or it
    // corrupts the very first message.
    expect(consoleError).toHaveBeenCalledWith(expect.stringContaining('revoker mcp v9.9.9'))
    expect(process.exitCode).toBeUndefined()
  })

  it('exits non-zero when the transport cannot be brought up', async () => {
    stdioState.failWith = new Error('stdin is closed')
    vi.resetModules()

    await import('../src/mcp.js')
    await flushMicrotasks()

    expect(consoleError).toHaveBeenCalledWith('fatal: stdin is closed')
    expect(process.exitCode).toBe(1)
  })

  it('stringifies a non-Error failure instead of logging "undefined"', async () => {
    // Rejections out of a transport stack are not always Errors. Deliberately
    // mistyped here, because a bare string is exactly the case that used to land
    // in a log as "undefined" and erase why the process died.
    stdioState.failWith = 'stdio went away, but nobody threw an Error' as unknown as Error
    vi.resetModules()

    await import('../src/mcp.js')
    await flushMicrotasks()

    expect(consoleError).toHaveBeenCalledWith(
      'fatal: stdio went away, but nobody threw an Error',
    )
    expect(process.exitCode).toBe(1)
  })
})
