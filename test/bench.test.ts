import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import type { Address } from 'viem'
import type { RevokeOutcome } from '../src/revoke.js'

/**
 * scripts/bench.ts calls `main().catch(...)` at module top level: importing it
 * for real drives 25 live detect→revoke cycles against Sepolia through
 * KeeperHub. Every external edge is mocked — node:fs (deployments.json in,
 * BENCHMARK.md out), config/keeperhub/chain/revoke/rules — and Date.now is
 * driven by a hand-wound clock so the reported p50/p95 are exact, known
 * arithmetic rather than whatever the wall clock happened to do.
 *
 * The clock advances ONLY inside the revokeApproval mock, which is precisely
 * the window bench.ts measures as exposure (threat live → revoke confirmed).
 * responseMs comes straight from the outcome's latencyMs. That lets a test
 * state both figures up front and assert the summary is arithmetically right —
 * a benchmark that reports the wrong percentile is worse than no benchmark.
 */

const OWNER = '0x5E2e5Fd3aD7fDC9B94482930db8b5F45E439bab7' as Address
const TOKEN = '0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb'
const SPENDER = '0x8eBf8540EdE8e40CD94825C418758d4029D8892e'
const MAX_UINT256 = (1n << 256n) - 1n

interface FsState {
  deployments: string
  /** Set to make readFileSync throw — `unknown` so a non-Error can be thrown too. */
  readError: unknown
  writes: { path: string; data: string }[]
}
const fsState = vi.hoisted((): FsState => ({ deployments: '', readError: undefined, writes: [] }))
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  return {
    ...actual,
    readFileSync: (path: Parameters<typeof actual.readFileSync>[0], enc?: BufferEncoding) => {
      if (String(path).includes('deployments.json')) {
        if (fsState.readError !== undefined) {
          // Re-widened to `unknown` deliberately: the point of the fixture is
          // that a failing read need not reject with an Error at all.
          const thrown: unknown = fsState.readError
          throw thrown
        }
        return fsState.deployments
      }
      return actual.readFileSync(path, enc)
    },
    // Capturing spy, never a real write: the repo's BENCHMARK.md is a committed
    // artifact and a test run must not touch it.
    writeFileSync: (path: Parameters<typeof actual.writeFileSync>[0], data: string) => {
      fsState.writes.push({ path: String(path), data })
    },
  }
})

const configMock = { walletAddress: OWNER, network: 'sepolia', chainId: 11155111 }
vi.mock('../src/config.js', () => ({ config: configMock }))

const khMock = vi.hoisted(() => {
  const writeContract = vi.fn()
  class KeeperHub {
    writeContract = writeContract
  }
  return { KeeperHub, writeContract }
})
vi.mock('../src/keeperhub.js', () => ({ KeeperHub: khMock.KeeperHub }))

const chainMock = vi.hoisted(() => ({ readAllowance: vi.fn(), getBlockNumber: vi.fn() }))
vi.mock('../src/chain.js', () => ({
  MAX_UINT256: (1n << 256n) - 1n,
  publicClient: { getBlockNumber: chainMock.getBlockNumber },
  readAllowance: chainMock.readAllowance,
}))

const revokeMock = vi.hoisted(() => ({ revokeApproval: vi.fn() }))
vi.mock('../src/revoke.js', () => ({ revokeApproval: revokeMock.revokeApproval }))

const rulesMock = vi.hoisted(() => ({ assess: vi.fn() }))
vi.mock('../src/rules.js', () => ({ assess: rulesMock.assess }))

const DEPLOYMENTS = {
  sepolia: {
    chainId: 11155111,
    contracts: {
      MockUSDC: { address: TOKEN },
      RoachMotelSpender: { address: SPENDER },
    },
  },
}

/** Hand-wound wall clock. Only the revokeApproval mock moves it. */
const clock = { ms: 1_700_000_000_000 }

let originalArgv: string[]

/**
 * Every mocked await resolves as a microtask, so a single real macrotask turn
 * is enough for main() to run to completion — including the results write.
 */
async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0))
}

function logged(): string {
  return vi
    .mocked(console.log)
    .mock.calls.map((call) => call.map((arg) => String(arg)).join(' '))
    .join('\n')
}

function fatal(): string {
  return vi
    .mocked(console.error)
    .mock.calls.map((call) => call.map((arg) => String(arg)).join(' '))
    .join('\n')
}

function report(): string {
  return fsState.writes[0]?.data ?? ''
}

interface CycleTiming {
  /** outcome.latencyMs — detection → revoke confirmed. */
  responseMs: number
  /** Clock advance inside revokeApproval — threat live → revoke confirmed. */
  exposureMs: number
  gasUsedWei?: string
  sponsored?: boolean
}

/** Queues one successful revoke outcome per cycle, in order. */
function queueCycles(timings: CycleTiming[]): void {
  for (const timing of timings) {
    revokeMock.revokeApproval.mockImplementationOnce(() => {
      clock.ms += timing.exposureMs
      const outcome: RevokeOutcome = {
        executed: true,
        latencyMs: timing.responseMs,
        allowanceAfter: 0n,
        transactionHash: '0xdeadbeefcafe',
        sponsored: timing.sponsored ?? true,
        gasUsedWei: timing.gasUsedWei ?? '46482',
      }
      return Promise.resolve(outcome)
    })
  }
}

beforeEach(() => {
  vi.resetModules()

  fsState.deployments = JSON.stringify(DEPLOYMENTS)
  fsState.readError = undefined
  fsState.writes.length = 0

  clock.ms = 1_700_000_000_000

  khMock.writeContract.mockReset().mockResolvedValue({ executionId: 'exec-1', status: 'pending' })
  chainMock.readAllowance.mockReset().mockResolvedValue(MAX_UINT256)
  chainMock.getBlockNumber.mockReset().mockResolvedValue(11_440_000n)
  rulesMock.assess.mockReset().mockResolvedValue({ threat: true, fired: [], all: [] })
  revokeMock.revokeApproval.mockReset().mockImplementation(() => {
    clock.ms += 2_500
    const outcome: RevokeOutcome = {
      executed: true,
      latencyMs: 1_000,
      allowanceAfter: 0n,
      transactionHash: '0xdeadbeefcafe',
      sponsored: true,
      gasUsedWei: '46482',
    }
    return Promise.resolve(outcome)
  })

  originalArgv = process.argv
  process.argv = ['node', 'bench.ts']
  process.exitCode = undefined
  vi.spyOn(Date, 'now').mockImplementation(() => clock.ms)
  vi.spyOn(console, 'log').mockImplementation(() => undefined)
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
})

afterEach(() => {
  vi.useRealTimers()
  process.argv = originalArgv
  process.exitCode = undefined
  vi.restoreAllMocks()
})

describe('bench.ts — reported statistics', () => {
  it('reports nearest-rank p50/p95 for a known set of cycle timings', async () => {
    // Five cycles, deliberately out of order. Sorted responses are
    // [1000, 2000, 3000, 4000, 5000]: nearest rank puts p50 at ceil(0.50*5)=3
    // → 3000ms, and p95 at ceil(0.95*5)=5 → 5000ms. Every exposure is its
    // response plus 1500ms, so sorted exposures are
    // [2500, 3500, 4500, 5500, 6500] → p50 4500ms, p95 6500ms.
    process.argv = ['node', 'bench.ts', '--n=5']
    queueCycles([
      { responseMs: 1_000, exposureMs: 2_500 },
      { responseMs: 5_000, exposureMs: 6_500 },
      { responseMs: 2_000, exposureMs: 3_500 },
      { responseMs: 4_000, exposureMs: 5_500 },
      { responseMs: 3_000, exposureMs: 4_500 },
    ])

    await import('../scripts/bench.js')
    await settle()

    expect(logged()).toContain('  response    3.00s    5.00s    1.00s    5.00s')
    expect(logged()).toContain('  exposure    4.50s    6.50s    2.50s    6.50s')
    expect(report()).toContain('| response | 3.00s | 5.00s | 1.00s | 5.00s |')
    expect(report()).toContain('| exposure | 4.50s | 6.50s | 2.50s | 6.50s |')
  })

  it('reports an exposure strictly larger than the response in every cycle', async () => {
    // The docblock promises two distinct numbers and that exposure is the
    // larger one; conflating them would flatter the result. Each cycle here
    // spends 1500ms live on-chain before detection even starts.
    process.argv = ['node', 'bench.ts', '--n=3']
    queueCycles([
      { responseMs: 1_000, exposureMs: 2_500 },
      { responseMs: 2_000, exposureMs: 3_500 },
      { responseMs: 3_000, exposureMs: 4_500 },
    ])

    await import('../scripts/bench.js')
    await settle()

    expect(report()).toContain('| 1 | 1.00s | 2.50s |')
    expect(report()).toContain('| 2 | 2.00s | 3.50s |')
    expect(report()).toContain('| 3 | 3.00s | 4.50s |')
    // …and the same ordering must survive into the headline figures.
    expect(report()).toContain('| response | 2.00s | 3.00s | 1.00s | 3.00s |')
    expect(report()).toContain('| exposure | 3.50s | 4.50s | 2.50s | 4.50s |')
  })

  it('reports the p50/p95 of a single cycle as that cycle itself', async () => {
    // Nearest rank with N=1: ceil(0.50*1) and ceil(0.95*1) both land on rank 1,
    // so both percentiles are the one observation — never an interpolation.
    process.argv = ['node', 'bench.ts', '--n=1']
    queueCycles([{ responseMs: 1_234, exposureMs: 4_321 }])

    await import('../scripts/bench.js')
    await settle()

    expect(report()).toContain('| response | 1.23s | 1.23s | 1.23s | 1.23s |')
    expect(report()).toContain('| exposure | 4.32s | 4.32s | 4.32s | 4.32s |')
  })

  it('summarises gas the same way and counts the sponsored cycles', async () => {
    // Sorted gas is [40000, 45000, 50000, 55000, 60000] → p50 50000, p95 60000.
    process.argv = ['node', 'bench.ts', '--n=5']
    queueCycles([
      { responseMs: 1_000, exposureMs: 2_500, gasUsedWei: '40000', sponsored: true },
      { responseMs: 1_000, exposureMs: 2_500, gasUsedWei: '60000', sponsored: true },
      { responseMs: 1_000, exposureMs: 2_500, gasUsedWei: '45000', sponsored: false },
      { responseMs: 1_000, exposureMs: 2_500, gasUsedWei: '55000', sponsored: true },
      { responseMs: 1_000, exposureMs: 2_500, gasUsedWei: '50000', sponsored: false },
    ])

    await import('../scripts/bench.js')
    await settle()

    expect(logged()).toContain('  gas per revoke   p50 50000  p95 60000')
    expect(logged()).toContain('  gas sponsored    3/5 cycles')
    expect(report()).toContain('Gas per revoke: p50 **50000**, p95 **60000**.')
    expect(report()).toContain('Sponsored by KeeperHub in 3/5 cycles.')
  })
})

describe('bench.ts — cycle count', () => {
  it('runs 25 cycles by default and prints a plain reproduce command', async () => {
    await import('../scripts/bench.js')
    await settle()

    expect(logged()).toContain('Revoker benchmark — N=25 full detect→revoke cycles')
    expect(revokeMock.revokeApproval).toHaveBeenCalledTimes(25)
    expect(logged()).toContain('  25/25 cycles succeeded')
    expect(report()).toContain('pnpm bench\n')
    expect(report()).not.toContain('pnpm bench --')
  })

  it('--n= overrides the cycle count and is echoed into the reproduce steps', async () => {
    process.argv = ['node', 'bench.ts', '--n=3']

    await import('../scripts/bench.js')
    await settle()

    expect(revokeMock.revokeApproval).toHaveBeenCalledTimes(3)
    expect(logged()).toContain('Revoker benchmark — N=3 full detect→revoke cycles')
    // Whoever reads BENCHMARK.md must be able to reproduce THIS run, not the
    // default one — a 3-cycle result reproduced as 25 cycles is a different
    // measurement wearing the same numbers.
    expect(report()).toContain('pnpm bench -- --n=3')
  })

  it('refuses a non-numeric --n= rather than benchmarking NaN cycles', async () => {
    process.argv = ['node', 'bench.ts', '--n=lots']

    await import('../scripts/bench.js')
    await settle()

    expect(fatal()).toContain('Benchmark failed: invalid --n=--n=lots')
    expect(revokeMock.revokeApproval).not.toHaveBeenCalled()
    expect(fsState.writes).toHaveLength(0)
    expect(process.exitCode).toBe(1)
  })

  it('refuses --n=0, which would report percentiles over nothing', async () => {
    process.argv = ['node', 'bench.ts', '--n=0']

    await import('../scripts/bench.js')
    await settle()

    expect(fatal()).toContain('Benchmark failed: invalid --n=--n=0')
    expect(process.exitCode).toBe(1)
  })
})

describe('bench.ts — fixtures', () => {
  it('reads the token and spender out of deployments.json', async () => {
    process.argv = ['node', 'bench.ts', '--n=1']

    await import('../scripts/bench.js')
    await settle()

    expect(logged()).toContain(`  token   ${TOKEN}`)
    expect(logged()).toContain(`  spender ${SPENDER}`)
    expect(logged()).toContain(`  owner   ${OWNER}`)
  })

  it('stops when deployments.json carries no token fixture', async () => {
    fsState.deployments = JSON.stringify({
      sepolia: { contracts: { RoachMotelSpender: { address: SPENDER } } },
    })

    await import('../scripts/bench.js')
    await settle()

    expect(fatal()).toContain('deployments.json is missing fixtures — run `pnpm seed`')
    expect(process.exitCode).toBe(1)
  })

  it('stops when deployments.json carries no spender fixture', async () => {
    fsState.deployments = JSON.stringify({
      sepolia: { contracts: { MockUSDC: { address: TOKEN } } },
    })

    await import('../scripts/bench.js')
    await settle()

    expect(fatal()).toContain('deployments.json is missing fixtures — run `pnpm seed`')
    expect(process.exitCode).toBe(1)
  })

  it('stringifies a non-Error failure from the fixture read', async () => {
    fsState.readError = 'EACCES, but nobody threw an Error'

    await import('../scripts/bench.js')
    await settle()

    expect(fatal()).toContain('Benchmark failed: EACCES, but nobody threw an Error')
    expect(process.exitCode).toBe(1)
  })
})

describe('bench.ts — arming the threat', () => {
  it('starts the exposure clock only once the approval is live on-chain', async () => {
    // The approval is not live when writeContract returns — it is live when it
    // is mined. The loop polls the chain rather than trusting the API, so the
    // second poll is the one that starts the measurement.
    process.argv = ['node', 'bench.ts', '--n=1']
    chainMock.readAllowance.mockReset()
    chainMock.readAllowance.mockResolvedValueOnce(0n).mockResolvedValue(MAX_UINT256)
    queueCycles([{ responseMs: 1_000, exposureMs: 2_500 }])
    vi.useFakeTimers({ toFake: ['setTimeout'] })

    await import('../scripts/bench.js')
    await vi.advanceTimersByTimeAsync(500)
    vi.useRealTimers()
    await settle()

    expect(khMock.writeContract).toHaveBeenCalledTimes(1)
    expect(logged()).toContain('  1/1 cycles succeeded')
    // Exposure covers only the confirmed-live window, not the poll that
    // preceded it — the clock is untouched by the retry.
    expect(report()).toContain('| 1 | 1.00s | 2.50s |')
  })

  it('fails the cycle when the approval never becomes live', async () => {
    process.argv = ['node', 'bench.ts', '--n=1']
    chainMock.readAllowance.mockReset().mockResolvedValue(0n)
    vi.useFakeTimers({ toFake: ['setTimeout'] })

    await import('../scripts/bench.js')
    // 60 polls at 500ms, then the arming gives up rather than measuring a
    // cycle whose threat was never actually on-chain.
    await vi.advanceTimersByTimeAsync(60 * 500)
    vi.useRealTimers()
    await settle()

    expect(chainMock.readAllowance).toHaveBeenCalledTimes(60)
    expect(logged()).toContain('FAILED — approval did not become live (execution exec-1)')
    // No cycle survived, so there is nothing honest to report.
    expect(fatal()).toContain('every cycle failed; no results to report')
    expect(fsState.writes).toHaveLength(0)
    expect(process.exitCode).toBe(1)
  })
})

describe('bench.ts — failing cycles', () => {
  it('records a failure and keeps going when the rules miss the armed threat', async () => {
    process.argv = ['node', 'bench.ts', '--n=3']
    rulesMock.assess
      .mockResolvedValueOnce({ threat: true, fired: [], all: [] })
      .mockResolvedValueOnce({ threat: false, fired: [], all: [] })
      .mockResolvedValue({ threat: true, fired: [], all: [] })
    // Only two outcomes are queued: cycle 2 never reaches the revoke at all.
    queueCycles([
      { responseMs: 1_000, exposureMs: 2_500 },
      { responseMs: 3_000, exposureMs: 4_500 },
    ])

    await import('../scripts/bench.js')
    await settle()

    // The failed cycle contributes no timing at all — a benchmark that folded a
    // skipped cycle into the percentiles would report a fiction.
    expect(logged()).toContain('  2/3 cycles succeeded, 1 failed')
    expect(logged()).toContain('  ! cycle 2: rules did not flag the armed threat')
    expect(report()).toContain('### Failures')
    expect(report()).toContain('- cycle 2: rules did not flag the armed threat')
    expect(report()).toContain('| response | 1.00s | 3.00s | 1.00s | 3.00s |')
    expect(report()).not.toContain('| 2 |')
  })

  it('surfaces the revoke’s own error when the revoke does not execute', async () => {
    process.argv = ['node', 'bench.ts', '--n=1']
    revokeMock.revokeApproval.mockReset().mockResolvedValue({
      executed: false,
      latencyMs: 120,
      error: 'gateway timeout',
    } satisfies RevokeOutcome)

    await import('../scripts/bench.js')
    await settle()

    expect(logged()).toContain('FAILED — gateway timeout')
    expect(fatal()).toContain('every cycle failed; no results to report')
  })

  it('falls back to a generic message when a skipped revoke reports no error', async () => {
    process.argv = ['node', 'bench.ts', '--n=1']
    revokeMock.revokeApproval.mockReset().mockResolvedValue({
      executed: false,
      latencyMs: 120,
    } satisfies RevokeOutcome)

    await import('../scripts/bench.js')
    await settle()

    expect(logged()).toContain('FAILED — revoke did not zero the allowance')
  })

  it('fails the cycle when the revoke reports success but the allowance survives', async () => {
    // Reported success with a live allowance is the one outcome a security
    // benchmark must never count as a win.
    process.argv = ['node', 'bench.ts', '--n=1']
    revokeMock.revokeApproval.mockReset().mockResolvedValue({
      executed: true,
      latencyMs: 900,
      allowanceAfter: 500n,
    } satisfies RevokeOutcome)

    await import('../scripts/bench.js')
    await settle()

    expect(logged()).toContain('FAILED — revoke did not zero the allowance')
    expect(fsState.writes).toHaveLength(0)
  })

  it('stringifies a non-Error rejection from inside a cycle', async () => {
    process.argv = ['node', 'bench.ts', '--n=2']
    revokeMock.revokeApproval.mockReset()
    revokeMock.revokeApproval.mockRejectedValueOnce('KeeperHub on fire').mockImplementation(() => {
      clock.ms += 2_500
      const outcome: RevokeOutcome = { executed: true, latencyMs: 1_000, allowanceAfter: 0n }
      return Promise.resolve(outcome)
    })

    await import('../scripts/bench.js')
    await settle()

    expect(logged()).toContain('FAILED — KeeperHub on fire')
    expect(logged()).toContain('  1/2 cycles succeeded, 1 failed')
  })
})

describe('bench.ts — results file', () => {
  it('writes BENCHMARK.md next to the repo root, never through a real write', async () => {
    process.argv = ['node', 'bench.ts', '--n=1']

    await import('../scripts/bench.js')
    await settle()

    expect(fsState.writes).toHaveLength(1)
    expect(fsState.writes[0]?.path).toMatch(/BENCHMARK\.md$/)
    expect(logged()).toContain('  results written to BENCHMARK.md')
  })

  it('restates the polling caveat the headline figures leave out', async () => {
    // The number is only honest alongside what it excludes; DEMO.md and the
    // script docblock make the same promise.
    process.argv = ['node', 'bench.ts', '--n=1']

    await import('../scripts/bench.js')
    await settle()

    expect(report()).toContain('## What this number does NOT include')
    expect(report()).toContain('adds an average of `pollIntervalMs/2` to real exposure')
    expect(report()).toContain('Network: Ethereum Sepolia (11155111).')
    expect(report()).toContain('1/1 cycles succeeded.')
    expect(report()).not.toContain('### Failures')
  })

  it('links every cycle to its transaction hash', async () => {
    process.argv = ['node', 'bench.ts', '--n=1']
    queueCycles([{ responseMs: 1_000, exposureMs: 2_500 }])

    await import('../scripts/bench.js')
    await settle()

    expect(report()).toContain(
      '| 1 | 1.00s | 2.50s | 46482 | [`0xdeadbeef…`](https://sepolia.etherscan.io/tx/0xdeadbeefcafe) |',
    )
  })

  it('degrades to zeros rather than crashing when the outcome omits gas and hash', async () => {
    // sponsored/gasUsedWei/transactionHash are all optional on RevokeOutcome —
    // a cycle that confirms without them is still a valid measurement.
    process.argv = ['node', 'bench.ts', '--n=1']
    revokeMock.revokeApproval.mockReset().mockImplementation(() => {
      clock.ms += 2_500
      const outcome: RevokeOutcome = { executed: true, latencyMs: 1_000, allowanceAfter: 0n }
      return Promise.resolve(outcome)
    })

    await import('../scripts/bench.js')
    await settle()

    expect(logged()).toContain('  gas per revoke   p50 0  p95 0')
    expect(logged()).toContain('  gas sponsored    0/1 cycles')
    expect(report()).toContain('| 1 | 1.00s | 2.50s | 0 | [`…`](https://sepolia.etherscan.io/tx/) |')
  })
})

/**
 * The statistics helpers, exercised directly.
 *
 * main() throws on an empty run before summarize() is ever reached, so the
 * degenerate cases below are unreachable through the entry point — but they are
 * the guards standing between a lost result set and a BENCHMARK.md full of
 * confident zeroes, which is the one failure mode a benchmark must not have.
 */
describe('bench.ts — the statistics themselves', () => {
  it('reports NaN rather than a number nobody measured', async () => {
    const { percentile, summarize } = await import('../scripts/bench.js')
    await settle()

    expect(percentile([], 50)).toBeNaN()
    expect(percentile([], 95)).toBeNaN()

    const empty = summarize([])
    expect(empty.p50).toBeNaN()
    expect(empty.p95).toBeNaN()
    expect(empty.min).toBeNaN()
    expect(empty.max).toBeNaN()
    expect(empty.mean).toBeNaN()
  })

  it('takes the nearest rank, never an interpolated value', async () => {
    const { percentile } = await import('../scripts/bench.js')
    await settle()

    const sorted = [1_000, 2_000, 3_000, 4_000, 5_000]
    // ceil(0.50 * 5) = 3 → the 3rd observation, not the mean of the 2nd and 3rd.
    expect(percentile(sorted, 50)).toBe(3_000)
    // ceil(0.95 * 5) = 5 → the slowest observation.
    expect(percentile(sorted, 95)).toBe(5_000)
    // Clamped at both ends: p0 must not index -1, p100 must not run off the end.
    expect(percentile(sorted, 0)).toBe(1_000)
    expect(percentile(sorted, 100)).toBe(5_000)
    // Every reported figure is one that was actually observed.
    for (const p of [10, 25, 50, 75, 90, 95, 99]) {
      expect(sorted).toContain(percentile(sorted, p))
    }
  })

  it('summarizes without mutating the caller’s array', async () => {
    const { summarize } = await import('../scripts/bench.js')
    await settle()

    const values = [5_000, 1_000, 3_000]
    const stats = summarize(values)

    expect(stats).toEqual({ p50: 3_000, p95: 5_000, min: 1_000, max: 5_000, mean: 3_000 })
    // summarize sorts a copy — the cycle order in the per-cycle table depends on it.
    expect(values).toEqual([5_000, 1_000, 3_000])
  })
})
