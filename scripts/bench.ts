/**
 * Detect→revoke benchmark.
 *
 *   pnpm bench              N=25 (the reported figure)
 *   pnpm bench -- --n=5     shorter run
 *
 * Answers the only question that matters about a security agent: when the
 * approval turns dangerous, how long is the money actually exposed?
 *
 * Two distinct numbers are reported, because conflating them would flatter the
 * result:
 *
 *   responseMs  detection → revoke confirmed on-chain.
 *               The agent's own speed. This is what the implementation controls.
 *
 *   exposureMs  threat live on-chain → revoke confirmed on-chain.
 *               What a user actually experiences. Strictly larger.
 *
 * HONEST CAVEAT, restated in the output and in DEMO.md: the benchmark triggers
 * a scan immediately rather than waiting for the poll timer, so neither figure
 * includes polling delay. In production, expected exposure adds an average of
 * pollIntervalMs/2 on top. We measure what the agent does, and state what the
 * measurement leaves out.
 */
import { writeFileSync } from 'node:fs'
import type { Address } from 'viem'
import { config } from '../src/config.js'
import { KeeperHub } from '../src/keeperhub.js'
import { MAX_UINT256, publicClient, readAllowance } from '../src/chain.js'
import { revokeApproval } from '../src/revoke.js'
import { assess } from '../src/rules.js'
import { readFileSync } from 'node:fs'

const APPROVE_ABI = [
  {
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'value', type: 'uint256' },
    ],
    name: 'approve',
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
]

interface Cycle {
  n: number
  responseMs: number
  exposureMs: number
  gasUsedWei: number
  sponsored: boolean
  txHash: string
}

/**
 * Nearest-rank percentile. No interpolation — every reported value is one actually observed.
 *
 * Exported for the test suite only. The empty-array guards below are unreachable
 * through main() — `cycles.length === 0` throws before summarize() is ever
 * called — so the statistics that every headline number in BENCHMARK.md rests on
 * could not otherwise be tested directly.
 */
export function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return Number.NaN
  const rank = Math.ceil((p / 100) * sorted.length)
  return sorted[Math.min(Math.max(rank, 1), sorted.length) - 1]!
}

/** Exported for the test suite only — see percentile(). */
export function summarize(values: number[]): {
  p50: number
  p95: number
  min: number
  max: number
  mean: number
} {
  const sorted = [...values].sort((a, b) => a - b)
  return {
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    min: sorted[0] ?? Number.NaN,
    max: sorted.at(-1) ?? Number.NaN,
    mean: values.reduce((a, b) => a + b, 0) / values.length,
  }
}

function loadFixtures(): { token: Address; spender: Address } {
  const raw = readFileSync(new URL('../deployments.json', import.meta.url), 'utf8')
  const parsed = JSON.parse(raw) as {
    sepolia: { contracts: Record<string, { address: string }> }
  }
  const token = parsed.sepolia.contracts['MockUSDC']?.address
  const spender = parsed.sepolia.contracts['RoachMotelSpender']?.address
  if (!token || !spender) throw new Error('deployments.json is missing fixtures — run `pnpm seed`')
  return { token: token as Address, spender: spender as Address }
}

async function armThreat(kh: KeeperHub, token: Address, spender: Address): Promise<number> {
  const result = await kh.writeContract({
    contractAddress: token,
    functionName: 'approve',
    functionArgs: [spender, MAX_UINT256.toString()],
    abi: APPROVE_ABI,
  })
  // The approval is live from the moment its transaction is mined. Poll the
  // chain rather than trusting a timestamp from the API.
  const armedAt = Date.now()
  for (let i = 0; i < 60; i += 1) {
    if ((await readAllowance(token, config.walletAddress, spender)) === MAX_UINT256) return armedAt
    await new Promise((r) => setTimeout(r, 500))
  }
  throw new Error(`approval did not become live (execution ${result.executionId})`)
}

async function main(): Promise<void> {
  const nArg = process.argv.find((a) => a.startsWith('--n='))
  const N = nArg ? Number(nArg.slice(4)) : 25
  if (!Number.isInteger(N) || N < 1) throw new Error(`invalid --n=${nArg}`)

  const kh = new KeeperHub()
  const { token, spender } = loadFixtures()
  const owner = config.walletAddress
  const denylist = new Set([spender.toLowerCase()])

  console.log(`Revoker benchmark — N=${N} full detect→revoke cycles`)
  console.log(`  token   ${token}`)
  console.log(`  spender ${spender}`)
  console.log(`  owner   ${owner}`)
  console.log()

  const cycles: Cycle[] = []
  const failures: string[] = []

  for (let n = 1; n <= N; n += 1) {
    process.stdout.write(`  cycle ${String(n).padStart(2)}/${N} … `)
    try {
      const threatLiveAt = await armThreat(kh, token, spender)

      // Detection: evaluate the rules against live chain state, exactly as the
      // watcher does. Timed, because rule evaluation is part of response time.
      const detectedAt = Date.now()
      const currentBlock = await publicClient.getBlockNumber()
      const allowance = await readAllowance(token, owner, spender)
      const assessment = await assess({
        token, spender, owner, allowance, balance: 0n, currentBlock, kh, denylist,
      })
      if (!assessment.threat) throw new Error('rules did not flag the armed threat')

      const outcome = await revokeApproval({ kh, token, owner, spender, detectedAt })
      if (!outcome.executed || outcome.allowanceAfter !== 0n) {
        throw new Error(outcome.error ?? 'revoke did not zero the allowance')
      }

      const confirmedAt = Date.now()
      const cycle: Cycle = {
        n,
        responseMs: outcome.latencyMs,
        exposureMs: confirmedAt - threatLiveAt,
        gasUsedWei: Number(outcome.gasUsedWei ?? 0),
        sponsored: outcome.sponsored ?? false,
        txHash: outcome.transactionHash ?? '',
      }
      cycles.push(cycle)
      console.log(`response ${(cycle.responseMs / 1000).toFixed(2)}s  exposure ${(cycle.exposureMs / 1000).toFixed(2)}s`)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      failures.push(`cycle ${n}: ${message}`)
      console.log(`FAILED — ${message}`)
    }
  }

  if (cycles.length === 0) throw new Error('every cycle failed; no results to report')

  const response = summarize(cycles.map((c) => c.responseMs))
  const exposure = summarize(cycles.map((c) => c.exposureMs))
  const gas = summarize(cycles.map((c) => c.gasUsedWei))
  const sponsoredCount = cycles.filter((c) => c.sponsored).length

  const fmt = (ms: number): string => `${(ms / 1000).toFixed(2)}s`

  console.log()
  console.log(`  ${cycles.length}/${N} cycles succeeded${failures.length ? `, ${failures.length} failed` : ''}`)
  console.log()
  console.log('  metric      p50      p95      min      max')
  console.log(`  response  ${fmt(response.p50).padStart(7)}  ${fmt(response.p95).padStart(7)}  ${fmt(response.min).padStart(7)}  ${fmt(response.max).padStart(7)}`)
  console.log(`  exposure  ${fmt(exposure.p50).padStart(7)}  ${fmt(exposure.p95).padStart(7)}  ${fmt(exposure.min).padStart(7)}  ${fmt(exposure.max).padStart(7)}`)
  console.log()
  console.log(`  gas per revoke   p50 ${Math.round(gas.p50)}  p95 ${Math.round(gas.p95)}`)
  console.log(`  gas sponsored    ${sponsoredCount}/${cycles.length} cycles`)
  console.log()
  for (const failure of failures) console.log(`  ! ${failure}`)

  const stamp = new Date().toISOString()
  const md = `# Benchmark — detect→revoke

> Generated by \`pnpm bench\` on ${stamp}. Network: Ethereum Sepolia (11155111).
> ${cycles.length}/${N} cycles succeeded${failures.length ? `, ${failures.length} failed` : ''}.

## What was measured

Each cycle arms a real unlimited approval on-chain, waits for it to be live,
evaluates the threat rules against live chain state, and revokes through
KeeperHub's \`check-and-execute\` — then confirms the allowance is zero by
reading the chain, not by trusting the execution report.

| Metric | Meaning |
|---|---|
| \`response\` | detection → revoke confirmed on-chain. The agent's own speed. |
| \`exposure\` | threat live on-chain → revoke confirmed. What a user experiences. |

## Results

| Metric | p50 | p95 | min | max |
|---|---|---|---|---|
| response | ${fmt(response.p50)} | ${fmt(response.p95)} | ${fmt(response.min)} | ${fmt(response.max)} |
| exposure | ${fmt(exposure.p50)} | ${fmt(exposure.p95)} | ${fmt(exposure.min)} | ${fmt(exposure.max)} |

Gas per revoke: p50 **${Math.round(gas.p50)}**, p95 **${Math.round(gas.p95)}**.
Sponsored by KeeperHub in ${sponsoredCount}/${cycles.length} cycles.

## What this number does NOT include

The benchmark triggers detection immediately instead of waiting for the poll
timer, so neither figure includes polling delay. A deployment polling every
\`pollIntervalMs\` adds an average of \`pollIntervalMs/2\` to real exposure. At the
default 5s poll that is ~2.5s on top of the figures above.

Latency is also dominated by block inclusion, which varies with network
conditions outside our control — hence p50/p95 over ${cycles.length} cycles
rather than a single headline number.

## Reproduce

\`\`\`bash
pnpm install
cd contracts && forge build && cd ..
pnpm seed
pnpm bench${nArg ? ` -- ${nArg}` : ''}
\`\`\`

Requires \`KH_API_KEY\`, \`KH_WALLET_ADDRESS\` and a funded Turnkey wallet. See README.

## Every cycle

| # | response | exposure | gas | tx |
|---|---|---|---|---|
${cycles.map((c) => `| ${c.n} | ${fmt(c.responseMs)} | ${fmt(c.exposureMs)} | ${c.gasUsedWei} | [\`${c.txHash.slice(0, 10)}…\`](https://sepolia.etherscan.io/tx/${c.txHash}) |`).join('\n')}
${failures.length ? `\n### Failures\n\n${failures.map((f) => `- ${f}`).join('\n')}\n` : ''}`

  writeFileSync(new URL('../BENCHMARK.md', import.meta.url), md)
  console.log('  results written to BENCHMARK.md')
}

main().catch((error: unknown) => {
  console.error(`\n❌ Benchmark failed: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
