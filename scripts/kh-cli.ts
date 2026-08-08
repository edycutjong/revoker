/**
 * Operator-side wrapper over the real KeeperHub CLI (`kh`).
 *
 * Revoker's *agent* has no business shelling out to a CLI — it runs unattended
 * and src/keeperhub.ts speaks the REST API directly. The *operator* is a
 * different user: arming the demo fixture is a human-at-a-terminal job, and the
 * command that human would type is `kh execute contract-call`. This module is
 * that command, and nothing in src/ imports it.
 *
 *   Install   brew install keeperhub/tap/kh
 *             go install github.com/keeperhub/cli/cmd/kh@latest
 *   Auth      KH_API_KEY — the same key .env already holds — or `kh auth login`
 *
 * Verified against kh 0.14.0 (darwin/arm64, go1.25.0).
 *
 * Every child process goes through one `run()`, so the process boundary is a
 * single seam the tests replace. spawnSync rather than an async spawn on
 * purpose: this runs in one-shot operator scripts where there is nothing else
 * to interleave with, and sync keeps the call sites readable.
 */
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/** Overridable so tests and unusual installs can point at a specific binary. */
const KH_BIN = process.env['KH_BIN'] ?? 'kh'

interface RunResult {
  code: number
  stdout: string
  stderr: string
}

function run(args: string[]): RunResult {
  const result = spawnSync(KH_BIN, args, { encoding: 'utf8' })
  // spawnSync reports "binary not on PATH" as .error rather than a exit code,
  // which is the case callers most need to distinguish — it is the difference
  // between "kh is missing" and "kh ran and said no".
  if (result.error) return { code: -1, stdout: '', stderr: result.error.message }
  return { code: result.status ?? -1, stdout: result.stdout ?? '', stderr: result.stderr ?? '' }
}

function runJson<T>(args: string[], label: string): T {
  const result = run([...args, '--json'])
  if (result.code !== 0) {
    // kh documents exit 2 as "not found or invalid argument" and 5 as rate
    // limited; surfacing the raw code keeps `kh exit-codes` useful to the
    // operator instead of flattening everything to "it failed".
    const detail = (result.stderr || result.stdout).trim()
    throw new Error(`kh ${label} failed (exit ${result.code}): ${detail}`)
  }
  try {
    return JSON.parse(result.stdout) as T
  } catch {
    throw new Error(`kh ${label} did not return JSON: ${result.stdout.trim()}`)
  }
}

/**
 * First line of `kh version`, or null when kh is not installed or not working.
 *
 * Deliberately `kh version` and not `kh --version`: the binary has no
 * `--version` flag and rejects it as an unknown flag, which would read as
 * "installed but broken" rather than "not installed".
 */
export function khVersion(): string | null {
  const result = run(['version'])
  if (result.code !== 0) return null
  // `''.split('\n')` is `['']`, not `[]`, so an exit-0-but-silent binary would
  // otherwise report an empty version — which callers test for truthiness and
  // would read as "installed".
  const first = result.stdout.trim().split('\n')[0]
  return first === undefined || first === '' ? null : first
}

/** Minimal shape of the direct-execution records `kh` prints with --json. */
interface KhExecution {
  executionId?: string
  transactionHash?: string
}

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

/**
 * Grant `spender` an allowance over `token`, signed by the org's Turnkey
 * wallet, using the CLI:
 *
 *   kh execute contract-call --chain <id> --contract <token> \
 *      --method approve --args '["<spender>","<amount>"]' --abi-file <tmp> --yes
 *   kh execute status <execution-id>
 *
 * Two commands rather than one `--wait`, to mirror the REST path exactly: the
 * submit response carries an executionId before a transaction hash is attached,
 * and `kh execute status` is the command whose whole job is resolving that id
 * into the hash. Both paths therefore return the same pair, and the caller
 * cannot tell them apart except by the version line it logged.
 *
 * The ABI is supplied explicitly for the same reason the REST path supplies it:
 * MockUSDC is a throwaway deploy that is not verified on Etherscan, so the
 * server cannot look its ABI up. `--abi-file` takes a path, not a literal, so
 * it goes to a temp file that is removed whatever happens.
 */
export function khArmApproval(input: {
  chainId: number
  token: string
  spender: string
  amount: string
}): { executionId: string; transactionHash?: string } {
  const dir = mkdtempSync(join(tmpdir(), 'revoker-abi-'))
  const abiFile = join(dir, 'approve.json')
  let submitted: KhExecution
  try {
    writeFileSync(abiFile, JSON.stringify(APPROVE_ABI))
    submitted = runJson<KhExecution>(
      [
        'execute',
        'contract-call',
        '--chain',
        String(input.chainId),
        '--contract',
        input.token,
        '--method',
        'approve',
        '--args',
        JSON.stringify([input.spender, input.amount]),
        '--abi-file',
        abiFile,
        // Non-interactive: without this kh waits on a confirmation prompt that
        // a script has no way to answer.
        '--yes',
      ],
      'execute contract-call',
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }

  const { executionId } = submitted
  if (!executionId) {
    throw new Error('kh execute contract-call returned no executionId')
  }
  const status = runJson<KhExecution>(['execute', 'status', executionId], 'execute status')
  return { executionId, transactionHash: status.transactionHash }
}
