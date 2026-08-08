import { describe, expect, it, beforeAll, afterAll } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/**
 * The Solidity coverage gate, tested as the thing it is: a shell script.
 *
 * It used to be `grep -E '^\| (src/|Total)' coverage.txt | grep -qv '100.00%'`
 * — which passes green against a summary table it does not recognise, because
 * the first grep matches nothing and `grep -qv` on empty input exits 1. That
 * gate would have waved through 50% branch coverage on any Foundry release
 * that renamed a column. The tests below hold it to both halves of its job:
 * catch a real drop, AND refuse to run blind.
 *
 * The script is EXTRACTED FROM ci.yml rather than copied here. A copy would
 * pass forever while the workflow rotted; extraction means the assertions
 * below are made against the exact bytes GitHub executes, and deleting the
 * markers breaks this file.
 */

const CI_YML = new URL('../.github/workflows/ci.yml', import.meta.url)
const BEGIN = '# --- BEGIN COVERAGE GATE'
const END = '# --- END COVERAGE GATE ---'

/** Pull the gate out of the workflow and undo its YAML block indentation. */
function extractGate(): string {
  const lines = readFileSync(CI_YML, 'utf8').split('\n')
  const start = lines.findIndex((l) => l.includes(BEGIN))
  const end = lines.findIndex((l) => l.includes(END))
  if (start === -1 || end === -1 || end < start) {
    throw new Error(
      'coverage-gate markers missing from .github/workflows/ci.yml — the gate cannot be tested, ' +
        'and an untested fail-open gate is exactly what this file exists to prevent',
    )
  }
  const body = lines.slice(start + 1, end)
  const indent = Math.min(
    ...body.filter((l) => l.trim().length > 0).map((l) => l.length - l.trimStart().length),
  )
  return body.map((l) => l.slice(indent)).join('\n')
}

/** One row of the summary table Foundry actually prints. */
function row(file: string, lines: string, statements: string, branches: string, funcs: string): string {
  return `| ${file} | ${lines} | ${statements} | ${branches} | ${funcs} |`
}

const HEADER = '| File | % Lines | % Statements | % Branches | % Funcs |'
const FULL = '100.00% (10/10)'

function summary(rows: string[]): string {
  return [HEADER, ...rows, ''].join('\n')
}

/** The table as it looks today: three contracts, two test files, all at 100%. */
const HEALTHY = summary([
  row('src/MockUSDC.sol', FULL, FULL, FULL, FULL),
  row('src/Permit2AllowanceView.sol', FULL, FULL, FULL, FULL),
  row('src/RoachMotelSpender.sol', FULL, FULL, FULL, FULL),
  row('test/RoachMotelSpender.t.sol', FULL, FULL, FULL, FULL),
  row('Total', FULL, FULL, FULL, FULL),
])

let dir: string
let script: string

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'revoker-covgate-'))
  script = join(dir, 'gate.sh')
  writeFileSync(script, extractGate())
})

afterAll(() => {
  rmSync(dir, { recursive: true, force: true })
})

/**
 * Runs the extracted gate against a fabricated `forge coverage` summary.
 * `null` deletes the file entirely — the shape a crashed forge leaves behind.
 */
function runGate(coverageTxt: string | null): { status: number; output: string } {
  if (coverageTxt === null) rmSync(join(dir, 'coverage.txt'), { force: true })
  else writeFileSync(join(dir, 'coverage.txt'), coverageTxt)
  // `bash -e` matches the shell GitHub Actions uses for a `run:` block, so a
  // command that fails here fails there.
  const result = spawnSync('bash', ['-e', script], { cwd: dir, encoding: 'utf8' })
  return { status: result.status ?? -1, output: `${result.stdout}${result.stderr}` }
}

describe('the Solidity 100% gate — when coverage is genuinely full', () => {
  it('passes and says how many contracts it checked', () => {
    const { status, output } = runGate(HEALTHY)

    expect(status).toBe(0)
    expect(output).toContain('Solidity coverage: 100%')
    // The count is in the message on purpose: "100% across 3 contract(s)" is
    // falsifiable at a glance, "100%" is not.
    expect(output).toContain('across 3 contract(s)')
  })
})

describe('the Solidity 100% gate — when a row drops below 100%', () => {
  it('fails on a partial branch score while the other three metrics are full', () => {
    // THE regression. `grep -v '100.00%'` tested the whole row as a substring,
    // so a row reading 100% / 100% / 50% / 100% still contained "100.00%" and
    // was never selected: the old gate went green at 50% branch coverage on a
    // security-relevant contract. Branch coverage is the metric that hides an
    // untested failure path, and it was the metric least protected.
    const { status, output } = runGate(
      summary([
        row('src/RoachMotelSpender.sol', FULL, FULL, '50.00% (2/4)', FULL),
        row('Total', FULL, FULL, '50.00% (2/4)', FULL),
      ]),
    )

    expect(status).toBe(1)
    expect(output).toContain('Solidity coverage dropped below 100%')
    // The offending row is echoed, so the log names the contract to go fix.
    expect(output).toContain('src/RoachMotelSpender.sol')
  })

  it('fails when one contract of several slips', () => {
    const { status, output } = runGate(
      summary([
        row('src/MockUSDC.sol', FULL, FULL, FULL, FULL),
        row('src/RoachMotelSpender.sol', FULL, FULL, '50.00% (2/4)', FULL),
        row('Total', FULL, FULL, '85.71% (6/7)', FULL),
      ]),
    )

    expect(status).toBe(1)
    expect(output).toContain('Solidity coverage dropped below 100%')
    expect(output).not.toContain('Solidity coverage: 100%')
  })

  it('fails when only the Total row slipped', () => {
    const { status, output } = runGate(
      summary([
        row('src/MockUSDC.sol', FULL, FULL, FULL, FULL),
        row('Total', '99.00% (99/100)', FULL, FULL, FULL),
      ]),
    )

    expect(status).toBe(1)
    expect(output).toContain('Solidity coverage dropped below 100%')
  })

  it('is not fooled by a 100.00% cell sitting next to a 0.00% one', () => {
    const { status } = runGate(
      summary([
        row('src/MockUSDC.sol', FULL, FULL, '0.00% (0/4)', FULL),
        row('Total', FULL, FULL, '0.00% (0/4)', FULL),
      ]),
    )

    expect(status).toBe(1)
  })

  it('is not fooled by a score whose digits merely start with 100', () => {
    // `100.00% (1/1)` vs a hypothetical `10.00%`: the cell match is anchored,
    // so a prefix cannot be mistaken for the real thing.
    const { status } = runGate(
      summary([
        row('src/MockUSDC.sol', '10.00% (1/10)', FULL, FULL, FULL),
        row('Total', '10.00% (1/10)', FULL, FULL, FULL),
      ]),
    )

    expect(status).toBe(1)
  })
})

describe('the Solidity 100% gate — when it does not recognise the table', () => {
  it('fails loudly instead of passing green when no row matches at all', () => {
    // The regression the auditor demonstrated: a summary this gate cannot
    // parse used to satisfy it. Note the coverage numbers here are terrible —
    // the old gate reported success on exactly this input.
    const { status, output } = runGate(
      [
        'File,% Lines,% Statements,% Branches,% Funcs',
        'src/MockUSDC.sol,50.00,50.00,50.00,50.00',
        'Total,50.00,50.00,50.00,50.00',
        '',
      ].join('\n'),
    )

    expect(status).toBe(1)
    expect(output).toContain('Unrecognised forge coverage summary')
    expect(output).toContain('asserted nothing')
    expect(output).not.toContain('Solidity coverage: 100%')
  })

  it('fails when the per-contract rows vanish but a Total row survives', () => {
    // A --report summary that stopped listing files would otherwise be graded
    // on one aggregate line, which is not what this gate claims to check.
    const { status, output } = runGate(summary([row('Total', FULL, FULL, FULL, FULL)]))

    expect(status).toBe(1)
    expect(output).toContain('Unrecognised forge coverage summary')
  })

  it('fails when the Total row is renamed', () => {
    const { status, output } = runGate(
      summary([row('src/MockUSDC.sol', FULL, FULL, FULL, FULL), row('Overall', FULL, FULL, FULL, FULL)]),
    )

    expect(status).toBe(1)
    expect(output).toContain('Unrecognised forge coverage summary')
  })

  it('fails on an empty summary', () => {
    const { status, output } = runGate('')

    expect(status).toBe(1)
    expect(output).toContain('Unrecognised forge coverage summary')
  })

  it('fails when there is no summary file at all', () => {
    // With no file, `grep -c` prints nothing, `src_rows` is the empty string,
    // and `[ "" -eq 0 ]` is a `test` syntax error — which inside an `if`
    // condition `set -e` deliberately ignores. Left unguarded the gate falls
    // straight through to its success message: a crashed forge reported as
    // 100% coverage.
    const { status, output } = runGate(null)

    expect(status).toBe(1)
    expect(output).toContain('wrote no summary file')
    expect(output).not.toContain('Solidity coverage: 100%')
  })

  it('prints the summary it could not parse, so the fix is possible from the log', () => {
    const { output } = runGate('something forge has never printed\n')

    expect(output).toContain('something forge has never printed')
    expect(output).toContain('0 src rows, 0 total rows')
  })
})

describe('the workflow still wires the gate up', () => {
  const yml = readFileSync(CI_YML, 'utf8')

  it('runs forge coverage before asserting on its output', () => {
    const forgeAt = yml.indexOf('forge coverage --report summary | tee coverage.txt')
    const gateAt = yml.indexOf(BEGIN)

    expect(forgeAt).toBeGreaterThan(-1)
    expect(gateAt).toBeGreaterThan(forgeAt)
  })

  it('counts rows before it judges them, and never judges a row by substring', () => {
    // The two tells of the old gate: the first thing it did with coverage.txt
    // was pipe a grep into `grep -qv`, with nothing checking the first grep
    // matched anything, and the comparison was a whole-line substring test.
    const gate = extractGate()
    const code = gate
      .split('\n')
      .filter((l) => !l.trimStart().startsWith('#'))
      .join('\n')

    const firstGrep = code.split('\n').find((l) => l.includes('grep') && l.includes('coverage.txt'))
    expect(firstGrep).toContain('grep -cE')
    expect(code).not.toContain("grep -qv '100.00%'")
  })
})

/**
 * check-submission-ready.sh existed, passed, and was referenced by no workflow
 * for its whole life. A check that never runs is documentation with a shebang —
 * and the things it catches (a badge pointing at the literal FILL_YOUTUBE_URL,
 * a README image that was never `git add`ed) surface on submission day, when
 * there is no time left to fix them.
 */
describe('the submission-readiness check is actually wired up', () => {
  // Sliced at `jobs:` on purpose — the `on:` block above it also carries
  // two-space keys (push, pull_request, workflow_dispatch) and they are
  // triggers, not jobs.
  const whole = readFileSync(CI_YML, 'utf8')
  const yml = whole.slice(whole.indexOf('\njobs:\n'))

  /** Job ids, taken from the two-space-indented keys under `jobs:`. */
  const jobs = [...yml.matchAll(/^ {2}([a-z][a-z0-9_-]*):$/gm)].map((m) => m[1] as string)

  /** The body of one job, up to the next job id at the same indentation. */
  function job(id: string): string {
    const start = yml.indexOf(`\n  ${id}:\n`)
    expect(start, `job ${id} not found`).toBeGreaterThan(-1)
    const rest = yml.slice(start + 1)
    const next = rest.slice(1).search(/^ {2}[a-z][a-z0-9_-]*:$/m)
    return next === -1 ? rest : rest.slice(0, next + 1)
  }

  it('declares a submission job', () => {
    expect(jobs).toContain('submission')
  })

  it('runs the package script rather than a second spelling of the command', () => {
    // So the command a maintainer runs locally and the command CI runs are the
    // same string, and fixing one fixes both.
    expect(job('submission')).toContain('run: pnpm check:submission')
  })

  it('runs it on a bare checkout, before anything can litter the tree', () => {
    // The placeholder scan walks the working directory, and coverage/,
    // .lighthouseci/ and playwright-report/ are full of generated HTML. An
    // install or a `needs:` on a job that produces artifacts would make the
    // result a property of what ran first rather than of the repository.
    const body = job('submission')

    expect(body).toContain('uses: actions/checkout@v4')
    expect(body).not.toContain('pnpm install')
    expect(body).not.toMatch(/^ {4}needs:/m)
  })

  it('is a hard gate, not a green tick nobody reads', () => {
    // continue-on-error, or absence from `gate.needs`, would leave it exactly
    // as advisory as never running it at all.
    expect(job('submission')).not.toContain('continue-on-error')
    expect(job('gate')).toMatch(/needs:.*\bsubmission\b/)
  })

  it('every job the workflow defines is one the ship gate waits on', () => {
    // The failure this catches is structural: adding a job and forgetting to
    // require it produces a repository whose CI runs a check and ships anyway.
    const needs = /needs: \[([^\]]+)\]/.exec(job('gate'))?.[1] ?? ''
    const required = needs.split(',').map((s) => s.trim())

    expect(jobs.filter((id) => id !== 'gate' && !required.includes(id))).toEqual([])
  })

  it('points at a script that exists and reports READY / NOT READY', () => {
    const script = readFileSync(new URL('../scripts/check-submission-ready.sh', import.meta.url), 'utf8')

    expect(script).toContain('READY')
    expect(script).toContain('NOT READY')
    // Deterministic by construction — file existence, tracked-ness and greps
    // over committed text. No network, no clock, no credentials, so promoting
    // it to a hard gate cannot introduce a flake.
    expect(script).not.toMatch(/\bcurl\b|\bwget\b|\bnc\b/)
  })
})
