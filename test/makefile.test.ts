import { describe, expect, it } from 'vitest'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

/**
 * `make help` is the first thing anyone types in a repo that has a Makefile,
 * and a target missing from it is a feature nobody finds. The old help pattern
 * (`^[a-z0-9-]+:.*?## `) silently dropped any target whose name used a capital,
 * an underscore or a dot, and nothing anywhere checked that the list it printed
 * was complete — meanwhile the two demo commands, which are the whole
 * zero-credential judge path, were not in the Makefile at all.
 *
 * These tests run the real `make help` rather than re-implementing its pattern
 * in TypeScript: a test that reasoned about the regex would pass while make
 * printed something else entirely.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const MAKEFILE = readFileSync(new URL('../Makefile', import.meta.url), 'utf8')
const PACKAGE = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as { scripts: Record<string, string> }

/** `ESC[36m` and friends, built without putting a control character in source. */
const SGR = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, 'g')

/** The non-blank lines of `make help`, with colour codes removed. */
function makeHelp(): string[] {
  const result = spawnSync('make', ['help'], { cwd: ROOT, encoding: 'utf8' })
  if (result.error) throw result.error
  expect(result.status, result.stderr).toBe(0)
  return result.stdout
    .split(SGR)
    .join('')
    .split('\n')
    .filter((l) => l.trim().length > 0)
}

/** The target name each help line starts with. */
function helpTargets(): string[] {
  return makeHelp().map((l) => l.trim().split(/\s+/)[0] as string)
}

/** Every target named on the `.PHONY` line — the file's own list of itself. */
function phonyTargets(): string[] {
  const line = MAKEFILE.split('\n').find((l) => l.startsWith('.PHONY:'))
  if (line === undefined) throw new Error('Makefile has no .PHONY line')
  return line.replace('.PHONY:', '').trim().split(/\s+/)
}

describe('make help', () => {
  it('lists every target declared .PHONY', () => {
    const listed = helpTargets()

    // A set difference rather than one expect() per target, so a failure names
    // every target that went missing instead of only the first.
    expect(phonyTargets().filter((t) => !listed.includes(t))).toEqual([])
  })

  it('declares every documented target .PHONY', () => {
    // The other direction. A documented target with no .PHONY entry breaks the
    // moment a file of that name appears in the repo: make sees `demo` as an
    // up-to-date file and the target silently becomes a no-op.
    const documented = [...MAKEFILE.matchAll(/^([A-Za-z0-9][A-Za-z0-9_.-]*):.*## /gm)].map(
      (m) => m[1] as string,
    )
    const phony = phonyTargets()

    expect(documented.filter((t) => !phony.includes(t))).toEqual([])
  })

  it('puts the two zero-credential commands at the top, right after help', () => {
    // These are what a judge runs first, so they are what the file offers
    // first. Discoverability is the whole feature here.
    expect(helpTargets().slice(0, 3)).toEqual(['help', 'demo', 'demo-verify'])
  })

  it('says out loud that the demo targets need no credentials', () => {
    const demoLines = makeHelp().filter((l) => l.trim().startsWith('demo'))

    expect(demoLines).toHaveLength(2)
    for (const line of demoLines) expect(line).toContain('Zero-credential')
  })

  it('keeps every description in one column, however long a name gets', () => {
    // The awk field width is a hard-coded number. A target name longer than it
    // shoves that one description a character to the right and the column
    // stops being a column — which is how `submission-check` first landed.
    const starts = makeHelp().map((line) => {
      const indent = line.length - line.trimStart().length
      const name = line.trim().split(/\s+/)[0] as string
      const after = indent + name.length
      return after + line.slice(after).search(/\S/)
    })

    expect(new Set(starts).size).toBe(1)
  })
})

describe('the Makefile and package.json cannot drift', () => {
  it('routes the demo targets at exactly the scripts package.json defines', () => {
    expect(PACKAGE.scripts['demo']).toBeDefined()
    expect(PACKAGE.scripts['demo:verify']).toBeDefined()
    // Delegation, not a second copy of the command line. A Makefile that
    // re-spelled `tsx src/index.ts --dry-run --once` would be one edit away
    // from a `make demo` that is no longer the demo.
    expect(MAKEFILE).toMatch(/^demo:\s*##[^\n]*\n\tpnpm demo$/m)
    expect(MAKEFILE).toMatch(/^demo-verify:\s*##[^\n]*\n\tpnpm demo:verify$/m)
  })

  it('calls no package script that does not exist', () => {
    // A recipe pointing at a renamed script fails only when someone runs that
    // target — which for `arm` or `bench` may be never, and for `demo` is in
    // front of a judge.
    const called = [...MAKEFILE.matchAll(/^\tpnpm ([a-z0-9:-]+)/gm)]
      .map((m) => m[1] as string)
      // pnpm's own subcommands, not scripts in this package.
      .filter((name) => !['audit', 'install'].includes(name))

    expect(called.length).toBeGreaterThan(0)
    expect(called.filter((name) => PACKAGE.scripts[name] === undefined)).toEqual([])
  })

  it('exposes the submission check that CI runs, under the same script name', () => {
    // FIX 2's other half: the script was in package.json, reachable from
    // neither CI nor `make`, and so had never run in anger.
    expect(PACKAGE.scripts['check:submission']).toBe('bash scripts/check-submission-ready.sh')
    expect(MAKEFILE).toMatch(/^submission-check:\s*##[^\n]*\n\tpnpm check:submission$/m)
  })
})
