import { defineConfig } from 'vitest/config'

/**
 * Vitest owns test/ only.
 *
 * Without this, Vitest's default glob also picks up e2e/*.spec.ts — which import
 * from @playwright/test and cannot run under Vitest. That failed as two broken
 * test FILES while still reporting "44 passed", so the summary line looked fine
 * at a glance and the suite was red underneath.
 */
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['node_modules/**', 'e2e/**', 'contracts/**'],
    coverage: {
      provider: 'v8',
      // json-summary feeds the CI step that writes the numbers into the run
      // summary — coverage that only exists inside a downloadable artifact is
      // coverage nobody ever looks at.
      reporter: ['text', 'json-summary', 'html'],
      // Still reported across scripts/ as well, because a module at 0% is
      // information rather than noise — but only src/ is gated. scripts/ are
      // one-shot operational entrypoints (seed arms a real approval, spike
      // proves the integration, bench drives 25 live cycles); they need a funded
      // wallet and a live API key, and mocking that away would leave a test that
      // asserts nothing about the thing the script exists to do.
      include: ['src/**/*.ts', 'scripts/**/*.ts'],
      exclude: ['e2e/**', 'contracts/**', 'starter/**'],
      // A ratchet, not an aspiration: pinned to what the suite actually achieves
      // today, so the number can only be raised deliberately and never drifts
      // down unnoticed. Solidity has been hard-gated at 100% since the start
      // (ci.yml); TypeScript coverage was collected, uploaded and enforced
      // nowhere — a repo that gates one and quietly publishes the other invites
      // the obvious question.
      thresholds: {
        'src/**/*.ts': {
          // Statements, functions and lines are exact counts and hold at 100 —
          // no headroom needed, and any drop is a real regression.
          statements: 100,
          functions: 100,
          lines: 100,
          // Branches gets headroom deliberately. v8 counts branch paths slightly
          // differently across Node builds: this suite measures 95.02-95.06%
          // locally and 94.98% on the CI runner, and pinning the threshold at
          // the observed maximum turned that 0.04% of jitter into a red build.
          // A gate that fails without the code changing is a gate people learn
          // to re-run rather than read. 94 still catches any real regression —
          // the smallest uncovered branch here is worth more than a point.
          branches: 94,
        },
      },
    },
  },
})
