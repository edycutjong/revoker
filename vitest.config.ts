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
          statements: 100,
          functions: 100,
          lines: 100,
          branches: 95,
        },
      },
    },
  },
})
