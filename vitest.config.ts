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
      // src/ and scripts/ are both measured and both gated. scripts/ are
      // one-shot operational entrypoints (seed arms a real approval, spike
      // proves the integration, bench drives 25 live cycles), so every external
      // edge is mocked — but the tests assert the thing the script exists to do,
      // not merely that its lines ran: seed's idempotency claim is proved by
      // replaying run 1's written state into run 2 and asserting zero deploys,
      // zero mints and zero approvals; bench's p50/p95 are asserted as exact
      // arithmetic against a hand-wound clock, because a benchmark that reports
      // the wrong percentile is worse than no benchmark; spike asserts the
      // receipt is fetched for the hash KeeperHub returned rather than one the
      // script already knew.
      include: ['src/**/*.ts', 'scripts/**/*.ts'],
      exclude: ['e2e/**', 'contracts/**', 'starter/**'],
      // A ratchet, not an aspiration: pinned to what the suite actually achieves,
      // so the number can only be raised deliberately and never drifts down
      // unnoticed. Solidity has been hard-gated at 100% since the start
      // (ci.yml); TypeScript coverage was collected, uploaded and enforced
      // nowhere — a repo that gates one and quietly publishes the other invites
      // the obvious question.
      //
      // All four metrics now hold at 100 across both trees. Branches previously
      // carried headroom at 94 because v8 counts branch paths slightly
      // differently across Node builds (95.02-95.06% locally, 94.98% on CI) and
      // pinning at the observed maximum turned that jitter into a red build.
      // At full coverage that jitter disappears: the denominator may move
      // between builds, but the numerator moves with it, so 100 is the one
      // threshold that cannot flake. Any drop is a real regression.
      thresholds: {
        'src/**/*.ts': {
          statements: 100,
          functions: 100,
          lines: 100,
          branches: 100,
        },
        'scripts/**/*.ts': {
          statements: 100,
          functions: 100,
          lines: 100,
          branches: 100,
        },
      },
    },
  },
})
