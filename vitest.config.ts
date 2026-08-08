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
      // Coverage still reports across the whole agent, including files with no
      // tests — a module at 0% is information, not noise.
      include: ['src/**/*.ts', 'scripts/**/*.ts'],
      exclude: ['e2e/**', 'contracts/**', 'starter/**'],
    },
  },
})
