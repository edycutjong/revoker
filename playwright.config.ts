import { defineConfig, devices } from '@playwright/test'

/**
 * E2E over the published pages.
 *
 * What is worth testing here is not "does a button work" — these are static
 * pages. It is that the *claims* on them stay true: the page asserts that every
 * figure traces to a real transaction, and that assertion silently rotted twice
 * during this build (a benchmark re-run left the proof timeline pointing at the
 * previous chain run, and the demo-video section shipped as a placeholder long
 * after the video existed). Those are the regressions these specs catch.
 *
 * Served from site/ over HTTP rather than file://, because the YouTube embed
 * refuses to load from a file origin (error 153) and the page would look broken
 * for reasons that have nothing to do with the page.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env['CI'],
  retries: process.env['CI'] ? 1 : 0,
  reporter: process.env['CI'] ? [['github'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
  webServer: {
    command: 'python3 -m http.server 4173 --directory site --bind 127.0.0.1',
    url: 'http://127.0.0.1:4173/index.html',
    reuseExistingServer: !process.env['CI'],
    timeout: 30_000,
  },
})
