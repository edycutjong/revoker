import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'

/**
 * The landing page's central claim is that every figure on it traces to a real
 * transaction. These tests exist because that claim broke twice without anyone
 * noticing: a benchmark re-run rewrote the summary figures and the chart array
 * but left the narrative proof timeline pointing at the PREVIOUS chain run, so
 * the page cited two different revokes and still looked perfectly fine.
 *
 * Figures are checked against BENCHMARK.md, which `pnpm bench` writes, rather
 * than against hard-coded numbers — a literal here would just be the same figure
 * copied to a third place, free to rot alongside the rest.
 */

// BENCHMARK.md drives the headline-figure assertions below.
const bench = readFileSync(new URL('../BENCHMARK.md', import.meta.url), 'utf8')

function benchStat(metric: 'response' | 'exposure') {
  const m = bench.match(
    new RegExp(`\\| ${metric} \\| ([\\d.]+)s \\| ([\\d.]+)s \\| ([\\d.]+)s \\| ([\\d.]+)s \\|`),
  )
  if (!m) throw new Error(`BENCHMARK.md has no ${metric} row — did the format change?`)
  return { p50: m[1]!, p95: m[2]!, min: m[3]!, max: m[4]! }
}

test.describe('landing page tells one story', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/index.html')
  })

  test('headline figures match BENCHMARK.md', async ({ page }) => {
    const { p50, p95 } = benchStat('response')

    // the counter animates from 0, so assert the target rather than the frame
    await expect(page.locator('.stat-v .count').first()).toHaveAttribute('data-to', p50)
    await expect(page.locator('.stat').first()).toContainText(`p95 ${p95}s`)
  })

  /* The hero stat above only covers the response row, so all four exposure
     figures drifted from BENCHMARK.md unnoticed — every one of them wrong, in
     both directions, while this suite stayed green. Assert the whole results
     table, cell by cell, for both metrics. */
  test('the results table matches BENCHMARK.md, every cell', async ({ page }) => {
    // scope to the latency table by its caption — other tables on the page also
    // carry rows whose text happens to contain these words
    const table = page.locator('table', { has: page.locator('caption', { hasText: 'Latency distribution' }) })
    const rows = await table.locator('tbody tr').evaluateAll((trs) =>
      trs.map((tr) => [...tr.querySelectorAll('td')].map((td) => td.textContent!.trim())),
    )
    for (const metric of ['response', 'exposure'] as const) {
      const { p50, p95, min, max } = benchStat(metric)
      const row = rows.find((cells) => cells[0]?.startsWith(metric))
      expect(row, `no ${metric} row in the latency table`).toBeTruthy()
      expect(row!.slice(1), `${metric} row must be [p50, p95, min, max] from BENCHMARK.md`)
        .toEqual([`${p50}s`, `${p95}s`, `${min}s`, `${max}s`])
    }
  })

  /* A bar taller than the chart's ceiling is clipped by the frame, so the slow
     cycles flatten into one another and the outlier reads as smaller than it is. */
  test('the chart scale clears the tallest cycle', async ({ page }) => {
    const heights = await page
      .locator('.bars a')
      .evaluateAll((els) => els.map((e) => parseFloat((e as HTMLElement).style.height)))
    expect(heights.length).toBeGreaterThan(0)
    expect(Math.max(...heights), 'a bar over 100% is rendered outside the frame').toBeLessThanOrEqual(100)
  })

  test('every linked transaction is a real 32-byte hash', async ({ page }) => {
    const hrefs = await page.locator('a[href*="/tx/"]').evaluateAll((els) =>
      els.map((e) => (e as HTMLAnchorElement).href),
    )
    expect(hrefs.length).toBeGreaterThan(3)
    for (const href of hrefs) {
      expect(href, `${href} is not a well-formed Sepolia tx link`).toMatch(
        /^https:\/\/sepolia\.etherscan\.io\/tx\/0x[0-9a-f]{64}$/,
      )
    }
  })

  test('the proof timeline agrees with the README', async ({ page }) => {
    // The regression that shipped: a benchmark re-run rewrote the chart and the
    // summary figures but left this timeline pointing at the previous chain run,
    // so the site and the README cited two different revokes and both looked
    // fine in isolation.
    //
    // Note this is deliberately NOT checked against BENCHMARK.md. The timeline
    // shows one demo cycle — approval, revoke, drain — while the benchmark is 25
    // separate automated cycles, so they legitimately share no hashes. The
    // invariant that actually matters is that every surface quotes the SAME
    // three transactions.
    const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
    const inReadme = new Set([...readme.matchAll(/\/tx\/(0x[0-9a-f]{64})/g)].map((m) => m[1]!))

    const timeline = await page.locator('.tstep a[href*="/tx/"]').evaluateAll((els) =>
      els.map((e) => (e as HTMLAnchorElement).href.split('/tx/')[1]!),
    )
    expect(timeline.length).toBe(3)
    expect(new Set(timeline).size, 'the three steps must be three distinct transactions').toBe(3)

    const drifted = timeline.filter((h) => !inReadme.has(h))
    expect(
      drifted,
      `these are on the page but not in README.md — the surfaces have drifted apart: ${drifted.join(', ')}`,
    ).toEqual([])
  })

  test('the demo video is published, not a placeholder', async ({ page }) => {
    await expect(page.locator('.video-placeholder')).toHaveCount(0)
    const frame = page.locator('#demo iframe')

    // Anchored at both ends deliberately. Unanchored, this matched anywhere in
    // the string, so https://evil.example/?u=youtube-nocookie.com/embed/abcdef
    // would have satisfied it — the assertion would have passed while the page
    // embedded someone else's origin. CodeQL flags exactly this shape, and it
    // was right to: the point of the test is that the embed is the privacy-mode
    // YouTube host and nothing else.
    await expect(frame).toHaveAttribute(
      'src',
      /^https:\/\/www\.youtube-nocookie\.com\/embed\/[\w-]{6,}$/,
    )
    await expect(frame).toHaveAttribute('title', /.{10,}/)
  })

  test('the version badge is stamped', async ({ page }) => {
    await expect(page.locator('.foot-ver .ver')).toHaveText(/^v\d+\.\d+\.\d+$/)
  })
})

test.describe('accessibility guarantees that regressed before', () => {
  test('links inside prose are underlined, not colour-only', async ({ page }) => {
    await page.goto('/index.html')
    // WCAG 1.4.1 — this was the one failing Lighthouse audit at 96/100.
    //
    // Chips are exempt and must stay exempt: the .tx transaction links and the
    // .ver version badge are bordered pills, so they are already distinguishable
    // by shape rather than by colour. Underlining them would be noise, and the
    // rule only concerns links embedded in running text.
    const links = await page
      .locator('p a:not(.tx):not(.ver), .video-cap a, .foot-line a')
      .evaluateAll((els) =>
        els
          .filter((e) => !e.querySelector('.ver'))
          .map((e) => ({
            text: (e.textContent ?? '').trim().slice(0, 30),
            line: getComputedStyle(e).textDecorationLine,
          })),
      )
    expect(links.length).toBeGreaterThan(2)
    for (const l of links) {
      expect(l.line, `"${l.text}" is distinguishable by colour alone`).toContain('underline')
    }
  })

  test('the page makes no external requests except the video embed', async ({ page }) => {
    const offsite: string[] = []
    page.on('request', (r) => {
      const url = new URL(r.url())
      if (url.hostname !== '127.0.0.1' && !/youtube|ytimg|google/.test(url.hostname)) {
        offsite.push(r.url())
      }
    })
    await page.goto('/index.html', { waitUntil: 'networkidle' })
    expect(offsite, `unexpected off-site requests: ${offsite.join(', ')}`).toEqual([])
  })
})

test.describe('pitch deck', () => {
  test('renders every slide and a real QR', async ({ page }) => {
    await page.goto('/pitch.html')
    await expect(page.locator('.slide')).toHaveCount(11)

    // the QR was a dashed "swap in when generated" box for most of the build
    await expect(page.locator('.qr-ph')).toHaveCount(0)
    const qr = page.locator('.qr svg path')
    await expect(qr).toHaveCount(1)
    // a real code has hundreds of module runs; a logo would have a handful
    const d = await qr.getAttribute('d')
    expect((d ?? '').split('M').length).toBeGreaterThan(100)
  })
})
