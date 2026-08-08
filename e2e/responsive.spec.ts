import { test, expect } from '@playwright/test'

/**
 * Layout integrity across viewports.
 *
 * The specific failure worth guarding is horizontal overflow: this page carries
 * wide monospace content — 66-character transaction hashes, a benchmark table,
 * terminal blocks — and any one of them can push the document wider than the
 * viewport on a phone. That does not throw, does not fail a build, and does not
 * show up in a desktop screenshot. It just makes the page feel broken to a judge
 * opening the link on their phone.
 */

const VIEWPORTS = [
  { name: 'phone', width: 390, height: 844 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'laptop', width: 1440, height: 900 },
] as const

for (const vp of VIEWPORTS) {
  test.describe(`${vp.name} (${vp.width}px)`, () => {
    test.use({ viewport: { width: vp.width, height: vp.height } })

    test('does not scroll horizontally', async ({ page }) => {
      await page.goto('/index.html')
      await page.waitForTimeout(300)
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      )
      expect(overflow, 'the document is wider than the viewport').toBeLessThanOrEqual(1)
    })

    test('hero headline and primary action are visible without scrolling', async ({ page }) => {
      await page.goto('/index.html')
      await expect(page.locator('.hero h1')).toBeInViewport()
      await expect(page.locator('.hero .btn-primary')).toBeInViewport()
    })

    test('wide content scrolls inside its own container, not the page', async ({ page }) => {
      await page.goto('/index.html')
      // any element wider than the viewport must sit in a scroll container
      const escapes = await page.evaluate((w) => {
        const bad: string[] = []
        document.querySelectorAll<HTMLElement>('main *').forEach((el) => {
          if (el.getBoundingClientRect().width > w + 1) {
            let p: HTMLElement | null = el
            let contained = false
            while (p && p !== document.body) {
              const ov = getComputedStyle(p).overflowX
              if (ov === 'auto' || ov === 'scroll' || ov === 'hidden') { contained = true; break }
              p = p.parentElement
            }
            if (!contained) bad.push(el.className || el.tagName)
          }
        })
        return bad
      }, vp.width)
      expect(escapes, `these overflow the viewport uncontained: ${escapes.join(', ')}`).toEqual([])
    })
  })
}
