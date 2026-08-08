import { readFileSync } from 'node:fs'

/**
 * The two operator-editable lists — data/watchlist.json and data/denylist.json.
 *
 * These loaders were byte-identical copies in index.ts and server.ts (a third,
 * differently-written copy still lives in mcp.ts's defaultContext()). Copies of
 * a parser are not a style problem here: the watchlist is keyed by chain id and
 * the denylist is not, so the two files have genuinely different shapes, and a
 * fix applied to one copy — a new key, a checksum, an address normalisation —
 * silently leaves the other agent entry point reading the file the old way.
 * The failure mode that buys is the worst one this project has: the dashboard
 * and the unattended watcher disagreeing about which spenders are denied, with
 * neither of them wrong on its own terms.
 *
 * One definition, imported by both entry points.
 */

/**
 * Every loader here degrades to an empty list rather than throwing.
 *
 * Deliberate: these files are hand-edited by an operator, and a stray comma at
 * 3am must not take down a running sentinel. An empty watchlist means the scan
 * finds nothing; a `throw` here means the agent is not watching at all and
 * nobody is told. Both are bad, but only one of them keeps the process alive to
 * report itself through /healthz.
 */
function readList<T>(relativePath: string, fallback: T): T {
  try {
    const raw = readFileSync(new URL(relativePath, import.meta.url), 'utf8')
    return JSON.parse(raw) as T
  } catch {
    return fallback
  }
}

/** Spenders the agent will never trust, regardless of what the rules say. */
export function loadDenylist(): string[] {
  const parsed = readList<{ addresses?: Array<{ address: string }> }>('../data/denylist.json', {})
  return (parsed.addresses ?? []).map((entry) => entry.address)
}

/**
 * Tokens to scan, for one chain only. The file is keyed by chain id so a single
 * checkout can be pointed at Sepolia or mainnet without editing the list — and
 * so a mainnet token can never be scanned by a testnet run because the key
 * simply is not there.
 */
export function loadWatchlist(chainId: number): string[] {
  const parsed = readList<Record<string, Array<{ address: string }> | undefined>>(
    '../data/watchlist.json',
    {},
  )
  return (parsed[String(chainId)] ?? []).map((entry) => entry.address)
}
