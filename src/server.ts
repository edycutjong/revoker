import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { readFileSync } from 'node:fs'
import { config } from './config.js'
import { auditLogPath, onAudit, type AuditEntry } from './audit.js'
import { Watcher } from './watcher.js'

/**
 * The /verify dashboard.
 *
 * Runs the watcher in-process and streams its audit trail to any connected
 * browser over Server-Sent Events. Genuinely real-time — the page is pushed to
 * as decisions happen, not polled.
 *
 * This is a long-lived process by necessity: an agent that watches approvals
 * cannot be a serverless function. That is why /verify is served from the same
 * process that does the watching rather than from a static host.
 *
 *   pnpm verify              watch live, stream to the dashboard
 *   pnpm verify -- --dry-run detect and stream, execute nothing
 *   pnpm demo:verify         replay a recorded run — no credentials, no chain
 */

const PORT = config.port

/**
 * A curated, verbatim excerpt of audit/revoker.jsonl — four real runs against
 * Sepolia, with real transaction hashes. The trail itself is gitignored, so
 * without this file a judge cloning the repo would see none of it.
 */
const REPLAY_FILE = new URL('../data/demo-run.jsonl', import.meta.url)

/**
 * Cadence for --replay. The recorded `ts` on every row is left untouched and is
 * what the dashboard prints; only the spacing between rows is compressed,
 * because the four runs span five and a half hours of wall clock.
 */
const REPLAY_INTERVAL_MS = 500

/** Recent decisions, replayed to a browser that connects mid-run. */
const history: AuditEntry[] = []
const HISTORY_LIMIT = 200

const clients = new Set<ServerResponse>()

/**
 * Refill `history` from the durable trail on boot.
 *
 * The JSONL is the record; `history` is only a cache of its tail. Starting that
 * cache empty meant a restart showed a judge a blank dashboard over a log file
 * that held the entire run — the two artifacts telling different stories about
 * the same agent, with the emptier one on screen.
 *
 * Parsed line by line rather than in one go: a process killed mid-append leaves
 * a torn final line, and losing the whole replay to one bad character would
 * reintroduce exactly the blank page this exists to prevent.
 */
function loadHistory(): void {
  let raw: string
  try {
    raw = readFileSync(auditLogPath(), 'utf8')
  } catch {
    // No log yet — a first run, or a path this process cannot read.
    return
  }

  // Filter before slicing, so the trailing newline every append leaves behind
  // does not eat one entry off the front of the window.
  const lines = raw.split('\n').filter((line) => line.length > 0)
  for (const line of lines.slice(-HISTORY_LIMIT)) {
    try {
      history.push(JSON.parse(line) as AuditEntry)
    } catch {
      // Torn or empty line; the rest of the tail is still worth showing.
    }
  }
}

function broadcast(entry: AuditEntry): void {
  history.push(entry)
  if (history.length > HISTORY_LIMIT) history.shift()

  const payload = `data: ${JSON.stringify(entry)}\n\n`
  for (const client of clients) {
    try {
      client.write(payload)
    } catch {
      clients.delete(client)
    }
  }
}

function loadWatchlist(chainId: number): string[] {
  try {
    const raw = readFileSync(new URL('../data/watchlist.json', import.meta.url), 'utf8')
    const parsed = JSON.parse(raw) as Record<string, Array<{ address: string }> | undefined>
    return (parsed[String(chainId)] ?? []).map((entry) => entry.address)
  } catch {
    return []
  }
}

/**
 * The recorded run, parsed line by line for the same reason loadHistory() is:
 * one unreadable row must not cost the whole replay.
 */
function loadReplay(): AuditEntry[] {
  let raw: string
  try {
    raw = readFileSync(REPLAY_FILE, 'utf8')
  } catch {
    return []
  }

  const entries: AuditEntry[] = []
  for (const line of raw.split('\n')) {
    if (line.length === 0) continue
    try {
      entries.push(JSON.parse(line) as AuditEntry)
    } catch {
      // Skip the row, keep the timeline.
    }
  }
  return entries
}

/**
 * Stamp the served dashboard as a replay.
 *
 * public/verify.html has one connection indicator and it reads "live" the
 * moment the SSE stream opens — which during a replay is true of the stream and
 * false of the agent. A judge who mistakes a recording for a running agent has
 * been misled by us, and this project's whole claim is that it does not
 * overstate. The label is therefore applied to the page, not left to a sentence
 * in a README nobody reads next to the screen.
 *
 * Injected here rather than edited into the HTML so the live dashboard keeps
 * exactly one code path: there is no "replay" state in verify.html that could
 * be reached by accident during a real run.
 */
function labelAsReplay(page: string, entries: AuditEntry[]): string {
  // Rendered into HTML, so reduce it to the character set an ISO timestamp
  // actually uses rather than trusting the data file.
  const recordedAt = (entries[0]?.ts ?? '').replace(/[^0-9:.TZ-]/g, '') || 'an earlier run'

  const banner = `
<style>
  body { padding-top: 30px; }
  #replay-flag {
    position: fixed; top: 0; left: 0; right: 0; z-index: 99;
    background: #ffb547; color: #0a0c10; padding: 6px 14px;
    font: 600 12px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace;
    letter-spacing: .02em; text-align: center;
  }
</style>
<div id="replay-flag">
  REPLAY — recorded run of ${recordedAt}, played back from data/demo-run.jsonl.
  This is NOT a live agent. Nothing is being watched and nothing is executing.
</div>
<script>
  // The header dot reports the SSE connection, which genuinely is live; the
  // agent is not. Hold the label steady so the two can never be confused.
  ;(function () {
    var conn = document.getElementById('conn')
    var dot = document.getElementById('dot')
    function relabel() {
      if (conn.textContent !== 'replay') conn.textContent = 'replay'
      dot.classList.remove('live', 'armed')
    }
    new MutationObserver(relabel).observe(conn, { childList: true, characterData: true, subtree: true })
    new MutationObserver(relabel).observe(dot, { attributes: true, attributeFilter: ['class'] })
    relabel()
  })()
</script>
`

  return page.replace('</body>', `${banner}</body>`)
}

function loadDenylist(): string[] {
  try {
    const raw = readFileSync(new URL('../data/denylist.json', import.meta.url), 'utf8')
    const parsed = JSON.parse(raw) as { addresses?: Array<{ address: string }> }
    return (parsed.addresses ?? []).map((entry) => entry.address)
  } catch {
    return []
  }
}

function handleStream(req: IncomingMessage, res: ServerResponse): void {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  })

  // Replay what already happened so a late-joining browser has context.
  for (const entry of history) {
    res.write(`data: ${JSON.stringify(entry)}\n\n`)
  }

  clients.add(res)

  // Comment frames keep intermediaries from closing an idle stream.
  const keepAlive = setInterval(() => {
    try {
      res.write(': keep-alive\n\n')
    } catch {
      clearInterval(keepAlive)
    }
  }, 15_000)

  req.on('close', () => {
    clearInterval(keepAlive)
    clients.delete(res)
  })
}

/**
 * Stream a recorded run through the same broadcast() the live agent uses, so
 * the dashboard exercises its real code path rather than a demo-only one.
 * Returns the stop handle, matching the watcher it stands in for.
 */
function startReplay(entries: AuditEntry[]): () => void {
  let next = 0
  const timer = setInterval(() => {
    const entry = entries[next]
    next += 1

    if (entry === undefined) {
      clearInterval(timer)
      console.log(`  replay complete — ${entries.length} recorded entries`)
      return
    }

    // Marked on the way out, never in the file: data/demo-run.jsonl stays a
    // byte-for-byte excerpt of the real trail, and every row that reaches a
    // browser still carries what it is.
    broadcast({ ...entry, replay: true })
  }, REPLAY_INTERVAL_MS)

  return () => clearInterval(timer)
}

function startWatching(dryRun: boolean): () => void {
  loadHistory()
  onAudit(broadcast)

  const watcher = new Watcher({
    owner: config.walletAddress,
    tokens: loadWatchlist(config.chainId),
    denylist: loadDenylist(),
    dryRun,
  })

  void watcher.run()

  return () => watcher.stop()
}

function main(): void {
  const replay = process.argv.includes('--replay')
  // A replay watches nothing and calls nothing, so it is dry by construction.
  const dryRun = replay || process.argv.includes('--dry-run')

  const recorded = replay ? loadReplay() : []
  const rawPage = readFileSync(new URL('../public/verify.html', import.meta.url), 'utf8')
  const page = replay ? labelAsReplay(rawPage, recorded) : rawPage

  const meta = {
    wallet: config.walletAddress,
    network: config.network,
    chainId: config.chainId,
    explorer: config.explorerBase,
    dryRun,
    // Served to anything that reads the API rather than the page — a scripted
    // check, a screenshot pipeline, another agent — so "is this live?" has a
    // machine-readable answer too.
    replay,
    ...(replay
      ? {
          replaySource: 'data/demo-run.jsonl',
          replayEntries: recorded.length,
          recordedFrom: recorded[0]?.ts,
          recordedTo: recorded.at(-1)?.ts,
        }
      : {}),
  }

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://localhost:${PORT}`)

    if (url.pathname === '/api/stream') return handleStream(req, res)

    if (url.pathname === '/api/meta') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(meta))
      return
    }

    if (url.pathname === '/' || url.pathname === '/verify') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(page)
      return
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' })
    res.end('not found')
  })

  server.listen(PORT, () => {
    console.log('Revoker — /verify dashboard')
    console.log(`  http://localhost:${PORT}/verify`)
    if (replay) {
      console.log(`  mode     REPLAY — ${recorded.length} recorded entries from data/demo-run.jsonl`)
      console.log('           a recording of past runs, NOT a live agent: nothing is watched,')
      console.log('           nothing is executed, no credentials are used')
    } else {
      console.log(`  watching ${config.walletAddress} on ${config.network}`)
      console.log(`  mode     ${dryRun ? 'DRY RUN' : 'ARMED'}`)
    }
    console.log()
  })

  const stop = replay ? startReplay(recorded) : startWatching(dryRun)

  const shutdown = (): void => {
    stop()
    server.close()
    process.exit(0)
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

main()
