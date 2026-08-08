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
 */

const PORT = Number(process.env['PORT'] ?? 3000)

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

function main(): void {
  const dryRun = process.argv.includes('--dry-run')
  const page = readFileSync(new URL('../public/verify.html', import.meta.url), 'utf8')

  const meta = {
    wallet: config.walletAddress,
    network: config.network,
    chainId: config.chainId,
    explorer: config.explorerBase,
    dryRun,
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

  loadHistory()
  onAudit(broadcast)

  server.listen(PORT, () => {
    console.log('Revoker — /verify dashboard')
    console.log(`  http://localhost:${PORT}/verify`)
    console.log(`  watching ${config.walletAddress} on ${config.network}`)
    console.log(`  mode     ${dryRun ? 'DRY RUN' : 'ARMED'}`)
    console.log()
  })

  const watcher = new Watcher({
    owner: config.walletAddress,
    tokens: loadWatchlist(config.chainId),
    denylist: loadDenylist(),
    dryRun,
  })

  void watcher.run()

  const shutdown = (): void => {
    watcher.stop()
    server.close()
    process.exit(0)
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

main()
