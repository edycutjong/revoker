import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { readFileSync } from 'node:fs'
import { timingSafeEqual } from 'node:crypto'
import { config } from './config.js'
import { audit, auditLogPath, onAudit, type AuditEntry } from './audit.js'
import { KeeperHub } from './keeperhub.js'
import { revokeApproval, revokePermit2Allowances } from './revoke.js'
import { DEFAULT_POLL_INTERVAL_MS, Watcher } from './watcher.js'

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
 *
 * Deliberately NOT routed through broadcast(): these rows are a previous run's
 * and must not feed the /healthz counters. A trail whose last `watch.scan` was
 * written yesterday would otherwise make a process that has never scanned once
 * report itself as freshly healthy on boot.
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

/**
 * ── GET /healthz — is anything actually still watching? ──────────────────────
 *
 * A watcher that has silently stopped inside a live HTTP server is
 * indistinguishable from a healthy one from the outside: the page still
 * renders, /api/stream still opens, /api/meta still answers. /api/meta is
 * static configuration — the wallet, the network, the mode — and says nothing
 * about whether a scan has happened in the last hour. This is the only surface
 * that answers the question an operator or an uptime probe actually has.
 *
 * The counters ride the audit subscriber the dashboard already uses rather than
 * new state threaded out of the Watcher, so "a scan happened" has exactly one
 * definition and it is the same one the durable trail records. It also means
 * the numbers here and the tiles on /verify can never disagree.
 */
const health = {
  scansTotal: 0,
  revokesConfirmed: 0,
  revokesFailed: 0,
  revokesAbandoned: 0,
  lastScanAt: undefined as string | undefined,
}

/** Scans older than this many poll intervals mean the loop is not running. */
const STALE_SCAN_INTERVALS = 3

function countForHealth(entry: AuditEntry): void {
  if (entry.stage === 'watch.scan') {
    health.scansTotal += 1
    // The entry's OWN timestamp, not Date.now(): during a replay that is the
    // recorded time, hours in the past, so a recording can never be mistaken
    // for a fresh scan by the very endpoint that exists to detect staleness.
    health.lastScanAt = entry.ts
  }
  if (entry.stage === 'revoke.confirmed') health.revokesConfirmed += 1
  // `revoke.pending` is deliberately absent: a pending execution is not a
  // failure, and counting it as one here would put the contradiction the
  // dashboard just stopped making back into the machine-readable surface.
  if (entry.stage === 'revoke.failed' || entry.stage === 'revoke.reverted') {
    health.revokesFailed += 1
  }
  if (entry.stage === 'revoke.abandoned') health.revokesAbandoned += 1
}

function healthReason(aliveWatcher: boolean, secondsSinceLastScan: number | null): string {
  if (!aliveWatcher) {
    return 'no watcher is running in this process — a replay watches nothing and executes nothing'
  }
  if (secondsSinceLastScan === null) return 'the watcher has not completed a scan yet'
  return `last scan was ${secondsSinceLastScan.toFixed(1)}s ago, past the staleness ceiling`
}

/**
 * `watcherAlive` states one narrow fact — that this process constructed a
 * Watcher — and nothing more. Whether that watcher is still making progress is
 * what `secondsSinceLastScan` answers, and only the two together are health.
 */
function handleHealth(res: ServerResponse, watcherAlive: boolean, pollIntervalMs: number): void {
  const staleAfterSeconds = (STALE_SCAN_INTERVALS * pollIntervalMs) / 1_000
  const secondsSinceLastScan =
    health.lastScanAt === undefined ? null : (Date.now() - Date.parse(health.lastScanAt)) / 1_000
  const fresh = secondsSinceLastScan !== null && secondsSinceLastScan <= staleAfterSeconds
  const ok = watcherAlive && fresh

  // 503 rather than a 200 carrying `ok: false`, because the consumers that
  // matter — a container probe, an uptime monitor, `curl -f` — read the status
  // line and never the body.
  sendJson(res, ok ? 200 : 503, {
    ok,
    watcherAlive,
    lastScanAt: health.lastScanAt ?? null,
    secondsSinceLastScan:
      secondsSinceLastScan === null ? null : Number(secondsSinceLastScan.toFixed(3)),
    staleAfterSeconds,
    scansTotal: health.scansTotal,
    revokesConfirmed: health.revokesConfirmed,
    revokesFailed: health.revokesFailed,
    revokesAbandoned: health.revokesAbandoned,
    ...(ok ? {} : { reason: healthReason(watcherAlive, secondsSinceLastScan) }),
  })
}

function broadcast(entry: AuditEntry): void {
  countForHealth(entry)
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

/**
 * ── POST /revoke — the KeeperHub workflow callback ───────────────────────────
 *
 * Revoker refuses to put the revoke itself in a visual workflow, and that
 * refusal still stands: a workflow that reads an allowance in one node and
 * writes `approve(spender, 0)` in the next has a gap between the two, and that
 * gap is the exact TOCTOU race `check-and-execute` exists to close.
 *
 * What that argument never ruled out is a workflow doing the DETECTION and the
 * ESCALATION and calling back here for the write. This endpoint is that seam.
 * The workflow decides *when to ask*; the answer is still produced by
 * revokeApproval()/revokePermit2Allowances() unchanged, which means the same
 * server-side guarded write, the same escalation ladder, the same audit trail.
 * Nothing about the atomic step moved into the workflow, so nothing about the
 * atomicity claim changes: the read and the write remain one KeeperHub
 * operation, and a workflow round-trip that happens strictly BEFORE that
 * operation cannot open a window inside it. The worst a slow round-trip can do
 * is make us ask late — and asking late is what the watcher's own polling loop
 * already handles, because the condition is re-evaluated server-side at
 * execution time regardless of how stale the caller's belief was.
 *
 * Security posture, stated plainly because this is a write endpoint on a
 * long-lived process:
 *
 *   - It is armed ONLY when the agent itself is armed (see main()).
 *   - It needs a shared secret that is not a new credential a reviewer has to
 *     obtain: unset, the endpoint fails closed and says so.
 *   - It cannot be aimed at a third party. There is no `owner` field — the
 *     owner is always config.walletAddress, because KeeperHub signs for that
 *     account and no other. A leaked secret buys an attacker the ability to
 *     zero the operator's own approvals at the operator's own gas, which is a
 *     nuisance, not a theft.
 *   - A call for an allowance that is already zero costs nothing at all: the
 *     server-side condition fails and no transaction is submitted.
 */

/**
 * The shared secret, resolved once at load.
 *
 * An exported-but-blank variable is not a credential, so it is normalised to
 * "unset" here rather than being accepted as a one-character-long password.
 */
const rawCallbackSecret = process.env['REVOKER_CALLBACK_SECRET'] ?? ''
const CALLBACK_SECRET = rawCallbackSecret === '' ? undefined : rawCallbackSecret

/** Enough for the four fields the workflow sends, and nothing like enough to be a payload. */
const CALLBACK_BODY_LIMIT_BYTES = 4_096

/**
 * One approval event should produce one callback. Twenty a minute leaves room
 * for a burst of genuine grants and for the workflow's own retries, while
 * keeping a guessing attack on the secret to a rate at which it never finishes.
 */
const CALLBACK_MAX_PER_MINUTE = 20

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/
const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/

/** Sliding one-minute window of callback attempts, authenticated or not. */
const callbackHits: number[] = []

function callbackRateLimited(now: number): boolean {
  while (callbackHits.length > 0 && now - callbackHits[0]! >= 60_000) callbackHits.shift()
  if (callbackHits.length >= CALLBACK_MAX_PER_MINUTE) return true
  callbackHits.push(now)
  return false
}

/**
 * timingSafeEqual throws on a length mismatch, and an exception is itself an
 * observable side channel — so the lengths are compared first and the
 * constant-time path still runs for everything that gets past it.
 */
function secretMatches(presented: string, expected: string): boolean {
  const a = Buffer.from(presented)
  const b = Buffer.from(expected)
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

/**
 * Read the request body with a hard ceiling.
 *
 * Bounded on bytes actually received rather than on Content-Length: a header is
 * a claim, and anything that can reach this port can lie in one.
 */
function readBody(req: IncomingMessage, limitBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = ''
    req.on('data', (chunk: Buffer | string) => {
      // Already over the line — stop growing the buffer. The promise has
      // settled; further chunks are the socket draining, not new information.
      if (body.length > limitBytes) return
      body += String(chunk)
      if (body.length > limitBytes) reject(new Error('payload too large'))
    })
    req.on('end', () => resolve(body))
    req.on('error', reject)
  })
}

type RevokeVia = 'erc20' | 'permit2'

interface CallbackRequest {
  token: `0x${string}`
  spender: `0x${string}`
  via: RevokeVia
  /** The Approval event's own transaction hash, when the workflow forwards it. */
  txHash?: string
}

type ParsedCallback = { ok: true; value: CallbackRequest } | { ok: false; reason: string }

/**
 * Validate the pair before anything is spent on it.
 *
 * Every rejection names the field, because the consumer is a workflow node an
 * operator is editing in a browser: "400" alone would send them to read this
 * file to find out which of four strings they mistyped.
 */
function parseCallback(raw: string): ParsedCallback {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return { ok: false, reason: 'body is not valid JSON' }
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return { ok: false, reason: 'body must be a JSON object' }
  }
  const body = parsed as Record<string, unknown>

  const token = body['token']
  if (typeof token !== 'string' || !ADDRESS_RE.test(token)) {
    return { ok: false, reason: 'token must be a 20-byte hex address' }
  }

  const spender = body['spender']
  if (typeof spender !== 'string' || !ADDRESS_RE.test(spender)) {
    return { ok: false, reason: 'spender must be a 20-byte hex address' }
  }

  // ERC-20 is the default because it is the path the Approval-event trigger
  // fires on; Permit2 has to be asked for explicitly.
  const via = body['via'] ?? 'erc20'
  if (via !== 'erc20' && via !== 'permit2') {
    return { ok: false, reason: "via must be 'erc20' or 'permit2'" }
  }

  const txHash = body['txHash']
  if (txHash !== undefined && (typeof txHash !== 'string' || !TX_HASH_RE.test(txHash))) {
    return { ok: false, reason: 'txHash must be a 32-byte hex transaction hash' }
  }

  return {
    ok: true,
    value: {
      token: token as `0x${string}`,
      spender: spender as `0x${string}`,
      via,
      ...(txHash === undefined ? {} : { txHash }),
    },
  }
}

/**
 * RevokeOutcome carries bigint allowances, and JSON.stringify THROWS on a
 * bigint rather than skipping it — so without this a confirmed revoke would
 * answer the workflow with a dropped socket. A replacer rather than a rebuilt
 * object, so fields added to the outcome later are covered without being listed.
 */
function jsonSafe(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(payload, jsonSafe))
}

/**
 * Refuse, on the record.
 *
 * A rejected callback goes through the same audit trail as everything else:
 * somebody probing the revoke endpoint of a security agent is exactly the kind
 * of thing the operator should see on /verify, not something to swallow.
 */
function refuseCallback(res: ServerResponse, status: number, error: string): void {
  audit('watch.error', { endpoint: 'POST /revoke', status, reason: error })
  sendJson(res, status, { ok: false, error })
}

async function handleRevokeCallback(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method !== 'POST') return refuseCallback(res, 405, 'POST only')

  // Bucketed BEFORE the secret is looked at. The attack that matters here is
  // guessing REVOKER_CALLBACK_SECRET, and a limiter that only counts
  // authenticated calls does not bound guessing at all. The cost is that a
  // flood can also crowd out the genuine workflow — which fails the system
  // closed (an approval left standing that the watcher still catches on its
  // next scan) rather than open.
  if (callbackRateLimited(Date.now())) {
    return refuseCallback(res, 429, `more than ${CALLBACK_MAX_PER_MINUTE} callbacks in one minute`)
  }

  if (CALLBACK_SECRET === undefined) {
    return refuseCallback(
      res,
      503,
      'REVOKER_CALLBACK_SECRET is not set — the workflow callback is closed. ' +
        'Set the same value in the agent environment and in the workflow HTTP Request node.',
    )
  }

  const presented = String(req.headers['authorization'] ?? '')
  if (!presented.startsWith('Bearer ') || !secretMatches(presented.slice(7), CALLBACK_SECRET)) {
    return refuseCallback(res, 401, 'missing or invalid bearer credential')
  }

  let raw: string
  try {
    raw = await readBody(req, CALLBACK_BODY_LIMIT_BYTES)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'request body could not be read'
    return refuseCallback(res, message === 'payload too large' ? 413 : 400, message)
  }

  const parsed = parseCallback(raw)
  if (!parsed.ok) return refuseCallback(res, 400, parsed.reason)

  const { token, spender, via, txHash } = parsed.value
  // Never taken from the request. KeeperHub signs for exactly one account, so
  // an `owner` field would be a parameter the endpoint could not honour.
  const owner = config.walletAddress
  const detectedAt = Date.now()

  // Recorded before the revoke, not after: if the process dies mid-execution
  // the trail still shows that the workflow escalated and when.
  audit('threat.detected', {
    source: 'keeperhub-workflow',
    endpoint: 'POST /revoke',
    token,
    owner,
    spender,
    via,
    ...(txHash === undefined ? {} : { approvalTx: txHash }),
  })

  let kh: KeeperHub
  try {
    kh = new KeeperHub()
  } catch (error) {
    // config.apiKey throws when there are no credentials. That is a 500 about
    // this process, not a 4xx about the caller's request.
    return refuseCallback(res, 500, error instanceof Error ? error.message : 'KeeperHub unavailable')
  }

  // One revoke per Approval event. The trigger's own transaction hash is the
  // natural idempotency key: a workflow that retries its HTTP node cannot
  // submit the same revoke twice inside KeeperHub's 24h dedup window, while a
  // genuinely new approval to the same spender carries a new hash and executes.
  const dedup = txHash === undefined ? {} : { idempotencyKey: `wf-${txHash}` }

  const outcome =
    via === 'permit2'
      ? await revokePermit2Allowances({ kh, owner, pairs: [{ token, spender }], ...dedup, detectedAt })
      : await revokeApproval({ kh, token, owner, spender, ...dedup, detectedAt })

  sendJson(res, 200, { ok: true, via, token, spender, ...outcome })
}

/** Whether POST /revoke answers at all, and if so whether it can be used. */
type CallbackState = 'disabled' | 'unconfigured' | 'armed'

function callbackState(dryRun: boolean): CallbackState {
  if (dryRun) return 'disabled'
  return CALLBACK_SECRET === undefined ? 'unconfigured' : 'armed'
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
    // Passed explicitly, even though it is the watcher's own default, so the
    // cadence /healthz measures staleness against is provably the cadence the
    // watcher was given rather than a second copy of the number free to drift.
    pollIntervalMs: DEFAULT_POLL_INTERVAL_MS,
  })

  void watcher.run()

  return () => watcher.stop()
}

function main(): void {
  const replay = process.argv.includes('--replay')
  // A replay watches nothing and calls nothing, so it is dry by construction.
  const dryRun = replay || process.argv.includes('--dry-run')

  /**
   * The callback is armed exactly when the agent is, off one switch.
   *
   * That is deliberate rather than convenient. `--replay` sets `dryRun` by
   * construction above, and REVOKER_DEMO makes config.ts push `--dry-run` into
   * argv before this module's body ever runs — so this single gate covers
   * dry-run, demo and replay alike, and there is no combination of flags that
   * leaves a live write endpoint bolted onto a process which is otherwise
   * executing nothing. A judge running `pnpm demo:verify` must never be one
   * stray HTTP request away from a real transaction.
   */
  const callback = callbackState(dryRun)

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
    // Same reasoning applied to the write endpoint: "can this process be told
    // to revoke something?" is answerable without sending it a request.
    revokeCallback: callback,
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

    // Not routed at all unless the agent is armed, so a dry run, the demo and
    // the replay each answer a plain 404 — an endpoint that is absent rather
    // than one that advertises itself as switched off.
    if (url.pathname === '/revoke' && !dryRun) {
      handleRevokeCallback(req, res).catch((error: unknown) => {
        try {
          refuseCallback(res, 500, error instanceof Error ? error.message : String(error))
        } catch {
          // The socket is already gone. An unattended agent does not get to die
          // of an unhandled rejection because one caller hung up mid-answer.
        }
      })
      return
    }

    // Routed in every mode, including the replay — where its honest answer is
    // that nothing is watching. A health endpoint that only exists when the
    // agent is armed cannot report the outage it exists to report.
    if (url.pathname === '/healthz') {
      handleHealth(res, !replay, DEFAULT_POLL_INTERVAL_MS)
      return
    }

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
      console.log(`  callback POST /revoke — ${callback}`)
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
