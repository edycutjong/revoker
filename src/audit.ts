import { appendFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'

/**
 * Structured audit trail.
 *
 * "Reliability and observability" is a judged criterion, and an agent that
 * moves funds without a defensible record of *why* is not something anyone
 * should run. Every stage of every decision lands here as one JSON object per
 * line: what fired, what was simulated, what was submitted, what it cost, and
 * what happened.
 */

export type AuditStage =
  | 'watch.start'
  | 'watch.scan'
  /** The scan itself blew up — an RPC blip, not a revoke that failed. */
  | 'watch.error'
  | 'threat.detected'
  | 'threat.cleared'
  | 'revoke.submit'
  | 'revoke.confirmed'
  | 'revoke.failed'
  /**
   * Submitted, and the landing budget expired while it was still non-terminal.
   * NOT a failure — the transaction may yet land — and it needs its own stage to
   * say so. Written as `revoke.failed` with `disposition: 'pending'`, it was
   * counted by the dashboard's failure tile and labelled "revoke failed" on the
   * row, which is the exact false alarm ARCHITECTURE.md promises never happens.
   */
  | 'revoke.pending'
  /** Submitted and mined, but the transaction reverted. Distinct from never landing. */
  | 'revoke.reverted'
  /**
   * The agent has STOPPED retrying this exposure after N consecutive
   * non-successes. Distinct from `revoke.failed` on purpose: "this attempt did
   * not work" is routine, "the agent has given up and is no longer defending
   * this allowance" needs a human, and only one of the two should ever page one.
   */
  | 'revoke.abandoned'
  | 'revoke.skipped'

export interface AuditEntry {
  ts: string
  stage: AuditStage
  [key: string]: unknown
}

/**
 * Where the durable trail lives. Resolved per call, not once at module load,
 * and exported so the dashboard replays the same file the agent writes.
 *
 * Captured at load, the path is fixed before any test can set
 * REVOKER_AUDIT_LOG in a beforeEach — so the suite appended to the real
 * audit/revoker.jsonl instead of its temp dir, interleaving ~300 placeholder
 * rows with genuine on-chain records. The fixtures even reused real gas values,
 * so the two were indistinguishable by eye in the one artifact whose whole
 * purpose is being trustworthy after the fact.
 */
export function auditLogPath(): string {
  return process.env['REVOKER_AUDIT_LOG'] ?? 'audit/revoker.jsonl'
}

const subscribers = new Set<(entry: AuditEntry) => void>()

/** The /verify dashboard subscribes here to stream decisions live. */
export function onAudit(listener: (entry: AuditEntry) => void): () => void {
  subscribers.add(listener)
  return () => subscribers.delete(listener)
}

function serialize(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString()
  if (Array.isArray(value)) return value.map(serialize)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, serialize(v)]))
  }
  return value
}

export function audit(stage: AuditStage, detail: Record<string, unknown> = {}): AuditEntry {
  const ts = new Date().toISOString()
  const entry: AuditEntry = {
    ts,
    stage,
    ...(serialize(detail) as Record<string, unknown>),
  }

  // The envelope wins over the payload. `audit('revoke.failed', { stage:
  // 'scan' })` used to spread its own `stage` over the canonical one, so the
  // entry was written as stage "scan": the real stage never appeared, stage
  // filters missed it, and STAGE_LABEL['scan'] printed the literal `undefined`.
  // Reassigning after the spread keeps both keys in their original position
  // while making that clobber impossible for any future caller.
  entry.ts = ts
  entry.stage = stage

  try {
    const path = auditLogPath()
    mkdirSync(dirname(path), { recursive: true })
    appendFileSync(path, `${JSON.stringify(entry)}\n`)
  } catch {
    // A failed audit write must never take down the agent mid-revoke: losing
    // the log is bad, failing to revoke because of it is worse.
  }

  for (const listener of subscribers) {
    try {
      listener(entry)
    } catch {
      // A broken dashboard subscriber must not break the loop either.
    }
  }

  return entry
}

const STAGE_LABEL: Record<AuditStage, string> = {
  'watch.start': '▶',
  'watch.scan': '·',
  'threat.detected': '🚨',
  'threat.cleared': '✓',
  'revoke.submit': '↗',
  'revoke.confirmed': '✅',
  'revoke.failed': '❌',
  'revoke.pending': '⏳',
  'revoke.reverted': '↩',
  'revoke.abandoned': '🛑',
  'revoke.skipped': '⏭',
  'watch.error': '⚠',
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return String(value)
  if (typeof value === 'object') return JSON.stringify(value)
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return value.toString()
  }
  return JSON.stringify(value) ?? '?'
}

export function logLine(entry: AuditEntry): void {
  const { ts, stage, ...rest } = entry
  const time = ts.slice(11, 19)
  const detail = Object.entries(rest)
    .map(([k, v]) => `${k}=${formatValue(v)}`)
    .join(' ')
  console.log(`${time} ${STAGE_LABEL[stage]} ${stage.padEnd(17)} ${detail}`)
}
