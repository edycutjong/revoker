import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/**
 * Credentials are resolved in priority order:
 *   1. process.env                          (CI, or an explicit `export`)
 *   2. ~/.config/keeperhub/env              (local dev — outside the repo, never committed)
 *   3. ./.env                               (gitignored fallback)
 *
 * Nothing here ever reads a private key: KeeperHub signs through a Turnkey
 * enclave, so this process only ever holds an API key.
 *
 * Set REVOKER_DEMO=1 and none of that is required — see "Demo mode" below.
 */

function parseEnvFile(path: string): Record<string, string> {
  let raw: string
  try {
    raw = readFileSync(path, 'utf8')
  } catch {
    return {}
  }

  const out: Record<string, string> = {}
  for (const line of raw.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const eq = trimmed.indexOf('=')
    if (eq === -1) continue
    const key = trimmed.slice(0, eq).trim()
    let value = trimmed.slice(eq + 1).trim()
    // strip matching surrounding quotes
    if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.at(-1) === value[0]) {
      value = value.slice(1, -1)
    }
    if (key) out[key] = value
  }
  return out
}

const fileEnv = {
  ...parseEnvFile(join(process.cwd(), '.env')),
  ...parseEnvFile(join(homedir(), '.config', 'keeperhub', 'env')),
}

function read(key: string): string | undefined {
  return process.env[key] ?? fileEnv[key]
}

/**
 * audit.ts resolves the trail location from `process.env` alone, on purpose: it
 * is the one module with no dependencies, so a failing config read can never
 * take the audit log down with it. But .env.example documents
 * REVOKER_AUDIT_LOG alongside every other key, which promised a resolution
 * chain that silently did not apply — put it in ~/.config/keeperhub/env and
 * nothing happened. Publishing the resolved value into process.env here is the
 * bridge: audit.ts stays dependency-free, and the documentation stops lying.
 * process.env still wins, so an explicit `export` overrides the file as ever.
 */
const auditLogFromFile = fileEnv['REVOKER_AUDIT_LOG']
if (auditLogFromFile !== undefined && process.env['REVOKER_AUDIT_LOG'] === undefined) {
  process.env['REVOKER_AUDIT_LOG'] = auditLogFromFile
}

/**
 * ── Demo mode ────────────────────────────────────────────────────────────────
 *
 * `REVOKER_DEMO=1` lets anyone run the product from a clean `git clone` with no
 * KeeperHub account. It exists because a single `throw` in this file was the
 * entire barrier: everything downstream already degrades correctly without
 * credentials (getHeldTokens swallows its own failure, sourceVerification
 * reports 'unknown' and the rules abstain rather than firing on it), so a
 * reviewer could reach the chain, read real Approval logs and see
 * real exposures — but only after obtaining an organisation API key first.
 *
 * The substitutions are UNCONDITIONAL, not fallbacks. Demo mode is the canned
 * public demo or it is nothing: it must never half-attach to somebody's real
 * organisation, and "the value you configured was quietly used anyway" is
 * exactly the surprise that turns a safety guarantee into a probability.
 */
/**
 * Opt-in by VALUE, not by presence.
 *
 * `Boolean(process.env['REVOKER_DEMO'])` is true for the string "0" and for
 * "false", so an operator turning demo mode off the obvious way turned it on:
 * a dead API key, --dry-run forced, and a sentinel that quietly executes
 * nothing. It fails safe in the sense that it can never enable a write — but
 * "your agent silently stopped defending the wallet" is the outage this product
 * exists to prevent, so getting it from `REVOKER_DEMO=0` is not acceptable.
 *
 * Anything that is not an explicit yes is off. An unrecognised value is off too,
 * and says so, rather than being guessed in either direction.
 */
const DEMO_FLAG = (process.env['REVOKER_DEMO'] ?? '').trim().toLowerCase()
const DEMO = ['1', 'true', 'yes', 'on'].includes(DEMO_FLAG)
if (!DEMO && DEMO_FLAG !== '' ) {
  console.warn(
    `REVOKER_DEMO="${process.env['REVOKER_DEMO'] ?? ''}" is not an enabling value — demo mode is OFF. ` +
      'Use REVOKER_DEMO=1 to enable it, or unset the variable entirely.',
  )
}

/**
 * Obviously fake, and fake in a way that cannot be mistaken for a redacted real
 * key. No KeeperHub organisation will ever accept it, which is the point: with
 * this key in hand the process can read the public chain and can sign nothing.
 */
const DEMO_API_KEY = 'kh_DEMO_MODE_NOT_A_REAL_KEY'

/**
 * The project's own demo wallet — already public in README.md and
 * deployments.json, and the account every recorded transaction in
 * data/demo-run.jsonl was sent from. Nothing here is a secret.
 */
const DEMO_WALLET_ADDRESS = '0x5E2e5Fd3aD7fDC9B94482930db8b5F45E439bab7'

/**
 * Only the two keys the read path needs. DEPLOYER_PRIVATE_KEY is deliberately
 * absent: `pnpm seed` deploys contracts and arms a live approval, and demo mode
 * must not make that one command easier to reach by accident.
 */
const DEMO_DEFAULTS: Record<string, string | undefined> = {
  KH_API_KEY: DEMO_API_KEY,
  KH_WALLET_ADDRESS: DEMO_WALLET_ADDRESS,
}

function require_(key: string, hint: string): string {
  const demoDefault = DEMO ? DEMO_DEFAULTS[key] : undefined
  if (demoDefault !== undefined) return demoDefault

  const value = read(key)
  if (!value || value.startsWith('PASTE_')) {
    throw new Error(
      `Missing ${key}. ${hint}\n` +
        `Set it in your shell, in ~/.config/keeperhub/env, or in a local .env file.\n` +
        `Or run with REVOKER_DEMO=1 to use the public demo wallet and execute nothing.`,
    )
  }
  return value
}

if (DEMO) {
  /**
   * The second, independent guarantee.
   *
   * A dead API key already makes execution impossible — but "impossible because
   * the remote signer will reject us" is a property of KeeperHub, not of this
   * process, and safety that lives on someone else's server is not safety. So
   * demo mode also forces the local arm switch off.
   *
   * Every entrypoint (index.ts, server.ts, mcp.ts) decides ARMED vs DRY RUN by
   * reading `process.argv`, and every one of them imports this module — which,
   * under ESM, is fully evaluated before the importing module's own body runs.
   * Injecting the flag here therefore covers `pnpm demo`, a hand-rolled
   * `REVOKER_DEMO=1 pnpm watch`, `pnpm verify` and the MCP server alike, rather
   * than trusting four separate call sites to remember. The demo script's argv
   * is not the guard; this is.
   */
  if (!process.argv.includes('--dry-run')) process.argv.push('--dry-run')

  // stderr, not stdout: src/mcp.ts speaks JSON-RPC over stdout, and a banner
  // there would corrupt the protocol for any client that ran the demo.
  console.warn(
    [
      '',
      '  ┌─ REVOKER — DEMO MODE ─────────────────────────────────────────────┐',
      '  │ REVOKER_DEMO is set. No credentials are configured, and none are  │',
      '  │ being used — any KH_API_KEY / KH_WALLET_ADDRESS you may have set  │',
      '  │ is ignored for this process.                                      │',
      '  │                                                                   │',
      `  │ KH_API_KEY        ${DEMO_API_KEY.padEnd(48)}│`,
      `  │ KH_WALLET_ADDRESS ${DEMO_WALLET_ADDRESS.padEnd(48)}│`,
      '  │                                                                   │',
      '  │ --dry-run is FORCED ON. This process cannot sign, submit or       │',
      '  │ execute a transaction. Chain reads against the public Sepolia RPC │',
      '  │ are real; every write path is disabled.                           │',
      '  └───────────────────────────────────────────────────────────────────┘',
      '',
    ].join('\n'),
  )
}

/**
 * ── The autonomous revoke ceiling ────────────────────────────────────────────
 *
 * A hard cap on how many approvals the unattended loop may revoke in a rolling
 * 24 hours. Not a throttle for the API's benefit — a blast-radius limit for the
 * wallet's.
 *
 * 12 is chosen against both ends. Above it: a real incident is remediated by
 * revoking the handful of grants one compromised counterparty holds — the demo
 * wallet has two, and a wallet that genuinely needs a thirteenth emergency
 * revoke inside one day is having an event a human should be awake for. Below
 * it: an agent wallet accumulates dozens of live router approvals, so 12 keeps
 * any systemic misfire to a fraction of them rather than all of them. Averaged
 * out it is one revoke every two hours, a rate no legitimate incident sustains.
 *
 * The window is ROLLING, not a calendar day, so the budget cannot be doubled by
 * straddling midnight.
 */
const DEFAULT_MAX_REVOKES_PER_DAY = 12

/**
 * A ceiling that parses to garbage must not silently become Infinity or 0.
 * Infinity is the rail switched off by a typo; 0 is an agent that has quietly
 * stopped defending anything. Either way the operator believes they configured
 * a number. Falling back to the documented default, loudly, is the only
 * behaviour that leaves the wallet in a state somebody can reason about.
 */
function positiveIntOr(raw: string | undefined, fallback: number, key: string): number {
  if (raw === undefined) return fallback
  const value = Number(raw)
  if (Number.isInteger(value) && value > 0) return value
  console.warn(`${key}="${raw}" is not a positive integer — using the default of ${fallback}.`)
  return fallback
}

/**
 * Spenders the operator has explicitly blessed. See data/allowlist.json for
 * what belongs there and why an entry is a standing instruction, not a note.
 *
 * Lives here rather than in rules.ts so that the watcher and the MCP surface
 * load the SAME list through one code path. Two loaders would eventually
 * disagree about which spenders are protected, and the surface that drifted
 * would be the one that revoked a router.
 *
 * Here rather than alongside the other list loaders because this one resolves
 * through the credential chain as well as the file: REVOKER_ALLOWLIST is read
 * with the same precedence as every other key, so an operator can bless an
 * address from the environment without editing a tracked file. That chain lives
 * in this module.
 *
 * Lowercased on the way in: an allow-list that misses because of checksum
 * casing is an allow-list that does not exist.
 */
export function loadAllowlist(): Set<string> {
  const addresses = new Set<string>()

  try {
    const raw = readFileSync(new URL('../data/allowlist.json', import.meta.url), 'utf8')
    const parsed = JSON.parse(raw) as { addresses?: Array<{ address?: string }> }
    for (const entry of parsed.addresses ?? []) {
      if (entry.address) addresses.add(entry.address.toLowerCase())
    }
  } catch {
    // A missing or malformed file must not stop the agent starting. It fails
    // toward "no blessings", which only ever makes the agent MORE willing to
    // revoke — never less — so it cannot be used to smuggle an address past a
    // rule. The rate ceiling and the correlated-failure brake still stand.
  }

  for (const entry of (read('REVOKER_ALLOWLIST') ?? '').split(',')) {
    const address = entry.trim().toLowerCase()
    if (address) addresses.add(address)
  }

  return addresses
}

export const config = {
  /** True when this process is running the credential-free public demo. */
  demo: DEMO,

  /**
   * Hard ceiling on autonomous revokes per rolling 24h. See
   * DEFAULT_MAX_REVOKES_PER_DAY for the reasoning behind the number.
   */
  maxRevokesPerDay: positiveIntOr(
    read('REVOKER_MAX_REVOKES_PER_DAY'),
    DEFAULT_MAX_REVOKES_PER_DAY,
    'REVOKER_MAX_REVOKES_PER_DAY',
  ),

  /**
   * Where the /verify dashboard listens. Documented in .env.example, so it has
   * to resolve through the same chain as everything else — server.ts used to
   * read process.env directly, which quietly excluded the two config files the
   * documentation told you to use.
   */
  port: Number(read('PORT') ?? 3000),

  /**
   * The interface the /verify dashboard binds to. LOOPBACK BY DEFAULT.
   *
   * `server.listen(PORT)` with no host binds 0.0.0.0 — every interface — and
   * only POST /revoke on that server carries a credential. Everything else (the
   * dashboard, /api/meta, and the /api/stream audit feed) is open, so a bind
   * that reaches the internet publishes the wallet's entire live exposure map:
   * every token/spender pair, the amount at risk on each, which rules fired,
   * and — worst of it — which exposures a hold has withheld from the autonomous
   * loop and will therefore NOT be revoked. That is a target list for precisely
   * the attacker this agent exists to beat.
   *
   * It has to default closed rather than be documented as a caveat, because
   * .env.example tells operators the callback URL must be publicly reachable.
   * Following that instruction with a 0.0.0.0 default is how the exposure map
   * ends up on the internet by doing what the documentation said.
   *
   * The documented deployment is unaffected: a tunnel or a reverse proxy
   * connects to loopback. Only a direct all-interfaces bind changes, and that is
   * the case being fixed — see the acknowledgement gate in server.ts.
   */
  bindHost: read('REVOKER_BIND_HOST') ?? '127.0.0.1',

  /** Organization-scoped KeeperHub API key (kh_ prefix). */
  get apiKey(): string {
    return require_('KH_API_KEY', 'Create one at app.keeperhub.com -> Settings -> API Keys.')
  },

  /** KeeperHub API base. */
  baseUrl: read('KH_BASE_URL') ?? 'https://app.keeperhub.com',

  /** KeeperHub network identifier for direct-execution calls. */
  network: read('KH_NETWORK') ?? 'sepolia',

  chainId: Number(read('KH_CHAIN_ID') ?? 11155111),

  /**
   * The org's Turnkey smart account. This is the ONLY address KeeperHub can
   * sign for, which makes it both the watched wallet and the revoke sender:
   * approve(spender, 0) clears msg.sender's allowance and nobody else's.
   */
  get walletAddress(): `0x${string}` {
    const value = require_('KH_WALLET_ADDRESS', 'Find it at app.keeperhub.com -> Wallet tab.')
    if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
      throw new Error(`KH_WALLET_ADDRESS is not a valid address: ${value}`)
    }
    return value as `0x${string}`
  },

  /** Public RPC, used only for independent verification of what KeeperHub reports. */
  rpcUrl: read('SEPOLIA_RPC_URL') ?? 'https://ethereum-sepolia-rpc.publicnode.com',

  explorerBase: read('KH_EXPLORER_BASE') ?? 'https://sepolia.etherscan.io',

  /**
   * Throwaway testnet key used ONLY to deploy the demo fixtures and to act as
   * the adversary in the demo. It is not the agent's key and never signs a
   * revoke: Foundry/viem must sign deploys locally, and the Turnkey key cannot
   * leave its enclave. Seeding is the only thing this is for.
   */
  get deployerPrivateKey(): `0x${string}` {
    const value = require_(
      'DEPLOYER_PRIVATE_KEY',
      'Generate a throwaway testnet key with `cast wallet new` and fund it from the Turnkey wallet.',
    )
    if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
      throw new Error('DEPLOYER_PRIVATE_KEY is not a valid 32-byte hex key')
    }
    return value as `0x${string}`
  },
} as const

export function explorerTxUrl(hash: string): string {
  return `${config.explorerBase}/tx/${hash}`
}
