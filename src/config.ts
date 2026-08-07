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

function require_(key: string, hint: string): string {
  const value = read(key)
  if (!value || value.startsWith('PASTE_')) {
    throw new Error(
      `Missing ${key}. ${hint}\n` +
        `Set it in your shell, in ~/.config/keeperhub/env, or in a local .env file.`,
    )
  }
  return value
}

export const config = {
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
} as const

export function explorerTxUrl(hash: string): string {
  return `${config.explorerBase}/tx/${hash}`
}
