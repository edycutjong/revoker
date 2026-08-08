import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { PathOrFileDescriptor } from 'node:fs'

/**
 * config.ts resolves credentials process.env -> ~/.config/keeperhub/env -> ./.env,
 * and reads both files at MODULE LOAD. Every test must therefore control the
 * filesystem before importing, then vi.resetModules() + re-import to get a fresh
 * read. Never touch the developer's real ~/.config/keeperhub/env: node:fs is
 * mocked so no real file is ever opened.
 */

vi.mock('node:fs', () => ({
  readFileSync: vi.fn(),
}))

const DOTENV_PATH = join(process.cwd(), '.env')
const KEEPERHUB_PATH = join(homedir(), '.config', 'keeperhub', 'env')

const ENV_KEYS = [
  'KH_API_KEY',
  'KH_BASE_URL',
  'KH_NETWORK',
  'KH_CHAIN_ID',
  'KH_WALLET_ADDRESS',
  'SEPOLIA_RPC_URL',
  'KH_EXPLORER_BASE',
  'DEPLOYER_PRIVATE_KEY',
] as const

const savedEnv: Partial<Record<(typeof ENV_KEYS)[number], string>> = {}

beforeEach(async () => {
  vi.resetModules()
  for (const key of ENV_KEYS) {
    savedEnv[key] = process.env[key]
    delete process.env[key]
  }
  // Default fixture: neither credentials file exists on disk.
  await mockFiles({})
})

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key]
    else process.env[key] = savedEnv[key]
  }
})

/**
 * Wires node:fs's readFileSync to serve fixed contents for the two credential
 * files config.ts reads, and to fail exactly like a missing file (ENOENT) for
 * anything else — mirroring parseEnvFile's own try/catch-returns-{} behaviour.
 */
async function mockFiles(files: { dotenv?: string; keeperhub?: string }): Promise<void> {
  const fs = await import('node:fs')
  vi.mocked(fs.readFileSync).mockImplementation((path: PathOrFileDescriptor) => {
    if (path === DOTENV_PATH && files.dotenv !== undefined) return files.dotenv
    if (path === KEEPERHUB_PATH && files.keeperhub !== undefined) return files.keeperhub
    const err = new Error('ENOENT: no such file or directory') as NodeJS.ErrnoException
    err.code = 'ENOENT'
    throw err
  })
}

describe('env file parser', () => {
  it('strips matching double and single quotes, but leaves unquoted values alone', async () => {
    await mockFiles({
      dotenv: ['KH_NETWORK="mainnet"', "KH_BASE_URL='https://example.test'", 'KH_EXPLORER_BASE=plain'].join(
        '\n',
      ),
    })
    const { config } = await import('../src/config.js')
    expect(config.network).toBe('mainnet')
    expect(config.baseUrl).toBe('https://example.test')
    expect(config.explorerBase).toBe('plain')
  })

  it('does not strip mismatched quote characters', async () => {
    // value[0] is '"' but the last char is "'" — the guard requires them to match.
    await mockFiles({ dotenv: `KH_NETWORK="mismatched'` })
    const { config } = await import('../src/config.js')
    expect(config.network).toBe(`"mismatched'`)
  })

  it('skips comment lines and blank lines', async () => {
    await mockFiles({
      dotenv: ['# a full-line comment', '', '   ', 'KH_NETWORK=holesky'].join('\n'),
    })
    const { config } = await import('../src/config.js')
    expect(config.network).toBe('holesky')
  })

  it('skips lines with no "=" entirely', async () => {
    await mockFiles({ dotenv: ['JUST_A_WORD_NO_EQUALS', 'KH_NETWORK=holesky'].join('\n') })
    const { config } = await import('../src/config.js')
    expect(config.network).toBe('holesky')
  })

  it('splits only on the first "=", preserving "=" inside the value', async () => {
    await mockFiles({ dotenv: 'KH_BASE_URL=https://example.test/path?a=1&b=2' })
    const { config } = await import('../src/config.js')
    expect(config.baseUrl).toBe('https://example.test/path?a=1&b=2')
  })

  it('trims surrounding whitespace around key and value', async () => {
    await mockFiles({ dotenv: '   KH_NETWORK   =   holesky   ' })
    const { config } = await import('../src/config.js')
    expect(config.network).toBe('holesky')
  })

  it('skips a line whose key is empty after trimming', async () => {
    // "=value" -> key slice is "" -> `if (key)` guard drops it silently.
    await mockFiles({ dotenv: ['=orphan-value', 'KH_NETWORK=holesky'].join('\n') })
    const { config } = await import('../src/config.js')
    expect(config.network).toBe('holesky')
  })

  it('treats an empty value as present (not missing)', async () => {
    // KH_BASE_URL=<nothing> parses to the empty string, which is falsy for
    // `??` fallback purposes only via require_'s explicit !value check — for
    // the plain read() + ?? path, "" is a real value that beats the default.
    await mockFiles({ dotenv: 'KH_BASE_URL=' })
    const { config } = await import('../src/config.js')
    expect(config.baseUrl).toBe('')
  })
})

describe('priority order', () => {
  it('process.env wins over both files', async () => {
    process.env['KH_NETWORK'] = 'from-process-env'
    await mockFiles({ dotenv: 'KH_NETWORK=from-dotenv', keeperhub: 'KH_NETWORK=from-keeperhub' })
    const { config } = await import('../src/config.js')
    expect(config.network).toBe('from-process-env')
  })

  it('~/.config/keeperhub/env wins over ./.env', async () => {
    await mockFiles({ dotenv: 'KH_NETWORK=from-dotenv', keeperhub: 'KH_NETWORK=from-keeperhub' })
    const { config } = await import('../src/config.js')
    expect(config.network).toBe('from-keeperhub')
  })

  it('falls back to ./.env when only it defines the key', async () => {
    await mockFiles({ dotenv: 'KH_NETWORK=from-dotenv-only', keeperhub: 'KH_API_KEY=kh_unrelated' })
    const { config } = await import('../src/config.js')
    expect(config.network).toBe('from-dotenv-only')
  })
})

describe('required getters', () => {
  it('throws a useful error when the key is missing everywhere', async () => {
    const { config } = await import('../src/config.js')
    expect(() => config.apiKey).toThrow(/Missing KH_API_KEY/)
      // Asserted as a substring of the error TEXT, not a URL check — an
      // unanchored host pattern is the shape CodeQL flags, and rightly so.
      expect(() => config.apiKey).toThrow('app.keeperhub.com')
  })

  it('throws when the value is still the PASTE_ placeholder', async () => {
    // Guards against the agent silently running against a template value the
    // user forgot to fill in.
    process.env['KH_API_KEY'] = 'PASTE_YOUR_KEY_HERE'
    const { config } = await import('../src/config.js')
    expect(() => config.apiKey).toThrow(/Missing KH_API_KEY/)
  })

  it('returns the value once it is set', async () => {
    process.env['KH_API_KEY'] = 'kh_real_key'
    const { config } = await import('../src/config.js')
    expect(config.apiKey).toBe('kh_real_key')
  })
})

describe('walletAddress validation', () => {
  it('rejects a malformed address with a message identifying the bad value', async () => {
    process.env['KH_WALLET_ADDRESS'] = 'not-an-address'
    const { config } = await import('../src/config.js')
    expect(() => config.walletAddress).toThrow(/KH_WALLET_ADDRESS is not a valid address: not-an-address/)
  })

  it('rejects an address that is short one hex digit', async () => {
    // 39 hex chars, not 40 — the classic off-by-one truncation bug.
    process.env['KH_WALLET_ADDRESS'] = '0x' + 'a'.repeat(39)
    const { config } = await import('../src/config.js')
    expect(() => config.walletAddress).toThrow(/not a valid address/)
  })

  it('rejects an address missing the 0x prefix', async () => {
    process.env['KH_WALLET_ADDRESS'] = 'a'.repeat(40)
    const { config } = await import('../src/config.js')
    expect(() => config.walletAddress).toThrow(/not a valid address/)
  })

  it('accepts a well-formed checksummed-length address', async () => {
    const addr = '0x' + 'AbCd'.repeat(10)
    process.env['KH_WALLET_ADDRESS'] = addr
    const { config } = await import('../src/config.js')
    expect(config.walletAddress).toBe(addr)
  })
})

describe('deployerPrivateKey validation', () => {
  it('rejects a key that is not 32-byte hex', async () => {
    // This guard is what stops the demo-seeding key from ever being mistaken
    // for a real 32-byte secp256k1 key.
    // gitleaks:allow — synthetic single-character fixture, not a key
    process.env['DEPLOYER_PRIVATE_KEY'] = '0x' + 'a'.repeat(62) // 31 bytes
    const { config } = await import('../src/config.js')
    expect(() => config.deployerPrivateKey).toThrow(/DEPLOYER_PRIVATE_KEY is not a valid 32-byte hex key/)
  })

  it('rejects a key missing the 0x prefix', async () => {
    // gitleaks:allow — synthetic single-character fixture, not a key
    process.env['DEPLOYER_PRIVATE_KEY'] = 'a'.repeat(64)
    const { config } = await import('../src/config.js')
    expect(() => config.deployerPrivateKey).toThrow(/not a valid 32-byte hex key/)
  })

  it('accepts a well-formed 32-byte hex key', async () => {
    // gitleaks:allow — synthetic single-character fixture, not a key
    const key = '0x' + 'f'.repeat(64)
    process.env['DEPLOYER_PRIVATE_KEY'] = key
    const { config } = await import('../src/config.js')
    expect(config.deployerPrivateKey).toBe(key)
  })
})

describe('defaults when nothing is configured', () => {
  it('falls back to the documented defaults', async () => {
    const { config } = await import('../src/config.js')
    expect(config.baseUrl).toBe('https://app.keeperhub.com')
    expect(config.network).toBe('sepolia')
    expect(config.chainId).toBe(11155111)
    expect(config.rpcUrl).toBe('https://ethereum-sepolia-rpc.publicnode.com')
    expect(config.explorerBase).toBe('https://sepolia.etherscan.io')
  })

  it('coerces a configured KH_CHAIN_ID to a number', async () => {
    process.env['KH_CHAIN_ID'] = '1'
    const { config } = await import('../src/config.js')
    expect(config.chainId).toBe(1)
    expect(typeof config.chainId).toBe('number')
  })
})

describe('explorerTxUrl', () => {
  it('joins the configured explorer base with the tx hash', async () => {
    process.env['KH_EXPLORER_BASE'] = 'https://custom.explorer.test'
    const { config, explorerTxUrl } = await import('../src/config.js')
    // explorerBase is read lazily via the module-level `config` object, so this
    // also proves explorerTxUrl reads live off config rather than a snapshot.
    expect(explorerTxUrl('0xdeadbeef')).toBe(`${config.explorerBase}/tx/0xdeadbeef`)
    expect(explorerTxUrl('0xdeadbeef')).toBe('https://custom.explorer.test/tx/0xdeadbeef')
  })

  it('uses the default explorer base when unset', async () => {
    const { explorerTxUrl } = await import('../src/config.js')
    expect(explorerTxUrl('0xabc123')).toBe('https://sepolia.etherscan.io/tx/0xabc123')
  })
})
