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
  'PORT',
  'REVOKER_AUDIT_LOG',
  'REVOKER_DEMO',
  'REVOKER_ALLOWLIST',
  'REVOKER_MAX_REVOKES_PER_DAY',
] as const

const savedEnv: Partial<Record<(typeof ENV_KEYS)[number], string>> = {}
let savedArgv: string[]

beforeEach(async () => {
  vi.resetModules()
  for (const key of ENV_KEYS) {
    savedEnv[key] = process.env[key]
    delete process.env[key]
  }
  // config.ts mutates process.argv in demo mode; every test gets a clean one.
  savedArgv = process.argv
  process.argv = ['node', 'src/index.ts']
  vi.spyOn(console, 'warn').mockImplementation(() => undefined)
  // Default fixture: neither credentials file exists on disk.
  await mockFiles({})
})

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key]
    else process.env[key] = savedEnv[key]
  }
  process.argv = savedArgv
  vi.mocked(console.warn).mockRestore()
})

/**
 * Wires node:fs's readFileSync to serve fixed contents for the two credential
 * files config.ts reads, and to fail exactly like a missing file (ENOENT) for
 * anything else — mirroring parseEnvFile's own try/catch-returns-{} behaviour.
 */
async function mockFiles(files: {
  dotenv?: string
  keeperhub?: string
  /** data/allowlist.json, read by loadAllowlist() rather than at module load. */
  allowlist?: string
}): Promise<void> {
  const fs = await import('node:fs')
  vi.mocked(fs.readFileSync).mockImplementation((path: PathOrFileDescriptor) => {
    if (path === DOTENV_PATH && files.dotenv !== undefined) return files.dotenv
    if (path === KEEPERHUB_PATH && files.keeperhub !== undefined) return files.keeperhub
    if (String(path).endsWith('allowlist.json') && files.allowlist !== undefined) {
      return files.allowlist
    }
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
    process.env['DEPLOYER_PRIVATE_KEY'] = '0x' + 'a'.repeat(62) // 31 bytes
    const { config } = await import('../src/config.js')
    expect(() => config.deployerPrivateKey).toThrow(/DEPLOYER_PRIVATE_KEY is not a valid 32-byte hex key/)
  })

  it('rejects a key missing the 0x prefix', async () => {
    process.env['DEPLOYER_PRIVATE_KEY'] = 'a'.repeat(64)
    const { config } = await import('../src/config.js')
    expect(() => config.deployerPrivateKey).toThrow(/not a valid 32-byte hex key/)
  })

  it('accepts a well-formed 32-byte hex key', async () => {
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

describe('demo mode (REVOKER_DEMO)', () => {
  const DEMO_WALLET = '0x5E2e5Fd3aD7fDC9B94482930db8b5F45E439bab7'
  const DEMO_KEY = 'kh_DEMO_MODE_NOT_A_REAL_KEY'

  it('is off unless REVOKER_DEMO is set', async () => {
    const { config } = await import('../src/config.js')
    expect(config.demo).toBe(false)
    expect(() => config.apiKey).toThrow(/Missing KH_API_KEY/)
    expect(process.argv).not.toContain('--dry-run')
  })

  /**
   * `Boolean(process.env.REVOKER_DEMO)` is true for the STRING "0", so an
   * operator disabling demo mode the obvious way switched it on: dead key,
   * --dry-run forced, and an agent that silently executes nothing. It fails
   * safe — it can never enable a write — but a sentinel that has quietly
   * stopped defending the wallet is the outage this product exists to prevent.
   */
  it.each(['0', 'false', 'no', 'off', ''])(
    'stays OFF for REVOKER_DEMO=%o rather than treating any value as consent',
    async (value) => {
      process.env['REVOKER_DEMO'] = value
      vi.spyOn(console, 'warn').mockImplementation(() => undefined)

      const { config } = await import('../src/config.js')

      expect(config.demo).toBe(false)
      expect(process.argv).not.toContain('--dry-run')
      expect(() => config.apiKey).toThrow(/Missing KH_API_KEY/)
    },
  )

  it('says so when the value is unrecognised, instead of silently picking a side', async () => {
    process.env['REVOKER_DEMO'] = '0'
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)

    await import('../src/config.js')

    expect(warn.mock.calls.map((c: unknown[]) => String(c[0])).join('\n')).toContain(
      'demo mode is OFF',
    )
  })

  it.each(['1', 'true', 'yes', 'on', 'TRUE', ' 1 '])(
    'enables demo mode for the explicit value %o',
    async (value) => {
      process.env['REVOKER_DEMO'] = value
      const { config } = await import('../src/config.js')
      expect(config.demo).toBe(true)
    },
  )

  it('serves the public demo wallet and a sentinel key instead of throwing', async () => {
    process.env['REVOKER_DEMO'] = '1'
    const { config } = await import('../src/config.js')

    expect(config.demo).toBe(true)
    expect(config.walletAddress).toBe(DEMO_WALLET)
    expect(config.apiKey).toBe(DEMO_KEY)
  })

  it('ignores real credentials, so demo mode cannot half-attach to a real org', async () => {
    // The substitution is unconditional by design: a demo that quietly used the
    // key you happened to have configured would be a demo that can execute.
    process.env['REVOKER_DEMO'] = '1'
    process.env['KH_API_KEY'] = 'kh_a_genuine_org_key'
    process.env['KH_WALLET_ADDRESS'] = '0x' + 'ab'.repeat(20)

    const { config } = await import('../src/config.js')
    expect(config.apiKey).toBe(DEMO_KEY)
    expect(config.walletAddress).toBe(DEMO_WALLET)
  })

  it('still refuses DEPLOYER_PRIVATE_KEY — seeding is not part of the demo', async () => {
    // `pnpm seed` deploys contracts and arms a live approval. Demo mode must
    // not make that command one env var easier to reach.
    process.env['REVOKER_DEMO'] = '1'
    const { config } = await import('../src/config.js')
    expect(() => config.deployerPrivateKey).toThrow(/Missing DEPLOYER_PRIVATE_KEY/)
  })

  it('points a stuck user at demo mode in the error it throws', async () => {
    const { config } = await import('../src/config.js')
    expect(() => config.apiKey).toThrow(/REVOKER_DEMO=1/)
  })

  it('forces --dry-run on an ARMED invocation, so demo mode can execute nothing', async () => {
    // The proof that the guarantee does not depend on the demo script's argv:
    // this is `REVOKER_DEMO=1 pnpm watch`, typed by hand, with no flags at all.
    process.argv = ['node', 'src/index.ts']
    process.env['REVOKER_DEMO'] = '1'

    const { config } = await import('../src/config.js')

    // index.ts / server.ts / mcp.ts all decide ARMED vs DRY RUN from argv, and
    // all of them import config.js — which ESM evaluates before their own body.
    expect(process.argv).toContain('--dry-run')
    expect(new Set(process.argv.slice(2)).has('--dry-run')).toBe(true)

    // ...and the second, independent guarantee: even a bypassed argv gate hands
    // KeeperHub a key no organisation will ever accept, so nothing can sign.
    expect(config.apiKey).toBe(DEMO_KEY)
  })

  it('does not duplicate --dry-run when the flag is already there', async () => {
    process.argv = ['node', 'src/index.ts', '--dry-run', '--once']
    process.env['REVOKER_DEMO'] = '1'

    await import('../src/config.js')

    expect(process.argv.filter((a) => a === '--dry-run')).toHaveLength(1)
  })

  it('announces itself on stderr, never stdout — mcp.ts speaks JSON-RPC on stdout', async () => {
    const stdout = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    process.env['REVOKER_DEMO'] = '1'

    await import('../src/config.js')

    const warned = vi.mocked(console.warn).mock.calls.map((c: unknown[]) => String(c[0])).join('\n')
    expect(warned).toContain('DEMO MODE')
    expect(warned).toContain('No credentials are configured')
    expect(warned).toContain('--dry-run is FORCED ON')
    expect(warned).toContain(DEMO_KEY)
    expect(warned).toContain(DEMO_WALLET)
    expect(stdout).not.toHaveBeenCalled()

    stdout.mockRestore()
  })
})

describe('PORT', () => {
  it('defaults to 3000', async () => {
    const { config } = await import('../src/config.js')
    expect(config.port).toBe(3000)
  })

  it('reads PORT from the environment', async () => {
    process.env['PORT'] = '4321'
    const { config } = await import('../src/config.js')
    expect(config.port).toBe(4321)
  })

  it('reads PORT from ~/.config/keeperhub/env, as .env.example promises', async () => {
    await mockFiles({ keeperhub: 'PORT=8088' })
    const { config } = await import('../src/config.js')
    expect(config.port).toBe(8088)
  })
})

describe('REVOKER_AUDIT_LOG', () => {
  it('publishes the file-resolved value into the environment for audit.ts', async () => {
    // audit.ts reads process.env directly so it can stay dependency-free; the
    // documented resolution chain still has to apply to it.
    await mockFiles({ keeperhub: 'REVOKER_AUDIT_LOG=/tmp/from-keeperhub.jsonl' })
    await import('../src/config.js')
    expect(process.env['REVOKER_AUDIT_LOG']).toBe('/tmp/from-keeperhub.jsonl')

    const { auditLogPath } = await import('../src/audit.js')
    expect(auditLogPath()).toBe('/tmp/from-keeperhub.jsonl')
  })

  it('never overrides an explicit process.env value', async () => {
    process.env['REVOKER_AUDIT_LOG'] = '/tmp/from-shell.jsonl'
    await mockFiles({ keeperhub: 'REVOKER_AUDIT_LOG=/tmp/from-keeperhub.jsonl' })
    await import('../src/config.js')
    expect(process.env['REVOKER_AUDIT_LOG']).toBe('/tmp/from-shell.jsonl')
  })

  it('leaves it unset when no file defines it, so audit.ts keeps its own default', async () => {
    await import('../src/config.js')
    expect(process.env['REVOKER_AUDIT_LOG']).toBeUndefined()

    const { auditLogPath } = await import('../src/audit.js')
    expect(auditLogPath()).toBe('audit/revoker.jsonl')
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

/**
 * The two safety rails config.ts owns. Both are documented in .env.example, so
 * both have to resolve through the same chain as every other key — and both
 * fail in a direction someone has to be able to reason about.
 */
describe('maxRevokesPerDay — the autonomous revoke ceiling', () => {
  it('defaults to 12 when nothing is configured', async () => {
    const { config } = await import('../src/config.js')
    expect(config.maxRevokesPerDay).toBe(12)
  })

  it('takes an explicit positive integer from the environment', async () => {
    process.env['REVOKER_MAX_REVOKES_PER_DAY'] = '3'
    const { config } = await import('../src/config.js')
    expect(config.maxRevokesPerDay).toBe(3)
  })

  it('resolves through ~/.config/keeperhub/env like every other key', async () => {
    await mockFiles({ keeperhub: 'REVOKER_MAX_REVOKES_PER_DAY=5' })
    const { config } = await import('../src/config.js')
    expect(config.maxRevokesPerDay).toBe(5)
  })

  it.each([
    ['not-a-number', 'a typo'],
    ['0', 'an agent that would never revoke anything'],
    ['-4', 'a negative budget'],
    ['2.5', 'a fractional revoke'],
    ['Infinity', 'the rail switched off by accident'],
  ])('falls back to the documented default on %s, loudly', async (raw) => {
    // A ceiling that parses to garbage must not silently become Infinity (the
    // rail off) or 0 (an agent that has quietly stopped defending anything).
    // Either way the operator believes they configured a number.
    process.env['REVOKER_MAX_REVOKES_PER_DAY'] = raw
    const { config } = await import('../src/config.js')

    expect(config.maxRevokesPerDay).toBe(12)
    expect(vi.mocked(console.warn).mock.calls.flat().join(' ')).toContain(
      'REVOKER_MAX_REVOKES_PER_DAY',
    )
  })
})

describe('loadAllowlist — spenders the operator has blessed', () => {
  it('reads data/allowlist.json and lower-cases every address', async () => {
    await mockFiles({
      allowlist: JSON.stringify({
        addresses: [{ address: '0x000000000022D473030F116dDEE9F6B43aC78BA3' }],
      }),
    })
    const { loadAllowlist } = await import('../src/config.js')

    // Checksum casing is how a real allow-list silently stops matching.
    expect([...loadAllowlist()]).toEqual(['0x000000000022d473030f116ddee9f6b43ac78ba3'])
  })

  it('adds REVOKER_ALLOWLIST on top of the file, trimmed and lower-cased', async () => {
    await mockFiles({ allowlist: JSON.stringify({ addresses: [{ address: '0xAAA' }] }) })
    process.env['REVOKER_ALLOWLIST'] = ' 0xBBB , 0xccc ,'
    const { loadAllowlist } = await import('../src/config.js')

    // The trailing empty segment must not become a blessed empty address.
    expect([...loadAllowlist()].sort()).toEqual(['0xaaa', '0xbbb', '0xccc'])
  })

  it('resolves REVOKER_ALLOWLIST through the config files too', async () => {
    await mockFiles({ keeperhub: 'REVOKER_ALLOWLIST=0xfromfile' })
    const { loadAllowlist } = await import('../src/config.js')
    expect([...loadAllowlist()]).toEqual(['0xfromfile'])
  })

  it('degrades to no blessings when the file is missing', async () => {
    const { loadAllowlist } = await import('../src/config.js')
    expect(loadAllowlist().size).toBe(0)
  })

  it('degrades to no blessings when the file is malformed, rather than throwing', async () => {
    // Fails toward "nothing is blessed", which can only ever make the agent MORE
    // willing to revoke. A corrupt file must never be a way to smuggle an
    // address past a rule, and must never stop the sentinel from starting.
    await mockFiles({ allowlist: '{ not json' })
    const { loadAllowlist } = await import('../src/config.js')
    expect(loadAllowlist().size).toBe(0)
  })

  it('tolerates a file with no addresses array and entries with no address', async () => {
    await mockFiles({ allowlist: JSON.stringify({ addresses: [{ label: 'no address here' }] }) })
    const { loadAllowlist } = await import('../src/config.js')
    expect(loadAllowlist().size).toBe(0)

    vi.resetModules()
    await mockFiles({ allowlist: JSON.stringify({ updated: '2026-08-08' }) })
    const again = await import('../src/config.js')
    expect(again.loadAllowlist().size).toBe(0)
  })
})
