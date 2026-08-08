import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'

/**
 * scripts/kh-cli.ts shells out to the real `kh` binary, which signs live
 * transactions with the org's Turnkey wallet. node:child_process is therefore
 * mocked outright: these tests assert the exact argv the wrapper builds, and a
 * regression that reached a real binary would spend gas rather than fail.
 *
 * node:fs is mocked for the same reason the wrapper needs it at all — kh's
 * --abi-file takes a path, so the wrapper writes a temp file. The tests record
 * those calls instead of touching the disk.
 */
const proc = vi.hoisted(() => ({
  spawnSync: vi.fn<(bin: string, args: string[], opts: unknown) => {
    status: number | null
    stdout: string
    stderr: string
    error?: Error
  }>(),
}))
vi.mock('node:child_process', () => ({ spawnSync: proc.spawnSync }))

const fsCalls = vi.hoisted(() => ({
  mkdtemp: [] as string[],
  writes: [] as { path: string; data: string }[],
  removed: [] as string[],
}))
vi.mock('node:fs', () => ({
  mkdtempSync: (prefix: string) => {
    fsCalls.mkdtemp.push(prefix)
    return `${prefix}XXXX`
  },
  writeFileSync: (path: string, data: string) => {
    fsCalls.writes.push({ path, data })
  },
  rmSync: (path: string) => {
    fsCalls.removed.push(path)
  },
}))

const MAX_UINT256 = ((1n << 256n) - 1n).toString()

const ARM = {
  chainId: 11155111,
  token: '0x4facb5fd1682c4449cad42b7590861f7ed5c88cb',
  spender: '0x8ebf8540ede8e40cd94825c418758d4029d8892e',
  amount: MAX_UINT256,
}

/** A successful `kh` run. */
function ok(stdout: string): { status: number; stdout: string; stderr: string } {
  return { status: 0, stdout, stderr: '' }
}

/** Load the module fresh so KH_BIN is re-read from the current environment. */
async function load(): Promise<typeof import('../scripts/kh-cli.js')> {
  return import('../scripts/kh-cli.js')
}

/** argv of the nth spawnSync call. */
function argv(n: number): string[] {
  return proc.spawnSync.mock.calls[n]![1]
}

/** Value following `flag` in the nth call's argv. */
function flag(n: number, name: string): string | undefined {
  const args = argv(n)
  const i = args.indexOf(name)
  return i === -1 ? undefined : args[i + 1]
}

let originalKhBin: string | undefined

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()
  fsCalls.mkdtemp.length = 0
  fsCalls.writes.length = 0
  fsCalls.removed.length = 0
  originalKhBin = process.env['KH_BIN']
  delete process.env['KH_BIN']
})

afterEach(() => {
  if (originalKhBin === undefined) delete process.env['KH_BIN']
  else process.env['KH_BIN'] = originalKhBin
})

describe('khVersion', () => {
  it('returns the first line of `kh version`', async () => {
    // `kh version` prints two lines; the second is the Go/platform build line.
    proc.spawnSync.mockReturnValue(ok('kh version 0.14.0\ndarwin/arm64 (go1.25.0)\n'))

    const { khVersion } = await load()

    expect(khVersion()).toBe('kh version 0.14.0')
    // `kh version`, never `kh --version` — the binary has no such flag.
    expect(proc.spawnSync).toHaveBeenCalledWith('kh', ['version'], { encoding: 'utf8' })
  })

  it('returns null when the binary is not on PATH', async () => {
    // spawnSync signals ENOENT through .error, not through an exit code.
    proc.spawnSync.mockReturnValue({
      status: null,
      stdout: '',
      stderr: '',
      error: new Error('spawnSync kh ENOENT'),
    })

    const { khVersion } = await load()

    expect(khVersion()).toBeNull()
  })

  it('returns null when kh is installed but exits non-zero', async () => {
    proc.spawnSync.mockReturnValue({ status: 1, stdout: '', stderr: 'boom' })

    const { khVersion } = await load()

    expect(khVersion()).toBeNull()
  })

  it('returns null when kh exits 0 but prints nothing', async () => {
    proc.spawnSync.mockReturnValue({ status: 0, stdout: '   \n', stderr: '' })

    const { khVersion } = await load()

    expect(khVersion()).toBeNull()
  })

  it('returns null when the binary is killed by a signal', async () => {
    // Not hypothetical: an ad-hoc-signed kh under macOS Gatekeeper is SIGKILLed,
    // which leaves status null and the stdio handles unset rather than empty.
    proc.spawnSync.mockReturnValue({
      status: null,
      stdout: undefined as unknown as string,
      stderr: undefined as unknown as string,
    })

    const { khVersion } = await load()

    expect(khVersion()).toBeNull()
  })

  it('honours KH_BIN for unusual installs', async () => {
    process.env['KH_BIN'] = '/opt/kh/bin/kh'
    proc.spawnSync.mockReturnValue(ok('kh version 0.14.0\n'))

    const { khVersion } = await load()
    khVersion()

    expect(proc.spawnSync).toHaveBeenCalledWith('/opt/kh/bin/kh', ['version'], { encoding: 'utf8' })
  })
})

describe('khArmApproval', () => {
  beforeEach(() => {
    proc.spawnSync
      .mockReturnValueOnce(ok(JSON.stringify({ executionId: 'exec-9', status: 'pending' })))
      .mockReturnValueOnce(ok(JSON.stringify({ executionId: 'exec-9', transactionHash: '0xfeed' })))
  })

  it('builds the documented contract-call argv and resolves the hash', async () => {
    const { khArmApproval } = await load()

    expect(khArmApproval(ARM)).toEqual({ executionId: 'exec-9', transactionHash: '0xfeed' })

    expect(argv(0).slice(0, 2)).toEqual(['execute', 'contract-call'])
    expect(flag(0, '--chain')).toBe('11155111')
    expect(flag(0, '--contract')).toBe(ARM.token)
    expect(flag(0, '--method')).toBe('approve')
    // kh takes --args as a JSON array string; spawnSync passes it as one argv
    // element, so there is no shell quoting to get wrong.
    expect(flag(0, '--args')).toBe(`["${ARM.spender}","${MAX_UINT256}"]`)
    expect(argv(0)).toContain('--yes') // non-interactive: no confirmation prompt
    expect(argv(0)).toContain('--json')

    // Second command resolves the executionId into a transaction hash.
    expect(argv(1)).toEqual(['execute', 'status', 'exec-9', '--json'])
  })

  it('writes the approve ABI to a temp file and removes it afterwards', async () => {
    const { khArmApproval } = await load()
    khArmApproval(ARM)

    const abiPath = flag(0, '--abi-file')!
    expect(abiPath).toBe(fsCalls.writes[0]!.path)
    const abi = JSON.parse(fsCalls.writes[0]!.data) as { name: string; inputs: unknown[] }[]
    expect(abi[0]!.name).toBe('approve')
    expect(abi[0]!.inputs).toHaveLength(2)
    expect(fsCalls.removed).toEqual([`${fsCalls.mkdtemp[0]!}XXXX`])
  })
})

describe('khArmApproval — failures', () => {
  it('removes the temp directory even when kh fails', async () => {
    proc.spawnSync.mockReturnValue({ status: 2, stdout: '', stderr: 'missing required flag' })

    const { khArmApproval } = await load()

    expect(() => khArmApproval(ARM)).toThrow(
      'kh execute contract-call failed (exit 2): missing required flag',
    )
    expect(fsCalls.removed).toHaveLength(1)
  })

  it('reports the exit code kh returned', async () => {
    // 5 is kh's documented rate-limit code; flattening it to "failed" would
    // lose the one detail that tells the operator to just retry.
    proc.spawnSync.mockReturnValue({ status: 5, stdout: '', stderr: 'rate limited' })

    const { khArmApproval } = await load()

    expect(() => khArmApproval(ARM)).toThrow('exit 5')
  })

  it('falls back to stdout when kh writes its error there', async () => {
    proc.spawnSync.mockReturnValue({ status: 1, stdout: 'not authenticated', stderr: '' })

    const { khArmApproval } = await load()

    expect(() => khArmApproval(ARM)).toThrow('exit 1): not authenticated')
  })

  it('reports a missing binary as exit -1', async () => {
    proc.spawnSync.mockReturnValue({
      status: null,
      stdout: '',
      stderr: '',
      error: new Error('spawnSync kh ENOENT'),
    })

    const { khArmApproval } = await load()

    expect(() => khArmApproval(ARM)).toThrow('exit -1): spawnSync kh ENOENT')
  })

  it('rejects output that is not JSON', async () => {
    proc.spawnSync.mockReturnValue(ok('Executing contract call...\n'))

    const { khArmApproval } = await load()

    expect(() => khArmApproval(ARM)).toThrow(
      'kh execute contract-call did not return JSON: Executing contract call...',
    )
  })

  it('rejects a submit response with no executionId', async () => {
    // Nothing to poll means nothing to report; guessing a hash would be worse.
    proc.spawnSync.mockReturnValue(ok(JSON.stringify({ status: 'pending' })))

    const { khArmApproval } = await load()

    expect(() => khArmApproval(ARM)).toThrow(
      'kh execute contract-call returned no executionId',
    )
  })

  it('surfaces a failure of the status command separately', async () => {
    proc.spawnSync
      .mockReturnValueOnce(ok(JSON.stringify({ executionId: 'exec-9' })))
      .mockReturnValueOnce({ status: 2, stdout: '', stderr: 'execution not found' })

    const { khArmApproval } = await load()

    expect(() => khArmApproval(ARM)).toThrow(
      'kh execute status failed (exit 2): execution not found',
    )
  })

  it('returns an undefined hash when the execution has not landed yet', async () => {
    proc.spawnSync
      .mockReturnValueOnce(ok(JSON.stringify({ executionId: 'exec-9' })))
      .mockReturnValueOnce(ok(JSON.stringify({ executionId: 'exec-9', status: 'pending' })))

    const { khArmApproval } = await load()

    expect(khArmApproval(ARM)).toEqual({ executionId: 'exec-9', transactionHash: undefined })
  })
})
