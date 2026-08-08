import { describe, expect, it, vi, beforeEach } from 'vitest'
import type { Address } from 'viem'

vi.mock('../src/chain.js', async () => {
  const actual = await vi.importActual<typeof import('../src/chain.js')>('../src/chain.js')
  return { ...actual, readAllowance: vi.fn() }
})

const { readAllowance } = await import('../src/chain.js')
const { revokeApproval } = await import('../src/revoke.js')
import type { KeeperHub } from '../src/keeperhub.js'

const TOKEN = '0xtoken000000000000000000000000000000000' as Address
const OWNER = '0xowner000000000000000000000000000000000' as Address
const SPENDER = '0xspender0000000000000000000000000000000' as Address

function fakeKh(overrides: Partial<KeeperHub> = {}): KeeperHub {
  return {
    checkAndExecute: vi.fn(),
    getExecutionStatus: vi.fn().mockResolvedValue({
      executionId: 'e1',
      status: 'completed',
      transactionHash: '0xhash',
      sponsored: true,
      gasUsedWei: '46482',
    }),
    ...overrides,
  } as unknown as KeeperHub
}

beforeEach(() => {
  vi.mocked(readAllowance).mockReset()
  process.env['REVOKER_AUDIT_LOG'] = '/dev/null'
})

describe('revokeApproval', () => {
  it('reports confirmed once the chain shows the allowance is zero', async () => {
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        executionId: 'e1',
        condition: { met: true, observedValue: '999', targetValue: '0', operator: 'gt' },
      }),
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome.executed).toBe(true)
    expect(outcome.allowanceAfter).toBe(0n)
    expect(outcome.transactionHash).toBe('0xhash')
    expect(outcome.explorerUrl).toContain('0xhash')
    expect(outcome.error).toBeUndefined()
  })

  it('reports FAILURE when the API claims success but the allowance survives', async () => {
    // This is a security property, not a nicety: an agent that reports a revoke
    // it did not achieve is worse than one that fails loudly. SECURITY.md calls
    // this out explicitly.
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        executionId: 'e1',
        condition: { met: true, observedValue: '999', targetValue: '0', operator: 'gt' },
      }),
    })
    vi.mocked(readAllowance).mockResolvedValue(500n)

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome.allowanceAfter).toBe(500n)
    expect(outcome.error).toMatch(/still non-zero/)
  })

  it('spends no gas when the allowance is already zero at execution time', async () => {
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: false,
        condition: { met: false, observedValue: '0', targetValue: '0', operator: 'gt' },
      }),
    })

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome.executed).toBe(false)
    expect(outcome.observedAllowance).toBe('0')
    // No confirmation read is needed when nothing was executed.
    expect(readAllowance).not.toHaveBeenCalled()
  })

  it('returns a failed outcome instead of throwing when KeeperHub errors', async () => {
    // The watcher loop must survive a failed revoke and retry on the next scan.
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockRejectedValue(new Error('gateway timeout')),
    })

    const outcome = await revokeApproval({ kh, token: TOKEN, owner: OWNER, spender: SPENDER })

    expect(outcome.executed).toBe(false)
    expect(outcome.error).toBe('gateway timeout')
  })

  it('measures latency from detection, not from submission', async () => {
    const kh = fakeKh({
      checkAndExecute: vi.fn().mockResolvedValue({
        executed: true,
        executionId: 'e1',
        condition: { met: true, observedValue: '9', targetValue: '0', operator: 'gt' },
      }),
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    const detectedAt = Date.now() - 5_000
    const outcome = await revokeApproval({
      kh,
      token: TOKEN,
      owner: OWNER,
      spender: SPENDER,
      detectedAt,
    })

    // Detection-to-confirmed is the number we publish; it must include the time
    // spent deciding, not just the time spent submitting.
    expect(outcome.latencyMs).toBeGreaterThanOrEqual(5_000)
  })

  it('forwards the idempotency key so a retried revoke cannot double-execute', async () => {
    const checkAndExecute = vi.fn().mockResolvedValue({
      executed: true,
      executionId: 'e1',
      condition: { met: true, observedValue: '9', targetValue: '0', operator: 'gt' },
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    await revokeApproval({
      kh: fakeKh({ checkAndExecute }),
      token: TOKEN,
      owner: OWNER,
      spender: SPENDER,
      idempotencyKey: 'revoke-abc-123',
    })

    expect(checkAndExecute.mock.calls[0]![0]).toMatchObject({ idempotencyKey: 'revoke-abc-123' })
  })

  it('asks for a revoke only while the allowance is still greater than zero', async () => {
    const checkAndExecute = vi.fn().mockResolvedValue({
      executed: true,
      executionId: 'e1',
      condition: { met: true, observedValue: '9', targetValue: '0', operator: 'gt' },
    })
    vi.mocked(readAllowance).mockResolvedValue(0n)

    await revokeApproval({
      kh: fakeKh({ checkAndExecute }),
      token: TOKEN,
      owner: OWNER,
      spender: SPENDER,
    })

    const arg = checkAndExecute.mock.calls[0]![0] as {
      condition: { operator: string; value: string }
      action: { functionName: string; functionArgs: unknown[] }
      check: { functionName: string }
    }
    expect(arg.check.functionName).toBe('allowance')
    expect(arg.condition).toEqual({ operator: 'gt', value: '0' })
    expect(arg.action.functionName).toBe('approve')
    expect(arg.action.functionArgs).toEqual([SPENDER, '0'])
  })
})
