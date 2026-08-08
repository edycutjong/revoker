import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { KeeperHub, KeeperHubError } from '../src/keeperhub.js'

/**
 * Retry semantics are a judged reliability claim and a correctness hazard:
 * blindly replaying a write is how an agent double-executes. These tests pin
 * the behaviour rather than trusting the comment above it.
 */

function response(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers })
}

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  vi.useFakeTimers()
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

/** Runs a request to completion while auto-advancing the backoff timers. */
async function run<T>(promise: Promise<T>): Promise<T> {
  const settled = promise.catch((e: unknown) => ({ __error: e }) as never)
  await vi.runAllTimersAsync()
  const result = (await settled) as T & { __error?: unknown }
  if (result && typeof result === 'object' && '__error' in result) throw result.__error
  return result
}

const kh = (): KeeperHub => new KeeperHub('kh_test', 'https://example.test', 'sepolia')

describe('KeeperHub retry policy', () => {
  it('retries a 429 and succeeds', async () => {
    fetchMock
      .mockResolvedValueOnce(response(429, { error: 'rate limited' }, { 'Retry-After': '1' }))
      .mockResolvedValueOnce(response(200, { hasWallet: true, walletAddress: '0xabc' }))

    const result = await run(kh().getWallet())

    expect(result.walletAddress).toBe('0xabc')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('retries 5xx', async () => {
    fetchMock
      .mockResolvedValueOnce(response(503, { error: 'unavailable' }))
      .mockResolvedValueOnce(response(500, { error: 'boom' }))
      .mockResolvedValueOnce(response(200, { hasWallet: true }))

    await run(kh().getWallet())
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('does NOT retry a 4xx — a bad request stays bad', async () => {
    fetchMock.mockResolvedValue(response(400, { error: 'bad params' }))

    await expect(run(kh().getWallet())).rejects.toThrow(KeeperHubError)
    // The critical assertion: exactly one attempt. Replaying a rejected write
    // is how you double-execute.
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('gives up after a bounded number of attempts', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(response(500, { error: 'always down' })))

    await expect(run(kh().getWallet())).rejects.toThrow(KeeperHubError)
    expect(fetchMock).toHaveBeenCalledTimes(5) // initial + 4 retries
  })

  it('surfaces status and body on the thrown error', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(response(403, { error: 'Daily spending cap exceeded' })),
    )

    await expect(run(kh().getWallet())).rejects.toMatchObject({
      status: 403,
      body: { error: 'Daily spending cap exceeded' },
    })
  })
})

describe('KeeperHub request shape', () => {
  it('sends the idempotency key when given one', async () => {
    fetchMock.mockResolvedValue(response(200, { executionId: 'x', status: 'completed' }))

    await run(kh().transfer({ recipientAddress: '0xabc', amount: '0.1', idempotencyKey: 'key-1' }))

    const headers = fetchMock.mock.calls[0]![1].headers as Record<string, string>
    expect(headers['Idempotency-Key']).toBe('key-1')
  })

  it('omits the idempotency header when not given one', async () => {
    fetchMock.mockResolvedValue(response(200, { executionId: 'x', status: 'completed' }))

    await run(kh().transfer({ recipientAddress: '0xabc', amount: '0.1' }))

    const headers = fetchMock.mock.calls[0]![1].headers as Record<string, string>
    expect(headers).not.toHaveProperty('Idempotency-Key')
  })

  it('encodes functionArgs and abi as JSON STRINGS, not arrays', async () => {
    // The API rejects arrays here. Getting this wrong fails at the boundary
    // with an opaque error, so pin it.
    fetchMock.mockResolvedValue(response(200, { executionId: 'x', status: 'completed' }))

    await run(
      kh().writeContract({
        contractAddress: '0xtoken',
        functionName: 'approve',
        functionArgs: ['0xspender', '0'],
        abi: [{ name: 'approve' }],
      }),
    )

    const body = JSON.parse(fetchMock.mock.calls[0]![1].body as string) as Record<string, unknown>
    expect(body['functionArgs']).toBe('["0xspender","0"]')
    expect(typeof body['abi']).toBe('string')
    expect(body['network']).toBe('sepolia')
  })

  it('passes simulate through as a strict boolean', async () => {
    fetchMock.mockResolvedValue(response(200, { success: true, status: 'simulated' }))

    await run(kh().simulate({ contractAddress: '0xt', functionName: 'approve' }))

    const body = JSON.parse(fetchMock.mock.calls[0]![1].body as string) as Record<string, unknown>
    expect(body['simulate']).toBe(true)
  })
})

describe('isSourceVerified', () => {
  it('is true when the explorer has the ABI', async () => {
    fetchMock.mockResolvedValue(response(200, { success: true, abi: [] }))
    expect(await run(kh().isSourceVerified('0xabc'))).toBe(true)
  })

  it('is false when the source is unverified', async () => {
    fetchMock.mockResolvedValue(
      response(200, { success: false, error: 'Contract source code is not verified' }),
    )
    expect(await run(kh().isSourceVerified('0xabc'))).toBe(false)
  })

  it('fails CLOSED — a lookup failure must not read as verified', async () => {
    // Failing open here would silently disable threat rule 1.
    fetchMock.mockImplementation(() => Promise.resolve(response(500, { error: 'explorer down' })))
    expect(await run(kh().isSourceVerified('0xabc'))).toBe(false)
  })
})

describe('getHeldTokens', () => {
  it('returns only tokens with a non-zero balance', async () => {
    fetchMock.mockResolvedValue(
      response(200, {
        walletAddress: '0xme',
        balances: [
          {
            chainId: 11155111,
            chainName: 'Ethereum Sepolia',
            nativeBalance: '0.05',
            tokens: [
              { tokenAddress: '0xheld', symbol: 'USDC', balanceRaw: '1000' },
              { tokenAddress: '0xempty', symbol: 'USDT', balanceRaw: '0' },
            ],
          },
        ],
      }),
    )

    expect(await run(kh().getHeldTokens(11155111))).toEqual(['0xheld'])
  })

  it('degrades to an empty list rather than throwing', async () => {
    // Token discovery failing must not take down the watcher.
    fetchMock.mockImplementation(() => Promise.resolve(response(500, { error: 'down' })))
    expect(await run(kh().getHeldTokens(11155111))).toEqual([])
  })
})
