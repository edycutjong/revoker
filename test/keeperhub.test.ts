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
  // Math.random is spied on by the jitter tests; unstubAllGlobals does not
  // undo vi.spyOn, and a leaked deterministic Math.random would quietly make
  // every later backoff assertion meaningless.
  vi.restoreAllMocks()
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

/**
 * Revoker is meant to run as several watchers against one API key, so a rate
 * limit or an upstream blip hits every instance in the same second. Lockstep
 * retries would then rebuild the exact burst that caused the 429. These tests
 * pin the jitter window rather than the mean, because a mean can be right while
 * every instance still fires at the same instant.
 */
describe('KeeperHub backoff jitter', () => {
  /** Attempt 0's deterministic term is 500ms; jitter scales it by 0.5–1.5. */
  async function firstBackoff(random: number): Promise<number> {
    vi.spyOn(Math, 'random').mockReturnValue(random)
    fetchMock
      .mockResolvedValueOnce(response(503, { error: 'down' }))
      .mockResolvedValueOnce(response(200, { hasWallet: true }))

    const settled = kh().getWallet()
    await vi.advanceTimersByTimeAsync(0)
    expect(fetchMock).toHaveBeenCalledTimes(1)

    let elapsed = 0
    while (fetchMock.mock.calls.length < 2 && elapsed < 5_000) {
      await vi.advanceTimersByTimeAsync(1)
      elapsed += 1
    }
    await settled
    return elapsed
  }

  it('waits the LOW end of the window when the jitter roll is minimal', async () => {
    expect(await firstBackoff(0)).toBe(250)
  })

  it('waits the HIGH end of the window when the jitter roll is maximal', async () => {
    // 250ms vs 750ms off the same attempt number is the whole point: two
    // instances that failed together no longer retry together.
    expect(await firstBackoff(1)).toBe(750)
  })

  it('jitters the transport-failure path on the same schedule as a 5xx', async () => {
    // fetch REJECTING is the same class of problem and must not be the one
    // path left retrying in lockstep.
    vi.spyOn(Math, 'random').mockReturnValue(0)
    fetchMock
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockResolvedValueOnce(response(200, { hasWallet: true }))

    const settled = kh().getWallet()
    await vi.advanceTimersByTimeAsync(249)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    await settled
  })

  it('honours an explicit Retry-After exactly, without jittering it', async () => {
    // The server named a time. Spreading around it would only make us early.
    vi.spyOn(Math, 'random').mockReturnValue(1)
    fetchMock
      .mockResolvedValueOnce(response(429, { error: 'slow down' }, { 'Retry-After': '2' }))
      .mockResolvedValueOnce(response(200, { hasWallet: true }))

    const settled = kh().getWallet()
    await vi.advanceTimersByTimeAsync(1_999)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    await settled
  })

  /**
   * RFC 9110 allows Retry-After to be delta-seconds OR an HTTP-date.
   * `Number("Wed, 21 Oct 2026 07:28:00 GMT")` is NaN, so the date form was
   * silently discarded and the jittered backoff used instead — the server named
   * a moment and we answered with a guess, which is exactly the lockstep retry
   * the jitter exists to break up.
   */
  describe('Retry-After as an HTTP-date', () => {
    it('waits until the named moment instead of falling back to jitter', async () => {
      // A jitter that would be visibly wrong if the fallback were taken.
      vi.spyOn(Math, 'random').mockReturnValue(1)
      const readyAt = new Date(Date.now() + 7_000).toUTCString()
      fetchMock
        .mockResolvedValueOnce(response(429, { error: 'slow down' }, { 'Retry-After': readyAt }))
        .mockResolvedValueOnce(response(200, { hasWallet: true }))

      const settled = kh().getWallet()
      // toUTCString truncates to whole seconds, so the wait lands inside the
      // second before the deadline rather than exactly on it.
      await vi.advanceTimersByTimeAsync(5_999)
      expect(fetchMock).toHaveBeenCalledTimes(1)
      await vi.advanceTimersByTimeAsync(1_001)
      expect(fetchMock).toHaveBeenCalledTimes(2)
      await settled
    })

    it('falls back to jittered backoff for a date already in the past', async () => {
      // A skewed clock must not turn "please wait" into an instant hammer.
      vi.spyOn(Math, 'random').mockReturnValue(0)
      fetchMock
        .mockResolvedValueOnce(
          response(429, { error: 'slow down' }, { 'Retry-After': new Date(0).toUTCString() }),
        )
        .mockResolvedValueOnce(response(200, { hasWallet: true }))

      const settled = kh().getWallet()
      await vi.advanceTimersByTimeAsync(249)
      expect(fetchMock).toHaveBeenCalledTimes(1)
      await vi.advanceTimersByTimeAsync(1)
      expect(fetchMock).toHaveBeenCalledTimes(2)
      await settled
    })

    it('falls back to jittered backoff for a header that is neither', async () => {
      vi.spyOn(Math, 'random').mockReturnValue(0)
      fetchMock
        .mockResolvedValueOnce(response(429, { error: 'slow down' }, { 'Retry-After': 'soon' }))
        .mockResolvedValueOnce(response(200, { hasWallet: true }))

      const settled = kh().getWallet()
      await vi.advanceTimersByTimeAsync(250)
      expect(fetchMock).toHaveBeenCalledTimes(2)
      await settled
    })

    it('falls back to jittered backoff for a non-positive delta-seconds', async () => {
      vi.spyOn(Math, 'random').mockReturnValue(0)
      fetchMock
        .mockResolvedValueOnce(response(429, { error: 'slow down' }, { 'Retry-After': '0' }))
        .mockResolvedValueOnce(response(200, { hasWallet: true }))

      const settled = kh().getWallet()
      await vi.advanceTimersByTimeAsync(250)
      expect(fetchMock).toHaveBeenCalledTimes(2)
      await settled
    })
  })

  /**
   * A 409 is normally terminal and must stay that way — `idempotency_conflict`
   * means the key was reused with a DIFFERENT body, and replaying that is how
   * you double-execute a write. `idempotency_in_progress` is the one the
   * platform documents as transient ("retry shortly"), and it is the one the
   * escalation ladder walks into: a rung racing its own predecessor got a hard
   * 409, and treating that as terminal threw away a revoke already in flight.
   */
  describe('409 idempotency', () => {
    it('retries idempotency_in_progress and succeeds', async () => {
      fetchMock
        .mockResolvedValueOnce(response(409, { error: { code: 'idempotency_in_progress' } }))
        .mockResolvedValueOnce(response(200, { hasWallet: true, walletAddress: '0xabc' }))

      const result = await run(kh().getWallet())

      expect(result.walletAddress).toBe('0xabc')
      expect(fetchMock).toHaveBeenCalledTimes(2)
    })

    it('finds the code wherever the envelope puts it', async () => {
      // The reference is not uniform across routes: {code}, {error} and
      // {error:{code}} all appear, and a client that matched only one shape
      // would retry on some routes and give up on others.
      for (const body of [
        { code: 'idempotency_in_progress' },
        { error: 'idempotency_in_progress' },
        { error: { code: 'idempotency_in_progress', message: 'still running' } },
      ]) {
        fetchMock.mockReset()
        fetchMock
          .mockResolvedValueOnce(response(409, body))
          .mockResolvedValueOnce(response(200, { hasWallet: true }))

        await run(kh().getWallet())
        expect(fetchMock).toHaveBeenCalledTimes(2)
      }
    })

    it('does NOT retry idempotency_conflict — the same key with a different body', async () => {
      fetchMock.mockResolvedValue(
        response(409, { error: { code: 'idempotency_conflict', originalExecutionId: 'e1' } }),
      )

      await expect(run(kh().getWallet())).rejects.toThrow(KeeperHubError)
      expect(fetchMock).toHaveBeenCalledTimes(1)
    })

    it('gives up on a permanently in-progress key rather than retrying forever', async () => {
      // A fresh Response per call: a body can only be read once, so a shared
      // instance would fail the second attempt for the wrong reason entirely.
      fetchMock.mockImplementation(() =>
        Promise.resolve(response(409, { error: { code: 'idempotency_in_progress' } })),
      )

      await expect(run(kh().getWallet())).rejects.toThrow(KeeperHubError)
      // The same 5-attempt ceiling every retryable status gets.
      expect(fetchMock).toHaveBeenCalledTimes(5)
    })
  })
})

/**
 * The docs are explicit: poll the status endpoint on the X-Poll-Interval-Hint
 * header rather than a fixed timer, and treat a hint of 0 as "terminal". The
 * header is control data that a body-only client throws away.
 */
describe('getExecutionStatus poll hint', () => {
  it('surfaces the X-Poll-Interval-Hint header as milliseconds', async () => {
    fetchMock.mockResolvedValue(
      response(200, { executionId: 'e1', status: 'pending' }, { 'X-Poll-Interval-Hint': '3' }),
    )

    expect((await run(kh().getExecutionStatus('e1'))).pollAfterMs).toBe(3_000)
  })

  it('preserves a hint of ZERO — the API saying the execution is terminal', async () => {
    // Must survive as 0 and not collapse to "absent": 0 carries meaning here.
    fetchMock.mockResolvedValue(
      response(200, { executionId: 'e1', status: 'completed' }, { 'X-Poll-Interval-Hint': '0' }),
    )

    expect((await run(kh().getExecutionStatus('e1'))).pollAfterMs).toBe(0)
  })

  it('omits pollAfterMs entirely when the header is absent', async () => {
    fetchMock.mockResolvedValue(response(200, { executionId: 'e1', status: 'pending' }))

    expect(await run(kh().getExecutionStatus('e1'))).not.toHaveProperty('pollAfterMs')
  })

  it('ignores an unparseable hint rather than sleeping for NaN', async () => {
    fetchMock.mockResolvedValue(
      response(200, { executionId: 'e1', status: 'pending' }, { 'X-Poll-Interval-Hint': 'soon' }),
    )

    expect(await run(kh().getExecutionStatus('e1'))).not.toHaveProperty('pollAfterMs')
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

  it('returns no tokens when the requested chain is absent from the response', async () => {
    // balances contains data for a different chain than was asked for — the
    // `chain?.tokens ?? []` fallback, not the try/catch, is what saves this.
    fetchMock.mockResolvedValue(
      response(200, {
        walletAddress: '0xme',
        balances: [
          {
            chainId: 11155111,
            chainName: 'Ethereum Sepolia',
            nativeBalance: '0.05',
            tokens: [{ tokenAddress: '0xheld', symbol: 'USDC', balanceRaw: '1000' }],
          },
        ],
      }),
    )

    expect(await run(kh().getHeldTokens(84532))).toEqual([])
  })
})

/**
 * fetch REJECTS (throws) on transport failure — DNS, ECONNRESET, TLS — rather
 * than resolving with a status. That path bypassed the retry policy entirely
 * until it was folded into the same schedule as a 5xx; these tests pin it.
 */
describe('KeeperHub transport-failure retry (fetch rejecting)', () => {
  it('retries a transport rejection and succeeds on a later attempt', async () => {
    fetchMock
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockResolvedValueOnce(response(200, { hasWallet: true, walletAddress: '0xabc' }))

    const result = await run(kh().getWallet())

    expect(result.walletAddress).toBe('0xabc')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('gives up after the bounded number of attempts', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNRESET'))

    await expect(run(kh().getWallet())).rejects.toThrow(/unreachable after 5 attempts$/)
    // initial + 4 retries, same bound as the 5xx/429 path
    expect(fetchMock).toHaveBeenCalledTimes(5)
  })

  it('preserves the original transport error as the cause of the thrown error', async () => {
    const original = new Error('ECONNRESET')
    fetchMock.mockRejectedValue(original)

    const error = (await run(kh().getWallet()).catch((e: unknown) => e)) as Error

    expect(error.cause).toBe(original)
  })
})

describe('KeeperHub throttle', () => {
  it('paces the request once the in-flight window is full, then proceeds', async () => {
    // RATE_LIMIT_PER_MINUTE is 60; the client throttles once 59 requests are
    // already recorded within the last minute, waiting out the window before
    // letting the 60th fire.
    // A fresh Response per call — a single shared instance can't have its
    // body read 60 times.
    fetchMock.mockImplementation(() => Promise.resolve(response(200, { hasWallet: true })))
    const client = kh()

    for (let i = 0; i < 59; i++) {
      await client.getWallet()
    }
    expect(fetchMock).toHaveBeenCalledTimes(59)

    const result = await run(client.getWallet())

    expect(result).toEqual({ hasWallet: true })
    expect(fetchMock).toHaveBeenCalledTimes(60)
  })
})

describe('KeeperHub error detail', () => {
  it('falls back to statusText when the error body is not JSON, and does not retry a 4xx', async () => {
    fetchMock.mockResolvedValue(
      new Response('<html>not json</html>', { status: 402, statusText: 'Payment Required' }),
    )

    await expect(run(kh().getWallet())).rejects.toMatchObject({
      status: 402,
      message: expect.stringContaining('Payment Required'),
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('treats an empty response body as null rather than failing to parse', async () => {
    // Some non-2xx responses (a 404 from a proxy in front of the API, say)
    // carry no body at all — `text` is `''`, which must short-circuit to
    // `null` rather than going through JSON.parse('').
    fetchMock.mockResolvedValue(new Response('', { status: 404, statusText: 'Not Found' }))

    await expect(run(kh().getWallet())).rejects.toMatchObject({
      status: 404,
      body: null,
      message: expect.stringContaining('Not Found'),
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('KeeperHub read/write wrappers', () => {
  it('getChains reads supported networks', async () => {
    fetchMock.mockResolvedValue(
      response(200, [{ chainId: 11155111, name: 'Ethereum Sepolia', explorerUrl: 'https://sepolia.etherscan.io' }]),
    )

    const chains = await run(kh().getChains())

    expect(chains).toEqual([
      { chainId: 11155111, name: 'Ethereum Sepolia', explorerUrl: 'https://sepolia.etherscan.io' },
    ])
    expect(fetchMock.mock.calls[0]![0]).toBe('https://example.test/api/chains')
    expect(fetchMock.mock.calls[0]![1].method).toBe('GET')
  })

  it('readContract POSTs a view call with simulate omitted', async () => {
    fetchMock.mockResolvedValue(response(200, { result: '1000' }))

    const result = await run(
      kh().readContract({ contractAddress: '0xtoken', functionName: 'balanceOf', functionArgs: ['0xowner'] }),
    )

    expect(result).toEqual({ result: '1000' })
    expect(fetchMock.mock.calls[0]![1].method).toBe('POST')
    const body = JSON.parse(fetchMock.mock.calls[0]![1].body as string) as Record<string, unknown>
    expect(body['functionName']).toBe('balanceOf')
    expect(body).not.toHaveProperty('simulate')
  })

  it('checkAndExecute nests the check, condition, and action bodies and reports whether it executed', async () => {
    fetchMock.mockResolvedValue(
      response(200, {
        executed: true,
        executionId: 'exec-1',
        status: 'completed',
        transactionHash: '0xhash',
        condition: { met: true, observedValue: '500', targetValue: '0', operator: 'gt' },
      }),
    )

    const result = await run(
      kh().checkAndExecute({
        check: { contractAddress: '0xtoken', functionName: 'allowance', functionArgs: ['0xowner', '0xspender'] },
        condition: { operator: 'gt', value: '0' },
        action: { contractAddress: '0xtoken', functionName: 'approve', functionArgs: ['0xspender', '0'] },
        idempotencyKey: 'revoke-1',
      }),
    )

    expect(result.executed).toBe(true)
    expect(result.condition.operator).toBe('gt')

    const headers = fetchMock.mock.calls[0]![1].headers as Record<string, string>
    expect(headers['Idempotency-Key']).toBe('revoke-1')

    const body = JSON.parse(fetchMock.mock.calls[0]![1].body as string) as Record<string, unknown>
    expect(body['functionName']).toBe('allowance')
    expect(body['condition']).toEqual({ operator: 'gt', value: '0' })
    expect((body['action'] as Record<string, unknown>)['functionName']).toBe('approve')
  })

  it('getExecutionStatus reads the audit record for an execution id', async () => {
    fetchMock.mockResolvedValue(
      response(200, { executionId: 'exec-1', status: 'completed', gasUsedWei: '21000', retryCount: 0 }),
    )

    const status = await run(kh().getExecutionStatus('exec-1'))

    expect(status.status).toBe('completed')
    expect(fetchMock.mock.calls[0]![0]).toBe('https://example.test/api/execute/exec-1/status')
    expect(fetchMock.mock.calls[0]![1].method).toBe('GET')
  })

  it('includes value and gasLimitMultiplier in the contract body when given', async () => {
    fetchMock.mockResolvedValue(response(200, { executionId: 'x', status: 'completed' }))

    await run(
      kh().writeContract({
        contractAddress: '0xtoken',
        functionName: 'deposit',
        value: '1000000000000000000',
        gasLimitMultiplier: '1.2',
      }),
    )

    const body = JSON.parse(fetchMock.mock.calls[0]![1].body as string) as Record<string, unknown>
    expect(body['value']).toBe('1000000000000000000')
    expect(body['gasLimitMultiplier']).toBe('1.2')
  })
})
