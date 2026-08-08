import { config, explorerTxUrl } from './config.js'

/**
 * Typed client over KeeperHub's Direct Execution API.
 *
 * KeeperHub is the execution layer: it holds the signing key in a Turnkey
 * enclave, sponsors gas, routes the transaction, and records the audit trail.
 * This process never sees a private key and never touches an RPC to write.
 */

export class KeeperHubError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: unknown,
  ) {
    super(message)
    this.name = 'KeeperHubError'
  }
}

export interface ExecutionResult {
  executionId: string
  status: string
  transactionHash?: string
  transactionLink?: string
  /** True when KeeperHub paid the gas rather than the org wallet. */
  sponsored?: boolean
  gasUsed?: string
  error?: string | null
}

export interface SimulationResult {
  success: boolean
  status: 'simulated'
  from: string
  to: string
  value: string
  gasEstimate: string
  simulatedReturnValue: unknown
  wouldRevert: boolean
}

export type ConditionOperator = 'eq' | 'neq' | 'gt' | 'lt' | 'gte' | 'lte'

export interface CheckAndExecuteResult {
  executed: boolean
  executionId?: string
  status?: string
  transactionHash?: string
  transactionLink?: string
  condition: {
    met: boolean
    observedValue: string
    targetValue: string
    operator: ConditionOperator
  }
}

interface ContractCallInput {
  contractAddress: string
  functionName: string
  functionArgs?: unknown[]
  abi?: unknown[]
  value?: string
  gasLimitMultiplier?: string
  simulate?: boolean
}

/** Direct-execution endpoints allow 60 req/min per key. */
const RATE_LIMIT_PER_MINUTE = 60

export class KeeperHub {
  #inFlight: number[] = []

  constructor(
    private readonly apiKey: string = config.apiKey,
    private readonly baseUrl: string = config.baseUrl,
    private readonly network: string = config.network,
  ) {}

  /**
   * Retries on 429 and 5xx with exponential backoff, honouring Retry-After.
   * Never retries a 4xx that isn't a rate limit — a bad request stays bad, and
   * blindly replaying a write is how you double-execute.
   */
  async #request<T>(
    path: string,
    init: { method?: string; body?: unknown; idempotencyKey?: string } = {},
    attempt = 0,
  ): Promise<T> {
    await this.#throttle()

    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
    }
    if (init.body !== undefined) headers['Content-Type'] = 'application/json'
    if (init.idempotencyKey) headers['Idempotency-Key'] = init.idempotencyKey

    const response = await fetch(`${this.baseUrl}${path}`, {
      method: init.method ?? 'GET',
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    })

    const text = await response.text()
    let parsed: unknown
    try {
      parsed = text ? JSON.parse(text) : null
    } catch {
      parsed = text
    }

    if (response.ok) return parsed as T

    const retryable = response.status === 429 || response.status >= 500
    if (retryable && attempt < 4) {
      const retryAfter = Number(response.headers.get('Retry-After'))
      const backoffMs = Number.isFinite(retryAfter) && retryAfter > 0
        ? retryAfter * 1000
        : 2 ** attempt * 500
      await sleep(backoffMs)
      return this.#request<T>(path, init, attempt + 1)
    }

    const detail =
      parsed && typeof parsed === 'object' && 'error' in parsed
        ? JSON.stringify(parsed.error)
        : response.statusText
    throw new KeeperHubError(`KeeperHub ${response.status} on ${path}: ${detail}`, response.status, parsed)
  }

  /** Client-side pacing so we surface fewer 429s in the first place. */
  async #throttle(): Promise<void> {
    const now = Date.now()
    this.#inFlight = this.#inFlight.filter((t) => now - t < 60_000)
    if (this.#inFlight.length >= RATE_LIMIT_PER_MINUTE - 1) {
      const oldest = this.#inFlight[0]!
      await sleep(60_000 - (now - oldest) + 50)
    }
    this.#inFlight.push(Date.now())
  }

  // ---- reads -------------------------------------------------------------

  /** GET /api/user/wallet — the org's Turnkey signer. */
  async getWallet(): Promise<{ hasWallet: boolean; walletAddress?: string; walletId?: string }> {
    return this.#request('/api/user/wallet')
  }

  /**
   * GET /api/user/wallet/balances — holdings across supported chains.
   *
   * Only covers KeeperHub's curated token registry, so it complements an
   * explicit watchlist rather than replacing it.
   */
  async getWalletBalances(chainId: number = config.chainId): Promise<{
    walletAddress: string
    balances: Array<{
      chainId: number
      chainName: string
      nativeBalance: string
      tokens: Array<{ tokenAddress: string; symbol: string; balanceRaw: string }>
    }>
  }> {
    return this.#request(`/api/user/wallet/balances?chainId=${chainId}`)
  }

  /** Token addresses this wallet actually holds a non-zero balance of. */
  async getHeldTokens(chainId: number = config.chainId): Promise<string[]> {
    try {
      const { balances } = await this.getWalletBalances(chainId)
      const chain = balances.find((b) => b.chainId === chainId)
      return (chain?.tokens ?? [])
        .filter((t) => t.balanceRaw !== '0')
        .map((t) => t.tokenAddress)
    } catch {
      return []
    }
  }

  /** GET /api/chains — supported networks with explorer metadata. */
  async getChains(): Promise<Array<{ chainId: number; name: string; explorerUrl: string }>> {
    return this.#request('/api/chains')
  }

  /** GET /api/chains/{chainId}/abi?address= — explorer-backed ABI resolution. */
  async getAbi(
    address: string,
    chainId: number = config.chainId,
  ): Promise<{ success: boolean; abi?: unknown[]; error?: string; explorerUrl?: string }> {
    return this.#request(`/api/chains/${chainId}/abi?address=${address}`)
  }

  /**
   * Whether the contract's source is verified on the block explorer.
   *
   * Derived from ABI resolution: KeeperHub returns `success: false` with
   * "Contract source code is not verified" for unverified contracts. Unverified
   * source is not proof of malice, but it means nobody can read what the code
   * actually does — which is exactly the position a victim is in when they
   * grant an unlimited approval.
   */
  async isSourceVerified(address: string, chainId: number = config.chainId): Promise<boolean> {
    try {
      return (await this.getAbi(address, chainId)).success === true
    } catch {
      // Treat a lookup failure as "unknown", not "verified" — failing open here
      // would silently disable the rule.
      return false
    }
  }

  /** Read a view/pure function. Returns immediately, costs no gas. */
  async readContract(input: Omit<ContractCallInput, 'simulate'>): Promise<{ result: string }> {
    return this.#request('/api/execute/contract-call', {
      method: 'POST',
      body: this.#contractBody(input),
    })
  }

  // ---- writes ------------------------------------------------------------

  /** POST /api/execute/transfer — native or ERC-20 transfer. */
  async transfer(input: {
    recipientAddress: string
    amount: string
    tokenAddress?: string
    idempotencyKey?: string
    simulate?: boolean
  }): Promise<ExecutionResult> {
    const { idempotencyKey, ...rest } = input
    return this.#request('/api/execute/transfer', {
      method: 'POST',
      body: { network: this.network, ...rest },
      idempotencyKey,
    })
  }

  /** POST /api/execute/contract-call — state-changing call. */
  async writeContract(
    input: ContractCallInput & { idempotencyKey?: string },
  ): Promise<ExecutionResult> {
    const { idempotencyKey, ...rest } = input
    return this.#request('/api/execute/contract-call', {
      method: 'POST',
      body: this.#contractBody(rest),
      idempotencyKey,
    })
  }

  /** Dry run: validates, encodes, estimates gas, and calls — without broadcasting. */
  async simulate(input: ContractCallInput): Promise<SimulationResult> {
    return this.#request('/api/execute/contract-call', {
      method: 'POST',
      body: this.#contractBody({ ...input, simulate: true }),
    })
  }

  /**
   * POST /api/execute/check-and-execute — read a value, evaluate a condition,
   * and conditionally write, in one server-side call.
   *
   * This is the core of Revoker: the allowance is re-read and the revoke is
   * fired inside the same operation, so a drainer cannot slip a transfer
   * between our check and our act (the classic TOCTOU race).
   */
  async checkAndExecute(input: {
    check: ContractCallInput
    condition: { operator: ConditionOperator; value: string }
    action: ContractCallInput
    idempotencyKey?: string
  }): Promise<CheckAndExecuteResult> {
    return this.#request('/api/execute/check-and-execute', {
      method: 'POST',
      body: {
        ...this.#contractBody(input.check),
        condition: input.condition,
        action: this.#contractBody(input.action),
      },
      idempotencyKey: input.idempotencyKey,
    })
  }

  /** GET /api/execute/{id}/status — audit record, receipts, gas, sponsorship. */
  async getExecutionStatus(executionId: string): Promise<
    ExecutionResult & {
      receipts?: Array<{ hash: string; blockNumber: number; receiptStatus: string; gasUsed: string }>
      createdAt?: string
      completedAt?: string
      retryCount?: number
      /** Gas is reported as `gasUsedWei` here, not `gasUsed` as on the execute responses. */
      gasUsedWei?: string
      gasPriceWei?: string
    }
  > {
    return this.#request(`/api/execute/${executionId}/status`)
  }

  #contractBody(input: ContractCallInput): Record<string, unknown> {
    const body: Record<string, unknown> = {
      network: this.network,
      contractAddress: input.contractAddress,
      functionName: input.functionName,
    }
    // The API takes args and ABI as JSON *strings*, not arrays.
    if (input.functionArgs !== undefined) body['functionArgs'] = JSON.stringify(input.functionArgs)
    if (input.abi !== undefined) body['abi'] = JSON.stringify(input.abi)
    if (input.value !== undefined) body['value'] = input.value
    if (input.gasLimitMultiplier !== undefined) body['gasLimitMultiplier'] = input.gasLimitMultiplier
    if (input.simulate !== undefined) body['simulate'] = input.simulate
    return body
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

export { explorerTxUrl }
