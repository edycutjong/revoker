import type { Address } from 'viem'
import { audit } from './audit.js'
import { readAllowance } from './chain.js'
import { explorerTxUrl, type KeeperHub } from './keeperhub.js'

/**
 * The revoke action.
 *
 * The whole design decision lives here: the allowance re-read and the
 * `approve(spender, 0)` are one server-side operation via check-and-execute,
 * not a read followed by a write. A read-then-write agent has a window between
 * deciding and acting, and that window is precisely what a drainer watching the
 * mempool needs. Closing it is the difference between a security agent and a
 * script that usually wins.
 */

const ALLOWANCE_ABI = JSON.stringify([
  {
    inputs: [
      { name: 'owner', type: 'address' },
      { name: 'spender', type: 'address' },
    ],
    name: 'allowance',
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
])

const APPROVE_ABI = JSON.stringify([
  {
    inputs: [
      { name: 'spender', type: 'address' },
      { name: 'value', type: 'uint256' },
    ],
    name: 'approve',
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
])

export interface RevokeOutcome {
  executed: boolean
  transactionHash?: string
  explorerUrl?: string
  /** Detect-to-confirmed latency in milliseconds. The headline number. */
  latencyMs: number
  observedAllowance?: string
  allowanceAfter?: bigint
  sponsored?: boolean
  gasUsedWei?: string
  error?: string
}

export async function revokeApproval(input: {
  kh: KeeperHub
  token: Address
  owner: Address
  spender: Address
  /** Deduplicates retries of the same logical revoke within KeeperHub's 24h window. */
  idempotencyKey?: string
  detectedAt?: number
}): Promise<RevokeOutcome> {
  const { kh, token, owner, spender } = input
  const startedAt = input.detectedAt ?? Date.now()

  audit('revoke.submit', { token, owner, spender, method: 'check-and-execute' })

  try {
    const result = await kh.checkAndExecute({
      check: {
        contractAddress: token,
        functionName: 'allowance',
        functionArgs: [owner, spender],
        abi: JSON.parse(ALLOWANCE_ABI) as unknown[],
      },
      // Only revoke if there is still something to revoke. If another actor
      // already zeroed it, the condition fails and no gas is spent.
      condition: { operator: 'gt', value: '0' },
      action: {
        contractAddress: token,
        functionName: 'approve',
        functionArgs: [spender, '0'],
        abi: JSON.parse(APPROVE_ABI) as unknown[],
      },
      ...(input.idempotencyKey ? { idempotencyKey: input.idempotencyKey } : {}),
    })

    if (!result.executed) {
      const latencyMs = Date.now() - startedAt
      audit('revoke.skipped', {
        token,
        spender,
        reason: 'allowance already zero at execution time',
        observed: result.condition?.observedValue,
        latencyMs,
      })
      return { executed: false, latencyMs, observedAllowance: result.condition?.observedValue }
    }

    // check-and-execute returns before the hash is attached; the execution
    // record is the authoritative source for it.
    let hash = result.transactionHash
    let sponsored: boolean | undefined
    let gasUsedWei: string | undefined

    if (result.executionId) {
      const status = await kh.getExecutionStatus(result.executionId)
      hash = status.transactionHash ?? hash
      sponsored = status.sponsored
      gasUsedWei = status.gasUsedWei
    }

    // Confirm against the chain rather than trusting the execution report.
    const allowanceAfter = await readAllowance(token, owner, spender)
    const latencyMs = Date.now() - startedAt

    const outcome: RevokeOutcome = {
      executed: true,
      latencyMs,
      allowanceAfter,
      ...(hash ? { transactionHash: hash, explorerUrl: explorerTxUrl(hash) } : {}),
      ...(result.condition ? { observedAllowance: result.condition.observedValue } : {}),
      ...(sponsored !== undefined ? { sponsored } : {}),
      ...(gasUsedWei ? { gasUsedWei } : {}),
    }

    if (allowanceAfter === 0n) {
      audit('revoke.confirmed', {
        token,
        spender,
        txHash: hash,
        explorerUrl: outcome.explorerUrl,
        latencyMs,
        sponsored,
        gasUsedWei,
        allowanceAfter: '0',
      })
    } else {
      // Reported success but the allowance is still live: report the truth.
      audit('revoke.failed', {
        token,
        spender,
        txHash: hash,
        reason: 'execution reported success but allowance is still non-zero',
        allowanceAfter: allowanceAfter.toString(),
        latencyMs,
      })
      outcome.error = 'allowance still non-zero after reported success'
    }

    return outcome
  } catch (error) {
    const latencyMs = Date.now() - startedAt
    const message = error instanceof Error ? error.message : String(error)
    audit('revoke.failed', { token, spender, error: message, latencyMs })
    return { executed: false, latencyMs, error: message }
  }
}
