/**
 * Day-1 integration spike: prove KeeperHub actually executes on-chain before
 * anything is built on top of it.
 *
 * Exercises five real KeeperHub surfaces end to end and then independently
 * verifies the result against a public RPC, because trusting an API's own
 * claim that it landed a transaction is not proof.
 *
 *   pnpm spike
 */
import { KeeperHub, explorerTxUrl } from '../src/keeperhub.js'
import { config } from '../src/config.js'

const kh = new KeeperHub()

async function rpc<T>(method: string, params: unknown[]): Promise<T> {
  const response = await fetch(config.rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  const json = (await response.json()) as { result?: T; error?: { message: string } }
  if (json.error) throw new Error(`RPC ${method}: ${json.error.message}`)
  return json.result as T
}

function step(n: number, title: string): void {
  console.log(`\n${'─'.repeat(64)}\n${n}. ${title}\n${'─'.repeat(64)}`)
}

async function main(): Promise<void> {
  console.log('Revoker — KeeperHub integration spike')
  console.log(`network: ${config.network} (chainId ${config.chainId})`)

  step(1, 'GET /api/user/wallet — resolve the signer')
  const wallet = await kh.getWallet()
  console.log(`  hasWallet     : ${wallet.hasWallet}`)
  console.log(`  walletAddress : ${wallet.walletAddress}`)
  if (!wallet.hasWallet || !wallet.walletAddress) {
    throw new Error('Org has no Turnkey wallet — nothing can be signed.')
  }
  if (wallet.walletAddress.toLowerCase() !== config.walletAddress.toLowerCase()) {
    throw new Error(
      `KH_WALLET_ADDRESS (${config.walletAddress}) does not match the org wallet ` +
        `(${wallet.walletAddress}). KeeperHub can only sign for its own wallet.`,
    )
  }
  console.log('  ✓ configured address matches the signer KeeperHub controls')

  step(2, 'GET /api/chains — confirm the target network is supported')
  const chains = await kh.getChains()
  const chain = chains.find((c) => c.chainId === config.chainId)
  if (!chain) throw new Error(`chainId ${config.chainId} not supported by KeeperHub`)
  console.log(`  ${chain.name} (${chain.chainId}) — ${chain.explorerUrl}`)

  step(3, 'eth_getBalance — is the signer funded?')
  const balanceHex = await rpc<string>('eth_getBalance', [config.walletAddress, 'latest'])
  const balanceWei = BigInt(balanceHex)
  console.log(`  ${balanceWei} wei (${Number(balanceWei) / 1e18} ETH)`)

  step(4, 'POST /api/execute/transfer {simulate:true} — dry run, no broadcast')
  const simulated = await kh.transfer({
    recipientAddress: config.walletAddress,
    amount: '0.0001',
    simulate: true,
  })
  console.log(`  ${JSON.stringify(simulated)}`)

  step(5, 'POST /api/execute/transfer — REAL transaction')
  // Stable idempotency key: re-running the spike replays the original response
  // for 24h rather than burning a second transaction.
  const idempotencyKey = `revoker-spike-${new Date().toISOString().slice(0, 10)}`
  const started = Date.now()
  const execution = await kh.transfer({
    recipientAddress: config.walletAddress,
    amount: '0.0001',
    idempotencyKey,
  })
  const elapsedMs = Date.now() - started
  console.log(`  executionId     : ${execution.executionId}`)
  console.log(`  status          : ${execution.status}`)
  console.log(`  transactionHash : ${execution.transactionHash}`)
  console.log(`  elapsed         : ${(elapsedMs / 1000).toFixed(1)}s`)

  const hash = execution.transactionHash
  if (!hash) throw new Error('KeeperHub reported completion without a transaction hash')

  step(6, 'GET /api/execute/{id}/status — audit record')
  const status = await kh.getExecutionStatus(execution.executionId)
  console.log(`  sponsored : ${status.sponsored}`)
  console.log(`  gasUsed   : ${status.gasUsedWei} @ ${status.gasPriceWei} wei/gas`)
  console.log(`  retries   : ${status.retryCount}`)
  for (const receipt of status.receipts ?? []) {
    console.log(`  receipt   : block ${receipt.blockNumber}, ${receipt.receiptStatus}`)
  }

  step(7, 'eth_getTransactionReceipt — independent on-chain verification')
  const receipt = await rpc<{ status: string; blockNumber: string; gasUsed: string } | null>(
    'eth_getTransactionReceipt',
    [hash],
  )
  if (!receipt) throw new Error(`Transaction ${hash} not found on-chain via ${config.rpcUrl}`)
  const mined = receipt.status === '0x1'
  console.log(`  on-chain status : ${mined ? 'SUCCESS' : 'FAILED'}`)
  console.log(`  block           : ${Number(BigInt(receipt.blockNumber))}`)
  if (!mined) throw new Error('Transaction reverted on-chain')

  const balanceAfter = BigInt(await rpc<string>('eth_getBalance', [config.walletAddress, 'latest']))
  console.log(`  balance delta   : ${balanceAfter - balanceWei} wei`)
  if (status.sponsored && balanceAfter === balanceWei) {
    console.log('  note            : gas was sponsored by KeeperHub — signer paid nothing')
  }

  console.log(`\n✅ Spike passed. Real transaction:\n   ${explorerTxUrl(hash)}\n`)
}

main().catch((error: unknown) => {
  console.error(`\n❌ Spike failed: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
