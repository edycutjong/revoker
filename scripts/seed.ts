/**
 * Deterministic Sepolia seed: stage the exact threat Revoker is built to stop.
 *
 *   pnpm seed              reuse existing deployments, re-arm the approval
 *   pnpm seed --redeploy   force fresh contract deployments
 *
 * Idempotent by design. Re-running does not redeploy, does not double-mint, and
 * leaves the chain in the same state: victim funded, unlimited approval live.
 * `pnpm bench` calls this between cycles to re-arm the threat.
 *
 * The victim is necessarily the org's Turnkey account. approve(spender, 0)
 * clears msg.sender's allowance and nobody else's, and KeeperHub signs only for
 * that account — so it must be the wallet that grants the approval too.
 *
 * The approval is armed through the `kh` CLI when it is installed (see
 * `make arm` for the full operator flow) and through the REST client when it is
 * not. Both leave the chain in the same state.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { createWalletClient, http, type Address, type Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'
import { config } from '../src/config.js'
import { KeeperHub } from '../src/keeperhub.js'
import { MAX_UINT256, publicClient, readAllowance, readBalance, hasCodeAt } from '../src/chain.js'
import { khArmApproval, khVersion } from './kh-cli.js'

const DEPLOYMENTS_PATH = new URL('../deployments.json', import.meta.url)
const MINT_AMOUNT = 10_000_000_000n // 10,000 mUSDC at 6 decimals

interface Deployments {
  sepolia: {
    chainId: number
    explorer: string
    contracts: Record<string, { address: string; deployTx: string; note: string }>
    watchedWallet: { address: string; note: string }
  }
}

function loadArtifact(name: string): { abi: unknown[]; bytecode: Hex } {
  const path = new URL(`../contracts/out/${name}.sol/${name}.json`, import.meta.url)
  let raw: string
  try {
    raw = readFileSync(path, 'utf8')
  } catch {
    throw new Error(
      `Missing build artifact for ${name}. Run: cd contracts && forge build`,
    )
  }
  const artifact = JSON.parse(raw) as { abi: unknown[]; bytecode: { object: Hex } }
  return { abi: artifact.abi, bytecode: artifact.bytecode.object }
}

function readDeployments(): Deployments {
  return JSON.parse(readFileSync(DEPLOYMENTS_PATH, 'utf8')) as Deployments
}

function writeDeployments(data: Deployments): void {
  writeFileSync(DEPLOYMENTS_PATH, `${JSON.stringify(data, null, 2)}\n`)
}

const MINT_ABI = [
  {
    inputs: [
      { name: 'to', type: 'address' },
      { name: 'amount', type: 'uint256' },
    ],
    name: 'mint',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
] as const

const APPROVE_ABI = [
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
]

async function main(): Promise<void> {
  const forceRedeploy = process.argv.includes('--redeploy')
  const account = privateKeyToAccount(config.deployerPrivateKey)
  const wallet = createWalletClient({ account, chain: sepolia, transport: http(config.rpcUrl) })
  const victim = config.walletAddress
  const deployments = readDeployments()

  console.log('Revoker — seeding the threat scenario')
  console.log(`  victim   : ${victim}  (Turnkey account — the only address KeeperHub signs for)`)
  console.log(`  deployer : ${account.address}  (throwaway; deploys fixtures, plays the adversary)`)
  console.log()

  // ---- 1. contracts ------------------------------------------------------
  const existing = deployments.sepolia.contracts
  const deployed: Record<string, Address> = {}

  for (const name of ['MockUSDC', 'RoachMotelSpender'] as const) {
    const recorded = existing[name]?.address as Address | undefined
    const live = recorded ? await hasCodeAt(recorded) : false

    if (!forceRedeploy && recorded && live) {
      deployed[name] = recorded
      console.log(`  ✓ ${name.padEnd(18)} reusing ${recorded}`)
      continue
    }

    const { abi, bytecode } = loadArtifact(name)
    const hash = await wallet.deployContract({ abi, bytecode, args: [] })
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    if (!receipt.contractAddress) throw new Error(`${name} deployment produced no address`)

    deployed[name] = receipt.contractAddress
    existing[name] = {
      address: receipt.contractAddress,
      deployTx: hash,
      note: existing[name]?.note ?? '',
    }
    console.log(`  + ${name.padEnd(18)} deployed ${receipt.contractAddress}`)
  }

  writeDeployments(deployments)

  const token = deployed['MockUSDC']!
  const spender = deployed['RoachMotelSpender']!

  // ---- 2. fund the victim ------------------------------------------------
  const balance = await readBalance(token, victim)
  if (balance < MINT_AMOUNT) {
    const hash = await wallet.writeContract({
      address: token,
      abi: MINT_ABI,
      functionName: 'mint',
      args: [victim, MINT_AMOUNT - balance],
    })
    await publicClient.waitForTransactionReceipt({ hash })
    console.log(`  + minted   ${(Number(MINT_AMOUNT - balance) / 1e6).toFixed(2)} mUSDC to victim`)
  } else {
    console.log(`  ✓ victim already holds ${(Number(balance) / 1e6).toFixed(2)} mUSDC`)
  }

  // ---- 3. arm the threat -------------------------------------------------
  // This MUST go through KeeperHub: only it can sign for the Turnkey account.
  //
  // Steps 1 and 2 are the throwaway deployer's own transactions, so they stay on
  // viem — kh signs as the org wallet and could not send them. This one is the
  // opposite: it is the Turnkey account's approval, it is an operator action
  // rather than something the agent ever does, and `kh execute contract-call` is
  // the command a human would type for it. So prefer the CLI and fall back to
  // the REST client when kh is not installed, rather than making the CLI a
  // prerequisite for contributing.
  const allowance = await readAllowance(token, victim, spender)
  if (allowance === MAX_UINT256) {
    console.log('  ✓ unlimited approval already live')
  } else {
    const version = khVersion()
    let transactionHash: string | undefined

    if (version === null) {
      console.log('  · kh not found — arming over REST (brew install keeperhub/tap/kh)')
      const kh = new KeeperHub()
      const result = await kh.writeContract({
        contractAddress: token,
        functionName: 'approve',
        functionArgs: [spender, MAX_UINT256.toString()],
        abi: APPROVE_ABI,
      })
      // The write returns before the hash is attached; poll for the record.
      const status = await kh.getExecutionStatus(result.executionId)
      transactionHash = status.transactionHash
    } else {
      console.log(`  · arming with ${version}`)
      const result = khArmApproval({
        chainId: config.chainId,
        token,
        spender,
        amount: MAX_UINT256.toString(),
      })
      transactionHash = result.transactionHash
    }

    console.log(`  + approved MAX_UINT256 -> ${spender}`)
    console.log(`    ${transactionHash}`)
  }

  // ---- 4. report ---------------------------------------------------------
  const finalAllowance = await readAllowance(token, victim, spender)
  const finalBalance = await readBalance(token, victim)

  console.log()
  console.log('  THREAT ARMED')
  console.log(`    token     ${token}`)
  console.log(`    spender   ${spender}`)
  console.log(`    at risk   ${(Number(finalBalance) / 1e6).toFixed(2)} mUSDC`)
  console.log(`    allowance ${finalAllowance === MAX_UINT256 ? 'MAX_UINT256 (unlimited)' : finalAllowance}`)
  console.log()

  if (finalAllowance !== MAX_UINT256) {
    throw new Error('Seed finished but the unlimited approval is not live')
  }
  console.log('  Run `pnpm watch -- --once` to watch Revoker take it away.')
}

main().catch((error: unknown) => {
  console.error(`\n❌ Seed failed: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
