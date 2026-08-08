/**
 * Deploy Permit2AllowanceView — the read the Permit2 revoke guard needs.
 *
 *   pnpm deploy:view              deploy if it is not already live, then verify
 *   pnpm deploy:view --redeploy   force a fresh deployment
 *
 * WHY THIS EXISTS. The Permit2 revoke goes through KeeperHub's
 * `check-and-execute`, whose condition schema is exactly `{operator, value}` —
 * no output index, no tuple path. Permit2's own `allowance()` returns three
 * values, so guarding on it directly gives the evaluator no scalar to compare:
 * it reports `observedValue: undefined`, scores `gt 0` as false, and SKIPS the
 * write while logging what looks like a clean skip. That was observed on Sepolia
 * against a real armed grant. The helper flattens the tuple to one `uint160` so
 * the guard has something to compare, and `lockdown()` stays the action — read
 * and write remain ONE server-side operation, so the TOCTOU property is intact.
 *
 * Without this address in deployments.json the Permit2 revoke path refuses to
 * run at all. That is deliberate: the only alternative to a guarded lockdown is
 * an unguarded one, and an unguarded write is the window this project closes.
 *
 * Signed by the throwaway DEPLOYER_PRIVATE_KEY, like every other fixture deploy
 * — Foundry/viem must sign locally and the Turnkey key cannot leave its enclave.
 * The helper is ownerless and stateless, so who deployed it confers nothing.
 *
 * Idempotent: a recorded address with live code is reused and nothing is sent.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { createWalletClient, http, type Address, type Hex } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { sepolia } from 'viem/chains'
import { config, explorerTxUrl } from '../src/config.js'
import { hasCodeAt, publicClient } from '../src/chain.js'
import {
  PERMIT2_ADDRESS,
  PERMIT2_ALLOWANCE_VIEW_ABI,
  PERMIT2_ALLOWANCE_VIEW_NAME,
  permit2AllowanceViewAddress,
  readPermit2Allowance,
} from '../src/permit2.js'

const DEPLOYMENTS_PATH = new URL('../deployments.json', import.meta.url)

const NOTE =
  'Guard read for the Permit2 revoke. Flattens Permit2 allowance() ' +
  "(uint160,uint48,uint48) to one uint160, because check-and-execute's condition " +
  'cannot select a tuple member. Ownerless, stateless, immutable, pure pass-through.'

/** Read back on the deployed helper to prove it is the contract we think it is. */
const PERMIT2_GETTER_ABI = [
  {
    inputs: [],
    name: 'PERMIT2',
    outputs: [{ name: '', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
] as const

interface Deployments {
  [network: string]:
    | {
        contracts?: Record<string, { address: string; deployTx?: string; note?: string }>
      }
    | undefined
}

function loadArtifact(name: string): { abi: unknown[]; bytecode: Hex } {
  const path = new URL(`../contracts/out/${name}.sol/${name}.json`, import.meta.url)
  let raw: string
  try {
    raw = readFileSync(path, 'utf8')
  } catch {
    throw new Error(`Missing build artifact for ${name}. Run: cd contracts && forge build`)
  }
  const artifact = JSON.parse(raw) as { abi: unknown[]; bytecode: { object: Hex } }
  return { abi: artifact.abi, bytecode: artifact.bytecode.object }
}

async function main(): Promise<void> {
  const forceRedeploy = process.argv.includes('--redeploy')
  const account = privateKeyToAccount(config.deployerPrivateKey)
  const wallet = createWalletClient({ account, chain: sepolia, transport: http(config.rpcUrl) })

  const deployments = JSON.parse(readFileSync(DEPLOYMENTS_PATH, 'utf8')) as Deployments
  const network = deployments[config.network]
  if (network === undefined) {
    throw new Error(`deployments.json has no "${config.network}" section to record the helper in`)
  }
  const contracts = (network.contracts ??= {})

  console.log(`Revoker — deploying ${PERMIT2_ALLOWANCE_VIEW_NAME}`)
  console.log(`  network  : ${config.network}  (chainId ${config.chainId})`)
  console.log(`  deployer : ${account.address}  (throwaway; the helper is ownerless)`)
  console.log(`  permit2  : ${PERMIT2_ADDRESS}  (canonical, hardcoded in the helper)`)
  console.log()

  // A CALL to an address with no code returns empty data rather than reverting,
  // so on a chain without Permit2 this helper would be a contract whose every
  // read reverts on decode — deployed, recorded, and useless. Refuse up front.
  if (!(await hasCodeAt(PERMIT2_ADDRESS))) {
    throw new Error(
      `No contract code at ${PERMIT2_ADDRESS} on chainId ${config.chainId} — ` +
        'Permit2 is not deployed on this chain, so the helper would have nothing to read',
    )
  }

  // ---- 1. deploy, or reuse -----------------------------------------------
  const recorded = contracts[PERMIT2_ALLOWANCE_VIEW_NAME]?.address as Address | undefined
  const live = recorded !== undefined && (await hasCodeAt(recorded))
  let address: Address

  if (!forceRedeploy && recorded !== undefined && live) {
    address = recorded
    console.log(`  ✓ reusing ${address}`)
  } else {
    const { abi, bytecode } = loadArtifact(PERMIT2_ALLOWANCE_VIEW_NAME)
    const hash = await wallet.deployContract({ abi, bytecode, args: [] })
    const receipt = await publicClient.waitForTransactionReceipt({ hash })
    if (!receipt.contractAddress) throw new Error('deployment produced no contract address')

    address = receipt.contractAddress
    contracts[PERMIT2_ALLOWANCE_VIEW_NAME] = { address, deployTx: hash, note: NOTE }
    writeFileSync(DEPLOYMENTS_PATH, `${JSON.stringify(deployments, null, 2)}\n`)
    console.log(`  + deployed ${address}`)
    console.log(`    ${explorerTxUrl(hash)}`)
  }

  // ---- 2. prove it is the right contract ----------------------------------
  // Bytecode at an address is not evidence of WHICH bytecode. Reading the
  // constant back is: a helper pointed anywhere but canonical Permit2 would
  // guard a number the lockdown does not zero.
  const delegatesTo = await publicClient.readContract({
    address,
    abi: PERMIT2_GETTER_ABI,
    functionName: 'PERMIT2',
  })
  if (delegatesTo.toLowerCase() !== PERMIT2_ADDRESS.toLowerCase()) {
    throw new Error(`Deployed helper reads ${delegatesTo}, not canonical Permit2 — refusing to record it`)
  }
  console.log(`  ✓ helper delegates to canonical Permit2`)

  // ---- 3. prove the agent can find it -------------------------------------
  // The same resolution src/revoke.ts performs, against the file just written.
  // A deploy that succeeds but leaves the agent unable to locate the address is
  // the failure this whole step exists to prevent.
  const resolved = permit2AllowanceViewAddress()
  if (resolved.toLowerCase() !== address.toLowerCase()) {
    throw new Error(`deployments.json resolves to ${resolved}, not the deployed ${address}`)
  }
  console.log('  ✓ deployments.json resolves to it — the Permit2 revoke path is armed')

  // ---- 4. cross-check against the live fixture ----------------------------
  // The strongest check available without sending anything: the helper's
  // flattened read must equal the `amount` member of a direct tuple read of the
  // very same slot. Skipped, loudly, when the demo fixtures are not seeded.
  const token = contracts['MockUSDC']?.address as Address | undefined
  const spender = contracts['RoachMotelSpender']?.address as Address | undefined

  if (token === undefined || spender === undefined) {
    console.log('  · fixtures not seeded — skipping the live cross-check (run `pnpm seed`)')
  } else {
    const owner = config.walletAddress
    const [viaHelper, direct] = await Promise.all([
      publicClient.readContract({
        address,
        abi: PERMIT2_ALLOWANCE_VIEW_ABI,
        functionName: 'amountOf',
        args: [owner, token, spender],
      }),
      readPermit2Allowance(owner, token, spender),
    ])

    if (viaHelper !== direct.amount) {
      throw new Error(`Helper reads ${viaHelper} where Permit2 reads ${direct.amount} — do not use it`)
    }

    const liveAmount = await publicClient.readContract({
      address,
      abi: PERMIT2_ALLOWANCE_VIEW_ABI,
      functionName: 'liveAmountOf',
      args: [owner, token, spender],
    })

    console.log()
    console.log('  CROSS-CHECK against the seeded slot')
    console.log(`    owner        ${owner}`)
    console.log(`    amountOf     ${viaHelper}  (matches Permit2's own amount member)`)
    console.log(`    liveAmountOf ${liveAmount}  (zero once expired — this is what guards the revoke)`)
    console.log(`    expiration   ${direct.expiration}`)
  }

  console.log()
  console.log('  Verify it yourself — plain eth_call, no credentials:')
  console.log(`    cast call ${address} "PERMIT2()(address)" --rpc-url ${config.rpcUrl}`)
  console.log(
    `    cast call ${address} "liveAmountOf(address,address,address)(uint160)" \\\n` +
      `      ${config.walletAddress} ${token ?? '<token>'} ${spender ?? '<spender>'} \\\n` +
      `      --rpc-url ${config.rpcUrl}`,
  )
  console.log()
  console.log('  Run `pnpm watch -- --once` to watch the Permit2 lockdown land.')
}

main().catch((error: unknown) => {
  console.error(
    `\n❌ ${PERMIT2_ALLOWANCE_VIEW_NAME} deploy failed: ${error instanceof Error ? error.message : String(error)}`,
  )
  process.exitCode = 1
})
