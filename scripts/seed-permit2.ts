/**
 * Arm a Permit2 allowance on Sepolia — the exposure an ERC-20 `Approval` log
 * cannot see.
 *
 *   pnpm seed:permit2            arm the grant, skipping whatever is already correct
 *   pnpm seed:permit2 --rearm    force a fresh grant (replay the demo after a lockdown)
 *
 * `pnpm seed` arms the ERC-20 side of the threat. This is its Permit2 twin, and
 * it is the fixture the Permit2 code path had been missing: without it,
 * `permit2-long-lived` and `lockdown()` were only ever exercised against mocks,
 * and "we support Permit2" was a claim about our test suite rather than about
 * the chain.
 *
 * TWO transactions, in this order, because the second is worthless without the
 * first:
 *
 *   1. MockUSDC.approve(PERMIT2, MAX_UINT256)
 *      Permit2 moves tokens with `transferFrom`, so the token contract must have
 *      approved it. Without this the Permit2 slot below is still WRITTEN and
 *      still DETECTED — but no transfer it authorises could actually succeed,
 *      which would make the fixture a threat only on paper.
 *
 *   2. Permit2.approve(token, spender, MAX_UINT160, expiration)
 *      The exposure itself, written into Permit2's own allowance ledger. The
 *      token contract emits nothing for this — that silence is the entire reason
 *      src/permit2.ts exists.
 *
 * Both go through KeeperHub. The owner of a Permit2 allowance is `msg.sender`,
 * and `lockdown()` clears `msg.sender`'s slots and nobody else's, so the grant
 * has to come from the same Turnkey account that will later revoke it. The
 * throwaway deployer key `pnpm seed` uses for its contract deploys cannot stand
 * in here: an allowance it granted would be a slot Revoker is structurally
 * unable to clear.
 *
 * Idempotent by design, like `pnpm seed`: it reads the live slot first and
 * sends only the transactions the chain actually needs. Re-running after a
 * lockdown re-arms (the amount is back to 0); re-running against an armed
 * fixture sends nothing at all.
 *
 * Deploys nothing and writes nothing to disk — the fixtures come from
 * deployments.json, which `pnpm seed` owns.
 */
import { readFileSync } from 'node:fs'
import type { Address } from 'viem'
import { config, explorerTxUrl } from '../src/config.js'
import { KeeperHub } from '../src/keeperhub.js'
import { MAX_UINT256, hasCodeAt, readAllowance, readChainTimeSeconds } from '../src/chain.js'
import { PERMIT2_ADDRESS, PERMIT2_MAX_AMOUNT, readPermit2Allowance } from '../src/permit2.js'
import { PERMIT2_LONG_LIVED_DAYS } from '../src/rules.js'

const DEPLOYMENTS_PATH = new URL('../deployments.json', import.meta.url)

const DAY_SECONDS = 86_400

/**
 * Imported from the rule rather than restated, so the fixture and the detector
 * cannot drift apart. If someone retunes `permit2-long-lived`, the assertion at
 * the end of this script fails on the next run instead of the demo quietly
 * arming a grant that no longer trips anything.
 */
const PERMIT2_LONG_LIVED_SECONDS = PERMIT2_LONG_LIVED_DAYS * DAY_SECONDS

/**
 * One year, not `type(uint48).max`.
 *
 * The sentinel would be the lazier fixture and the weaker proof: a detector
 * could pass on it by pattern-matching "expiration == uint48 max" without ever
 * doing the lifetime arithmetic the rule is actually built on. A finite,
 * ordinary-looking far-future date can only be caught by measuring
 * `expiration - block.timestamp` against the 30-day norm — which is exactly what
 * `permit2-long-lived` does, and exactly what this fixture needs to prove.
 *
 * A year also means the armed fixture survives ~11 months of demos before the
 * remaining lifetime drops under the threshold and this script re-arms it.
 */
const EXPIRATION_DAYS = 365
const EXPIRATION_SECONDS = EXPIRATION_DAYS * DAY_SECONDS

interface Deployments {
  sepolia: {
    contracts: Record<string, { address: string }>
  }
}

function fixture(deployments: Deployments, name: string): Address {
  const address = deployments.sepolia.contracts[name]?.address
  if (address === undefined) {
    throw new Error(`deployments.json records no ${name} address — run \`pnpm seed\` first`)
  }
  return address as Address
}

function readFixtures(): { token: Address; spender: Address } {
  const deployments = JSON.parse(readFileSync(DEPLOYMENTS_PATH, 'utf8')) as Deployments
  return {
    token: fixture(deployments, 'MockUSDC'),
    spender: fixture(deployments, 'RoachMotelSpender'),
  }
}

/**
 * ERC-20 `approve`. Supplied explicitly because MockUSDC is a throwaway deploy
 * that is not verified on Etherscan, so KeeperHub cannot resolve its ABI
 * server-side.
 */
const ERC20_APPROVE_ABI: unknown[] = [
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

/**
 * Permit2's `approve(address,address,uint160,uint48)`, transcribed from
 * Uniswap's `IAllowanceTransfer.sol`.
 *
 * Deliberately local rather than added to `PERMIT2_ABI` in src/permit2.ts. That
 * ABI is the slice the AGENT uses — read an allowance, revoke it — and it is
 * handed straight to KeeperHub as the action ABI for `lockdown()`. Putting a
 * grant-side write into it would place "widen the victim's exposure" one
 * mistyped `functionName` away from the revoke path, in the one module whose
 * job is to take exposure away. Granting is a fixture and attacker action; it
 * lives with the fixture.
 */
const PERMIT2_APPROVE_ABI: unknown[] = [
  {
    inputs: [
      { name: 'token', type: 'address' },
      { name: 'spender', type: 'address' },
      { name: 'amount', type: 'uint160' },
      { name: 'expiration', type: 'uint48' },
    ],
    name: 'approve',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
]

interface ContractCall {
  contractAddress: Address
  functionName: string
  functionArgs: unknown[]
  abi: unknown[]
}

/**
 * Submit one write and resolve it to a transaction hash.
 *
 * Two steps rather than reading the hash off the submit response, mirroring
 * scripts/seed.ts: the execute endpoint returns an executionId before a hash is
 * attached, and the status endpoint is the one whose job is resolving it. A
 * missing hash is raised rather than logged — an operator who is told a fixture
 * was armed, with no hash to check, has been told nothing.
 */
async function submit(kh: KeeperHub, label: string, call: ContractCall): Promise<string> {
  const result = await kh.writeContract(call)
  const status = await kh.getExecutionStatus(result.executionId)
  const hash = status.transactionHash
  if (hash === undefined) {
    throw new Error(`${label} returned execution ${result.executionId} with no transaction hash`)
  }
  console.log(`    ${explorerTxUrl(hash)}`)
  return hash
}

function days(seconds: number): string {
  return (seconds / DAY_SECONDS).toFixed(2)
}

/**
 * Why this run is (re)granting. Printed so a re-run states which of the several
 * "not armed" chain states it actually found — "arming" alone would not
 * distinguish a fresh fixture from one Revoker just locked down.
 */
function rearmReason(unlimited: boolean, longLived: boolean, forced: boolean): string {
  if (forced) return '--rearm given; regranting regardless of the current slot'
  if (!unlimited) {
    return 'slot amount is not MAX_UINT160 — never granted, bounded, or already locked down'
  }
  return `slot is unlimited but expires inside the ${PERMIT2_LONG_LIVED_DAYS}-day window`
}

async function main(): Promise<void> {
  const forceRearm = process.argv.includes('--rearm')
  const owner = config.walletAddress
  const { token, spender } = readFixtures()
  const kh = new KeeperHub()

  console.log('Revoker — arming the Permit2 threat scenario')
  console.log(`  owner   : ${owner}  (Turnkey account — the only address KeeperHub signs for)`)
  console.log(`  token   : ${token}  (MockUSDC)`)
  console.log(`  spender : ${spender}  (RoachMotelSpender)`)
  console.log(`  permit2 : ${PERMIT2_ADDRESS}  (canonical, same address on every chain)`)
  console.log()

  // A CALL to an address with no code SUCCEEDS — the EVM treats it as a no-op
  // that returns empty data, not as a revert. So on a chain where Permit2 was
  // never deployed, step 2 below would be mined, marked successful, emit
  // nothing, and this script would report a fully armed fixture that does not
  // exist. Check for code before trusting any of it.
  if (!(await hasCodeAt(PERMIT2_ADDRESS))) {
    throw new Error(
      `No contract code at ${PERMIT2_ADDRESS} on chainId ${config.chainId} — ` +
        'Permit2 is not deployed on this chain, and approving it would be a silent no-op',
    )
  }

  // ---- 1. the upstream ERC-20 approval to Permit2 ------------------------
  // The enabling grant. Reported by the `upstream-permit2-approval` HOLD and
  // never revoked unattended, which is precisely why arming it here is safe to
  // leave in place across demo runs: Revoker will name it and refuse to touch it.
  const upstream = await readAllowance(token, owner, PERMIT2_ADDRESS)
  if (upstream === MAX_UINT256) {
    console.log('  ✓ upstream ERC-20 approval to Permit2 already unlimited — skipping')
  } else {
    // Skipped only on an exact MAX_UINT256 match, not on "non-zero". A bounded
    // upstream allowance is spent down by every transfer that flows through
    // Permit2, so a fixture built on one decays into a dead exposure without
    // anything on chain saying so.
    console.log(`  · approving Permit2 on MockUSDC (was ${upstream})`)
    await submit(kh, 'ERC-20 approve', {
      contractAddress: token,
      functionName: 'approve',
      functionArgs: [PERMIT2_ADDRESS, MAX_UINT256.toString()],
      abi: ERC20_APPROVE_ABI,
    })
    console.log('  + approved MAX_UINT256 -> Permit2')
  }

  // ---- 2. the Permit2 allowance ------------------------------------------
  // Chain time, never Date.now(). The expiration written here is compared
  // against `block.timestamp` by both Permit2 and by permit2-long-lived, so a
  // host clock running slow would silently produce a grant with less lifetime
  // than intended — possibly under the threshold this fixture exists to cross.
  const chainTime = await readChainTimeSeconds()
  const before = await readPermit2Allowance(owner, token, spender)
  const unlimited = before.amount === PERMIT2_MAX_AMOUNT
  const longLived = before.expiration - chainTime > PERMIT2_LONG_LIVED_SECONDS

  if (unlimited && longLived && !forceRearm) {
    console.log(
      `  ✓ Permit2 allowance already armed — MAX_UINT160, ` +
        `${days(before.expiration - chainTime)} days left — skipping`,
    )
  } else {
    const expiration = chainTime + EXPIRATION_SECONDS
    console.log(`  · arming Permit2: ${rearmReason(unlimited, longLived, forceRearm)}`)
    await submit(kh, 'Permit2 approve', {
      contractAddress: PERMIT2_ADDRESS,
      functionName: 'approve',
      // MAX_UINT160, not MAX_UINT256. Permit2 packs `amount` into 160 bits: a
      // uint256 max is out of range for the parameter, so the encoder rejects
      // the call outright — and any encoder lenient enough to truncate it
      // instead would write a value that `unlimitedSentinel` scores as BOUNDED,
      // producing a fixture that looks armed and trips no rule.
      functionArgs: [token, spender, PERMIT2_MAX_AMOUNT.toString(), String(expiration)],
      abi: PERMIT2_APPROVE_ABI,
    })
    console.log(
      `  + granted MAX_UINT160 to ${spender}, expiring ${new Date(expiration * 1000).toISOString()}`,
    )
  }

  // ---- 3. report against the live slot -----------------------------------
  // Re-read rather than reporting what we just sent. The submitted arguments are
  // a claim; the slot is the fact.
  const finalTime = await readChainTimeSeconds()
  const final = await readPermit2Allowance(owner, token, spender)
  const finalUpstream = await readAllowance(token, owner, PERMIT2_ADDRESS)
  const remaining = final.expiration - finalTime

  console.log()
  console.log('  THREAT ARMED — Permit2')
  console.log(
    `    upstream   ${finalUpstream === MAX_UINT256 ? 'MAX_UINT256 (unlimited)' : finalUpstream}` +
      '  (ERC-20 approve -> Permit2)',
  )
  console.log(
    `    amount     ${final.amount === PERMIT2_MAX_AMOUNT ? 'MAX_UINT160 (Permit2 unlimited)' : final.amount}`,
  )
  console.log(`    expiration ${final.expiration}  (${new Date(final.expiration * 1000).toISOString()})`)
  console.log(`    lifetime   ${days(remaining)} days remaining`)
  console.log(`    nonce      ${final.nonce}`)
  console.log()

  if (finalUpstream === 0n) {
    throw new Error(
      'Seed finished but the ERC-20 approval to Permit2 is still zero — ' +
        'the grant is detectable but no transfer it authorises could succeed',
    )
  }
  if (final.amount !== PERMIT2_MAX_AMOUNT) {
    throw new Error(`Seed finished but the Permit2 amount is ${final.amount}, not MAX_UINT160`)
  }
  if (remaining <= PERMIT2_LONG_LIVED_SECONDS) {
    throw new Error(
      `Seed finished but the Permit2 allowance has ${days(remaining)} days left, ` +
        `which does not exceed the ${PERMIT2_LONG_LIVED_DAYS}-day permit2-long-lived threshold`,
    )
  }

  // An independent read, deliberately not through this process. `eth_call` needs
  // no auth and no key, so anyone can disagree with the report above.
  console.log('  Verify the slot yourself — plain eth_call, no credentials:')
  console.log(`    cast call ${PERMIT2_ADDRESS} \\`)
  console.log('      "allowance(address,address,address)(uint160,uint48,uint48)" \\')
  console.log(`      ${owner} ${token} ${spender} \\`)
  console.log(`      --rpc-url ${config.rpcUrl}`)
  console.log(
    `    kh read ${PERMIT2_ADDRESS} "allowance(address,address,address)" ` +
      `${owner} ${token} ${spender} --chain ${config.chainId}`,
  )
  console.log()
  console.log(
    `  permit2-long-lived will fire: ${days(remaining)} days remaining > ` +
      `${PERMIT2_LONG_LIVED_DAYS}-day threshold, on an unverified spender.`,
  )
  console.log('  Run `pnpm watch -- --once` to watch Revoker lock it down.')
}

main().catch((error: unknown) => {
  console.error(
    `\n❌ Permit2 seed failed: ${error instanceof Error ? error.message : String(error)}`,
  )
  process.exitCode = 1
})
