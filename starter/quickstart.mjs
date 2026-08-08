#!/usr/bin/env node
/**
 * KeeperHub quickstart — zero to a landed on-chain transaction, in one command.
 *
 *   KH_API_KEY=kh_... node quickstart.mjs
 *
 * No dependencies. No build step. No config file. Node 20+ only, because it has
 * fetch built in.
 *
 * Written after doing this the slow way. Every check below exists because
 * something cost me time in that order, and each failure explains itself
 * instead of handing you a status code — see feedback.md in the parent repo for
 * the teardown this came from.
 */

const API = process.env.KH_BASE_URL ?? 'https://app.keeperhub.com'
const KEY = process.env.KH_API_KEY
const NETWORK = process.env.KH_NETWORK ?? 'sepolia'
const RPC = process.env.RPC_URL ?? 'https://ethereum-sepolia-rpc.publicnode.com'
const DOCTOR = process.argv.includes('--doctor')

const c = {
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  ok: (s) => `\x1b[32m${s}\x1b[0m`,
  bad: (s) => `\x1b[31m${s}\x1b[0m`,
  warn: (s) => `\x1b[33m${s}\x1b[0m`,
  b: (s) => `\x1b[1m${s}\x1b[0m`,
}

const step = (n, t) => console.log(`\n${c.b(`${n}.`)} ${t}`)
const ok = (m) => console.log(`   ${c.ok('✓')} ${m}`)
const info = (m) => console.log(`   ${c.dim(m)}`)

function die(what, why, fix) {
  console.error(`\n   ${c.bad('✗')} ${c.b(what)}`)
  console.error(`     ${why}`)
  if (fix) console.error(`\n     ${c.warn('Fix:')} ${fix}`)
  process.exit(1)
}

/**
 * A custom User-Agent is not optional.
 *
 * The edge in front of the API rejects some default scripted user-agents with a
 * bare Cloudflare 403 that carries no JSON body. On an endpoint that takes a
 * bearer token, a 403 reads as "your key is wrong", and you can lose a long time
 * re-checking a key that was fine. Setting this avoids the whole class.
 */
const UA = 'keeperhub-quickstart/1.0 (+https://github.com/edycutjong/revoker)'

async function kh(path, { method = 'GET', body, idempotencyKey } = {}) {
  const headers = { Authorization: `Bearer ${KEY}`, 'User-Agent': UA }
  if (body) headers['Content-Type'] = 'application/json'
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey

  let res
  try {
    res = await fetch(`${API}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    })
  } catch (e) {
    die('Could not reach KeeperHub', `${API} — ${e.message}`, 'Check your network, or KH_BASE_URL if you set it.')
  }

  const text = await res.text()
  let json = null
  try {
    json = text ? JSON.parse(text) : null
  } catch {
    /* keep the raw text for the error path below */
  }

  if (!res.ok) {
    if (res.status === 401) {
      die('Unauthorized (401)', 'The API key was rejected.',
        'Check KH_API_KEY. It must be an ORGANISATION key starting `kh_`,\n          from app.keeperhub.com → Settings → API Keys.')
    }
    if (res.status === 403 && !json) {
      die('Blocked before reaching the API (403, no JSON body)',
        'This is the edge, not KeeperHub — the response carries no API error shape.\n     It usually means the request had an unrecognised User-Agent.',
        'This script already sets one. If you copied this code, keep the\n          User-Agent header — that is the whole fix.')
    }
    if (res.status === 403) {
      die('Forbidden (403)', json?.error ?? text,
        'Often a daily spending cap. Check app.keeperhub.com → Settings.')
    }
    if (res.status === 429) {
      die('Rate limited (429)', 'Direct execution allows 60 requests/minute per key.',
        `Wait ${res.headers.get('Retry-After') ?? 'a few'} seconds and re-run.`)
    }
    die(`HTTP ${res.status} on ${path}`, json?.error ?? text?.slice(0, 300) ?? res.statusText)
  }
  return json
}

async function rpc(method, params) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': UA },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  const j = await res.json()
  if (j.error) throw new Error(`${method}: ${j.error.message}`)
  return j.result
}

// ---------------------------------------------------------------------------

console.log(c.b('\nKeeperHub quickstart'))
console.log(c.dim(`${API} · network ${NETWORK}`))

if (!KEY) {
  die('KH_API_KEY is not set', 'Nothing can run without it.',
    'app.keeperhub.com → Settings → API Keys → Organisation, then:\n\n            export KH_API_KEY=kh_your_key_here\n            node quickstart.mjs')
}
if (!KEY.startsWith('kh_')) {
  // Deliberately does NOT echo any part of the value. Whatever was pasted here
  // is a secret of *some* kind, and this message ends up in terminals and CI logs.
  die('KH_API_KEY does not look like a KeeperHub key',
    'Organisation keys start "kh_"; the value that is set does not.',
    'Make sure you copied an Organisation key, not a personal token.')
}

step(1, 'Who am I? — GET /api/user/wallet')
const wallet = await kh('/api/user/wallet')
if (!wallet?.hasWallet) {
  die('Your organisation has no wallet', 'KeeperHub signs with a Turnkey wallet created on email verification.',
    'Verify your email at app.keeperhub.com, then check the Wallet tab.')
}
ok(`signer ${wallet.walletAddress}`)
info('KeeperHub signs with this key inside a Turnkey enclave.')
info('Your code never sees a private key — that is the point.')

step(2, 'Which networks? — GET /api/chains')
const chains = await kh('/api/chains')
const chain = chains.find((x) => String(x.chainId) === NETWORK || x.name?.toLowerCase().includes(NETWORK))
ok(`${chains.length} networks available`)
if (chain) info(`${chain.name} (${chain.chainId}) · ${chain.explorerUrl}`)
info(`Note: the "network" field below wants "${NETWORK}" — the slug, not the`)
info(`display name from this response. "${chain?.name ?? 'Ethereum Sepolia'}" is rejected.`)

step(3, 'Am I funded? — eth_getBalance')
const before = BigInt(await rpc('eth_getBalance', [wallet.walletAddress, 'latest']))
ok(`${before} wei (${Number(before) / 1e18} ETH)`)
if (before === 0n) {
  console.log(`   ${c.warn('!')} Zero balance. Gas may still be sponsored, but fund it to be safe:`)
  console.log(`     https://cloud.google.com/application/web3/faucet/ethereum/sepolia`)
}

step(4, 'Dry run first — simulate: true')
const sim = await kh('/api/execute/transfer', {
  method: 'POST',
  body: { network: NETWORK, recipientAddress: wallet.walletAddress, amount: '0.0001', simulate: true },
})
ok(`would use ~${sim.gasEstimate} gas · wouldRevert: ${sim.wouldRevert}`)
info('simulate costs nothing and catches reverts, bad ABIs and')
info('allowance mistakes before you spend gas. Use it liberally.')

if (DOCTOR) {
  console.log(`\n${c.ok('Doctor passed.')} Everything is configured. Drop --doctor to land a real transaction.\n`)
  process.exit(0)
}

step(5, 'Land a real transaction — POST /api/execute/transfer')
info('Sending 0.0001 ETH to yourself: real, on-chain, and costs only gas.')
const started = Date.now()
const exec = await kh('/api/execute/transfer', {
  method: 'POST',
  // An idempotency key makes a retry safe. Without one, a network blip plus a
  // retry is how you send the same transaction twice.
  idempotencyKey: `quickstart-${new Date().toISOString().slice(0, 10)}`,
  body: { network: NETWORK, recipientAddress: wallet.walletAddress, amount: '0.0001' },
})
ok(`status ${exec.status} in ${((Date.now() - started) / 1000).toFixed(1)}s`)

step(6, 'Get the hash — GET /api/execute/{id}/status')
info('Some execute endpoints return before the hash is attached, so the')
info('status endpoint is the reliable place to read it.')
const status = await kh(`/api/execute/${exec.executionId}/status`)
const hash = status.transactionHash ?? exec.transactionHash
if (!hash) die('No transaction hash', 'KeeperHub reported completion without one.', 'Re-run; if it persists, report it.')
ok(`${hash}`)
info(`sponsored: ${status.sponsored} · gas: ${status.gasUsedWei ?? 'n/a'}`)
info('Gas is `gasUsed` on the execute response and `gasUsedWei` here.')

step(7, 'Trust nothing — verify on-chain yourself')
let receipt = null
for (let i = 0; i < 30 && !receipt; i += 1) {
  receipt = await rpc('eth_getTransactionReceipt', [hash])
  if (!receipt) await new Promise((r) => setTimeout(r, 2000))
}
if (!receipt) die('Not found on-chain', `${hash} did not appear via ${RPC}`, 'It may still be pending — check the explorer link below.')
if (receipt.status !== '0x1') die('Transaction reverted on-chain', `status ${receipt.status}`)
ok(`mined in block ${Number(BigInt(receipt.blockNumber))}, status SUCCESS`)

const after = BigInt(await rpc('eth_getBalance', [wallet.walletAddress, 'latest']))
info(`balance delta: ${after - before} wei`)
if (status.sponsored && after === before) info('Gas was sponsored — your balance is untouched.')

const explorer = chain?.explorerUrl ?? 'https://sepolia.etherscan.io'
console.log(`\n${c.ok(c.b('Done.'))} You executed a real on-chain transaction through KeeperHub.\n`)
console.log(`   ${explorer}/tx/${hash}\n`)
console.log(c.dim('   Next: swap step 5 for /api/execute/contract-call to call a contract,'))
console.log(c.dim('   or /api/execute/check-and-execute to read a value and act on it atomically.\n'))
