# DEMO — reproduce the whole thing

Every claim in the README can be reproduced from a clean checkout. This file is
the exact path, with the outputs you should see.

Nothing here is mocked. The threat is a real unlimited approval on Ethereum
Sepolia, the revoke is a real transaction executed through KeeperHub, and the
drain attempt is a real contract call that really fails to take anything.

---

## 0. Prerequisites

- Node 22+, pnpm 10+, [Foundry](https://book.getfoundry.sh/)
- A KeeperHub organisation API key (`kh_…`) — app.keeperhub.com → Settings → API Keys
- The org's Turnkey wallet address — app.keeperhub.com → Wallet tab
- A little Sepolia ETH in that wallet

> Gas turned out to be sponsored by KeeperHub on Sepolia in every execution we
> ran, so the balance was never actually consumed. The docs say sponsorship is
> mainnet-only, so do not rely on that — fund the wallet anyway.

Credentials resolve from `process.env`, then `~/.config/keeperhub/env`, then a
local `.env`. Nothing secret is ever committed.

```bash
KH_API_KEY=kh_...
KH_WALLET_ADDRESS=0x...
KH_NETWORK=sepolia
KH_CHAIN_ID=11155111
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
DEPLOYER_PRIVATE_KEY=0x...   # throwaway; only needed to deploy the fixtures
```

`DEPLOYER_PRIVATE_KEY` is a throwaway testnet key that deploys the demo
contracts and plays the adversary. It never signs a revoke. Generate one with
`cast wallet new` and send it ~0.02 Sepolia ETH.

```bash
pnpm install
cd contracts && forge build && cd ..
```

---

## 1. Prove the integration — `pnpm spike`

Seven steps against the live API and chain, ending in a real transaction.

```
1. GET /api/user/wallet        resolve + assert the signer
2. GET /api/chains             confirm network support
3. eth_getBalance              is the signer funded?
4. POST /execute/transfer      simulate: true — no broadcast
5. POST /execute/transfer      REAL transaction
6. GET /execute/{id}/status    audit record
7. eth_getTransactionReceipt   independent on-chain verification

✅ Spike passed. Real transaction:
   https://sepolia.etherscan.io/tx/0x1f95fdd3…
```

Step 7 is the point: the result is verified against a public RPC rather than
trusting KeeperHub's own report. If the transaction is not on-chain, the spike
fails.

---

## 2. Arm the threat — `pnpm seed`

Idempotent. Re-running reuses the deployed contracts, skips the mint, and leaves
the chain in one known state.

```
  ✓ MockUSDC           reusing 0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb
  ✓ RoachMotelSpender  reusing 0x8eBf8540EdE8e40CD94825C418758d4029D8892e
  ✓ victim already holds 10000.00 mUSDC
  + approved MAX_UINT256 -> 0x8eBf8540EdE8e40CD94825C418758d4029D8892e

  THREAT ARMED
    at risk   10000.00 mUSDC
    allowance MAX_UINT256 (unlimited)
```

Confirm it independently:

```bash
cast call 0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb \
  "allowance(address,address)(uint256)" \
  <YOUR_TURNKEY_WALLET> 0x8eBf8540EdE8e40CD94825C418758d4029D8892e \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
# 115792089237316195423570985008687907853269984665640564039457584007913129639935
```

> **Why the victim is the Turnkey wallet.** `approve(spender, 0)` clears
> `msg.sender`'s allowance and nobody else's, and KeeperHub signs only for the
> org's Turnkey account. So that account must be both the watched wallet and the
> revoke sender. A separate "victim" wallet is structurally impossible.

---

## 3. Watch it get taken away — `pnpm watch -- --once`

```
🚨 threat.detected   mUSDC  allowance=MAX_UINT256  atRisk=10000000000
                     rules=[unlimited-to-unverified, denylisted]
↗  revoke.submit     method=check-and-execute
✅ revoke.confirmed  0x96028414…  allowanceAfter=0  latencyMs=6909  sponsored=true
```

No manual step happens between detection and revoke. Use `--dry-run` to watch it
decide without executing.

The allowance is now zero:

```bash
cast call 0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb \
  "allowance(address,address)(uint256)" \
  <YOUR_TURNKEY_WALLET> 0x8eBf8540EdE8e40CD94825C418758d4029D8892e \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
# 0
```

---

## 4. Let the drainer try anyway

This is the step that proves the point. Point the drain contract at the victim:

```bash
cast send 0x8eBf8540EdE8e40CD94825C418758d4029D8892e \
  "drain(address,address)" \
  0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb <YOUR_TURNKEY_WALLET> \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
  --private-key $DEPLOYER_PRIVATE_KEY
# status  1 (success)
```

The transaction **succeeds**. It does not revert, it is not blocked, it runs
exactly as its author intended — and it takes nothing, because the approval is
already gone. It emits `DrainFailed(token, victim, "allowance revoked")`.

Balance unchanged:

```bash
cast call 0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb \
  "balanceOf(address)(uint256)" <YOUR_TURNKEY_WALLET> \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
# 10000000000
```

Reference run: [`0xe127f3d2…`](https://sepolia.etherscan.io/tx/0xe127f3d2e2eb20a9825fbec63c56028815ce145c8cdd9e143a02600e2da1a303)

---

## 5. Measure it — `pnpm bench`

N=25 full cycles, reporting p50/p95. Results and per-cycle transaction links are
written to [BENCHMARK.md](./BENCHMARK.md).

```bash
pnpm bench            # N=25
pnpm bench -- --n=5   # shorter
```

Two figures are reported separately, because conflating them would flatter the
result: `response` (detection → confirmed, the agent's own speed) and `exposure`
(threat live → confirmed, what a user experiences).

---

## 6. Tests — `pnpm test`

15 tests over the three threat rules. The negatives matter most: a verified,
aged, non-deny-listed spender must raise **no** threat — an agent that cries
wolf gets turned off.

---

## Reading the transaction links

KeeperHub executes through a sponsored relay, so the explorer shows its relayer
in `from`, not your wallet:

```
relayer 0x809d…0444  →  forwarder 0x5af5…f07d  →  your Turnkey account
```

Your address appears in the calldata and the value moves internally. This is
expected. Do not expect the signer address in the `from` field.
