# DEMO — reproduce the whole thing

Every claim in the README can be reproduced from a clean checkout. This file is
the exact path, with the outputs you should see.

Nothing here is mocked. The threat is a real unlimited approval on Ethereum
Sepolia, the revoke is a real transaction executed through KeeperHub, and the
drain attempt is a real contract call that really fails to take anything.

> **Who the wallet is.** The demo protects an **agent wallet** — the Turnkey
> account KeeperHub signs for. That is the whole target market: keeper bots,
> liquidation and rebalancing signers, DeFi automation. `approve(spender, 0)`
> clears `msg.sender`'s allowance and nobody else's, so the watched wallet and
> the revoke sender are necessarily the same account. `scripts/seed.ts` prints
> that account under the label `victim`; read it as *the wallet under attack*,
> which here is the agent's own.

---

## 0. Run it with no credentials at all

Before any of the on-chain setup below, the product runs from a fresh clone with
nothing configured:

```bash
pnpm install
pnpm demo:verify     # http://localhost:3000/verify
```

That serves the **real** `/verify` dashboard, replaying **68 verbatim rows** of a
recorded Sepolia run from `data/demo-run.jsonl` — every `threat.detected`,
`revoke.submit` and `revoke.confirmed` in the order and cadence they happened,
with clickable Etherscan links to transactions that really landed. The page
stamps itself `REPLAY` so it cannot be mistaken for a live run.

```bash
pnpm demo            # one REAL scan of the public demo wallet, executes nothing
```

`REVOKER_DEMO=1` substitutes a sentinel API key no organisation will accept,
substitutes the project's public demo wallet, **ignores any real credentials you
have**, and pushes `--dry-run` into `process.argv` at config load — before any
module that reads flags has run. `REVOKER_DEMO=1 pnpm watch` is therefore dry
too. There is no flag combination that lets demo mode sign, submit or spend.

Everything from section 1 on needs real credentials.

---

## 1. Prerequisites

- Node 22+, pnpm 10+, [Foundry](https://book.getfoundry.sh/)
- A KeeperHub organisation API key (`kh_…`) — app.keeperhub.com → Settings → API Keys
- The org's Turnkey wallet address — app.keeperhub.com → Wallet tab
- A little Sepolia ETH in that wallet
- Optional but recommended: the `kh` CLI — `brew install keeperhub/tap/kh`

> Gas turned out to be sponsored by KeeperHub on Sepolia in every execution we
> ran, so the balance was never actually consumed. The docs say sponsorship is
> mainnet-only, so do not rely on that — fund the wallet anyway.

Credentials resolve from `process.env`, then `~/.config/keeperhub/env`, then a
local `.env`. See [`.env.example`](./.env.example) for every variable. Nothing
secret is ever committed.

```bash
KH_API_KEY=kh_...
KH_WALLET_ADDRESS=0x...
KH_NETWORK=sepolia
KH_CHAIN_ID=11155111
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
DEPLOYER_PRIVATE_KEY=0x...   # throwaway; deploys the fixtures AND plays the adversary
```

`DEPLOYER_PRIVATE_KEY` is a throwaway testnet key. It deploys the demo contracts
and **sends the drain transaction, because it is the attacker.** It never signs a
revoke, and it is the **only non-KeeperHub transaction in the attack/defence
path.** Generate one with `cast wallet new` and send it ~0.02 Sepolia ETH.

```bash
pnpm install
cd contracts && forge build && cd ..
```

---

## 2. Prove the integration — `pnpm spike`

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
fails. Step 1 also asserts that `KH_WALLET_ADDRESS` matches the account
KeeperHub actually controls — if it does not, nothing downstream could work and
the spike says so loudly.

---

## 3. Arm the ERC-20 threat — `pnpm seed`

Idempotent. Re-running reuses the deployed contracts, skips the mint, and leaves
the chain in one known state.

```
  ✓ MockUSDC           reusing 0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb
  ✓ RoachMotelSpender  reusing 0x8eBf8540EdE8e40CD94825C418758d4029D8892e
  ✓ victim already holds 10000.00 mUSDC
  · arming with kh version 0.14.0
  + approved MAX_UINT256 -> 0x8eBf8540EdE8e40CD94825C418758d4029D8892e

  THREAT ARMED
    at risk   10000.00 mUSDC
    allowance MAX_UINT256 (unlimited)
```

The approval is armed through the **real `kh` CLI** — `kh execute contract-call`
followed by `kh execute status` — and falls back to the REST client when `kh` is
not installed (`· kh not found — arming over REST`). The CLI is a real path, not
a hard dependency.

Confirm it independently:

```bash
cast call 0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb \
  "allowance(address,address)(uint256)" \
  <YOUR_TURNKEY_WALLET> 0x8eBf8540EdE8e40CD94825C418758d4029D8892e \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
# 115792089237316195423570985008687907853269984665640564039457584007913129639935
```

### The operator flow — `make arm`

Arming is the one genuinely CLI-shaped step in this project: it must be signed by
the Turnkey account, and it is an **operator** action, not the agent's.
`make arm` is that flow written out rather than buried in a script — who am I,
can the wallet pay, arm it, and then verify on chain:

```bash
make arm
#   kh version
#   kh auth status
#   kh wallet balance --chain Sepolia
#   pnpm seed
#   kh read <token> "allowance(address,address)" <victim> <spender> --chain 11155111
```

The last step is deliberately an **independent** read — `kh read` is `eth_call`
and needs no auth — so it is free to disagree with the seed's own report.

---

## 4. Watch it get taken away — `pnpm watch -- --once`

```
🚨 threat.detected   mUSDC  allowance=MAX_UINT256  atRisk=10000000000
                     rules=[unlimited-to-unverified, denylisted]
↗  revoke.submit     method=check-and-execute  executionId=…
✅ revoke.confirmed  0xc45a19a6…  executionId=…  allowanceAfter=0  sponsored=true
```

No manual step happens between detection and revoke. Use `--dry-run` to watch it
decide without executing.

`executionId` is elided above because it is per-run — yours will differ. It is
KeeperHub's own handle on the execution, and it is the field that makes
"executed **via KeeperHub**" checkable instead of inferred: the explorer shows a
relayer calling `approve`, while the execution record shows the *guarded*
`check-and-execute` behind it. Both revoke paths write it into
`audit/revoker.jsonl` on every stage — see
[the executionId section in the README](./README.md#the-keeperhub-side-of-those-same-transactions--executionid).

The allowance is now zero:

```bash
cast call 0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb \
  "allowance(address,address)(uint256)" \
  <YOUR_TURNKEY_WALLET> 0x8eBf8540EdE8e40CD94825C418758d4029D8892e \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
# 0
```

Reference run: [`0xc45a19a6…a86d7c`](https://sepolia.etherscan.io/tx/0xc45a19a63808c106db3a3394d130db486fef17b5e920bbd860d6907729a86d7c) (block 11445665)

> **Reading that link.** It opens on KeeperHub's relayer page, which looks
> opaque. **Open the `Logs` tab** — MockUSDC emits `Approval(owner, spender, 0)`.
> That is the revoke.

---

## 5. Let the drainer try anyway

This is the step that proves the point. Point the drain contract at the wallet:

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

Reference run: [`0xf0c69049…8ab3a9d`](https://sepolia.etherscan.io/tx/0xf0c690494418178f4e0eae105b39835a72a3ae5a4d805a430097d367d8ab3a9d) (block 11445667 — two blocks after the revoke above)

> **Reading that link.** `Logs` shows `DrainFailed` and, decisively, **no
> `Transfer` event**. The drain ran; nothing moved. This is the whole thesis in
> one tab.
>
> This transaction is signed by the throwaway key **because it is the
> attacker** — the only non-KeeperHub transaction in the demo.

---

## 6. The Permit2 path — the grant an ERC-20 watcher cannot see

Permit2 keeps its own allowance ledger. A signature-based grant writes that slot
without the token contract being touched, so the token emits nothing at all.

### 6a. Deploy the guard helper — `pnpm deploy:view`

Once per network. Required, because `check-and-execute`'s condition schema is
`{operator, value}` with no tuple member selector, and `Permit2.allowance()`
returns a 3-tuple.

```
Revoker — deploying Permit2AllowanceView
  network  : sepolia  (chainId 11155111)
  deployer : 0xf40c…3ff3  (throwaway; the helper is ownerless)
  permit2  : 0x000000000022D473030F116dDEE9F6B43aC78BA3  (canonical, hardcoded in the helper)

  + deployed 0x252e03162936563e345e616fa60e0f33831b67db
    https://sepolia.etherscan.io/tx/0x04fe33e1…
  ✓ helper delegates to canonical Permit2
  ✓ deployments.json resolves to it — the Permit2 revoke path is armed
```

723 bytes, ownerless, storageless, non-payable, with Permit2's address as a
compile-time constant. Verify it delegates where it claims — no credentials:

```bash
cast call 0x252e03162936563e345e616fa60e0f33831b67db "PERMIT2()(address)" \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
# 0x000000000022D473030F116dDEE9F6B43aC78BA3
```

If the helper is missing, the agent **refuses to submit the lockdown** rather
than sending an unguarded write.

### 6b. Arm the Permit2 threat — `pnpm seed:permit2`

Idempotent; `--rearm` forces a fresh grant.

```
Revoker — arming the Permit2 threat scenario
  owner   : 0x5E2e…bab7  (Turnkey account — the only address KeeperHub signs for)
  token   : 0x4facb5FD…88Cb  (MockUSDC)
  spender : 0x8eBf8540…892e  (RoachMotelSpender)
  permit2 : 0x000000000022D473030F116dDEE9F6B43aC78BA3  (canonical, same address on every chain)

  + approved MAX_UINT256 -> Permit2

  THREAT ARMED — Permit2
    amount     MAX_UINT160 (unlimited)
    expiration 1817728584
    lifetime   … days remaining
    nonce      0
```

Two grants, because there are two layers:

| Step | Block | Transaction | What it does |
|---|---|---|---|
| upstream `approve(PERMIT2, MAX)` | `11445297` | [`0xa52cb025…5855a2`](https://sepolia.etherscan.io/tx/0xa52cb025170b45b58ba804ce6747aa0f9ae5ce87cdd66813688d8fd81c5855a2) | lets Permit2 move the token at all |
| `Permit2.approve` | `11445298` | [`0xe978f12f…c73297`](https://sepolia.etherscan.io/tx/0xe978f12fb5fe7766b7659bb74569a9cfdb08ec3e4762c9eeaabb539a0c753297) | writes the downstream slot — this is the exposure |

Note that Permit2's "unlimited" is `type(uint160).max`, not `type(uint256).max`.

### 6c. Watch the lockdown land — `pnpm watch -- --once`

The revoke is `lockdown()`, batching every fired slot into **one** transaction.

Reference run: [`0x20d70cf1…6ba124`](https://sepolia.etherscan.io/tx/0x20d70cf1577f084944931eada7955b5772a5de3553fda890131354d97f6ba124)
— `status 0x1`, block **11445392**, **52,213 gas**, sponsored, **16.2s**
detect-to-confirmed.

> **Reading that link.** `Logs` has exactly one entry: a `Lockdown` event emitted
> by **Permit2 itself** (`0x0000…78BA3`). The slot's `amount` went from
> `MAX_UINT160` to `0`.

Confirm the slot is empty:

```bash
cast call 0x000000000022D473030F116dDEE9F6B43aC78BA3 \
  "allowance(address,address,address)(uint160,uint48,uint48)" \
  0x5E2e5Fd3aD7fDC9B94482930db8b5F45E439bab7 \
  0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb \
  0x8eBf8540EdE8e40CD94825C418758d4029D8892e \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
# 0  1817728584  0
```

`amount` is `0`. The expiration is a dead field on an emptied slot.

The **upstream** `approve(PERMIT2, MAX)` from 6b is deliberately *not* revoked.
It trips the `upstream-permit2-approval` **hold**, which reports it and refuses
to act unattended — `approve(PERMIT2, 0)` would break every DEX route for that
token. It is offered to a human through the MCP `revoke_approval` tool, which
requires `confirm: true`.

---

## 7. Ask it questions — `pnpm mcp`

An MCP server over stdio with four tools:

| Tool | Writes? |
|---|---|
| `list_exposures` | no |
| `explain_exposure` | no |
| `simulate_revoke` | no — `simulate: true` against KeeperHub, no broadcast |
| `revoke_approval` | **yes**, and it refuses unless `confirm` is exactly `true` |

This is a query surface for a human investigating, **not a model in the decision
path.** `src/watcher.ts` does not import `src/mcp.ts`, so the autonomous loop
gains nothing from it and stays fully deterministic.

---

## 8. The dashboard and the callback — `pnpm verify`

`pnpm verify` runs the watcher and streams its audit trail to
`http://localhost:3000/verify` over Server-Sent Events — pushed as decisions
happen, not polled. Run `pnpm seed` in another terminal and watch the timeline
animate: `threat.detected` → `revoke.submit` → `revoke.confirmed`, with the
Etherscan link rendered the moment it lands. It backfills recent history from
the durable JSONL on connect, so a late browser still sees what happened, and
has a failures tile.

The same process exposes `POST /revoke`, the callback a KeeperHub workflow uses
to escalate a detection into the atomic write. It **fails closed**: `503` when
`REVOKER_CALLBACK_SECRET` is unset, and a plain `404` in any dry-run or demo
mode — absent rather than merely disabled.

> The sentinel workflow (`workflows/revoker-sentinel.json`) is **authored and
> pre-flight validated but NOT deployed.** Creating it returns
> `402 upgrade_required` — its `HTTP Request` action needs a paid Pro plan.
> `pnpm workflow:deploy` is the deploy path and creates it **disabled** on an
> eligible org, so a human still has to turn it on.

---

## 9. Measure it — `pnpm bench`

N=25 full cycles, reporting p50/p95. Results and per-cycle transaction links are
written to [BENCHMARK.md](./BENCHMARK.md).

```bash
pnpm bench            # N=25
pnpm bench -- --n=5   # shorter
```

Two figures are reported separately, because conflating them would flatter the
result: `response` (detection → confirmed, the agent's own speed) and `exposure`
(threat live → confirmed, what the wallet actually experiences).

---

## 10. Tests

```bash
pnpm test               # 580 TypeScript tests
pnpm contracts:test     # 54 Solidity tests
pnpm e2e                # 34 Playwright tests
```

**668 total.** 100% statements, branches, functions and lines on `src/` **and**
`scripts/` — gated in `vitest.config.ts`, so CI fails on a regression — plus
100% Solidity coverage and 6 fuzz suites.

The negatives matter most: a verified, aged, non-deny-listed spender must raise
**no** threat; a pending execution must **not** be reported as failed; demo mode
must be unable to execute whatever flags are passed. An agent that cries wolf
gets turned off.

---

## Reading the transaction links

KeeperHub executes through a sponsored relay, so the explorer shows its relayer
in `from`, not your wallet:

```
relayer 0x809d…0444  →  forwarder 0x5af5…f07d  →  your Turnkey account
```

Every `from` in this demo is one of four addresses:

| Address | Who |
|---|---|
| `0x809d…0444` | KeeperHub relayer — the `from` on every sponsored execution |
| `0x5af5…f07d` | KeeperHub forwarder — the `to` the relayer calls |
| `0x5E2e…bab7` | the Turnkey account — watched wallet *and* revoke sender |
| `0xf40c…3ff3` | throwaway deploy/adversary key — fixtures and the drain |

Your address appears in the calldata and the value moves internally. This is
expected. Do not expect the signer address in the `from` field — check the
`Logs` tab instead, which names the real actors.
