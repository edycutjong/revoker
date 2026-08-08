# Revoker

**The agent that lands the revoke before the drainer moves.**

Token approvals are the most common wallet-drain vector. You grant
`approve(spender, MAX_UINT256)` once to try a new dApp, then forget it exists.
Months later the spender is compromised, upgraded maliciously, or was a scam all
along — and once the drain starts it is instant and irreversible.

The industry's answer to this is **read-only**: scanners and trust scores that
*tell you* an approval is risky. KeeperHub's own marketplace has
`token-approval-risk-scanner-*` and `wallet-trust-score-*`. None of them **act**.

Revoker acts. It watches a wallet's live approval set and, the instant a concrete
threat condition fires, autonomously executes `approve(spender, 0)` through
KeeperHub — landing a real, linkable, state-changing transaction.

---

## Proof of execution

Every claim below links to a transaction anyone can verify.

### The headline: a real drain, really stopped

The full cycle, executed on Sepolia. Every step is a transaction you can open.

| # | Step | Transaction | Result |
|---|---|---|---|
| 1 | Victim grants `approve(spender, MAX_UINT256)` | [`0xfe39a5f4…017482`](https://sepolia.etherscan.io/tx/0xfe39a5f42d4967548751989c98b0a35971273752e009d90d70c3430d09017482) | allowance = `1.157e77` |
| 2 | **Revoker fires `approve(spender, 0)`** via `check-and-execute` | [`0x325f6d51…7e09f9`](https://sepolia.etherscan.io/tx/0x325f6d51be89243ed26e8bceba973d41a7a9657addab6d1395210ddfbc7e09f9) | **allowance = 0**, in **11.3s** |
| 3 | Drainer fires anyway | [`0xe127f3d2…a1a303`](https://sepolia.etherscan.io/tx/0xe127f3d2e2eb20a9825fbec63c56028815ce145c8cdd9e143a02600e2da1a303) | **takes 0. Funds intact.** |

Step 3 is the one that matters. The drain transaction **succeeded** — it did not
revert, it was not blocked, it ran exactly as its author intended. It simply had
nothing left to take, because the approval was already gone. The victim's balance
is unchanged at 10,000 mUSDC across the whole sequence.

### How fast, measured over 25 cycles

| Metric | p50 | p95 | min | max |
|---|---|---|---|---|
| **response** — detection → revoke confirmed | **12.95s** | 24.88s | 10.33s | 24.95s |
| **exposure** — threat live → revoke confirmed | **13.38s** | 25.01s | 10.47s | 25.28s |

25/25 cycles succeeded. Gas per revoke was a flat 46,482, sponsored in every
cycle. Two figures rather than one because conflating the agent's own speed with
the user's real exposure window would flatter the result.

Neither figure includes polling delay — the benchmark triggers detection
immediately rather than waiting for the timer, so a deployment polling every
`pollIntervalMs` adds an average of `pollIntervalMs/2` on top. The p95 is more
than double the p50 because four consecutive cycles hit a slow block-inclusion
window; that variance is the network's, not the agent's, which is exactly why
this is reported as a distribution instead of a headline number.

Full per-cycle transaction links: [BENCHMARK.md](./BENCHMARK.md).

Verify it yourself, no credentials needed:

```bash
cast call 0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb \
  "allowance(address,address)(uint256)" \
  0x5E2e5Fd3aD7fDC9B94482930db8b5F45E439bab7 \
  0x8eBf8540EdE8e40CD94825C418758d4029D8892e \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
# 0
```

The condition was evaluated against the live chain, not a cached value —
KeeperHub reported `observedValue: 115792089237316195423570985008687907853269984665640564039457584007913129639935`
at execution time.

### Supporting executions

| What | Transaction |
|---|---|
| First execution via KeeperHub | [`0xacc7979a…c11409`](https://sepolia.etherscan.io/tx/0xacc7979a1c59a64764210f8a5a9068ad9243c5b2646cd02141ee1d3316c11409) |
| `pnpm spike` — full integration proof | [`0x1f95fdd3…bf3d9d`](https://sepolia.etherscan.io/tx/0x1f95fdd3a519a74ef2e919f272bcc8c89d3e4175efde97bbd536f7e7bcbf3d9d) |
| Funding the deploy key, via KeeperHub | [`0x00b4c5fb…e5c739`](https://sepolia.etherscan.io/tx/0x00b4c5fb4eacceaf3f273273b5035bf393fdd3fdfbe40672baf1f948b2e5c739) |

All verified independently of KeeperHub's own reporting, via public RPC
`eth_getTransactionReceipt`. `pnpm spike` reproduces the integration proof and
fails loudly if any step cannot be verified on-chain.

Contract addresses: [`deployments.json`](./deployments.json).

### Reading these links

KeeperHub executes through a **sponsored relay**, so the `from` address on the
explorer is KeeperHub's relayer — not the signer. The flow is:

```
relayer 0x809d…0444  →  forwarder 0x5af5…f07d  →  our Turnkey account 0x5E2e…bab7
```

Our account address appears in the transaction calldata, and the value moves
internally. This is expected: KeeperHub sponsors gas (the signer's balance is
untouched — verified) and submits through its own routing. Do not expect the
signer address in the `from` field.

---

## Architecture

```
Approval / ApprovalForAll logs
            │
            ▼
      watcher  ──▶  3 concrete threat rules
                            │  fires
                            ▼
        KeeperHub  POST /api/execute/check-and-execute
              re-read allowance  +  approve(spender, 0)
                     in ONE atomic operation
                            │
                            ▼
              real transaction  ──▶  audit trail
```

The revoke goes through `check-and-execute` rather than a read followed by a
write. That matters: the allowance is re-read and the revoke fired inside the
same server-side operation, so a drainer cannot slip a `transferFrom` between our
check and our act. A check-then-act implementation has a race window; this
does not.

### Why KeeperHub is the engine, not decoration

Remove KeeperHub and Revoker needs seven separate systems: a transaction
relayer, a congestion-aware gas oracle with backoff, an MEV-protected submission
route, a status/confirmation poller, an action-discovery layer, an ABI
resolution service, and an audit-log pipeline — plus a custody solution.
KeeperHub signs through a Turnkey enclave, so this process never holds a private
key.

KeeperHub surfaces used so far:

| Surface | Used for |
|---|---|
| `POST /api/execute/check-and-execute` | the atomic revoke |
| `POST /api/execute/contract-call` | allowance reads, contract writes |
| `POST /api/execute/transfer` | native transfers |
| `GET /api/execute/{id}/status` | confirmation + audit record |
| `GET /api/chains` | network + explorer resolution |
| `GET /api/chains/{id}/abi` | ABI resolution |
| `GET /api/user/wallet` | signer identity |
| `simulate: true` | pre-flight dry runs before spending gas |

---

## Running it

Requires Node 22+, pnpm, and Foundry.

```bash
pnpm install
cd contracts && forge build && cd ..

pnpm spike              # prove the KeeperHub integration end-to-end
pnpm seed               # stage the threat (idempotent — safe to re-run)
pnpm watch -- --once    # watch Revoker detect it and take it away
pnpm test               # 15 tests
```

`pnpm watch -- --dry-run` detects and reports without executing anything.

### Threat rules

| Rule | Fires when | Signal source |
|---|---|---|
| `unlimited-to-unverified` | `MAX_UINT256` allowance to a contract whose source is unreadable | KeeperHub ABI resolution |
| `young-spender` | spender contract deployed < 7 days ago | `eth_getCode`, binary search |
| `denylisted` | spender is on the known-bad list | `data/denylist.json` |

Any one rule firing is sufficient — these are independent signals of different
kinds, not weighted terms in a score. Requiring consensus would mean ignoring a
confirmed deny-list hit because the contract happened to be verified.

Every firing carries the evidence that produced it into the audit trail, so a
revoke can be justified after the fact. Deliberately not an ML "maliciousness
score": *the model said so* is not a defence when it is wrong.

Credentials resolve from `process.env`, then `~/.config/keeperhub/env`, then a
local `.env`. Nothing secret is ever committed.

```
KH_API_KEY=kh_...                  # app.keeperhub.com -> Settings -> API Keys
KH_WALLET_ADDRESS=0x...            # app.keeperhub.com -> Wallet tab
KH_NETWORK=sepolia
KH_CHAIN_ID=11155111
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
```

> **Note on the signer.** `approve(spender, 0)` clears the allowance of
> `msg.sender` and nobody else's. KeeperHub signs exclusively for your org's
> Turnkey account, so that account is necessarily both the watched wallet and
> the revoke sender. The spike asserts your configured address matches the one
> KeeperHub actually controls, and fails loudly if it does not.

### Known limits, stated plainly

**Token discovery requires an explicit watchlist** (`data/watchlist.json`). No
public RPC will serve an address-less `eth_getLogs` over a useful block range —
publicnode requires an address filter, 1rpc caps the range at 50 blocks — and
KeeperHub's balances endpoint only covers a curated token registry. Production
would resolve this set from an indexer. Revoker protects the tokens it is told
to watch, rather than implying coverage it does not have.

**`young-spender` needs an archive node.** `eth_getCode` at a block from last
week is unanswerable on a pruning RPC. The rule returns `INDETERMINATE` and
names the remedy instead of reporting "safe" — a threat rule that silently
degrades into a rubber stamp is worse than one that admits it cannot see. Point
`SEPOLIA_RPC_URL` at an archive node to enable it.

**The threat model is narrow on purpose.** A spender that is verified, aged, and
absent from the deny-list trips nothing. That case is out of scope, not silently
mishandled.

---

## Status

This is an active hackathon build for
[Agents Onchain](https://dorahacks.io/hackathon/agents-onchain) (KeeperHub).

Shipped: KeeperHub client with retry/backoff, rate-limit pacing and idempotency;
seed contracts deployed to Sepolia; a verified integration spike; and the
complete detect→revoke→proof cycle above. Landing next: the autonomous watcher
with three threat rules, unit tests, `scripts/bench.ts` (p50/p95 over N=25), and
the live `/verify` stream.

## Documentation

| Document | What's in it |
|---|---|
| [DEMO.md](./DEMO.md) | Reproduce everything from a clean checkout, with expected output |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | The loop, the TOCTOU decision, failure modes, why KeeperHub |
| [BENCHMARK.md](./BENCHMARK.md) | p50/p95 detect→revoke latency over N=25, per-cycle transaction links |
| [deployments.json](./deployments.json) | Contract addresses and deploy transactions |

## License

MIT — see [LICENSE](./LICENSE).
