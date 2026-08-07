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

| What | Transaction |
|---|---|
| First execution via KeeperHub | [`0xacc7979a…c11409`](https://sepolia.etherscan.io/tx/0xacc7979a1c59a64764210f8a5a9068ad9243c5b2646cd02141ee1d3316c11409) |
| `pnpm spike` — full integration proof | [`0x1f95fdd3…bf3d9d`](https://sepolia.etherscan.io/tx/0x1f95fdd3a519a74ef2e919f272bcc8c89d3e4175efde97bbd536f7e7bcbf3d9d) |

Both verified independently of KeeperHub's own reporting, via public RPC
`eth_getTransactionReceipt`. The spike transaction: block **11,440,768**,
`status: 0x1`, sponsored, end-to-end latency **14.6s**. `pnpm spike` reproduces
this and fails loudly if any step cannot be verified on-chain.

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

Requires Node 22+ and pnpm.

```bash
pnpm install
pnpm spike     # proves the KeeperHub integration end-to-end
```

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

---

## Status

This is an active hackathon build for
[Agents Onchain](https://dorahacks.io/hackathon/agents-onchain) (KeeperHub).
Shipped so far: KeeperHub client with retry/backoff and rate-limit pacing,
credential resolution, and a verified integration spike. The watcher, threat
rules, seed contracts, and benchmark land next.

## License

MIT — see [LICENSE](./LICENSE).
