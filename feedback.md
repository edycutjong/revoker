# KeeperHub — a zero-to-first-transaction teardown

Written while building [Revoker](./README.md) for Agents Onchain, by someone who
had never used KeeperHub before. Seven findings, every one hit in practice. Each
has a proposed fix, and each says plainly what evidence backs it — five are
reproducible from this repo, two rest on my own observation and are marked as
such.

Context for weighting: I got from a fresh API key to a **real Sepolia
transaction in under an hour**, and to an autonomous agent landing revokes the
same day. The platform is good. These are the specific places it cost me time.

**Time lost to these, total: roughly 2 hours** — and about 40 minutes of that was
one finding (#2) that presents as something it isn't.

---

## 1. Gas sponsorship works on Sepolia, but the docs say mainnet-only

**Severity: medium — it causes builders to design around a cost that isn't there.**

The hackathon brief and docs state gas sponsorship applies to mainnet Ethereum.
Taking that at face value, I specced an entire escrow contract (`GuardVault`) so
the agent could self-fund gas on testnet.

The first real execution disproved it. Every Revoker execution on **Ethereum
Sepolia** returns `sponsored: true`, and the signer's balance is byte-for-byte
unchanged — verified by `eth_getBalance` before and after, not by trusting the
API's own report.

```
25/25 benchmark cycles: sponsored: true          (recorded in BENCHMARK.md)
signer balance before/after the integration spike: 50000000000000000 wei, unchanged
first observed: 2026-08-08, tx 0x1f95fdd3a519a74ef2e919f272bcc8c89d3e4175efde97bbd536f7e7bcbf3d9d
```

(The balance check runs once, in `scripts/spike.ts`. The benchmark records the
`sponsored` flag on every cycle but does not re-read the balance each time.)

I cut `GuardVault` rather than ship an escrow for a cost that does not exist.
That was the right call, but I'd built the spec around a documented constraint
that turned out not to hold.

**Proposed fix:** state the sponsorship policy per-network explicitly, including
testnets, and say whether testnet sponsorship is a standing allowance or
best-effort. A builder needs to know whether to design for it. Right now the docs
imply "you pay on testnet" and reality says otherwise, which is the more
expensive direction to be wrong in — you build machinery you don't need.

---

## 2. The edge rejects Python's default user-agent, and it looks exactly like an auth failure

**Severity: high — highest time-cost finding in this list.**

A `POST` to `/api/execute/check-and-execute` from Python's standard library
returns **HTTP 403** with a Cloudflare `error code: 1010` body, before the
request ever reaches KeeperHub.

```python
# fails with 403 — looks like a bad API key
import urllib.request, json
req = urllib.request.Request(
    "https://app.keeperhub.com/api/execute/check-and-execute",
    data=json.dumps(body).encode(),
    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
urllib.request.urlopen(req)          # HTTP Error 403: Forbidden

# identical request via curl or fetch — 202 Accepted
```

**Why this costs so much time:** 403 on an authenticated endpoint reads as
"your key is wrong". I re-checked the key, regenerated it mentally, re-read the
auth docs, and diffed my request against the reference — all before noticing the
response body was Cloudflare's, not KeeperHub's. The body says `error code: 1010`
and nothing else; there is no JSON, no KeeperHub error shape, no hint that the
request was never seen.

**Proposed fix, in order of preference:**
1. Allow the default `Python-urllib` user-agent. It is the standard library of
   the language most agent frameworks are written in.
2. If the WAF rule must stay, return **401/403 with a KeeperHub-shaped JSON body**
   that names the cause: `{"error":"blocked_by_edge","detail":"unrecognised user-agent"}`.
3. At minimum, add a line to the API authentication page: *"Requests with default
   scripted user-agents may be blocked at the edge; set a custom `User-Agent`."*

Any of the three turns a 40-minute dead end into a 30-second one.

---

## 3. `check-and-execute` returns success without a transaction hash

**Severity: medium.**

`POST /api/execute/check-and-execute` returns:

```json
{"executionId":"vgxqucg0ofa2o4evjs0tr","status":"completed","executed":true,
 "conditionResult":{"met":true,"observedValue":"1157920892…","operator":"gt"}}
```

`status: "completed"`, `executed: true`, and **no `transactionHash`**. The hash
only appears on `GET /api/execute/{id}/status`.

The [Direct Execution docs](https://docs.keeperhub.com/api/direct-execution) show
`transactionHash` in the `/execute/transfer` response shape, so it is reasonable
to expect it here too. An agent that logs "revoked, tx: undefined" looks broken
to its own operator.

**Proposed fix:** include `transactionHash` in the `check-and-execute` response
when `executed: true` — or, if it genuinely isn't available yet at return time,
say so explicitly in the docs next to that response shape: *"the hash is
attached asynchronously; poll `/api/execute/{id}/status`."*

---

## 4. Gas is `gasUsed` on one response and `gasUsedWei` on another

**Severity: low, but it's a silent one.**

| Endpoint | Field |
|---|---|
| `POST /api/execute/transfer` | `gasUsed` |
| `GET /api/execute/{id}/status` (top level) | `gasUsedWei` |

I typed the client against the execute-response shape, and every status poll
logged `gasUsed: undefined` — no error, no warning, just a missing number in the
audit trail. It surfaced only because I was reading the log output closely.

**Proposed fix:** use one name. If both must exist for compatibility, document
the pairing on the status endpoint. (Minor: `gasUsedWei` is also a slight
misnomer — the value is gas *units*, not wei. `gasPriceWei` alongside it is
correctly named, which makes the pair read as if both were wei.)

---

## 5. The `network` parameter won't accept the name the API itself returns

**Severity: medium — this is a discoverability trap.**

`GET /api/chains` returns, for Sepolia:

```json
{"chainId": 11155111, "name": "Ethereum Sepolia", "symbol": "ETH", …}
```

The natural next step is to pass that `name` into an execute call. It fails.
I probed four forms with `simulate: true`:

| `network` value | Result |
|---|---|
| `"sepolia"` | ✅ accepted |
| `"11155111"` | ✅ accepted |
| `"Ethereum Sepolia"` — the API's own `name` | ❌ |
| `"ethereum-sepolia"` | ❌ |

So the field that discovers a chain returns an identifier the field that
*executes* on that chain rejects.

**Proposed fix:** either accept the `name` from `/api/chains`, or add a
`networkSlug` field to that response carrying the exact string `network` expects.
The second is a one-field change and removes the guesswork entirely.

Credit where due: `simulate: true` is what made this cheap to find. Being able to
probe four values without spending gas is genuinely good API design, and it is
the reason this cost me five minutes instead of an hour.

---

## 6. `/api/user/wallet/balances` only sees a curated token registry

**Severity: low — expected behaviour, undocumented consequence.**

I tried to use this endpoint for token discovery in the watcher. For Sepolia it
returns `tokens: []` and `supportedTokens: ["USDC","USDT"]`, even when the wallet
holds a non-zero balance of a token outside that registry.

That's a reasonable product decision. But nothing on the endpoint says the token
set is curated, so it reads as "this wallet holds nothing" rather than "this
wallet holds nothing *I track*". I built discovery around it before finding out.

**Proposed fix:** one sentence in the docs — *"balances cover KeeperHub's
supported-token registry; tokens outside it are not reported"* — and ideally a
`registryScoped: true` flag on the response so a client can tell the two cases
apart programmatically.

---

## 7. Two documented CLI commands are 404

**Severity: low, but trivially fixable.**

Both verified returning HTTP 404 on 2026-08-08:

- `https://docs.keeperhub.com/cli/commands/kh_execute_contract`
- `https://docs.keeperhub.com/cli/commands/kh_workflow_go`

`https://docs.keeperhub.com/api/overview` is also 404.

**Proposed fix:** fix or remove the links. If those CLI verbs don't exist and the
functionality is REST/MCP-only, saying so is more useful than a dead page —
"contract calls are available via the API and MCP server, not the CLI" would have
saved me checking whether I'd mistyped.

---

## What worked well — because a teardown that only complains isn't useful

- **`simulate: true`** is the single best thing in this API. Validating a call,
  catching a revert and getting a gas estimate without spending gas made every
  subsequent step cheap to attempt. Finding #5 above took five minutes *because*
  of it.
- **`Idempotency-Key`** is exactly right for an autonomous agent. Retrying a
  write is how agents double-execute; having a first-class way to make retries
  safe meant I never had to build my own dedupe.
- **Turnkey-enclave signing** is why this project is defensible at all. An
  autonomous agent holding a hot key that can move funds is a liability. Being
  able to say "this process never holds a private key" is a security property I
  got for free.
- **`GET /api/chains/{id}/abi`** returns a clean `success: false` with
  `"Contract source code is not verified"` rather than an error. That distinction
  is useful enough that I built a **threat rule** on it — unverified source is a
  real signal, and this endpoint is the cheapest way to get it.
- **Error bodies are well-shaped** everywhere the edge didn't intercept them.
  `{"error": "..."}` with a meaningful status made retry logic straightforward:
  back off on 429/5xx, never retry a 4xx.

---

## Reproductions

Not all of these are equally reproducible from this repo, so here is exactly
what backs each one:

| # | Backed by |
|---|---|
| 1 | `BENCHMARK.md` — `sponsored: true` on 25/25 cycles. The single balance check is in `scripts/spike.ts`. |
| 2 | **My observation only.** No artifact in this repo; needs a live key to reproduce. |
| 3 | `src/revoke.ts` — the code polls `/status` for the hash, with a comment saying why. |
| 4 | `src/keeperhub.ts` — the status response type carries `gasUsedWei` where the execute response carries `gasUsed`. |
| 5 | **My observation only.** The probe was run by hand and not recorded. |
| 6 | `src/watcher.ts` + `src/keeperhub.ts` — token discovery falls back to an explicit watchlist because of this. |
| 7 | Verified live on 2026-08-08 with `curl`. |

`pnpm spike` exercises the integration end to end and verifies its result against
a public RPC rather than trusting KeeperHub's own report — see
[DEMO.md](./DEMO.md). Findings #2 and #5 rest on my word; I have flagged them
rather than dressing them up.
