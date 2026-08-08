# KeeperHub — a zero-to-first-transaction teardown

Written while building [Revoker](./README.md) for Agents Onchain, by someone who
had never used KeeperHub before. Six findings hit in practice, plus one correction
to a claim I made and later disproved (#7). Each
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

## 7. Guessable CLI command names land on a 404 with no suggestion

**Severity: low. Also a correction to something I got wrong.**

I originally reported this as "two documented commands are 404". **That was
wrong, and I want to be precise about how**, because it is itself a DX finding.

The commands are `kh execute contract-call` and `kh workflow go-live`. I guessed
`contract` and `go`, constructed the doc URLs from those guesses, got 404s, and
concluded the docs were broken. They are not — both pages exist and return 200:

| URL | Status |
|---|---|
| `/cli/commands/kh_execute_contract-call` | **200** |
| `/cli/commands/kh_workflow_go-live` | **200** |
| `/cli/commands/kh_execute_contract` — my guess | 404 |
| `/cli/commands/kh_workflow_go` — my guess | 404 |

Same for `/api/overview`, which I also invented; the real index is `/api`, 200.

**The real finding is why the guesses were natural.** `kh execute transfer` and
`kh execute status` are single words, so `kh execute contract` is the obvious
extrapolation — the odd one out is the hyphenated `contract-call`. And every
other verb in the CLI is short (`get`, `list`, `set`), which makes `go` a more
natural guess than `go-live`.

**Proposed fix, in order of value:**
1. **Have the CLI suggest.** `kh execute contract` currently isn't a command; a
   "did you mean `contract-call`?" on unknown subcommands would end this class of
   problem at the source, not just in docs.
2. **Redirect the near-misses** in the docs site — `/cli/commands/kh_execute_contract`
   → `contract-call`, `/cli/commands/kh_workflow_go` → `go-live`, `/api/overview`
   → `/api`. Cheap, and it catches everyone who guesses the same way I did.
3. A 404 page that lists near-matching slugs would generalise both.

**Method note, offered honestly:** I should have hit `/cli/commands` and read the
index before asserting a page was missing. That mistake is in here rather than
quietly deleted, because a teardown that only reports the platform's errors and
not the tester's is not an honest teardown.

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

## The teardown, turned into code

Everything above is now a runnable starter template: **[`starter/`](./starter/)**.

```bash
export KH_API_KEY=kh_...
node starter/quickstart.mjs
```

One file, no dependencies, no build step, Node 20+. Seven steps from a fresh API
key to a real on-chain transaction, verified against a public RPC rather than
against KeeperHub's own report. `--doctor` runs the checks and stops before
spending anything.

Every guard in it exists because one of the findings above cost me time in that
order. It sets a `User-Agent` (finding #2), warns about the network slug at the
moment you would get it wrong (#5), reads the hash from `/status` (#3), and
notes the `gasUsed`/`gasUsedWei` split inline (#4). The failure paths explain
themselves — a bodiless 403 says "this is the edge, not your key" instead of
letting you re-check a good key for forty minutes.

Verified end to end before shipping: landed
[`0x191cc3cb…`](https://sepolia.etherscan.io/tx/0x191cc3cbb8abb1e6f7fc6983132b91f1b4c9ebd12e93defdf1818198f4fd22d4)
in 8.3s, mined in block 11,442,960.

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
| 7 | Verified live with `curl` and against the docs source in `KeeperHub/keeperhub`. Includes a correction to my own earlier claim. |

`pnpm spike` exercises the integration end to end and verifies its result against
a public RPC rather than trusting KeeperHub's own report — see
[DEMO.md](./DEMO.md). Findings #2 and #5 rest on my word; I have flagged them
rather than dressing them up.
