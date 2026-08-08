# KeeperHub quickstart

**Zero to a real on-chain transaction in one command.** No dependencies, no build
step, no config file.

```bash
export KH_API_KEY=kh_your_key_here     # app.keeperhub.com → Settings → API Keys → Organisation
node quickstart.mjs
```

That's it. Node 20+ (it has `fetch` built in). One file, ~200 lines, zero `npm install`.

```
1. Who am I?              GET  /api/user/wallet
2. Which networks?        GET  /api/chains
3. Am I funded?           eth_getBalance
4. Dry run first          POST /api/execute/transfer  simulate: true
5. Land a real one        POST /api/execute/transfer
6. Get the hash           GET  /api/execute/{id}/status
7. Trust nothing          eth_getTransactionReceipt
```

Just checking your setup? `node quickstart.mjs --doctor` runs steps 1–4 and stops
before spending anything.

---

## Why this exists

I built [Revoker](../README.md) for the Agents Onchain hackathon having never
used KeeperHub before. I got to a landed transaction in under an hour — the
platform is good — but I lost about two hours to things that were not the hard
part.

**Every check in this script exists because something cost me time in that
order.** The full write-up is in [feedback.md](../feedback.md); this is that
teardown turned into code so the next person skips it.

The four that cost the most:

**A 403 that isn't an auth failure.** The edge rejects some default scripted
user-agents with a bare Cloudflare body and no JSON. On a bearer-token endpoint
that reads as "your key is wrong", and I re-checked a perfectly good key for
forty minutes. This script sets a `User-Agent` on every request — **if you copy
one thing from here, copy that** — and if it still sees a bodiless 403, it says
so explicitly instead of blaming your key.

**`network` wants the slug, not the name.** `GET /api/chains` returns
`"name": "Ethereum Sepolia"`. Passing that back is rejected; it wants `sepolia`
or the chain ID. Step 2 prints the warning at the moment you'd otherwise get it
wrong.

**The hash isn't always on the execute response.** Some endpoints return
`status: completed` before the transaction hash is attached. Step 6 reads it from
`/status`, which always has it.

**`gasUsed` on one response is `gasUsedWei` on another.** Typing against the
first and reading the second gives you `undefined` with no error. Step 6 notes it
inline.

---

## What to copy into your own agent

The three patterns that matter, all in `quickstart.mjs`:

| Pattern | Why |
|---|---|
| A custom `User-Agent` | Avoids the bodiless-403 dead end entirely |
| `simulate: true` before a write | Catches reverts, bad ABIs and allowance mistakes for free — no gas |
| `Idempotency-Key` on writes | A network blip plus a retry is how you send the same transaction twice |

And one habit: **verify on-chain rather than trusting the API's own report.**
Step 7 reads `eth_getTransactionReceipt` from a public RPC and fails loudly if
the transaction isn't really there. An execution API telling you it succeeded is
a claim; a receipt is evidence.

## Where to go next

Swap step 5's endpoint:

- **`/api/execute/contract-call`** — call any contract method. Pass `functionArgs`
  and `abi` as JSON **strings**, not arrays; the API rejects arrays and the error
  is not obvious.
- **`/api/execute/check-and-execute`** — read a value, evaluate a condition, and
  write, in one server-side operation. This is what Revoker uses for the revoke:
  a read-then-write leaves a window for someone to front-run you, and this
  closes it.

## License

MIT. Take it, strip the comments, ship your own thing.
