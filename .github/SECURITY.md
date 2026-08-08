# Security Policy

Revoker is a security tool that holds an API key capable of moving funds. Treat
issues here accordingly.

## Supported versions

| Version | Supported |
|---|---|
| `main` | ✅ |
| tagged releases | ❌ — none yet; this is a hackathon build |

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Use [GitHub private vulnerability reporting](https://github.com/edycutjong/revoker/security/advisories/new),
or email the maintainer at edy.cu@live.com.

Please include what you can: affected file or endpoint, reproduction steps, and
the impact you believe it has. A proof-of-concept against a testnet is welcome;
please do not test against anyone else's mainnet funds.

Expect an acknowledgement within 72 hours.

## Threat model

What this project assumes, so you know what counts as a vulnerability:

- **The agent never holds a private key.** Signing happens inside a Turnkey
  enclave via KeeperHub. Anything that would cause this process to obtain, log,
  or transmit raw key material is a vulnerability.
- **The API key is the sensitive credential.** It can authorise transactions
  from the org wallet. It is read from `process.env`, then
  `~/.config/keeperhub/env`, then a gitignored `.env` — never from the repo.
  Anything that logs, serialises, or transmits it is a vulnerability.
- **Threat rules are advisory, not authoritative.** A missed detection is a
  known limitation of a deliberately narrow rule set (see README), not a
  vulnerability. A *false* revoke fired against a benign spender is.
- **The audit trail must be truthful.** Any path where a revoke is reported as
  confirmed while the allowance is still non-zero is a vulnerability — the
  agent's honesty about its own actions is a security property.

## Known limitations (by design, not vulnerabilities)

These are documented in the README and are deliberate scope boundaries:

- Token discovery is watchlist-scoped; no public RPC serves address-less
  `eth_getLogs` over a useful block range.
- The `young-spender` rule requires an archive RPC and abstains — loudly, as
  `INDETERMINATE` — when historical state is unavailable.
- A spender that is verified, aged, and absent from the deny-list trips no rule.
- Demo contracts (`MockUSDC`, `RoachMotelSpender`) are unaudited testnet
  fixtures. They are not intended for any other use.
