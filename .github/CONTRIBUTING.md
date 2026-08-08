# Contributing

Thanks for taking a look. This started as a hackathon build for
[Agents Onchain](https://dorahacks.io/hackathon/agents-onchain), and the code is
written to be read.

## Getting started

Requires Node 22+, pnpm 10+, and [Foundry](https://book.getfoundry.sh/).

```bash
pnpm install
cd contracts && forge install foundry-rs/forge-std --no-git && forge build && cd ..
pnpm test              # unit tests
pnpm contracts:test    # Solidity tests + fuzz
```

Credentials resolve from `process.env`, then `~/.config/keeperhub/env`, then a
gitignored `.env`. Copy `.env.example` to get started. You need a KeeperHub
organisation API key and its Turnkey wallet address to run anything that touches
a chain — see [DEMO.md](../DEMO.md).

## Before you open a PR

```bash
pnpm check   # lint + typecheck + coverage + contract tests
```

That is exactly what CI runs. If it passes locally it passes there.

## House rules

- **Never mock the thing being demonstrated.** The revoke must be a real
  transaction. If a flow cannot be real, cut it rather than fake it.
- **Verify against the chain, not against the API's own report.** An execution
  API saying it succeeded is a claim; `eth_call` is evidence.
- **A rule that cannot evaluate must say so.** Returning "safe" when the data
  was unavailable turns a threat rule into a rubber stamp. See
  `young-spender`'s `INDETERMINATE` path for the pattern.
- **No credentials in the tree, ever.** CI fails the build on any
  credential-shaped string.
- **Comments explain why, not what.** The code already says what it does.

## Commit messages

Say what changed and why it matters. Prose over prefixes — the history is meant
to be readable months later.
