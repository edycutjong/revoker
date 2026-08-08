# Contributing

Thanks for taking a look. This started as a hackathon build for
[Agents Onchain](https://dorahacks.io/hackathon/agents-onchain), and the code is
written to be read.

## Getting started

Requires Node 22+, pnpm 10+, and [Foundry](https://book.getfoundry.sh/).

```bash
pnpm install
cd contracts && forge install foundry-rs/forge-std --no-git && forge build && cd ..
pnpm test              # 580 TypeScript tests
pnpm contracts:test    # 54 Solidity tests + fuzz
pnpm e2e               # 34 Playwright tests over the published pages
```

No credentials are needed to try the product itself:

```bash
pnpm demo:verify       # the real /verify dashboard, replaying a recorded run
pnpm demo              # one real read-only scan of the public demo wallet
```

Credentials resolve from `process.env`, then `~/.config/keeperhub/env`, then a
gitignored `.env`. Copy `.env.example` to get started. You need a KeeperHub
organisation API key and its Turnkey wallet address to run anything that touches
a chain — see [DEMO.md](../DEMO.md).

## Before you open a PR

```bash
pnpm check   # fast local gate: lint, typecheck, TS coverage, contract tests
```

**This is not everything CI runs.** CI additionally runs `pnpm audit`, gitleaks
over the full history, the credential grep, `forge build --sizes`,
`forge snapshot --check`, Slither, the Solidity coverage gate, Playwright and
Lighthouse. `make security-scan`, `make e2e` and `make lighthouse` cover some of
that locally; the rest is CI-only. Green here means the fast gate passed, not
that CI will.

Coverage is **gated at 100%** for statements, branches, functions and lines
across `src/` *and* `scripts/` (see `vitest.config.ts`), and at 100% for the
contracts. A PR that adds an unreachable branch fails the build.

## House rules

- **Never mock the thing being demonstrated.** The revoke must be a real
  transaction. If a flow cannot be real, cut it rather than fake it.
- **Verify against the chain, not against the API's own report.** An execution
  API saying it succeeded is a claim; `eth_call` is evidence.
- **A green test suite is not proof the write lands.** The Permit2 tuple-guard
  bug passed every mocked test *and* a dry-run simulation, and was only found by
  a real transaction. Anything that changes the execution path needs one real
  run before it is believed.
- **Never send an unguarded write.** If the guard read cannot be resolved, the
  revoke must refuse rather than submit. See `permit2AllowanceViewAddress()`.
- **A rule that cannot evaluate must say so.** Returning "safe" when the data
  was unavailable turns a threat rule into a rubber stamp. See
  `young-spender`'s `INDETERMINATE` path for the pattern.
- **No credentials in the tree, ever.** CI fails the build on any
  credential-shaped string.
- **Comments explain why, not what.** The code already says what it does.

## Commit messages

Say what changed and why it matters. Prose over prefixes — the history is meant
to be readable months later.
