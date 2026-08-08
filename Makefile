.PHONY: help install check lint typecheck test contracts spike seed seed-permit2 arm watch verify bench clean e2e lighthouse security-scan

help:  ## Show this help
	@grep -E '^[a-z0-9-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## Install deps + forge-std
	pnpm install
	cd contracts && forge install foundry-rs/forge-std --no-git && forge build

# NOT everything CI runs — CI additionally runs `pnpm audit`, gitleaks, the
# credential grep, `forge build --sizes`, `forge snapshot --check`, Slither, the
# Solidity coverage gate, Playwright and Lighthouse. `make security-scan`, `make
# e2e` and `make lighthouse` cover some of that locally; the rest is CI-only.
# Green here means the fast gate passed, not that CI will.
check:  ## Fast local gate: lint, types, TS coverage, contract tests
	pnpm check

lint:  ## ESLint
	pnpm lint

typecheck:  ## tsc --noEmit
	pnpm typecheck

test:  ## Unit tests
	pnpm test

contracts:  ## Solidity tests + fuzz
	pnpm contracts:test

spike:  ## Prove the KeeperHub integration end-to-end (needs credentials)
	pnpm spike

seed:  ## Arm the threat scenario on Sepolia (idempotent)
	pnpm seed

# The Permit2 twin of `seed`. Separate target because it arms a different
# surface: `seed` writes the token's own allowance mapping, this writes Permit2's
# ledger — the grant an ERC-20 Approval log cannot see. Both are idempotent.
seed-permit2:  ## Arm the Permit2 allowance on Sepolia (idempotent; --rearm to force)
	pnpm seed:permit2

# Addresses come from deployments.json so this target never drifts from what the
# seed actually deployed. Lazy `=`, not `:=`: these shell out to node, and only
# `arm` needs them.
CHAIN_ID = $(shell node -e "console.log(require('./deployments.json').sepolia.chainId)")
TOKEN    = $(shell node -e "console.log(require('./deployments.json').sepolia.contracts.MockUSDC.address)")
SPENDER  = $(shell node -e "console.log(require('./deployments.json').sepolia.contracts.RoachMotelSpender.address)")
VICTIM   = $(shell node -e "console.log(require('./deployments.json').sepolia.watchedWallet.address)")

# The operator flow, spelled out rather than buried inside a script. `make seed`
# does the same arming; what this adds is the checks a human actually runs by
# hand around it — who am I, can the wallet pay for gas, and is the approval the
# seed claims to have armed really on chain. The last step is deliberately an
# independent read (`kh read` is eth_call and needs no auth), so it can disagree
# with the seed's own report.
arm:  ## Operator flow: kh identity + gas check, arm the approval, verify on chain
	@command -v kh >/dev/null 2>&1 || { \
	  echo "kh is not installed — brew install keeperhub/tap/kh"; exit 1; }
	kh version
	kh auth status
	kh wallet balance --chain Sepolia
	pnpm seed
	kh read $(TOKEN) "allowance(address,address)" $(VICTIM) $(SPENDER) --chain $(CHAIN_ID)

watch:  ## Run the agent for one scan
	pnpm watch -- --once

verify:  ## Run the agent with the live dashboard at :3000/verify
	pnpm verify

bench:  ## N=25 detect->revoke benchmark, writes BENCHMARK.md
	pnpm bench

clean:  ## Remove build artifacts
	rm -rf coverage contracts/out contracts/cache audit

e2e:  ## Playwright E2E over the published pages
	pnpm e2e

lighthouse:  ## Lighthouse budgets (a11y, SEO, perf) against site/
	pnpm lighthouse

security-scan:  ## Credential grep + dependency audit (CI also runs gitleaks)
	bash scripts/check-no-credentials.sh
	pnpm audit --audit-level=high
