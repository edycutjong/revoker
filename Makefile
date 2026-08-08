.PHONY: help install check lint typecheck test contracts spike seed watch verify bench clean

help:  ## Show this help
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## Install deps + forge-std
	pnpm install
	cd contracts && forge install foundry-rs/forge-std --no-git && forge build

check:  ## Everything CI runs: lint, types, coverage, contract tests
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

watch:  ## Run the agent for one scan
	pnpm watch -- --once

verify:  ## Run the agent with the live dashboard at :3000/verify
	pnpm verify

bench:  ## N=25 detect->revoke benchmark, writes BENCHMARK.md
	pnpm bench

clean:  ## Remove build artifacts
	rm -rf coverage contracts/out contracts/cache audit
