import { config } from './config.js'
import { onAudit, logLine } from './audit.js'
import { loadDenylist, loadWatchlist } from './lists.js'
import { Watcher } from './watcher.js'

/**
 * Entry point for the unattended agent.
 *
 *   pnpm watch              run continuously
 *   pnpm watch -- --dry-run detect and report, execute nothing
 *   pnpm watch -- --once    a single scan, then exit
 */

async function main(): Promise<void> {
  const args = new Set(process.argv.slice(2))
  const dryRun = args.has('--dry-run')
  const once = args.has('--once')

  onAudit(logLine)

  console.log('Revoker — autonomous approval sentinel')
  console.log(`  watching : ${config.walletAddress}`)
  console.log(`  network  : ${config.network} (chainId ${config.chainId})`)
  console.log(`  mode     : ${dryRun ? 'DRY RUN — nothing will be executed' : 'ARMED'}`)
  console.log()

  const tokens = loadWatchlist(config.chainId)
  console.log(`  tokens   : ${tokens.length} on the watchlist`)
  console.log()

  const watcher = new Watcher({
    owner: config.walletAddress,
    denylist: loadDenylist(),
    tokens,
    dryRun,
  })

  const shutdown = (): void => {
    console.log('\nstopping after current scan…')
    watcher.stop()
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)

  if (once) {
    await watcher.scan()
    return
  }
  await watcher.run()
}

main().catch((error: unknown) => {
  console.error(`\nfatal: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
