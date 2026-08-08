/**
 * Create or update the Revoker sentinel workflow on KeeperHub from the
 * definition committed at workflows/revoker-sentinel.json.
 *
 *   pnpm workflow:deploy
 *
 * The definition lives in the repo rather than only in somebody's KeeperHub
 * account so it can be reviewed as source: a workflow you cannot diff is a
 * workflow nobody can check. This script is the one-way bridge from that file
 * to the platform.
 *
 * ── Why the validation is local ──────────────────────────────────────────────
 *
 * KeeperHub's `validate_workflow` takes a workflowId and validates a workflow
 * that has ALREADY been persisted to your org — there is no endpoint that
 * validates a definition you are merely holding. Sending it first and asking
 * afterwards is not validation, it is a rollback plan. So the checks below are
 * a local mirror of that tool's documented fast tier (empty nodes, edge
 * references, trigger config, bare-@ literals, chain id in the chains table,
 * contract address format), run BEFORE anything is sent. Once the workflow
 * exists, the real `validate_workflow` can be pointed at the id this prints —
 * and the deep tier, which does ABI bytecode matching over the network, is only
 * reachable that way at all.
 *
 * ── What this deliberately does not do ───────────────────────────────────────
 *
 * It never enables the workflow. `enabled` defaults to false on create, and an
 * Event trigger wired to a live write endpoint is a human's decision, not a
 * script's. The command to flip it is printed instead of run.
 */
import { readFileSync } from 'node:fs'
import { config } from '../src/config.js'

const DEFINITION_PATH = new URL('../workflows/revoker-sentinel.json', import.meta.url)
const DEPLOYMENTS_PATH = new URL('../deployments.json', import.meta.url)

/**
 * Chain ids KeeperHub reports as supported, transcribed from
 * `GET /api/mcp/schemas` (the same registry `list_action_schemas` serves).
 * Checked locally because a typo'd chain id is otherwise a runtime failure on
 * a trigger that simply never fires — the quietest possible way for a security
 * workflow to be broken.
 */
const KNOWN_CHAIN_IDS = new Set([
  '1', '10', '56', '97', '101', '103', '137', '4217', '8453', '9745', '9746',
  '16602', '16661', '42161', '42431', '43113', '43114', '80002', '84532',
  '421614', '11155111', '11155420',
])

/** System action types are Pascal-case with spaces; plugin actions are `slug/name`. */
const CONDITION_ACTION = 'Condition'

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/
/** `${NAME}` — the substitution markers the committed definition carries. */
const PLACEHOLDER_RE = /\$\{([A-Z0-9_]+)\}/g

/**
 * Permitted characters in the callback secret.
 *
 * Not paranoia about exotic passwords — a nesting problem. The secret is
 * substituted into `httpHeaders`, which is itself a JSON string INSIDE the JSON
 * document, so it needs escaping twice; and nothing here can tell how deeply
 * any given placeholder is nested. Rather than guess at the depth, the secret
 * is restricted to characters that need no escaping at any level. A bearer
 * token has no business containing a quote or a backslash in the first place.
 */
const SAFE_SECRET_RE = /^[A-Za-z0-9._~+/=-]{8,}$/
/** `{{@nodeId:Label.field}}` — KeeperHub's own template reference syntax. */
const TEMPLATE_REF_RE = /\{\{@[^:}]+:[^}]*\}\}/g

interface WorkflowNode {
  id?: string
  type?: string
  data?: {
    label?: string
    config?: Record<string, unknown>
  }
}

interface WorkflowEdge {
  id?: string
  source?: string
  target?: string
  sourceHandle?: string
}

interface WorkflowDefinition {
  name?: string
  description?: string
  nodes?: WorkflowNode[]
  edges?: WorkflowEdge[]
}

interface DeploymentsFile {
  sepolia: { contracts: Record<string, { address: string } | undefined> }
}

/** The watched token, so an operator only has to configure what is truly theirs. */
function watchedTokenFromDeployments(): string | undefined {
  try {
    const parsed = JSON.parse(readFileSync(DEPLOYMENTS_PATH, 'utf8')) as DeploymentsFile
    // A malformed file throws its way into the catch rather than being probed
    // key by key. The outcome is identical either way, and the operator gets
    // told which variable to set instead of which file looked odd.
    return parsed.sepolia.contracts['MockUSDC']?.address
  } catch {
    return undefined
  }
}

function placeholderValues(): Record<string, string | undefined> {
  return {
    REVOKER_CALLBACK_URL: process.env['REVOKER_CALLBACK_URL'],
    REVOKER_CALLBACK_SECRET: process.env['REVOKER_CALLBACK_SECRET'],
    // Defaulted from the tree. The two above are genuinely per-deployment —
    // where this agent is reachable, and the secret it will accept — and are
    // the only two an operator must supply.
    REVOKER_WATCHED_WALLET: process.env['REVOKER_WATCHED_WALLET'] ?? config.walletAddress,
    REVOKER_WATCHED_TOKEN: process.env['REVOKER_WATCHED_TOKEN'] ?? watchedTokenFromDeployments(),
  }
}

/**
 * Fill the `${NAME}` markers, reporting any that could not be filled.
 *
 * Substituted into a JSON *document*, so each value is escaped as a JSON string
 * body first: a secret containing a quote or a backslash would otherwise not be
 * rejected, it would silently corrupt the definition into something that still
 * parses and means something else.
 */
function substitute(
  raw: string,
  values: Record<string, string | undefined>,
): { text: string; missing: string[] } {
  const missing = new Set<string>()
  const text = raw.replace(PLACEHOLDER_RE, (_match, name: string) => {
    const value = values[name]
    if (value === undefined || value === '') {
      missing.add(name)
      return `\${${name}}`
    }
    return JSON.stringify(value).slice(1, -1)
  })
  return { text, missing: [...missing] }
}

/** Every string buried anywhere in a node's config, for the text-level checks. */
function configStrings(node: WorkflowNode): string[] {
  const found: string[] = []
  const walk = (value: unknown): void => {
    if (typeof value === 'string') found.push(value)
    else if (Array.isArray(value)) value.forEach(walk)
    else if (value !== null && typeof value === 'object') Object.values(value).forEach(walk)
  }
  walk(node.data?.config)
  return found
}

/**
 * Local mirror of `validate_workflow`'s fast tier. Returns every problem found
 * rather than the first: an operator fixing a workflow definition should get
 * one list, not one round-trip per mistake.
 */
interface Preflight {
  errors: string[]
  /** The normalised node/edge arrays, so callers never re-derive them. */
  nodes: WorkflowNode[]
  edges: WorkflowEdge[]
}

function preflight(wf: WorkflowDefinition): Preflight {
  const errors: string[] = []
  const nodes = wf.nodes ?? []
  const edges = wf.edges ?? []

  if (wf.name === undefined || wf.name === '') errors.push('workflow has no name')
  if (nodes.length === 0) errors.push('workflow has no nodes')

  const ids = new Set<string>()
  const conditionIds = new Set<string>()
  let triggers = 0

  for (const node of nodes) {
    const id = node.id
    if (id === undefined || id === '') {
      errors.push('a node has no id')
      continue
    }
    if (ids.has(id)) errors.push(`duplicate node id: ${id}`)
    ids.add(id)

    const nodeConfig = node.data?.config ?? {}

    if (node.type === 'trigger') {
      triggers += 1
      if (typeof nodeConfig['triggerType'] !== 'string') {
        errors.push(`trigger node ${id} has no config.triggerType`)
      }
      const network = nodeConfig['network']
      // Only chain-bound triggers carry one; Manual and Webhook do not.
      if (typeof network === 'string' && !KNOWN_CHAIN_IDS.has(network)) {
        errors.push(`node ${id} targets unknown chain id ${network}`)
      }
    } else {
      const actionType = nodeConfig['actionType']
      if (typeof actionType !== 'string') {
        errors.push(`action node ${id} has no config.actionType`)
      } else if (actionType === CONDITION_ACTION) {
        conditionIds.add(id)
      }
    }

    const contractAddress = nodeConfig['contractAddress']
    if (typeof contractAddress === 'string' && !ADDRESS_RE.test(contractAddress)) {
      errors.push(`node ${id} has a malformed contractAddress: ${contractAddress}`)
    }

    // A bare `@something` outside a {{ }} wrapper is the classic broken
    // reference — it looks like a node reference and is treated as a literal.
    // (No "leftover placeholder" check here: substitute() reports every
    // unresolved ${MARKER} by name before pre-flight is ever reached, so a
    // second check at this level could only ever be dead code.)
    for (const text of configStrings(node)) {
      if (text.replace(TEMPLATE_REF_RE, '').includes('@')) {
        errors.push(`node ${id} contains a bare @ reference outside {{ }}`)
      }
    }
  }

  if (triggers !== 1) errors.push(`workflow must have exactly one trigger node, found ${triggers}`)

  for (const edge of edges) {
    if (edge.source === undefined || !ids.has(edge.source)) {
      errors.push(`edge ${edge.id ?? '(unnamed)'} has an unknown source: ${edge.source ?? '(none)'}`)
    }
    if (edge.target === undefined || !ids.has(edge.target)) {
      errors.push(`edge ${edge.id ?? '(unnamed)'} has an unknown target: ${edge.target ?? '(none)'}`)
    }
    // Condition nodes branch. An edge leaving one without a handle is not a
    // default path, it is an ambiguous one.
    if (edge.source !== undefined && conditionIds.has(edge.source)) {
      if (edge.sourceHandle !== 'true' && edge.sourceHandle !== 'false') {
        errors.push(`edge ${edge.id ?? '(unnamed)'} leaves a Condition node without sourceHandle`)
      }
    }
  }

  // Every {{@nodeId:...}} must name a node that exists, or the reference
  // resolves to nothing at runtime and the step silently reads an empty string
  // — a workflow that runs, alerts, and says nothing useful.
  for (const node of nodes) {
    for (const text of configStrings(node)) {
      for (const ref of text.match(TEMPLATE_REF_RE) ?? []) {
        // `{{@` is three characters; the node id runs to the first colon.
        const referenced = ref.slice(3, ref.indexOf(':'))
        if (referenced !== '__system' && !ids.has(referenced)) {
          errors.push(`node ${node.id ?? '(unnamed)'} references unknown node ${referenced}`)
        }
      }
    }
  }

  return { errors, nodes, edges }
}

async function api<T>(
  apiKey: string,
  path: string,
  init: { method: string; body?: unknown },
): Promise<T> {
  const response = await fetch(`${config.baseUrl}${path}`, {
    method: init.method,
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'User-Agent': 'revoker-workflow-deploy (+https://github.com/edycutjong/revoker)',
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  })

  const text = await response.text()
  let parsed: unknown
  try {
    parsed = text === '' ? null : JSON.parse(text)
  } catch {
    parsed = text
  }

  if (!response.ok) {
    const detail = typeof parsed === 'string' ? parsed : JSON.stringify(parsed)
    throw new Error(`KeeperHub ${response.status} on ${init.method} ${path}: ${detail}`)
  }
  return parsed as T
}

async function main(): Promise<void> {
  console.log('Revoker — deploy the KeeperHub sentinel workflow\n')

  if (config.demo) {
    throw new Error(
      'REVOKER_DEMO is set. Demo mode substitutes a sentinel API key that no KeeperHub\n' +
        'organisation will accept, so this would fail with a confusing 401 rather than\n' +
        'deploy anything. Unset REVOKER_DEMO and supply real credentials.',
    )
  }

  // Resolved first, so an unconfigured run fails on the missing key instead of
  // after a wall of successful-looking pre-flight output. config.apiKey throws
  // with the same message every other operational script surfaces.
  const apiKey = config.apiKey

  const values = placeholderValues()
  const { text, missing } = substitute(readFileSync(DEFINITION_PATH, 'utf8'), values)
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment values: ${missing.join(', ')}\n` +
        'REVOKER_CALLBACK_URL is the agent\'s public https://<host>/revoke endpoint.\n' +
        'REVOKER_CALLBACK_SECRET must be the SAME value the agent process has set —\n' +
        'the workflow presents it as a bearer token and the agent refuses anything else.',
    )
  }

  // Safe to assert: `missing` above proved every marker resolved to a non-empty
  // value, so this one is present.
  const secret = values['REVOKER_CALLBACK_SECRET']!
  if (!SAFE_SECRET_RE.test(secret)) {
    throw new Error(
      'REVOKER_CALLBACK_SECRET must be at least 8 characters of [A-Za-z0-9._~+/=-].\n' +
        'It is embedded in a JSON string nested inside the workflow document, and a\n' +
        'quote or backslash there would corrupt the definition rather than be rejected.\n' +
        'Generate one with: openssl rand -base64 32 | tr -d "\\n"',
    )
  }

  const definition = JSON.parse(text) as WorkflowDefinition
  const { errors, nodes, edges } = preflight(definition)
  if (errors.length > 0) {
    throw new Error(
      `Definition failed pre-flight validation:\n${errors.map((e) => `  - ${e}`).join('\n')}`,
    )
  }
  console.log(`  pre-flight   ${nodes.length} nodes, ${edges.length} edges — OK`)

  const body = { name: definition.name, description: definition.description, nodes, edges }

  // Matched by name so re-running is an update, not a second copy. A drawer
  // full of near-identical sentinels is how you end up unsure which one is live.
  const listed = await api<Array<{ id: string; name: string }>>(apiKey, '/api/workflows', {
    method: 'GET',
  })
  const existing = (Array.isArray(listed) ? listed : []).find((w) => w.name === definition.name)

  let workflowId: string
  if (existing === undefined) {
    const created = await api<{ id: string }>(apiKey, '/api/workflows/create', {
      method: 'POST',
      body,
    })
    workflowId = created.id
    console.log(`  created      ${workflowId}`)
  } else {
    await api(apiKey, `/api/workflows/${existing.id}`, { method: 'PATCH', body })
    workflowId = existing.id
    console.log(`  updated      ${workflowId}`)
  }

  console.log('\n  The workflow is saved and DISABLED. Nothing fires until a human enables it.')
  console.log('  Verify it server-side, then turn it on:')
  console.log(`    validate_workflow  workflowId=${workflowId} deepCheck=true`)
  console.log(`    update_workflow    workflowId=${workflowId} enabled=true`)
  console.log('\n  Before enabling, confirm the agent is running ARMED with the same')
  console.log('  REVOKER_CALLBACK_SECRET — /api/meta must report revokeCallback "armed".\n')
}

main().catch((error: unknown) => {
  console.error(`\n❌ Workflow deploy failed: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
