import { describe, expect, it, vi, beforeEach, afterEach, type Mock } from 'vitest'

/**
 * scripts/deploy-workflow.ts calls `main().catch(...)` at module top level:
 * importing it for real resolves live credentials and POSTs a workflow into
 * somebody's KeeperHub organisation. ../src/config.js is mocked so its getters
 * never demand real KH_* env vars, node:fs is partially mocked so a broken
 * definition can be fed in without editing the committed one, and global fetch
 * is stubbed so nothing leaves the process.
 *
 * The happy-path tests deliberately let the REAL workflows/revoker-sentinel.json
 * through, so the committed definition is itself under test: if someone edits it
 * into something the pre-flight rejects, this suite goes red rather than the
 * deploy failing in front of a judge.
 */

const configState = {
  demo: false,
  apiKey: 'kh_test_key' as string | null,
  baseUrl: 'https://keeperhub.test',
}

const configMock = {
  get baseUrl(): string {
    return configState.baseUrl
  },
  walletAddress: '0x5E2e5Fd3aD7fDC9B94482930db8b5F45E439bab7',
  get demo(): boolean {
    return configState.demo
  },
  get apiKey(): string {
    if (configState.apiKey === null) throw new Error('Missing KH_API_KEY. Create one at ...')
    return configState.apiKey
  },
}
vi.mock('../src/config.js', () => ({ config: configMock }))

/**
 * `'real'` passes the read through to the file that actually ships; anything
 * else is served verbatim, and `'enoent'` forces the missing-file path.
 */
const fsState = vi.hoisted(() => ({
  definition: 'real',
  deployments: 'real',
}))
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>()
  const serve = (state: string, path: Parameters<typeof actual.readFileSync>[0], enc?: BufferEncoding): string => {
    if (state === 'enoent') throw Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT' })
    // Not an Error instance — the top-level catch has to cope with those too,
    // which is the whole point of throwing a bare string here.
    // eslint-disable-next-line @typescript-eslint/only-throw-error
    if (state === 'throw-string') throw 'the disk said no'
    if (state === 'real') return actual.readFileSync(path, enc) as string
    return state
  }
  return {
    ...actual,
    readFileSync: (path: Parameters<typeof actual.readFileSync>[0], enc?: BufferEncoding) => {
      const p = String(path)
      if (p.includes('revoker-sentinel.json')) return serve(fsState.definition, path, enc)
      if (p.includes('deployments.json')) return serve(fsState.deployments, path, enc)
      return actual.readFileSync(path, enc)
    },
  }
})

interface FetchInit {
  method?: string
  headers?: Record<string, string>
  body?: string
}
type FetchStub = (url: string, init?: FetchInit) => Promise<Response>

interface Call {
  url: string
  method: string
  headers: Record<string, string>
  body?: string
}
const calls: Call[] = []

/** What the stubbed KeeperHub answers, per request. Overridden per test. */
let respond: (url: string, init: FetchInit) => { status: number; body: string }

function defaultResponder(url: string, init: FetchInit): { status: number; body: string } {
  if (url.endsWith('/api/workflows')) return { status: 200, body: '[]' }
  if (url.endsWith('/api/workflows/create')) return { status: 200, body: '{"id":"wf_created"}' }
  if (init.method === 'PATCH') return { status: 200, body: '' }
  return { status: 404, body: '{"error":"unroutable in test"}' }
}

let fetchMock: Mock<FetchStub>
let logSpy: Mock<(...args: unknown[]) => void>
let errorSpy: Mock<(...args: unknown[]) => void>

function logged(): string {
  return logSpy.mock.calls.map((call) => String(call[0])).join('\n')
}

function reported(): string {
  return errorSpy.mock.calls.map((call) => String(call[0])).join('\n')
}

/**
 * main()'s promise is never exported, so the only observable end of a run is the
 * closing instructions or the top-level catch. Polled with real timers rather
 * than by draining microtasks, so the stubbed Response bodies resolve too.
 */
async function run(): Promise<void> {
  await import('../scripts/deploy-workflow.js')
  await vi.waitFor(
    () => {
      expect(logged().includes('saved and DISABLED') || reported() !== '').toBe(true)
    },
    { interval: 1, timeout: 5_000 },
  )
}

/** A minimal definition that passes pre-flight, as a base for broken variants. */
function definition(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    name: 'Fixture',
    description: 'fixture',
    nodes: [
      {
        id: 'trigger-1',
        type: 'trigger',
        data: { label: 'Approval', config: { triggerType: 'Event', network: '11155111' } },
      },
      {
        id: 'alert-1',
        type: 'action',
        data: { label: 'Alert', config: { actionType: 'discord/send-message' } },
      },
    ],
    edges: [{ id: 'e1', source: 'trigger-1', target: 'alert-1' }],
    ...overrides,
  })
}

beforeEach(() => {
  vi.resetModules()

  configState.demo = false
  configState.baseUrl = 'https://keeperhub.test'
  configState.apiKey = 'kh_test_key'
  fsState.definition = 'real'
  fsState.deployments = 'real'
  calls.length = 0
  respond = defaultResponder

  process.env['REVOKER_CALLBACK_URL'] = 'https://revoker.example.test/revoke'
  process.env['REVOKER_CALLBACK_SECRET'] = 'test-callback-secret'

  fetchMock = vi.fn<FetchStub>((url, init = {}) => {
    calls.push({
      url,
      method: init.method ?? 'GET',
      headers: init.headers ?? {},
      ...(init.body === undefined ? {} : { body: init.body }),
    })
    const { status, body } = respond(url, init)
    return Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      text: () => Promise.resolve(body),
    } as Response)
  })
  vi.stubGlobal('fetch', fetchMock)

  logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined) as typeof logSpy
  errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined) as typeof errorSpy
})

afterEach(() => {
  delete process.env['REVOKER_CALLBACK_URL']
  delete process.env['REVOKER_CALLBACK_SECRET']
  delete process.env['REVOKER_WATCHED_TOKEN']
  delete process.env['REVOKER_WATCHED_WALLET']
  process.exitCode = 0
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('deploy-workflow — the committed definition', () => {
  it('passes pre-flight and is created as six nodes and five edges', async () => {
    await run()

    expect(reported()).toBe('')
    expect(logged()).toContain('pre-flight   6 nodes, 5 edges — OK')
    expect(logged()).toContain('created      wf_created')
  })

  it('sends the definition to POST /api/workflows/create with a bearer key', async () => {
    await run()

    const create = calls.find((c) => c.url.endsWith('/api/workflows/create'))
    expect(create?.method).toBe('POST')
    expect(create?.headers['Authorization']).toBe('Bearer kh_test_key')
    const body = JSON.parse(create?.body ?? '{}') as { name: string; nodes: unknown[] }
    expect(body.name).toBe('Revoker — Approval Sentinel')
    expect(body.nodes).toHaveLength(6)
  })

  it('substitutes the callback URL and secret rather than committing them', async () => {
    await run()

    const create = calls.find((c) => c.url.endsWith('/api/workflows/create'))
    expect(create?.body).toContain('https://revoker.example.test/revoke')
    expect(create?.body).toContain('Bearer test-callback-secret')
    expect(create?.body).not.toContain('${REVOKER_CALLBACK_SECRET}')

    // ...and the file on disk still carries only placeholders.
    const { readFileSync } = await vi.importActual<typeof import('node:fs')>('node:fs')
    const onDisk = readFileSync(
      new URL('../workflows/revoker-sentinel.json', import.meta.url),
      'utf8',
    )
    expect(onDisk).toContain('${REVOKER_CALLBACK_SECRET}')
    expect(onDisk).not.toContain('test-callback-secret')
  })

  it('defaults the watched token and wallet from the tree', async () => {
    await run()

    const create = calls.find((c) => c.url.endsWith('/api/workflows/create'))
    // deployments.json -> sepolia.contracts.MockUSDC
    expect(create?.body).toContain('0x4facb5FD1682c4449cAD42b7590861f7eD5c88Cb')
    expect(create?.body).toContain(configMock.walletAddress)
  })

  it('honours explicit overrides for the token and wallet', async () => {
    process.env['REVOKER_WATCHED_TOKEN'] = '0x1111111111111111111111111111111111111111'
    process.env['REVOKER_WATCHED_WALLET'] = '0x2222222222222222222222222222222222222222'

    await run()

    const create = calls.find((c) => c.url.endsWith('/api/workflows/create'))
    expect(create?.body).toContain('0x1111111111111111111111111111111111111111')
    expect(create?.body).toContain('0x2222222222222222222222222222222222222222')
  })

  it('never enables the workflow, and prints the commands a human would run', async () => {
    await run()

    const create = calls.find((c) => c.url.endsWith('/api/workflows/create'))
    expect(JSON.parse(create?.body ?? '{}')).not.toHaveProperty('enabled')
    expect(logged()).toContain('saved and DISABLED')
    expect(logged()).toContain('validate_workflow  workflowId=wf_created deepCheck=true')
    expect(logged()).toContain('update_workflow    workflowId=wf_created enabled=true')
  })

  it('updates in place when a workflow of the same name already exists', async () => {
    respond = (url, init) => {
      if (url.endsWith('/api/workflows') && init.method === 'GET') {
        return {
          status: 200,
          body: JSON.stringify([
            { id: 'wf_other', name: 'Something else' },
            { id: 'wf_existing', name: 'Revoker — Approval Sentinel' },
          ]),
        }
      }
      return { status: 200, body: '' }
    }

    await run()

    const patch = calls.find((c) => c.method === 'PATCH')
    expect(patch?.url).toBe('https://keeperhub.test/api/workflows/wf_existing')
    expect(calls.some((c) => c.url.endsWith('/create'))).toBe(false)
    expect(logged()).toContain('updated      wf_existing')
  })

  it('creates when the list endpoint answers with something that is not an array', async () => {
    respond = (url, init) => {
      if (url.endsWith('/api/workflows') && init.method === 'GET') {
        return { status: 200, body: '{"error":"unexpected shape"}' }
      }
      return defaultResponder(url, init)
    }

    await run()

    expect(logged()).toContain('created      wf_created')
  })
})

describe('deploy-workflow — refusing to run', () => {
  it('refuses under REVOKER_DEMO rather than 401-ing against a sentinel key', async () => {
    configState.demo = true

    await run()

    expect(reported()).toContain('REVOKER_DEMO is set')
    expect(fetchMock).not.toHaveBeenCalled()
    expect(process.exitCode).toBe(1)
  })

  it('refuses without credentials, before doing any work', async () => {
    configState.apiKey = null

    await run()

    expect(reported()).toContain('Missing KH_API_KEY')
    expect(fetchMock).not.toHaveBeenCalled()
    // The credential check comes first: no pre-flight output precedes it.
    expect(logged()).not.toContain('pre-flight')
  })

  it('names every unfilled placeholder instead of shipping a broken definition', async () => {
    delete process.env['REVOKER_CALLBACK_URL']
    process.env['REVOKER_CALLBACK_SECRET'] = ''

    await run()

    expect(reported()).toContain('REVOKER_CALLBACK_URL')
    expect(reported()).toContain('REVOKER_CALLBACK_SECRET')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('reports the missing token when deployments.json cannot be read', async () => {
    fsState.deployments = 'enoent'

    await run()

    expect(reported()).toContain('REVOKER_WATCHED_TOKEN')
  })

  it('reports the missing token when deployments.json has no MockUSDC entry', async () => {
    fsState.deployments = JSON.stringify({ sepolia: { contracts: {} } })

    await run()

    expect(reported()).toContain('REVOKER_WATCHED_TOKEN')
  })

  it('refuses a secret containing characters that would corrupt the nested JSON', async () => {
    // The secret is embedded in `httpHeaders`, which is a JSON string INSIDE the
    // JSON document — two levels of escaping. A quote survives the first and
    // breaks the second, so the charset is constrained instead of guessed at.
    process.env['REVOKER_CALLBACK_SECRET'] = 'a"b\\c-and-long-enough'

    await run()

    expect(reported()).toContain('REVOKER_CALLBACK_SECRET must be at least 16 characters')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('refuses a secret that is too short to be a credential', async () => {
    process.env['REVOKER_CALLBACK_SECRET'] = 'short'

    await run()

    expect(reported()).toContain('REVOKER_CALLBACK_SECRET must be at least 16 characters')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('accepts a base64 secret of the shape `openssl rand -base64 32` produces', async () => {
    // A real 32-byte base64 secret, at its true length of 44 — the command in
    // the error message has to produce something this check accepts, and a
    // token-sized fixture would let the floor regress without failing here.
    process.env['REVOKER_CALLBACK_SECRET'] = 'aB3+xY/z9QcDeFgHiJkLmNoPqRsTuVwXyZ012345678='

    await run()

    expect(reported()).toBe('')
    const create = calls.find((c) => c.url.endsWith('/api/workflows/create'))
    const body = JSON.parse(create?.body ?? '{}') as {
      nodes: Array<{ data: { config: Record<string, string> } }>
    }
    const headers = body.nodes
      .map((n) => n.data.config['httpHeaders'])
      .find((h) => h !== undefined)
    // The nested JSON string still parses, and carries the secret intact.
    expect(JSON.parse(headers ?? '{}')).toMatchObject({
      Authorization: 'Bearer aB3+xY/z9QcDeFgHiJkLmNoPqRsTuVwXyZ012345678=',
    })
  })
})

describe('deploy-workflow — pre-flight validation', () => {
  async function rejects(source: string): Promise<string> {
    fsState.definition = source
    await run()
    expect(fetchMock).not.toHaveBeenCalled()
    return reported()
  }

  it('accepts a minimal well-formed definition', async () => {
    fsState.definition = definition()
    await run()
    expect(reported()).toBe('')
    expect(logged()).toContain('pre-flight   2 nodes, 1 edges — OK')
  })

  it('rejects a definition with no name', async () => {
    expect(await rejects(definition({ name: undefined }))).toContain('workflow has no name')
  })

  it('rejects a blank name', async () => {
    expect(await rejects(definition({ name: '' }))).toContain('workflow has no name')
  })

  it('rejects a definition with no nodes at all', async () => {
    expect(await rejects(JSON.stringify({ name: 'Empty' }))).toContain('workflow has no nodes')
  })

  it('rejects a node with no id', async () => {
    expect(await rejects(definition({ nodes: [{ type: 'trigger' }] }))).toContain('a node has no id')
  })

  it('rejects a node whose id is blank', async () => {
    expect(await rejects(definition({ nodes: [{ id: '', type: 'trigger' }] }))).toContain(
      'a node has no id',
    )
  })

  it('rejects duplicate node ids', async () => {
    const nodes = [
      { id: 'trigger-1', type: 'trigger', data: { config: { triggerType: 'Manual' } } },
      { id: 'trigger-1', type: 'action', data: { config: { actionType: 'Condition' } } },
    ]
    expect(await rejects(definition({ nodes, edges: [] }))).toContain('duplicate node id: trigger-1')
  })

  it('rejects a trigger with no triggerType', async () => {
    const nodes = [{ id: 'trigger-1', type: 'trigger', data: { config: {} } }]
    expect(await rejects(definition({ nodes, edges: [] }))).toContain(
      'trigger node trigger-1 has no config.triggerType',
    )
  })

  it('accepts a chain-free trigger such as Manual', async () => {
    const nodes = [
      { id: 'trigger-1', type: 'trigger', data: { config: { triggerType: 'Manual' } } },
    ]
    fsState.definition = definition({ nodes, edges: [] })
    await run()
    expect(reported()).toBe('')
  })

  it('rejects an unknown chain id', async () => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        data: { config: { triggerType: 'Event', network: '99999' } },
      },
    ]
    expect(await rejects(definition({ nodes, edges: [] }))).toContain(
      'node trigger-1 targets unknown chain id 99999',
    )
  })

  it('rejects an action node with no actionType', async () => {
    const nodes = [
      { id: 'trigger-1', type: 'trigger', data: { config: { triggerType: 'Manual' } } },
      { id: 'step-1', type: 'action', data: { config: {} } },
    ]
    expect(await rejects(definition({ nodes, edges: [] }))).toContain(
      'action node step-1 has no config.actionType',
    )
  })

  it('rejects a node carrying no data at all', async () => {
    const nodes = [
      { id: 'trigger-1', type: 'trigger', data: { config: { triggerType: 'Manual' } } },
      { id: 'step-1', type: 'action' },
    ]
    expect(await rejects(definition({ nodes, edges: [] }))).toContain(
      'action node step-1 has no config.actionType',
    )
  })

  it('rejects a malformed contract address', async () => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        data: { config: { triggerType: 'Event', network: '1', contractAddress: '0xnope' } },
      },
    ]
    expect(await rejects(definition({ nodes, edges: [] }))).toContain(
      'node trigger-1 has a malformed contractAddress: 0xnope',
    )
  })

  it('names an unresolved placeholder before pre-flight is ever reached', async () => {
    // Substitution reports every unfilled ${MARKER} by name, which is why
    // pre-flight carries no second placeholder check: it could only be dead code.
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        data: { config: { triggerType: 'Manual', note: '${SOME_OTHER_MARKER}' } },
      },
    ]
    expect(await rejects(definition({ nodes, edges: [] }))).toContain('SOME_OTHER_MARKER')
  })

  it('rejects a bare @ reference outside a {{ }} wrapper', async () => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        data: { config: { triggerType: 'Manual', note: '@trigger-1.value' } },
      },
    ]
    expect(await rejects(definition({ nodes, edges: [] }))).toContain(
      'node trigger-1 contains a bare @ reference outside {{ }}',
    )
  })

  it('rejects a workflow with no trigger node', async () => {
    const nodes = [
      { id: 'step-1', type: 'action', data: { config: { actionType: 'Condition' } } },
    ]
    expect(await rejects(definition({ nodes, edges: [] }))).toContain(
      'workflow must have exactly one trigger node, found 0',
    )
  })

  it('rejects a workflow with two trigger nodes', async () => {
    const nodes = [
      { id: 'trigger-1', type: 'trigger', data: { config: { triggerType: 'Manual' } } },
      { id: 'trigger-2', type: 'trigger', data: { config: { triggerType: 'Manual' } } },
    ]
    expect(await rejects(definition({ nodes, edges: [] }))).toContain(
      'workflow must have exactly one trigger node, found 2',
    )
  })

  it('rejects an edge pointing at a node that does not exist', async () => {
    const edges = [{ id: 'e1', source: 'trigger-1', target: 'ghost' }]
    expect(await rejects(definition({ edges }))).toContain('edge e1 has an unknown target: ghost')
  })

  it('rejects an edge with no source or target, and names it as unnamed', async () => {
    const report = await rejects(definition({ edges: [{}] }))
    expect(report).toContain('edge (unnamed) has an unknown source: (none)')
    expect(report).toContain('edge (unnamed) has an unknown target: (none)')
  })

  it('rejects an edge leaving a Condition node without a sourceHandle', async () => {
    const nodes = [
      { id: 'trigger-1', type: 'trigger', data: { config: { triggerType: 'Manual' } } },
      {
        id: 'cond-1',
        type: 'action',
        data: { config: { actionType: 'Condition', condition: 'true' } },
      },
      { id: 'alert-1', type: 'action', data: { config: { actionType: 'discord/send-message' } } },
    ]
    const edges = [
      { id: 'e1', source: 'trigger-1', target: 'cond-1' },
      { id: 'e2', source: 'cond-1', target: 'alert-1' },
    ]
    expect(await rejects(definition({ nodes, edges }))).toContain(
      'edge e2 leaves a Condition node without sourceHandle',
    )
  })

  it('names an unnamed edge leaving a Condition node without a sourceHandle', async () => {
    const nodes = [
      { id: 'trigger-1', type: 'trigger', data: { config: { triggerType: 'Manual' } } },
      { id: 'cond-1', type: 'action', data: { config: { actionType: 'Condition' } } },
      { id: 'alert-1', type: 'action', data: { config: { actionType: 'discord/send-message' } } },
    ]
    const edges = [{ source: 'cond-1', target: 'alert-1' }]
    expect(await rejects(definition({ nodes, edges }))).toContain(
      'edge (unnamed) leaves a Condition node without sourceHandle',
    )
  })

  it('still reports a dangling reference on a node that has no id either', async () => {
    const nodes = [
      { id: 'trigger-1', type: 'trigger', data: { config: { triggerType: 'Manual' } } },
      { type: 'action', data: { config: { actionType: 'Condition', condition: '{{@ghost:X.y}}' } } },
    ]
    const report = await rejects(definition({ nodes, edges: [] }))
    expect(report).toContain('a node has no id')
    expect(report).toContain('node (unnamed) references unknown node ghost')
  })

  it('rejects a template reference to a node that does not exist', async () => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        data: { config: { triggerType: 'Manual', note: '{{@ghost-1:Ghost.value}}' } },
      },
    ]
    expect(await rejects(definition({ nodes, edges: [] }))).toContain(
      'node trigger-1 references unknown node ghost-1',
    )
  })

  it('accepts the built-in __system reference', async () => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        data: {
          config: { triggerType: 'Manual', note: 'at {{@__system:System.isoTimestamp}}' },
        },
      },
    ]
    fsState.definition = definition({ nodes, edges: [] })
    await run()
    expect(reported()).toBe('')
  })

  it('walks arrays, nested objects, numbers and nulls in a config without tripping', async () => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        data: {
          config: {
            triggerType: 'Manual',
            timeout: 30,
            failOnError: false,
            unset: null,
            nested: { list: ['{{@trigger-1:Manual.triggeredAt}}', 7, null] },
          },
        },
      },
    ]
    fsState.definition = definition({ nodes, edges: [] })
    await run()
    expect(reported()).toBe('')
  })

  it('reports every problem at once rather than one per round-trip', async () => {
    const report = await rejects(JSON.stringify({ nodes: [], edges: [] }))
    expect(report).toContain('workflow has no name')
    expect(report).toContain('workflow has no nodes')
    expect(report).toContain('found 0')
  })
})

describe('deploy-workflow — the KeeperHub API boundary', () => {
  it('surfaces a JSON error body verbatim', async () => {
    respond = () => ({ status: 401, body: '{"error":"invalid api key"}' })

    await run()

    expect(reported()).toContain('KeeperHub 401 on GET /api/workflows')
    expect(reported()).toContain('invalid api key')
  })

  it('surfaces a non-JSON error body as text', async () => {
    respond = () => ({ status: 502, body: '<html>bad gateway</html>' })

    await run()

    expect(reported()).toContain('KeeperHub 502')
    expect(reported()).toContain('bad gateway')
  })

  it('reports a failure that is not an Error instance', async () => {
    fsState.definition = 'throw-string'

    await run()

    expect(reported()).toContain('the disk said no')
    expect(process.exitCode).toBe(1)
  })

  it('treats an empty successful body as null rather than failing to parse it', async () => {
    // The PATCH path answers with no body at all; the run must still complete.
    respond = (url, init) => {
      if (url.endsWith('/api/workflows') && init.method === 'GET') {
        return { status: 200, body: JSON.stringify([{ id: 'wf_1', name: 'Revoker — Approval Sentinel' }]) }
      }
      return { status: 200, body: '' }
    }

    await run()

    expect(reported()).toBe('')
    expect(logged()).toContain('updated      wf_1')
  })
})

/**
 * The request carries the org API key in the header AND the workflow definition
 * with REVOKER_CALLBACK_SECRET already substituted into the body. KH_BASE_URL
 * decides where both go, so a plaintext origin must be refused outright rather
 * than merely discouraged. CodeQL flags this call as file-data-to-network and is
 * right to; these tests are the reason the flow is safe rather than the reason
 * the alert is quiet.
 */
describe('deploy-workflow — where the secrets are allowed to go', () => {
  it('refuses to send the API key to a plaintext origin', async () => {
    configState.baseUrl = 'http://not-keeperhub.example'
    fsState.definition = definition()
    await run()
    expect(reported()).toContain('plaintext origin')
    expect(reported()).toContain('http://not-keeperhub.example')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('refuses a KH_BASE_URL that is not a URL at all', async () => {
    configState.baseUrl = 'keeperhub.test'
    fsState.definition = definition()
    await run()
    expect(reported()).toContain('not a valid URL')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('allows plaintext loopback, so the deploy can be pointed at a local mock', async () => {
    configState.baseUrl = 'http://localhost:8787'
    fsState.definition = definition()
    await run()
    expect(reported()).not.toContain('plaintext origin')
    expect(fetchMock).toHaveBeenCalled()
  })

  it('allows 127.0.0.1 for the same reason', async () => {
    configState.baseUrl = 'http://127.0.0.1:8787'
    fsState.definition = definition()
    await run()
    expect(reported()).not.toContain('plaintext origin')
    expect(fetchMock).toHaveBeenCalled()
  })
})
