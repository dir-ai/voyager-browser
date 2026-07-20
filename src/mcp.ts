#!/usr/bin/env node
/**
 * voyager-browser MCP server (stdio). One tool: observe_page — safe, read-only
 * observation of ONE live URL. Static HTML, no JS execution. isError:true means
 * the page could not be observed (invalid/SSRF-blocked/fetch error), not that it
 * is clean.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { observe } from './observe.js'
import { VERSION } from './version.js'

const server = new Server({ name: 'voyager-browser', version: VERSION }, { capabilities: { tools: {} } })

const TOOLS = [
  {
    name: 'observe_page',
    description:
      "Read-only observation of ONE live web page: title/structure, forms (with insecure/cross-origin/sensitive flags), links (external + unsafe target=_blank), script origins, security posture (HTTPS/HSTS/CSP/mixed-content/cookies) and accessibility signals (lang, img alt coverage, heading order) → findings with DESCRIBED (never applied) fixes. ALSO runs read-only leak detectors: body-content signatures (directory listings, language-specific stack traces, verbose framework debug/error pages), exposed JWTs decoded from the HTML/headers/cookies/same-origin bundles (flags alg:none, expired, and no-exp — NO signature verification, NO secret cracking), and PASSIVE DISCOVERY of a short fixed list of well-known sensitive paths (/.git/config, /.env, /.svn/entries, /.DS_Store, /config.json, /wp-config.php~, /backup/, /uploads/) via bounded same-origin GETs that flag only a CONFIRMED signature (never a bare 200). Parses STATIC HTML only — no JavaScript execution, no headless browser, so it cannot see client-side-rendered runtime state. All target-derived text is returned FRAMED as untrusted. SSRF-gated: refuses non-http(s) URLs and, by default, anything resolving to private/loopback/cloud-metadata addresses — pass authorized:true to observe your OWN private/loopback/intranet target (cloud-metadata + link-local stay blocked). NEVER mutates, submits a form, or exploits — every request is a GET. isError:true means the page could not be observed, not that it is clean.",
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        url: { type: 'string', minLength: 1, maxLength: 2048, description: 'A single http(s) URL to observe.' },
        authorized: { type: 'boolean', description: 'Set true to observe your OWN private/loopback/intranet target (staging, an internal app). Permits private ranges but STILL refuses cloud-metadata + link-local. Default false = public URLs only.' },
        discoverPaths: { type: 'boolean', description: 'Passive discovery of well-known sensitive paths via bounded same-origin read-only GETs (flags CONFIRMED signatures only). Default true; set false to skip.' },
        timeoutMs: { type: 'integer', minimum: 1000, maximum: 30000 },
        maxBytes: { type: 'integer', minimum: 10000, maximum: 10000000 },
      },
      required: ['url'],
    },
  },
] as const

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }))

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params
  const a = args as Record<string, unknown>
  const ok = (data: unknown, isError = false) => ({ content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }], ...(isError ? { isError: true } : {}) })
  const err = (message: string) => ok({ error: message }, true)

  try {
    if (name === 'observe_page') {
      const url = typeof a.url === 'string' ? a.url.slice(0, 2048) : ''
      if (!url) return err('url required')
      const timeoutMs = typeof a.timeoutMs === 'number' && Number.isInteger(a.timeoutMs) ? a.timeoutMs : undefined
      const maxBytes = typeof a.maxBytes === 'number' && Number.isInteger(a.maxBytes) ? a.maxBytes : undefined
      const authorized = a.authorized === true
      const discoverPaths = a.discoverPaths === false ? false : undefined
      const brief = await observe(url, { timeoutMs, maxBytes, authorized, discoverPaths })
      return ok(brief, Boolean(brief.error))
    }
    return err(`Unknown tool: ${name}`)
  } catch (e) {
    return err(e instanceof Error ? e.message : String(e))
  }
})

export async function startMcpServer(): Promise<void> {
  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error(`voyager-browser MCP server v${VERSION} ready (stdio)`)
}

import { fileURLToPath } from 'node:url'
import { realpathSync } from 'node:fs'
function isDirectEntry(): boolean {
  const argv1 = process.argv[1]
  if (!argv1) return false
  const self = fileURLToPath(import.meta.url)
  try {
    return realpathSync(self) === realpathSync(argv1)
  } catch {
    return self === argv1
  }
}
if (isDirectEntry()) {
  startMcpServer().catch((e) => {
    console.error(e instanceof Error ? e.stack : String(e))
    process.exit(1)
  })
}
