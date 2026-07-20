import { safePost } from './fetch.js'
import { clean } from './html.js'
import type { PageFinding } from './types.js'

/**
 * READ-ONLY GraphQL introspection probe. Introspection is a QUERY (no mutation),
 * but it is a POST to the OWNER'S OWN endpoint, so observe() only calls this when
 * `authorized` is set. Each request is pinned to the page's already-vetted IP
 * (SSRF-safe), same-origin only, bounded by a small body cap + the shared timeout.
 * If the schema comes back, we flag it and surface the exposed type/field names —
 * framed (injection-stripped) — with extra weight on names that look sensitive.
 */

// One standard introspection query — the minimal schema shape (no fragments).
export const INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name} types{name fields{name}}}}"}'

const SENSITIVE_NAME = /pass(word)?|hash|ssn|token|secret|admin|credential|api[_-]?key|apikey|private[_-]?key/i

/**
 * Turn an introspection RESPONSE body into a finding (or null). Pure + testable:
 * parses JSON, confirms a real `data.__schema.types`, collects non-internal type
 * and field names, and raises severity to high when a sensitive-looking name is
 * exposed. All names are cleaned before they enter the finding.
 */
export function graphqlIntrospectionFinding(endpointUrl: string, body: string): PageFinding | null {
  let obj: unknown
  try {
    obj = JSON.parse(body)
  } catch {
    return null
  }
  const schema = (obj as { data?: { __schema?: { types?: unknown } } })?.data?.__schema
  if (!schema || !Array.isArray(schema.types)) return null

  const typeNames: string[] = []
  const fieldNames = new Set<string>()
  for (const t of schema.types as Array<{ name?: unknown; fields?: unknown }>) {
    const name = typeof t?.name === 'string' ? t.name : ''
    if (!name || name.startsWith('__')) continue // skip GraphQL internals
    typeNames.push(name)
    if (Array.isArray(t.fields)) {
      for (const fld of t.fields as Array<{ name?: unknown }>) {
        if (typeof fld?.name === 'string') fieldNames.add(fld.name)
        if (fieldNames.size > 200) break
      }
    }
    if (typeNames.length > 200) break
  }
  if (!typeNames.length) return null

  const sensitive = [...typeNames, ...fieldNames].filter((n) => SENSITIVE_NAME.test(n))
  const severity: PageFinding['severity'] = sensitive.length ? 'high' : 'medium'
  const detail =
    `GraphQL introspection is ENABLED at ${clean(endpointUrl, 120)} — the full schema is queryable ` +
    `(${typeNames.length} type(s)): ${typeNames.slice(0, 15).map((n) => clean(n, 60)).join(', ')}` +
    (sensitive.length ? `; SENSITIVE-looking names exposed: ${sensitive.slice(0, 10).map((n) => clean(n, 60)).join(', ')}` : '')
  return {
    severity,
    kind: 'graphql-introspection-enabled',
    detail,
    at: clean(endpointUrl, 200),
    suggestedFix: 'disable introspection in production (or gate it behind auth) — it hands an attacker the complete API schema; also enforce authorization on every resolver',
    confidence: 'strong',
  }
}

export interface GraphqlProbeOptions {
  timeoutMs: number
  allowPrivate: boolean
  onLog?: (line: string) => void
}

/**
 * POST ONE introspection query to each candidate GraphQL endpoint (bounded), pinned
 * to `pinnedIp`. Returns a finding per endpoint whose schema is exposed. Never throws
 * — an endpoint that won't answer is simply skipped.
 */
export async function probeGraphqlIntrospection(candidates: string[], pinnedIp: string, opts: GraphqlProbeOptions): Promise<PageFinding[]> {
  const out: PageFinding[] = []
  const log = opts.onLog ?? (() => {})
  const seen = new Set<string>()
  for (const url of candidates.slice(0, 4)) {
    if (seen.has(url)) continue
    seen.add(url)
    log(`probing GraphQL introspection at ${url}…`)
    try {
      const res = await safePost(url, { pinnedIp, timeoutMs: opts.timeoutMs, maxBytes: 500_000, allowPrivate: opts.allowPrivate }, INTROSPECTION_QUERY)
      if (res.status < 200 || res.status >= 300) continue
      const finding = graphqlIntrospectionFinding(url, res.body)
      if (finding) out.push(finding)
    } catch {
      /* an endpoint that won't answer is skipped — the rest still run */
    }
  }
  return out
}
