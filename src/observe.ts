import { lookup as dnsLookupCb } from 'node:dns'
import { promisify } from 'node:util'
import { blockedIpReason, parseUrl } from './authorize.js'
import { extractStructure } from './html.js'
import type { ObserveOptions, PageBrief, PageFinding, SecurityPosture } from './types.js'

const dnsLookup = promisify(dnsLookupCb)

/** Resolve a host and refuse if ANY resolved address is private/loopback/metadata
 *  — the SSRF gate, applied to the real destination not just the literal host. */
async function resolveSafe(host: string): Promise<{ ip: string | null; reason?: string }> {
  const ipLiteral = /^[\d.]+$/.test(host) || host.includes(':')
  if (ipLiteral) {
    const r = blockedIpReason(host)
    return r ? { ip: host, reason: r } : { ip: host }
  }
  try {
    const addrs = await dnsLookup(host, { all: true })
    for (const a of addrs) {
      const r = blockedIpReason(a.address)
      if (r) return { ip: a.address, reason: `${host} ${r}` }
    }
    return { ip: addrs[0]?.address ?? null }
  } catch {
    return { ip: null, reason: `could not resolve ${host}` }
  }
}

/**
 * Observe ONE live web page, read-only. Fetches static HTML (no JS execution, no
 * headless browser), frames all page text as untrusted, and reports structure,
 * forms, links, security posture and accessibility signals with described fixes.
 */
export async function observe(input: string, opts: ObserveOptions = {}): Promise<PageBrief> {
  const now = Date.now()
  const log = opts.onLog ?? (() => {})
  const timeoutMs = Math.min(Math.max(opts.timeoutMs ?? 10000, 1000), 30000)
  const maxBytes = Math.min(Math.max(opts.maxBytes ?? 2_000_000, 10_000), 10_000_000)

  const base = (): PageBrief => ({
    target: { input, url: null, origin: null }, resolvedIp: null, fetchedAt: now, status: null, contentType: null,
    summary: '', structure: null, forms: [], links: { total: 0, internal: 0, external: 0, unsafeBlank: 0, sample: [] },
    security: null, a11y: { lang: false, imgAltCoverage: null, formFieldsLabeled: null, headingOrderOk: true },
    findings: [], confidence: 'weak', suggestedNextProbes: [], sanitization: { framedFields: 0, strippedPayloads: 0 }, notes: [],
  })

  const decision = parseUrl(input)
  if (!decision.ok || !decision.url || !decision.host) return { ...base(), error: `invalid URL: ${decision.reason}` }

  // Follow redirects manually so each hop is re-vetted against the SSRF gate.
  let url = new URL(decision.url)
  let resolvedIp: string | null = null
  let res: Response | null = null
  const notes: string[] = []
  for (let hop = 0; hop < 6; hop++) {
    const safe = await resolveSafe(url.hostname.replace(/^\[|\]$/g, ''))
    if (safe.reason) return { ...base(), target: { input, url: url.toString(), origin: url.origin }, resolvedIp: safe.ip, error: safe.reason }
    resolvedIp = safe.ip
    log(`fetching ${url.toString()}…`)
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), timeoutMs)
    try {
      res = await fetch(url.toString(), { method: 'GET', redirect: 'manual', signal: ctrl.signal, headers: { accept: 'text/html,*/*', 'user-agent': 'voyager-browser (read-only page sense)' } })
    } catch (e) {
      clearTimeout(timer)
      return { ...base(), target: { input, url: url.toString(), origin: url.origin }, resolvedIp, error: `fetch failed: ${e instanceof Error ? e.message : String(e)}` }
    }
    clearTimeout(timer)
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      let next: URL
      try {
        next = new URL(res.headers.get('location')!, url)
      } catch {
        break
      }
      const nd = parseUrl(next.toString())
      if (!nd.ok) return { ...base(), target: { input, url: next.toString(), origin: null }, resolvedIp, error: `redirect to a disallowed URL: ${nd.reason}` }
      notes.push(`redirect ${res.status} → ${next.origin}`)
      url = next
      continue
    }
    break
  }
  if (!res) return { ...base(), error: 'no response' }

  const status = res.status
  const contentType = res.headers.get('content-type')
  const isHtml = (contentType ?? '').includes('html')

  // Read the body up to the cap.
  let html = ''
  if (res.body) {
    const reader = res.body.getReader()
    const dec = new TextDecoder('utf-8', { fatal: false })
    let total = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      html += dec.decode(value, { stream: true })
      if (total >= maxBytes) {
        notes.push(`body truncated at ${maxBytes} bytes`)
        try {
          await reader.cancel()
        } catch {
          /* ignore */
        }
        break
      }
    }
    html += dec.decode()
  }

  const brief = base()
  brief.target = { input, url: url.toString(), origin: url.origin }
  brief.resolvedIp = resolvedIp
  brief.status = status
  brief.contentType = contentType
  brief.notes = notes

  const findings: PageFinding[] = []
  const https = url.protocol === 'https:'

  if (!isHtml) {
    brief.summary = `${url.origin} — ${status}, non-HTML content (${contentType ?? 'unknown'}). Nothing to observe structurally.`
    brief.confidence = 'moderate'
    return brief
  }

  const { structure, forms, links } = extractStructure(html, url)
  brief.structure = structure
  brief.forms = forms

  // ── Security posture from headers + content ──────────────────────────────
  const h = (n: string) => res!.headers.get(n)
  const mixedContent = https ? uniq([...html.matchAll(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+)["']/gi)].map((m) => m[1]).filter((u) => !u.startsWith('http://' + url.hostname))).slice(0, 20) : []
  const thirdPartyScripts = structure.scriptOrigins.filter((o) => o !== url.origin)
  const setCookie = h('set-cookie') ?? ''
  const security: SecurityPosture = {
    https,
    hsts: Boolean(h('strict-transport-security')),
    csp: Boolean(h('content-security-policy')),
    xContentTypeOptions: (h('x-content-type-options') ?? '').toLowerCase() === 'nosniff',
    referrerPolicy: Boolean(h('referrer-policy')),
    mixedContent,
    thirdPartyScripts,
    setCookieInsecure: Boolean(setCookie) && (!/;\s*secure/i.test(setCookie) || !/;\s*httponly/i.test(setCookie)),
  }
  brief.security = security

  if (!https) findings.push({ severity: 'high', kind: 'no-https', detail: 'page served over plain HTTP', at: url.toString(), suggestedFix: 'serve the page over HTTPS and redirect HTTP→HTTPS', confidence: 'strong' })
  if (https && !security.hsts) findings.push({ severity: 'medium', kind: 'missing-hsts', detail: 'HTTPS without HSTS', at: url.origin, suggestedFix: 'add Strict-Transport-Security: max-age=63072000; includeSubDomains', confidence: 'strong' })
  if (!security.csp) findings.push({ severity: 'medium', kind: 'missing-csp', detail: 'no Content-Security-Policy', at: url.origin, suggestedFix: 'add a Content-Security-Policy to constrain scripts/resources', confidence: 'moderate' })
  if (!security.xContentTypeOptions) findings.push({ severity: 'low', kind: 'missing-nosniff', detail: 'no X-Content-Type-Options: nosniff', at: url.origin, suggestedFix: 'add X-Content-Type-Options: nosniff', confidence: 'strong' })
  if (mixedContent.length) findings.push({ severity: 'high', kind: 'mixed-content', detail: `${mixedContent.length} insecure http:// sub-resource(s) on an HTTPS page`, at: mixedContent[0], suggestedFix: 'load all sub-resources over HTTPS', confidence: 'strong' })
  if (security.setCookieInsecure) findings.push({ severity: 'medium', kind: 'weak-cookie', detail: 'Set-Cookie missing Secure and/or HttpOnly', at: url.origin, suggestedFix: 'set Secure + HttpOnly (and SameSite) on cookies', confidence: 'strong' })

  for (const f of forms) {
    if (f.insecureTarget) findings.push({ severity: 'critical', kind: 'form-insecure', detail: `form on an HTTPS page posts to a plain-HTTP target (${f.action})`, at: f.action, suggestedFix: 'point the form action at an HTTPS endpoint', confidence: 'strong' })
    if (f.sensitive && f.crossOrigin) findings.push({ severity: 'high', kind: 'form-sensitive-cross-origin', detail: `a form collecting sensitive fields posts cross-origin (${f.action})`, at: f.action, suggestedFix: 'post sensitive forms to your own origin; verify the third party is intended', confidence: 'moderate' })
    if (f.sensitive && !https) findings.push({ severity: 'critical', kind: 'form-sensitive-http', detail: 'a form collecting sensitive fields is on a plain-HTTP page', at: url.toString(), suggestedFix: 'serve any page collecting credentials/payment over HTTPS', confidence: 'strong' })
  }

  const unsafeBlank = links.filter((l) => l.unsafeBlank)
  if (unsafeBlank.length) findings.push({ severity: 'low', kind: 'reverse-tabnabbing', detail: `${unsafeBlank.length} external target=_blank link(s) without rel=noopener`, at: unsafeBlank[0].href, suggestedFix: 'add rel="noopener noreferrer" to external _blank links', confidence: 'strong' })

  // ── Accessibility signals ────────────────────────────────────────────────
  if (!structure.lang) findings.push({ severity: 'low', kind: 'a11y-no-lang', detail: '<html> has no lang attribute', at: url.origin, suggestedFix: 'add lang="…" to <html> for screen readers', confidence: 'strong' })
  const imgAltCoverage = structure.imgCount ? Number(((structure.imgCount - structure.imgMissingAlt) / structure.imgCount).toFixed(2)) : null
  if (structure.imgMissingAlt > 0) findings.push({ severity: 'low', kind: 'a11y-img-no-alt', detail: `${structure.imgMissingAlt}/${structure.imgCount} images have no alt text`, at: url.origin, suggestedFix: 'add alt text to informative images (alt="" for decorative)', confidence: 'strong' })
  const headingOrderOk = isHeadingOrderOk(structure.headings.map((x) => x.level))
  if (!headingOrderOk) findings.push({ severity: 'info', kind: 'a11y-heading-order', detail: 'heading levels skip (e.g. h1→h3)', at: url.origin, suggestedFix: "don't skip heading levels; keep a logical outline", confidence: 'moderate' })
  const labeledFields = countLabeled(html, forms)

  brief.a11y = { lang: Boolean(structure.lang), imgAltCoverage, formFieldsLabeled: labeledFields, headingOrderOk }

  // ── Links summary + probes ───────────────────────────────────────────────
  const external = links.filter((l) => l.external).length
  brief.links = { total: links.length, internal: links.length - external, external, unsafeBlank: unsafeBlank.length, sample: links.slice(0, 12) }

  const worst = (['critical', 'high', 'medium', 'low', 'info'] as const).find((s) => findings.some((f) => f.severity === s))
  brief.findings = findings
  brief.summary = findings.length
    ? `${url.origin} — ${status}; ${findings.length} finding(s), worst: ${worst}. ${forms.length} form(s), ${links.length} link(s), ${thirdPartyScripts.length} third-party script origin(s).`
    : `${url.origin} — ${status}; clean across security + a11y checks. ${forms.length} form(s), ${links.length} link(s).`
  brief.confidence = status === 200 ? 'strong' : 'moderate'

  const framedFields = [structure.title, structure.metaDescription, ...structure.headings.map((x) => x.text)].filter(Boolean).length
  const strippedPayloads = (structure.title?.stripped ?? 0) + (structure.metaDescription?.stripped ?? 0) + structure.headings.reduce((s, x) => s + x.text.stripped, 0)
  brief.sanitization = { framedFields, strippedPayloads }

  const probes: string[] = []
  if (thirdPartyScripts.length) probes.push(`vet the third-party script origin(s): ${thirdPartyScripts.slice(0, 3).join(', ')} (via @dir-ai/voyager-net or @dir-ai/voyager)`)
  if (forms.some((f) => f.sensitive)) probes.push('audit the host serving the sensitive form (via @dir-ai/voyager-net --authorized)')
  if (structure.headings[0]?.level !== 1) probes.push('confirm the page has a single top-level <h1>')
  brief.suggestedNextProbes = probes

  return brief
}

function uniq(xs: string[]): string[] {
  return [...new Set(xs)]
}
function isHeadingOrderOk(levels: number[]): boolean {
  let prev = 0
  for (const l of levels) {
    if (prev && l > prev + 1) return false
    prev = l
  }
  return true
}
function countLabeled(html: string, forms: PageBrief['forms']): number | null {
  const total = forms.reduce((s, f) => s + f.fields.filter((x) => x.type !== 'hidden' && x.type !== 'submit' && x.type !== 'button').length, 0)
  if (!total) return null
  const labelFor = new Set([...html.matchAll(/<label\b[^>]*\bfor\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]))
  let labeled = 0
  for (const f of forms) for (const field of f.fields) {
    if (field.type === 'hidden' || field.type === 'submit' || field.type === 'button') continue
    const idM = new RegExp(`<[^>]*name\\s*=\\s*["']${escapeRe(field.name)}["'][^>]*\\bid\\s*=\\s*["']([^"']+)["']`, 'i').exec(html)
    if (field.name && idM && labelFor.has(idM[1])) labeled++
  }
  return Number((labeled / total).toFixed(2))
}
function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
