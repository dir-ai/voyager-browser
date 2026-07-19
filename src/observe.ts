import { lookup as dnsLookupCb } from 'node:dns'
import { promisify } from 'node:util'
import { blockedIpReason, parseUrl } from './authorize.js'
import { safeGet } from './fetch.js'
import { extractStructure } from './html.js'
import type { ObserveOptions, PageBrief, PageFinding, RenderMode, SecurityPosture } from './types.js'

const dnsLookup = promisify(dnsLookupCb)

/** Resolve a host and refuse if ANY resolved address is non-public — the SSRF
 *  gate, applied to the real destination. Returns the single address to PIN. */
async function resolveSafe(host: string): Promise<{ ip: string | null; reason?: string }> {
  if (/^[\d.]+$/.test(host) || host.includes(':')) {
    const r = blockedIpReason(host)
    return r ? { ip: host, reason: r } : { ip: host }
  }
  try {
    const addrs = await dnsLookup(host, { all: true })
    if (!addrs.length) return { ip: null, reason: `could not resolve ${host}` }
    for (const a of addrs) {
      const r = blockedIpReason(a.address)
      if (r) return { ip: a.address, reason: `${host} ${r}` }
    }
    return { ip: addrs[0].address }
  } catch {
    return { ip: null, reason: `could not resolve ${host}` }
  }
}

/**
 * Observe ONE live web page, read-only. Pins the connection to a pre-vetted IP
 * (defeating DNS rebinding), fetches static HTML (no JS execution, no headless
 * browser), frames all page text as untrusted, and reports structure, forms,
 * links, security posture and accessibility signals with described fixes.
 */
export async function observe(input: string, opts: ObserveOptions = {}): Promise<PageBrief> {
  const now = Date.now()
  const log = opts.onLog ?? (() => {})
  const timeoutMs = Math.min(Math.max(opts.timeoutMs ?? 10000, 1000), 30000)
  const maxBytes = Math.min(Math.max(opts.maxBytes ?? 2_000_000, 10_000), 10_000_000)

  const base = (): PageBrief => ({
    target: { input, url: null, origin: null }, resolvedIp: null, fetchedAt: now, status: null, contentType: null,
    render: 'static', renderConfidence: 'weak', truncated: false,
    summary: '', structure: null, forms: [], links: { total: 0, internal: 0, external: 0, unsafeBlank: 0, sample: [] },
    security: null, a11y: { lang: false, imgAltCoverage: null, formFieldsLabeled: null, headingOrderOk: true },
    findings: [], confidence: 'weak', suggestedNextProbes: [], sanitization: { framedFields: 0, strippedPayloads: 0 }, notes: [],
  })

  const decision = parseUrl(input)
  if (!decision.ok || !decision.url || !decision.host) return { ...base(), error: `invalid URL: ${decision.reason}` }

  // Follow redirects manually so each hop is re-vetted AND re-pinned.
  let url = new URL(decision.url)
  let resolvedIp: string | null = null
  let res: Awaited<ReturnType<typeof safeGet>> | null = null
  const notes: string[] = []
  let tooManyHops = false
  for (let hop = 0; ; hop++) {
    if (hop >= 6) { tooManyHops = true; break }
    const safe = await resolveSafe(url.hostname.replace(/^\[|\]$/g, ''))
    if (safe.reason) return { ...base(), target: { input, url: url.toString(), origin: url.origin }, resolvedIp: safe.ip, error: safe.reason }
    resolvedIp = safe.ip
    log(`fetching ${url.toString()}…`)
    try {
      res = await safeGet(url.toString(), { pinnedIp: resolvedIp!, timeoutMs, maxBytes })
    } catch (e) {
      return { ...base(), target: { input, url: url.toString(), origin: url.origin }, resolvedIp, error: `fetch failed: ${e instanceof Error ? e.message : String(e)}` }
    }
    if (res.status >= 300 && res.status < 400) {
      const locRaw = res.headers.location
      const loc = Array.isArray(locRaw) ? locRaw[0] : locRaw
      if (!loc) return { ...base(), target: { input, url: url.toString(), origin: url.origin }, resolvedIp, status: res.status, error: `redirect ${res.status} without a Location header — cannot observe the destination` }
      let next: URL
      try {
        next = new URL(loc, url)
      } catch {
        return { ...base(), target: { input, url: url.toString(), origin: url.origin }, resolvedIp, status: res.status, error: `redirect ${res.status} to a malformed Location — not observed` }
      }
      const nd = parseUrl(next.toString())
      if (!nd.ok) return { ...base(), target: { input, url: next.toString(), origin: null }, resolvedIp, status: res.status, error: `redirect to a disallowed URL: ${nd.reason}` }
      notes.push(`redirect ${res.status} → ${next.origin}`)
      url = next
      continue
    }
    break
  }
  if (tooManyHops || !res) return { ...base(), target: { input, url: url.toString(), origin: url.origin }, resolvedIp, error: 'too many redirects (>6) — not observed' }

  const status = res.status
  const ctRaw = res.headers['content-type']
  const contentType = Array.isArray(ctRaw) ? ctRaw[0] : ctRaw ?? null
  const isHtml = (contentType ?? '').includes('html')
  const truncated = res.truncated
  if (truncated) notes.push(`body truncated at ${maxBytes} bytes — observation is PARTIAL`)

  const brief = base()
  brief.target = { input, url: url.toString(), origin: url.origin }
  brief.resolvedIp = resolvedIp
  brief.status = status
  brief.contentType = contentType
  brief.truncated = truncated
  brief.notes = notes

  const findings: PageFinding[] = []
  const https = url.protocol === 'https:'
  const h = (n: string): string => {
    const v = res!.headers[n]
    return (Array.isArray(v) ? v[0] : v ?? '') as string
  }

  if (!isHtml) {
    brief.summary = `${url.origin} — ${status}, non-HTML content (${contentType ?? 'unknown'}). Nothing to observe structurally.`
    brief.confidence = 'moderate'
    return brief
  }

  const html = res.body
  const { structure, forms, links } = extractStructure(html, url)
  brief.structure = structure
  brief.forms = forms

  // ── Render-mode honesty: how much did a static fetch actually see? ─────────
  const render: RenderMode = structure.visibleTextLength < 200 && (structure.hasMountNode || structure.scriptOrigins.length + structure.inlineScripts > 0)
    ? 'client-heavy'
    : structure.hasMountNode && structure.visibleTextLength < 1200
      ? 'hybrid'
      : 'static'
  brief.render = render
  brief.renderConfidence = render === 'static' ? 'strong' : 'moderate'
  if (render !== 'static') findings.push({ severity: 'info', kind: 'client-rendered', detail: `page appears ${render} (JavaScript renders most content) — a static fetch sees only ${structure.visibleTextLength} chars of text; structure/forms below may be incomplete`, at: url.origin, suggestedFix: 'observe with a rendering pass for full coverage; treat the static view as partial', confidence: 'moderate' })

  // ── Security posture from headers + content ──────────────────────────────
  const cspStr = h('content-security-policy')
  const cspWeaknesses = cspStr ? gradeCsp(cspStr) : []
  const hstsStr = h('strict-transport-security')
  const hstsMaxAge = Number(/max-age\s*=\s*(\d+)/i.exec(hstsStr)?.[1] ?? 0)
  const hstsWeak = Boolean(hstsStr) && (hstsMaxAge < 15_552_000 || !/includesubdomains/i.test(hstsStr))
  const frameAncestors = /frame-ancestors/i.test(cspStr)
  const versionLeakRaw = [h('server'), h('x-powered-by')].filter((s) => s && /\d/.test(s)).join('; ')

  const mixedContent = https ? collectMixedContent(html, url) : []
  const thirdPartyScripts = structure.scriptOrigins.filter((o) => o !== url.origin)
  const insecureCookies = evalCookies(res.setCookies)

  const security: SecurityPosture = {
    https,
    hsts: Boolean(hstsStr),
    hstsWeak,
    csp: Boolean(cspStr),
    cspWeaknesses,
    xContentTypeOptions: h('x-content-type-options').toLowerCase() === 'nosniff',
    referrerPolicy: Boolean(h('referrer-policy')),
    frameProtection: Boolean(h('x-frame-options')) || frameAncestors,
    coop: Boolean(h('cross-origin-opener-policy')),
    corp: Boolean(h('cross-origin-resource-policy')),
    permissionsPolicy: Boolean(h('permissions-policy')),
    versionLeak: versionLeakRaw || null,
    mixedContent,
    thirdPartyScripts,
    insecureCookies,
  }
  brief.security = security

  if (!https) findings.push(f('high', 'no-https', 'page served over plain HTTP', url.toString(), 'serve the page over HTTPS and redirect HTTP→HTTPS'))
  if (https && !security.hsts) findings.push(f('medium', 'missing-hsts', 'HTTPS without HSTS', url.origin, 'add Strict-Transport-Security: max-age=63072000; includeSubDomains'))
  else if (hstsWeak) findings.push(f('low', 'weak-hsts', `HSTS is weak (${hstsMaxAge < 15_552_000 ? 'max-age below 180d' : 'no includeSubDomains'})`, url.origin, 'use max-age ≥ 63072000 with includeSubDomains (and consider preload)'))
  if (!security.csp) findings.push(f('medium', 'missing-csp', 'no Content-Security-Policy', url.origin, 'add a Content-Security-Policy to constrain scripts/resources', 'moderate'))
  else if (cspWeaknesses.length) findings.push(f('medium', 'weak-csp', `CSP present but weak: ${cspWeaknesses.join(', ')}`, url.origin, "remove unsafe-inline/unsafe-eval and wildcard sources; set object-src 'none' and base-uri 'self'"))
  if (!security.frameProtection) findings.push(f('medium', 'missing-frame-protection', 'no clickjacking protection (X-Frame-Options / CSP frame-ancestors)', url.origin, "add X-Frame-Options: DENY or CSP frame-ancestors 'none'"))
  if (!security.xContentTypeOptions) findings.push(f('low', 'missing-nosniff', 'no X-Content-Type-Options: nosniff', url.origin, 'add X-Content-Type-Options: nosniff'))
  if (https && !security.referrerPolicy) findings.push(f('low', 'missing-referrer-policy', 'no Referrer-Policy', url.origin, 'add Referrer-Policy: strict-origin-when-cross-origin', 'moderate'))
  if (!security.permissionsPolicy) findings.push(f('info', 'missing-permissions-policy', 'no Permissions-Policy', url.origin, 'add a Permissions-Policy to disable unused powerful features (camera, geolocation…)', 'moderate'))
  if (security.versionLeak) findings.push(f('low', 'version-leak', `server version disclosed: ${security.versionLeak}`, url.origin, 'remove version details from Server / X-Powered-By headers', 'moderate'))
  if (mixedContent.length) findings.push(f('high', 'mixed-content', `${mixedContent.length} insecure http:// sub-resource(s) on an HTTPS page`, mixedContent[0], 'load all sub-resources over HTTPS'))
  for (const c of insecureCookies.slice(0, 5)) findings.push(f('medium', 'weak-cookie', `cookie "${c}" missing Secure and/or HttpOnly`, url.origin, 'set Secure + HttpOnly (and SameSite) on cookies'))
  if (structure.externalScriptsNoSri > 0) findings.push(f('low', 'missing-sri', `${structure.externalScriptsNoSri} third-party <script> without Subresource Integrity`, url.origin, 'add integrity + crossorigin to third-party scripts', 'moderate'))

  for (const fo of forms) {
    if (fo.insecureTarget) findings.push(f('critical', 'form-insecure', `form on an HTTPS page posts to a plain-HTTP target (${fo.action})`, fo.action, 'point the form action at an HTTPS endpoint'))
    if (fo.sensitive && fo.crossOrigin) findings.push(f('high', 'form-sensitive-cross-origin', `a form collecting sensitive fields posts cross-origin (${fo.action})`, fo.action, 'post sensitive forms to your own origin; verify the third party is intended', 'moderate'))
    if (fo.sensitive && !https) findings.push(f('critical', 'form-sensitive-http', 'a form collecting sensitive fields is on a plain-HTTP page', url.toString(), 'serve any page collecting credentials/payment over HTTPS'))
    if (fo.sensitive && fo.method === 'POST' && !fo.hasCsrfToken) findings.push(f('low', 'form-no-csrf', 'a sensitive POST form has no visible anti-CSRF token', fo.action, 'include a CSRF/anti-forgery token (or rely on SameSite cookies + verification)', 'moderate'))
    if (fo.sensitive && fo.method === 'GET') findings.push(f('medium', 'form-sensitive-get', 'a form collecting sensitive fields uses GET (values leak into URL/logs)', fo.action, 'use POST for forms that submit sensitive data'))
  }

  const unsafeBlank = links.filter((l) => l.unsafeBlank)
  if (unsafeBlank.length) findings.push(f('low', 'reverse-tabnabbing', `${unsafeBlank.length} external target=_blank link(s) without rel=noopener`, unsafeBlank[0].href, 'add rel="noopener noreferrer" to external _blank links'))

  // ── Accessibility signals ────────────────────────────────────────────────
  if (!structure.lang) findings.push(f('low', 'a11y-no-lang', '<html> has no lang attribute', url.origin, 'add lang="…" to <html> for screen readers'))
  const imgAltCoverage = structure.imgCount ? Number(((structure.imgCount - structure.imgMissingAlt) / structure.imgCount).toFixed(2)) : null
  if (structure.imgMissingAlt > 0) findings.push(f('low', 'a11y-img-no-alt', `${structure.imgMissingAlt}/${structure.imgCount} images have no alt text`, url.origin, 'add alt text to informative images (alt="" for decorative)'))
  const headingOrderOk = isHeadingOrderOk(structure.headings.map((x) => x.level))
  if (!headingOrderOk) findings.push(f('info', 'a11y-heading-order', 'heading levels skip (e.g. h1→h3)', url.origin, "don't skip heading levels; keep a logical outline", 'moderate'))
  const labeledFields = countLabeled(html, forms)
  brief.a11y = { lang: Boolean(structure.lang), imgAltCoverage, formFieldsLabeled: labeledFields, headingOrderOk }

  // ── Links summary + probes ───────────────────────────────────────────────
  const external = links.filter((l) => l.external).length
  brief.links = { total: links.length, internal: links.length - external, external, unsafeBlank: unsafeBlank.length, sample: links.slice(0, 12) }

  const worst = (['critical', 'high', 'medium', 'low', 'info'] as const).find((s) => findings.some((x) => x.severity === s))
  brief.findings = findings
  const partial = truncated || render !== 'static'
  brief.summary =
    (findings.filter((x) => x.severity !== 'info').length
      ? `${url.origin} — ${status}; ${findings.length} finding(s), worst: ${worst}.`
      : `${url.origin} — ${status}; no significant security/a11y issues surfaced.`) +
    ` ${forms.length} form(s), ${links.length} link(s), ${thirdPartyScripts.length} third-party script origin(s).` +
    (partial ? ` (PARTIAL: ${truncated ? 'body truncated' : render + ' render'} — structure may be incomplete.)` : '')
  brief.confidence = partial ? 'weak' : status === 200 ? 'strong' : 'moderate'

  const framedFields = [structure.title, structure.metaDescription, ...structure.headings.map((x) => x.text)].filter(Boolean).length
  const strippedPayloads = (structure.title?.stripped ?? 0) + (structure.metaDescription?.stripped ?? 0) + structure.headings.reduce((s, x) => s + x.text.stripped, 0)
  brief.sanitization = { framedFields, strippedPayloads }

  const probes: string[] = []
  if (thirdPartyScripts.length) probes.push(`vet the third-party script origin(s): ${thirdPartyScripts.slice(0, 3).join(', ')} (via @dir-ai/voyager-net or @dir-ai/voyager)`)
  if (forms.some((fo) => fo.sensitive)) probes.push('audit the host serving the sensitive form (via @dir-ai/voyager-net --authorized)')
  if (render !== 'static') probes.push('re-observe with a rendering pass to see the client-rendered content')
  if (structure.headings[0]?.level !== 1) probes.push('confirm the page has a single top-level <h1>')
  brief.suggestedNextProbes = probes

  return brief
}

function f(severity: PageFinding['severity'], kind: string, detail: string, at: string, suggestedFix: string, confidence: PageFinding['confidence'] = 'strong'): PageFinding {
  return { severity, kind, detail, at, suggestedFix, confidence }
}

/** Grade a CSP string for the weaknesses that make it decorative rather than real. */
function gradeCsp(csp: string): string[] {
  const c = csp.toLowerCase()
  const w: string[] = []
  if (c.includes("'unsafe-inline'")) w.push('unsafe-inline')
  if (c.includes("'unsafe-eval'")) w.push('unsafe-eval')
  if (/(?:default|script|style|img|connect)-src[^;]*\*(?![.\w-])/.test(c)) w.push('wildcard-src')
  if (!/object-src\s+'none'/.test(c) && !/default-src\s+'none'/.test(c)) w.push('no-object-src')
  if (!c.includes('base-uri')) w.push('no-base-uri')
  if (!c.includes('frame-ancestors')) w.push('no-frame-ancestors')
  return w
}

/** Evaluate EACH Set-Cookie line individually (a blob join would mask one bad
 *  cookie among several). Returns the names of cookies missing Secure/HttpOnly. */
function evalCookies(setCookies: string[]): string[] {
  const bad: string[] = []
  for (const line of setCookies) {
    const name = /^\s*([^=;\s]+)\s*=/.exec(line)?.[1] ?? '(unnamed)'
    if (!/;\s*secure/i.test(line) || !/;\s*httponly/i.test(line)) bad.push(name)
  }
  return bad
}

/** Collect http:// sub-resources on an https page by comparing parsed ORIGINS
 *  (not string prefixes — a prefix test both misses look-alikes and self-exempts
 *  wrongly). Scans src/href/action/srcset/url(). */
function collectMixedContent(html: string, pageUrl: URL): string[] {
  const out = new Set<string>()
  for (const m of html.matchAll(/(?:src|href|action|data-src)\s*=\s*["'](http:\/\/[^"']+)["']/gi)) out.add(m[1])
  for (const m of html.matchAll(/url\(\s*["']?(http:\/\/[^"')]+)/gi)) out.add(m[1])
  for (const m of html.matchAll(/srcset\s*=\s*["']([^"']*http:\/\/[^"']+)["']/gi)) {
    for (const part of m[1].split(',')) {
      const u = part.trim().split(/\s+/)[0]
      if (u.startsWith('http://')) out.add(u)
    }
  }
  // Every http:// sub-resource on an https page is mixed content (including the
  // page's own host over http) — do not self-exempt.
  return [...out].filter((u) => u.startsWith('http://')).slice(0, 20)
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
  const total = forms.reduce((s, fo) => s + fo.fields.filter((x) => x.type !== 'hidden' && x.type !== 'submit' && x.type !== 'button').length, 0)
  if (!total) return null
  const labelFor = new Set([...html.matchAll(/<label\b[^>]*\bfor\s*=\s*["']([^"']+)["']/gi)].map((m) => m[1]))
  let labeled = 0
  for (const fo of forms) for (const field of fo.fields) {
    if (field.type === 'hidden' || field.type === 'submit' || field.type === 'button') continue
    const idM = new RegExp(`<[^>]*name\\s*=\\s*["']${escapeRe(field.name)}["'][^>]*\\bid\\s*=\\s*["']([^"']+)["']`, 'i').exec(html)
    if (field.name && idM && labelFor.has(idM[1])) labeled++
  }
  return Number((labeled / total).toFixed(2))
}
function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
