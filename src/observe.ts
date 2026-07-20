import { lookup as dnsLookupCb } from 'node:dns'
import { promisify } from 'node:util'
import { blockedIpReason, parseUrl } from './authorize.js'
import { safeGet } from './fetch.js'
import { extractStructure, clean } from './html.js'
import { detectBodySignatures, bodySignatureFindings, analyzeJwts, scanSecrets, secretFindings, type JwtSource } from './detect.js'
import { discoverWellKnown } from './discover.js'
import { probeGraphqlIntrospection } from './graphql.js'
import type { ObserveOptions, PageBrief, PageFinding, RenderMode, SecurityPosture } from './types.js'

const dnsLookup = promisify(dnsLookupCb)

/** Resolve a host and refuse if ANY resolved address is non-public — the SSRF
 *  gate, applied to the real destination. Returns the single address to PIN. */
async function resolveSafe(host: string, allowPrivate: boolean): Promise<{ ip: string | null; reason?: string }> {
  if (/^[\d.]+$/.test(host) || host.includes(':')) {
    const r = blockedIpReason(host, allowPrivate)
    return r ? { ip: host, reason: r } : { ip: host }
  }
  try {
    const addrs = await dnsLookup(host, { all: true })
    if (!addrs.length) return { ip: null, reason: `could not resolve ${host}` }
    for (const a of addrs) {
      const r = blockedIpReason(a.address, allowPrivate)
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

  const allowPrivate = opts.authorized === true
  const decision = parseUrl(input, { allowPrivate })
  if (!decision.ok || !decision.url || !decision.host) return { ...base(), error: `invalid URL: ${decision.reason}` }

  // Follow redirects manually so each hop is re-vetted AND re-pinned.
  let url = new URL(decision.url)
  let resolvedIp: string | null = null
  let res: Awaited<ReturnType<typeof safeGet>> | null = null
  const notes: string[] = []
  let tooManyHops = false
  for (let hop = 0; ; hop++) {
    if (hop >= 6) { tooManyHops = true; break }
    const safe = await resolveSafe(url.hostname.replace(/^\[|\]$/g, ''), allowPrivate)
    if (safe.reason) return { ...base(), target: { input, url: url.toString(), origin: url.origin }, resolvedIp: safe.ip, error: safe.reason }
    resolvedIp = safe.ip
    log(`fetching ${url.toString()}…`)
    try {
      res = await safeGet(url.toString(), { pinnedIp: resolvedIp!, timeoutMs, maxBytes, allowPrivate })
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
      const nd = parseUrl(next.toString(), { allowPrivate })
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

  // ── Read-only detectors that apply to ANY response (HTML or not) ───────────
  // Body-content signatures on the page body (directory listing / stack trace /
  // verbose framework error), plus JWT sources (headers + Set-Cookie + body;
  // same-origin bundles are added below for HTML pages).
  const bodySigFindings = bodySignatureFindings(detectBodySignatures(res.body), url.toString())
  const jwtSources: JwtSource[] = []
  for (const [k, v] of Object.entries(res.headers)) {
    const val = Array.isArray(v) ? v.join(' ') : String(v ?? '')
    if (val && val.includes('eyJ')) jwtSources.push({ where: `response header ${k}`, text: val })
  }
  for (const c of res.setCookies) if (c.includes('eyJ')) jwtSources.push({ where: 'Set-Cookie', text: c })
  jwtSources.push({ where: 'page body', text: res.body })

  // PASSIVE DISCOVERY of well-known sensitive paths (bounded same-origin GETs,
  // pinned to the vetted IP, confirmed-signature only). Read-only. Default on.
  const doDiscover = opts.discoverPaths !== false
  const discoveryFindings = doDiscover ? await discoverWellKnown(url.origin, resolvedIp!, { timeoutMs, allowPrivate, onLog: log }) : []
  if (doDiscover) notes.push('probed a fixed list of well-known sensitive paths (read-only, same-origin) — flags CONFIRMED signatures only')

  if (!isHtml) {
    const jwtFindings = analyzeJwts(jwtSources, url.toString())
    brief.findings = [...bodySigFindings, ...discoveryFindings, ...jwtFindings]
    brief.summary =
      `${url.origin} — ${status}, non-HTML content (${contentType ?? 'unknown'}).` +
      (brief.findings.length ? ` ${brief.findings.length} finding(s) from read-only detectors (no structural parse).` : ' Nothing to observe structurally.')
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

  // ── Mine SAME-ORIGIN JS bundles for the API surface the empty page hides (Kimi
  // #7). An SPA's real endpoints (/api/admin/backup, …) live in bundle.js, not the
  // HTML. Same-origin only + pinned to the page's vetted IP (SSRF-safe), bounded.
  const endpoints = new Set<string>()
  for (const srcUrl of structure.scriptSrcs.slice(0, 6)) {
    try {
      const js = await safeGet(srcUrl, { pinnedIp: resolvedIp!, timeoutMs, maxBytes: 1_500_000, allowPrivate })
      if (js.status >= 200 && js.status < 300) {
        extractEndpoints(js.body, endpoints)
        // Kimi: a secret shipped in the bundle is downloadable → compromised. Scan the
        // body for hardcoded provider keys + high-entropy assignments (REDACTED evidence).
        for (const sf of secretFindings(scanSecrets(js.body), srcUrl)) findings.push(sf)
        if (js.body.includes('eyJ')) jwtSources.push({ where: `bundle ${clean(srcUrl, 120)}`, text: js.body })
      }
    } catch {
      /* a bundle that won't fetch is skipped — the rest still run */
    }
  }
  if (endpoints.size) findings.push(f('medium', 'exposed-endpoint', `${endpoints.size} API endpoint(s) referenced in the JS bundles (the SPA's real surface, invisible in the static HTML): ${[...endpoints].slice(0, 15).map((e) => clean(e, 80)).join(', ')}`, url.origin, 'confirm every endpoint enforces authorization server-side — a path in a bundle is not a secret; treat each as reachable', 'moderate'))

  // ── GraphQL introspection (authorized, READ-ONLY POST) ────────────────────
  // Candidate endpoints: the conventional paths + any discovered endpoint whose
  // path looks like GraphQL. All same-origin (endpoints are absolute PATHS resolved
  // against this origin) so the page's vetted IP pins them SSRF-safe.
  const gqlCandidates = new Set<string>()
  for (const p of ['/graphql', '/api/graphql']) {
    try { gqlCandidates.add(new URL(p, url.origin).toString()) } catch { /* ignore */ }
  }
  for (const e of endpoints) if (/graphql/i.test(e)) { try { gqlCandidates.add(new URL(e, url.origin).toString()) } catch { /* ignore */ } }
  let graphqlSuggested: string | null = null
  if (gqlCandidates.size) {
    if (allowPrivate) {
      // authorized — send ONE read-only introspection query per candidate, pinned.
      findings.push(...(await probeGraphqlIntrospection([...gqlCandidates], resolvedIp!, { timeoutMs, allowPrivate, onLog: log })))
    } else {
      // not authorized — do NOT send the POST; surface it as a suggested probe.
      graphqlSuggested = `a GraphQL endpoint appears reachable (${clean([...gqlCandidates][0], 120)}) — re-run with --authorized to send a READ-ONLY introspection query`
    }
  }

  // Merge the read-only detector findings (body signatures, well-known-path
  // discovery, and JWTs across HTML + headers + cookies + same-origin bundles).
  findings.push(...bodySigFindings, ...discoveryFindings, ...analyzeJwts(jwtSources, url.toString()))

  // ── Security posture from headers + content ──────────────────────────────
  const cspStr = h('content-security-policy')
  const cspWeaknesses = cspStr ? gradeCsp(cspStr) : []
  const hstsStr = h('strict-transport-security')
  const hstsMaxAge = Number(/max-age\s*=\s*(\d+)/i.exec(hstsStr)?.[1] ?? 0)
  const hstsWeak = Boolean(hstsStr) && (hstsMaxAge < 15_552_000 || !/includesubdomains/i.test(hstsStr))
  const frameAncestors = /frame-ancestors/i.test(cspStr)
  // Server/X-Powered-By are target-controlled → clean before they enter a finding.
  const versionLeakRaw = [h('server'), h('x-powered-by')].filter((s) => s && /\d/.test(s)).map((s) => clean(s, 120)).join('; ')

  const mixedContent = https ? collectMixedContent(html, url) : []
  const thirdPartyScripts = structure.scriptOrigins.filter((o) => o !== url.origin)
  const cookieIssues = evalCookies(res.setCookies)
  const insecureCookies = cookieIssues.filter((c) => c.noSecureHttpOnly).map((c) => c.name)

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
  for (const c of cookieIssues.filter((x) => x.noSecureHttpOnly).slice(0, 5)) findings.push(f('medium', 'weak-cookie', `cookie "${clean(c.name, 80)}" missing Secure and/or HttpOnly`, url.origin, 'set Secure + HttpOnly (and SameSite) on cookies'))
  // Kimi: a cookie with no SameSite (or SameSite=None) is sendable on cross-site
  // requests → CSRF-able even when Secure+HttpOnly are present.
  for (const c of cookieIssues.filter((x) => x.sameSite).slice(0, 5)) findings.push(f('medium', 'cookie-samesite', `cookie "${clean(c.name, 80)}" ${c.sameSite === 'none' ? 'has SameSite=None' : 'is missing SameSite'} — sendable cross-site (CSRF)`, url.origin, 'set SameSite=Lax (or Strict) on session/auth cookies; only use SameSite=None (with Secure) for cookies that MUST be cross-site, and pair with anti-CSRF tokens'))
  // Kimi: CORS posture on the response. `*` lets any origin read responses; a
  // reflected/echoed specific origin WITH credentials:true exposes authenticated data.
  const acao = h('access-control-allow-origin').trim()
  const acaCreds = h('access-control-allow-credentials').trim().toLowerCase() === 'true'
  if (acao === '*') findings.push(f('medium', 'cors-wildcard', 'Access-Control-Allow-Origin: * — any origin may read responses from this endpoint', url.origin, 'restrict CORS to an explicit allow-list of trusted origins; never expose authenticated data with ACAO: *'))
  else if (acao && acaCreds) findings.push(f('high', 'cors-credentials', `Access-Control-Allow-Origin reflects a specific origin ("${clean(acao, 120)}") WITH Access-Control-Allow-Credentials: true — authenticated responses are readable cross-origin`, url.origin, 'never combine a reflected/echoed ACAO with credentials:true; pin ACAO to a fixed trusted origin (or drop credentials) — this is the dangerous CORS combo'))
  if (structure.externalScriptsNoSri > 0) findings.push(f('low', 'missing-sri', `${structure.externalScriptsNoSri} third-party <script> without Subresource Integrity`, url.origin, 'add integrity + crossorigin to third-party scripts', 'moderate'))
  for (const fr of structure.iframes.slice(0, 8)) findings.push(f(fr.sandboxed ? 'info' : 'medium', fr.sandboxed ? 'embedded-frame' : 'embedded-frame-unsandboxed', `embeds cross-origin ${fr.origin} in an iframe${fr.sandboxed ? ' (sandboxed)' : ' WITHOUT sandbox — full-privilege third-party frame'}`, fr.origin, fr.sandboxed ? 'confirm the embedded third party is intended' : "add a sandbox attribute and restrict allowed capabilities", 'moderate'))
  // Inventory the FULL embedded third-party surface (scripts + iframes + hints +
  // srcset), so "who does this page pull in?" is answered, not just script hosts.
  const thirdParties = [...new Set([...thirdPartyScripts, ...structure.iframes.map((i) => i.origin), ...structure.resourceHintOrigins, ...structure.srcsetOrigins])]
  if (thirdParties.length) findings.push(f('info', 'third-party-origins', `page pulls in ${thirdParties.length} third-party origin(s): ${thirdParties.slice(0, 10).join(', ')}`, url.origin, 'vet each third-party origin (voyager-net/voyager) and minimize embedded parties', 'moderate'))

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
  if (graphqlSuggested) probes.push(graphqlSuggested)
  if (structure.headings[0]?.level !== 1) probes.push('confirm the page has a single top-level <h1>')
  brief.suggestedNextProbes = probes

  return brief
}

/** Pull API endpoint paths out of a JS bundle: absolute-path string literals like
 *  "/api/…" and fetch/axios call targets. Bounded; de-duplicated by the caller's Set. */
function extractEndpoints(js: string, out: Set<string>): void {
  for (const m of js.matchAll(/["'`](\/(?:api|v\d|graphql|rest|internal|admin|rpc)\/[A-Za-z0-9_\-/.:{}$]*)["'`]/g)) if (out.size < 60) out.add(m[1].slice(0, 120))
  for (const m of js.matchAll(/\b(?:fetch|axios(?:\.[a-z]+)?)\s*\(\s*["'`](\/[A-Za-z0-9_\-/.:{}$]+)["'`]/g)) if (out.size < 60) out.add(m[1].slice(0, 120))
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

interface CookieIssue {
  name: string
  /** Missing Secure and/or HttpOnly. */
  noSecureHttpOnly: boolean
  /** SameSite posture: 'missing' (no SameSite attr) or 'none' (SameSite=None) — both
   *  are cross-site-sendable (CSRF surface); null when SameSite=Lax/Strict. */
  sameSite: 'missing' | 'none' | null
}

/** Evaluate EACH Set-Cookie line individually (a blob join would mask one bad
 *  cookie among several). Flags missing Secure/HttpOnly AND a cross-site-sendable
 *  SameSite posture (missing entirely, or explicit SameSite=None). */
function evalCookies(setCookies: string[]): CookieIssue[] {
  const out: CookieIssue[] = []
  for (const line of setCookies) {
    const name = /^\s*([^=;\s]+)\s*=/.exec(line)?.[1] ?? '(unnamed)'
    const noSecureHttpOnly = !/;\s*secure/i.test(line) || !/;\s*httponly/i.test(line)
    const ssMatch = /;\s*samesite\s*=\s*([a-z]+)/i.exec(line)
    const sameSite: CookieIssue['sameSite'] = !ssMatch ? 'missing' : ssMatch[1].toLowerCase() === 'none' ? 'none' : null
    if (noSecureHttpOnly || sameSite) out.push({ name, noSecureHttpOnly, sameSite })
  }
  return out
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
