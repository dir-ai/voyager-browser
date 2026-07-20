import { clean } from './html.js'
import type { PageFinding, Severity } from './types.js'

/**
 * READ-ONLY body-content + token detectors. Every one of these inspects text the
 * TARGET produced (page body, well-known-path responses, headers, cookies, same-
 * origin bundles) and NEVER sends a mutating request. All target-derived strings
 * that enter a finding are run through `clean()` (the family's injection-strip),
 * so a hostile stack trace / claim value cannot smuggle instructions to the agent.
 */

// ── Directory listing ───────────────────────────────────────────────────────
/** Apache/generic and nginx autoindex signatures. Returns a signature label or null. */
function directoryListing(body: string): string | null {
  const head = body.slice(0, 20_000)
  const parentLink = /Parent Directory|<a[^>]+href=["']\.\.\/?["']\s*>\s*\.\.\/?\s*</i
  if (/<title>\s*Index of \//i.test(head) && parentLink.test(head)) return 'Apache/generic autoindex ("Index of /" + Parent Directory)'
  if (/<h1>\s*Index of \//i.test(head) && /<a href="\.\.\/">\.\.\/<\/a>/i.test(head)) return 'nginx autoindex ("Index of /" listing)'
  return null
}

// ── Stack trace / error disclosure (language-specific, low false-positive) ──
const STACK_SIGS: Array<[RegExp, string]> = [
  [/Traceback \(most recent call last\)/, 'Python traceback'],
  [/\bat java\.[\w.$]+\([\w$]+\.java:\d+\)/, 'Java stack trace'],
  [/PHP Stack trace/i, 'PHP stack trace'],
  [/\bat Object\.<anonymous>\s*\([^)]*\.js:\d+/, 'Node.js stack trace'],
  [/\bORA-\d{4,5}\b/, 'Oracle DB error (ORA-)'],
  [/SQLSTATE\[/, 'SQLSTATE DB error'],
  [/You have an error in your SQL syntax/i, 'MySQL syntax error'],
]

// ── Verbose framework debug / error pages (secret-leaking) ──────────────────
const VERBOSE_SIGS: Array<[RegExp, string]> = [
  [/Werkzeug Debugger|The debugger caught an exception/i, 'Werkzeug/Flask debugger (interactive, RCE-adjacent)'],
  [/Action Controller: Exception/i, 'Rails exception page'],
  [/Whoops\\|Symfony\\Component\\HttpKernel/i, 'Symfony/Whoops error page'],
  [/Server Error in '[^']*' Application/i, 'ASP.NET yellow-screen-of-death'],
]

export interface BodySignature {
  kind: 'directory-listing' | 'stack-trace' | 'verbose-error'
  severity: Severity
  signature: string
  sample: string
}

/** Scan a response body for directory listings, stack traces and verbose error
 *  pages. Reports the FIRST match per category (no noise). `sample` is cleaned. */
export function detectBodySignatures(body: string): BodySignature[] {
  const out: BodySignature[] = []
  if (!body) return out

  const dl = directoryListing(body)
  if (dl) out.push({ kind: 'directory-listing', severity: 'medium', signature: dl, sample: sampleAround(body, /Index of \/[^<\r\n]{0,80}/i) })

  for (const [re, label] of STACK_SIGS) {
    const m = re.exec(body)
    if (m) { out.push({ kind: 'stack-trace', severity: 'high', signature: label, sample: clean(m[0], 160) }); break }
  }
  for (const [re, label] of VERBOSE_SIGS) {
    const m = re.exec(body)
    if (m) { out.push({ kind: 'verbose-error', severity: 'high', signature: label, sample: clean(m[0], 160) }); break }
  }
  return out
}

function sampleAround(body: string, re: RegExp): string {
  const m = re.exec(body)
  return m ? clean(m[0], 120) : ''
}

/** Turn body signatures into findings. `at` = where they were seen (page/path URL). */
export function bodySignatureFindings(sigs: BodySignature[], at: string): PageFinding[] {
  return sigs.map((s) => ({
    severity: s.severity,
    kind: s.kind === 'directory-listing' ? 'directory-listing' : s.kind === 'stack-trace' ? 'stack-trace-disclosure' : 'verbose-error-page',
    detail:
      s.kind === 'directory-listing'
        ? `directory listing is enabled — files are browsable (${s.signature})`
        : s.kind === 'stack-trace'
          ? `a server stack trace / error is disclosed in the response (${s.signature}${s.sample ? `: "${s.sample}"` : ''}) — leaks paths, versions and internals`
          : `a verbose framework debug/error page is exposed (${s.signature}${s.sample ? `: "${s.sample}"` : ''}) — leaks source, env and internals`,
    at,
    suggestedFix:
      s.kind === 'directory-listing'
        ? 'disable automatic directory indexing (Options -Indexes / autoindex off) and add an index file or 403'
        : s.kind === 'stack-trace'
          ? 'disable stack traces in production; return a generic error page and log details server-side'
          : 'turn OFF the framework debugger/verbose errors in production (DEBUG=false, customErrors on) — it can leak source and enable RCE',
    confidence: 'strong',
  }))
}

// ── JWT analyzer (decode-only, NO verification, NO secret cracking) ──────────
// header.payload.signature — signature may be empty (alg:none). base64url segments.
const JWT_RE = /eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g

function b64urlToObj(seg: string): Record<string, unknown> | null {
  try {
    const json = Buffer.from(seg, 'base64url').toString('utf-8')
    const obj = JSON.parse(json) as unknown
    return obj && typeof obj === 'object' && !Array.isArray(obj) ? (obj as Record<string, unknown>) : null
  } catch {
    return null
  }
}

/** A source of text to scan for JWTs, labelled by WHERE it came from. */
export interface JwtSource {
  where: string
  text: string
}

/**
 * Scan sources for JWT-shaped tokens, decode header+payload (base64url, NO crypto
 * verification, NO dictionary attack), and flag alg:none, expired, and missing-exp.
 * Decoded claim values are framed (injection-stripped) before entering a finding,
 * and the token itself is shown only as a short redacted prefix.
 */
export function analyzeJwts(sources: JwtSource[], at: string): PageFinding[] {
  const out: PageFinding[] = []
  const seen = new Set<string>()
  const nowSec = Math.floor(Date.now() / 1000)

  for (const { where, text } of sources) {
    if (!text) continue
    for (const m of text.matchAll(JWT_RE)) {
      const tok = m[0]
      if (seen.has(tok)) continue
      seen.add(tok)
      if (seen.size > 40) return out // bounded

      const [hSeg, pSeg] = tok.split('.')
      const header = b64urlToObj(hSeg)
      const payload = b64urlToObj(pSeg)
      if (!header || !payload || header.alg === undefined) continue // not a real JWT

      const alg = String(header.alg).toLowerCase()
      const preview = clean(tok.slice(0, 16), 20)
      const claims = claimSummary(payload)
      const w = clean(where, 80)

      if (alg === 'none') {
        out.push(f('critical', 'jwt-alg-none', `an UNSIGNED JWT (alg:none — forgeable, any claims accepted) is exposed in ${w} [${preview}… ${claims}]`, at, 'reject alg:none server-side; require a fixed signing algorithm (e.g. RS256) and verify the signature on every request'))
        continue
      }

      const exp = typeof payload.exp === 'number' ? payload.exp : null
      if (exp === null) {
        out.push(f('low', 'jwt-no-exp', `a JWT with NO exp claim (never expires) is exposed in ${w} — alg:${clean(alg, 20)} [${preview}… ${claims}]`, at, 'always set a short exp on JWTs so a leaked token cannot be replayed indefinitely'))
      } else if (exp < nowSec) {
        out.push(f('medium', 'jwt-expired', `an EXPIRED JWT is exposed in ${w} — alg:${clean(alg, 20)}, expired ${new Date(exp * 1000).toISOString()} [${preview}… ${claims}]`, at, 'stop embedding tokens in the page/bundle; verify exp server-side and rotate any leaked token'))
      }
    }
  }
  return out
}

/** A tiny, framed summary of identity claims (values are UNTRUSTED → cleaned). */
function claimSummary(payload: Record<string, unknown>): string {
  const parts: string[] = []
  for (const k of ['iss', 'sub', 'aud'] as const) {
    const v = payload[k]
    if (typeof v === 'string' || typeof v === 'number') parts.push(`${k}=${clean(String(v), 40)}`)
  }
  return parts.length ? parts.join(' ') : 'no iss/sub/aud'
}

function f(severity: PageFinding['severity'], kind: string, detail: string, at: string, suggestedFix: string): PageFinding {
  return { severity, kind, detail, at, suggestedFix, confidence: 'strong' }
}

// ── Hardcoded-secret scanner for same-origin JS bundles (Kimi web-audit) ─────
// A secret shipped inside a client bundle is downloadable by anyone → compromised.
// We match HIGH-SIGNAL provider key shapes plus one generic high-entropy assignment,
// and report ONLY a REDACTED fingerprint (short prefix + length) — never the value.
export interface SecretMatch {
  label: string
  /** REDACTED fingerprint: a short prefix + the total length. The full secret is
   *  NEVER stored in a finding. */
  redacted: string
}

/** Provider key shapes + a generic assignment. `group` picks the captured secret
 *  when the whole regex is broader than the secret itself. `prefix` = chars shown. */
const SECRET_PATTERNS: Array<{ re: RegExp; label: string; prefix: number; group?: number }> = [
  { re: /sk-live-[A-Za-z0-9]{16,}/g, label: 'Stripe live secret key (sk-live-…)', prefix: 8 },
  { re: /sk-[A-Za-z0-9]{20,}/g, label: 'secret key (sk-…, Stripe/OpenAI-style)', prefix: 3 },
  { re: /AKIA[0-9A-Z]{16}/g, label: 'AWS access key id (AKIA…)', prefix: 4 },
  { re: /github_pat_[A-Za-z0-9_]{20,}/g, label: 'GitHub fine-grained PAT (github_pat_…)', prefix: 11 },
  { re: /ghp_[A-Za-z0-9]{20,}/g, label: 'GitHub personal access token (ghp_…)', prefix: 4 },
  { re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, label: 'Slack token (xox…)', prefix: 5 },
  { re: /AIza[0-9A-Za-z_-]{35}/g, label: 'Google API key (AIza…)', prefix: 4 },
  { re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, label: 'PEM private key block', prefix: 16 },
  { re: /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["']([A-Za-z0-9_-]{16,})["']/gi, label: 'hardcoded high-entropy credential assignment', prefix: 4, group: 1 },
]

function redactSecret(raw: string, prefix: number): string {
  return `${raw.slice(0, prefix)}…(len ${raw.length})`
}

/** Scan a bundle body for hardcoded secrets. De-duplicated by the raw token (so a
 *  provider-shape match and the generic assignment don't double-report the same
 *  value); the raw token stays local — only the redacted fingerprint escapes. */
export function scanSecrets(text: string): SecretMatch[] {
  if (!text) return []
  const out: SecretMatch[] = []
  const seen = new Set<string>()
  for (const { re, label, prefix, group } of SECRET_PATTERNS) {
    for (const m of text.matchAll(re)) {
      const raw = (group ? m[group] : m[0]) ?? ''
      if (!raw || seen.has(raw)) continue
      seen.add(raw)
      out.push({ label, redacted: redactSecret(raw, prefix) })
      if (out.length >= 25) return out
    }
  }
  return out
}

/** Turn secret matches into critical findings. Both the label and the redacted
 *  fingerprint are cleaned before they enter a finding. */
export function secretFindings(matches: SecretMatch[], bundleUrl: string): PageFinding[] {
  return matches.map((s) => ({
    severity: 'critical' as const,
    kind: 'exposed-secret',
    detail: `a hardcoded secret is shipped in a same-origin JS bundle: ${clean(s.label, 80)} [${clean(s.redacted, 60)}] — anyone who downloads the bundle has it`,
    at: clean(bundleUrl, 200),
    suggestedFix: 'remove the secret from client-side code and ROTATE it immediately; keep secrets server-side / in a secret store — a key shipped in a bundle must be treated as compromised',
    confidence: 'strong' as const,
  }))
}
