/** A single framed (untrusted) piece of page text. */
export interface Framed {
  text: string
  /** How many injection payloads were neutralized while framing it. */
  stripped: number
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Confidence = 'strong' | 'moderate' | 'weak'

export interface PageFinding {
  severity: Severity
  /** Stable kind slug, e.g. 'mixed-content', 'form-insecure', 'missing-csp', 'img-no-alt'. */
  kind: string
  detail: string
  /** Where on the page (selector-ish hint / URL / resource). */
  at?: string
  /** Described, NEVER applied. */
  suggestedFix: string
  confidence: Confidence
}

export interface FormField {
  name: string
  type: string
  required: boolean
}

export interface PageForm {
  /** Resolved absolute action URL (or the page URL when action is empty). */
  action: string
  method: string
  /** True when a form on an HTTPS page posts to a non-HTTPS / cross-origin target. */
  insecureTarget: boolean
  crossOrigin: boolean
  fields: FormField[]
  /** True when the form collects a password / payment-like field. */
  sensitive: boolean
  /** True when a hidden CSRF/anti-forgery token field is present. */
  hasCsrfToken: boolean
}

export interface PageLink {
  href: string
  external: boolean
  /** target=_blank without rel=noopener → reverse-tabnabbing risk. */
  unsafeBlank: boolean
}

export interface PageStructure {
  title: Framed | null
  lang: string | null
  /** Heading outline (level + framed text), in document order, capped. */
  headings: Array<{ level: number; text: Framed }>
  /** Distinct origins of <script src>. */
  scriptOrigins: string[]
  /** Full SAME-ORIGIN script bundle URLs — fetched to mine the SPA's API endpoints. */
  scriptSrcs: string[]
  inlineScripts: number
  /** Third-party <script src> without Subresource Integrity (supply-chain surface). */
  externalScriptsNoSri: number
  imgCount: number
  imgMissingAlt: number
  metaDescription: Framed | null
  viewport: string | null
  /** <meta generator> value, if any (tech-stack hint). */
  generator: string | null
  /** Visible (tag-stripped) text length — feeds render-mode detection. */
  visibleTextLength: number
  /** A single SPA mount node (#root/#app/#__next…) was found. */
  hasMountNode: boolean
  /** Cross-origin <iframe> embeds (with sandbox presence) — third parties given a
   *  frame on the page (data-leak / clickjacking-relay surface). */
  iframes: Array<{ origin: string; sandboxed: boolean }>
  /** Third-party origins the page hints it will reach (dns-prefetch/preconnect/
   *  preload/prefetch). */
  resourceHintOrigins: string[]
  /** Third-party origins referenced from img/source srcset. */
  srcsetOrigins: string[]
}

export interface SecurityPosture {
  https: boolean
  hsts: boolean
  /** HSTS present but weak (max-age too low / no includeSubDomains). */
  hstsWeak: boolean
  csp: boolean
  /** Specific CSP weaknesses, e.g. 'unsafe-inline', 'wildcard-src', 'no-object-src'. */
  cspWeaknesses: string[]
  xContentTypeOptions: boolean
  referrerPolicy: boolean
  /** Clickjacking protection: X-Frame-Options or CSP frame-ancestors. */
  frameProtection: boolean
  /** Cross-origin isolation headers. */
  coop: boolean
  corp: boolean
  permissionsPolicy: boolean
  /** Version-leaking Server / X-Powered-By value, if present. */
  versionLeak: string | null
  /** http:// sub-resources referenced from an https page. */
  mixedContent: string[]
  /** Distinct third-party script origins (not the page origin). */
  thirdPartyScripts: string[]
  /** Per-cookie: names of cookies missing Secure/HttpOnly. */
  insecureCookies: string[]
}

/** How much of the page a static fetch actually saw. `client-heavy` means most
 *  content is rendered by JavaScript that voyager-browser does NOT execute — an
 *  honest signal so an agent knows it is looking at a shell, not the real page. */
export type RenderMode = 'static' | 'hybrid' | 'client-heavy'

export interface PageBrief {
  target: { input: string; url: string | null; origin: string | null }
  resolvedIp: string | null
  fetchedAt: number
  status: number | null
  contentType: string | null
  /** How much of the page the static fetch saw — honesty signal for SPAs. */
  render: RenderMode
  renderConfidence: Confidence
  /** True when the observed body was cut at the byte cap (partial observation). */
  truncated: boolean
  /** One-line, honest summary. */
  summary: string
  structure: PageStructure | null
  forms: PageForm[]
  links: { total: number; internal: number; external: number; unsafeBlank: number; sample: PageLink[] }
  security: SecurityPosture | null
  a11y: { lang: boolean; imgAltCoverage: number | null; formFieldsLabeled: number | null; headingOrderOk: boolean }
  findings: PageFinding[]
  confidence: Confidence
  suggestedNextProbes: string[]
  sanitization: { framedFields: number; strippedPayloads: number }
  notes: string[]
  /** Set only when the page could not be observed (tool error) — exit 2. */
  error?: string
}

export interface ObserveOptions {
  timeoutMs?: number
  /** Max bytes of HTML to read (protects against huge pages). */
  maxBytes?: number
  /** Extra request header pairs (never used to send credentials). */
  onLog?: (line: string) => void
}
