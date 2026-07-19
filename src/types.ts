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
  inlineScripts: number
  imgCount: number
  imgMissingAlt: number
  metaDescription: Framed | null
  viewport: string | null
}

export interface SecurityPosture {
  https: boolean
  hsts: boolean
  csp: boolean
  xContentTypeOptions: boolean
  referrerPolicy: boolean
  /** http:// sub-resources referenced from an https page. */
  mixedContent: string[]
  /** Distinct third-party script origins (not the page origin). */
  thirdPartyScripts: string[]
  setCookieInsecure: boolean
}

export interface PageBrief {
  target: { input: string; url: string | null; origin: string | null }
  resolvedIp: string | null
  fetchedAt: number
  status: number | null
  contentType: string | null
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
