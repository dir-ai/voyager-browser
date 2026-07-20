// @dir-ai/voyager-browser — Voyager's web-page sense.
//
// A safe, read-only observation of ONE live URL: structure, forms, links,
// scripts, security posture (CSP/HSTS/mixed-content) and accessibility signals.
// It parses STATIC HTML — no JavaScript execution, no headless browser — so it
// is honest about what it can and cannot see (it will not render a client-side
// SPA's runtime state). All page text is framed as untrusted. SSRF-gated:
// refuses non-http(s) URLs and anything resolving to private/metadata addresses.
export { observe } from './observe.js'
export { parseUrl, blockedIpReason } from './authorize.js'
export { frame, extractStructure } from './html.js'
export { detectBodySignatures, bodySignatureFindings, analyzeJwts } from './detect.js'
export type { BodySignature, JwtSource } from './detect.js'
export { discoverWellKnown } from './discover.js'
export type {
  PageBrief, PageFinding, PageForm, FormField, PageLink, PageStructure,
  SecurityPosture, RenderMode, Framed, Severity, Confidence, ObserveOptions,
} from './types.js'
export { VERSION } from './version.js'
