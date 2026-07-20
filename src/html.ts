import { stripInjection } from '@dir-ai/voyager'
import type { Framed, FormField, PageForm, PageLink, PageStructure } from './types.js'

/** Frame owner/third-party page text as UNTRUSTED: strip injection payloads and
 *  record whether anything was neutralized. The agent must treat `text` as data. */
export function frame(raw: string): Framed {
  const collapsed = decodeEntities(raw).replace(/\s+/g, ' ').trim().slice(0, 400)
  const cleaned = stripInjection(collapsed)
  return { text: cleaned, stripped: cleaned !== collapsed ? 1 : 0 }
}

/** Neutralize an owner-controlled string that enters structured output (href,
 *  action, field name/type, viewport, lang). Keeps it a plain string but strips
 *  injection payloads so raw page text never reaches the agent as instructions. */
export function clean(raw: string, max = 300): string {
  return stripInjection(decodeEntities(raw).slice(0, max)).trim()
}

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", '#39': "'", nbsp: ' ' }
function decodeEntities(s: string): string {
  return s.replace(/&(#\d+|#x[0-9a-f]+|[a-z]+);/gi, (m, code: string) => {
    if (code[0] === '#') {
      const n = code[1] === 'x' || code[1] === 'X' ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10)
      return Number.isFinite(n) && n > 0 && n < 0x110000 ? safeFromCode(n) : m
    }
    return ENTITIES[code.toLowerCase()] ?? m
  })
}
function safeFromCode(n: number): string {
  try {
    return String.fromCodePoint(n)
  } catch {
    return ''
  }
}

// Match an attribute so a `data-`/other prefix cannot masquerade as it: the name
// must be preceded by the start of string, whitespace, or a quote — never `-`.
function attr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`(?:^|[\\s"'])${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'))
  return m ? (m[2] ?? m[3] ?? m[4] ?? '') : null
}

function stripComments(html: string): string {
  return html.replace(/<!--[\s\S]*?-->/g, ' ')
}
function stripScriptsAndStyles(html: string): string {
  return html.replace(/<script\b[\s\S]*?<\/script>/gi, ' ').replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
}

const SENSITIVE_FIELD = /pass|pwd|card|cvv|cvc|ssn|iban|account|secret|token|otp|pin\b/i

/** Extract the structural signals we reason over — dependency-free, best-effort,
 *  honest. It parses static HTML; it does NOT execute JavaScript or render SPAs.
 *  Comments and script/style bodies are removed FIRST so commented-out markup and
 *  code-string look-alikes cannot fabricate (or mask) forms, links, and findings. */
export function extractStructure(html: string, pageUrl: URL): {
  structure: PageStructure
  forms: PageForm[]
  links: PageLink[]
} {
  const noComments = stripComments(html) // scripts still present → we need their src
  const text = stripScriptsAndStyles(noComments) // real, rendered markup only

  const titleM = text.match(/<title[^>]*>([\s\S]*?)<\/title>/i)
  const title = titleM ? frame(titleM[1]) : null
  const htmlTag = text.match(/<html\b[^>]*>/i)?.[0] ?? ''
  const lang = htmlTag ? nz(clean(attr(htmlTag, 'lang') ?? '', 35)) : null

  const metas = [...noComments.matchAll(/<meta\b[^>]*>/gi)].map((m) => m[0])
  const descTag = metas.find((t) => (attr(t, 'name') ?? '').toLowerCase() === 'description')
  const metaDescription = descTag ? frame(attr(descTag, 'content') ?? '') : null
  const viewportTag = metas.find((t) => (attr(t, 'name') ?? '').toLowerCase() === 'viewport')
  const viewport = viewportTag ? nz(clean(attr(viewportTag, 'content') ?? '', 120)) : null
  const generatorTag = metas.find((t) => (attr(t, 'name') ?? '').toLowerCase() === 'generator')
  const generator = generatorTag ? nz(clean(attr(generatorTag, 'content') ?? '', 120)) : null

  const headings = [...text.matchAll(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi)]
    .slice(0, 40)
    .map((m) => ({ level: Number(m[1]), text: frame(m[2].replace(/<[^>]+>/g, ' ')) }))

  // Honor <base href>: relative URLs resolve against IT, not the page URL. A
  // hostile <base href="http://attacker/"> would otherwise make attacker-hosted
  // resources look same-origin (or hide external ones). Resolve with `base`, but
  // still judge "external" against the PAGE's origin.
  let base = pageUrl
  const baseHref = attr(noComments.match(/<base\b[^>]*>/i)?.[0] ?? '', 'href')
  if (baseHref) {
    try {
      base = new URL(baseHref, pageUrl)
    } catch {
      /* keep pageUrl */
    }
  }

  // Scripts from comment-stripped html (need the tags), before script bodies go away.
  const scripts = [...noComments.matchAll(/<script\b[^>]*>/gi)].map((m) => m[0])
  const scriptOrigins = new Set<string>()
  const scriptSrcs: string[] = [] // full SAME-ORIGIN script URLs — the SPA's bundles
  let inlineScripts = 0
  let externalNoSri = 0
  for (const s of scripts) {
    const src = attr(s, 'src')
    if (src) {
      try {
        const o = new URL(src, base)
        scriptOrigins.add(o.origin)
        if (o.origin === pageUrl.origin) scriptSrcs.push(o.toString())
        if (o.origin !== pageUrl.origin && !attr(s, 'integrity')) externalNoSri++ // SRI missing on 3rd-party
      } catch {
        /* ignore malformed src */
      }
    } else inlineScripts++
  }

  const imgs = [...text.matchAll(/<img\b[^>]*>/gi)].map((m) => m[0])
  const imgCount = imgs.length
  const imgMissingAlt = imgs.filter((t) => attr(t, 'alt') === null).length

  const external = (u: string): string | null => {
    try { const o = new URL(u, base); return o.origin !== pageUrl.origin && /^https?:$/.test(o.protocol) ? o.origin : null } catch { return null }
  }
  // Cross-origin IFRAMES — embedded third parties (data-leak / clickjacking-relay
  // surface). Sandbox presence matters, so we record it.
  const iframes: Array<{ origin: string; sandboxed: boolean }> = []
  for (const m of noComments.matchAll(/<iframe\b[^>]*>/gi)) {
    const src = attr(m[0], 'src'); if (!src) continue
    // `sandbox` is a boolean attribute (often valueless), so detect its PRESENCE.
    const origin = external(src); if (origin) iframes.push({ origin, sandboxed: /\bsandbox\b/i.test(m[0]) })
  }
  // Resource HINTS (dns-prefetch/preconnect/preload/prefetch/modulepreload) — the
  // third-party origins the page deliberately reaches out to.
  const hintOrigins = new Set<string>()
  for (const m of noComments.matchAll(/<link\b[^>]*>/gi)) {
    const rel = (attr(m[0], 'rel') ?? '').toLowerCase()
    if (!/dns-prefetch|preconnect|preload|prefetch|modulepreload/.test(rel)) continue
    const href = attr(m[0], 'href'); if (!href) continue
    const origin = external(href); if (origin) hintOrigins.add(origin)
  }
  // srcset third-party origins (responsive images / <source>).
  const srcsetOrigins = new Set<string>()
  for (const m of text.matchAll(/<(?:img|source)\b[^>]*\bsrcset\s*=\s*["']([^"']+)["']/gi)) {
    for (const cand of m[1].split(',')) {
      const url = cand.trim().split(/\s+/)[0]; if (!url) continue
      const origin = external(url); if (origin) srcsetOrigins.add(origin)
    }
  }

  // Signals for honest SPA/client-render detection.
  const bodyText = text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
  const mountNode = /<(?:div|main)\b[^>]*\bid\s*=\s*["'](?:root|app|__next|__nuxt|q-app|svelte)["']/i.test(text)

  const structure: PageStructure = {
    title,
    lang,
    headings,
    scriptOrigins: [...scriptOrigins],
    scriptSrcs: scriptSrcs.slice(0, 12),
    inlineScripts,
    externalScriptsNoSri: externalNoSri,
    imgCount,
    imgMissingAlt,
    metaDescription,
    viewport,
    generator,
    visibleTextLength: bodyText.length,
    hasMountNode: mountNode,
    iframes,
    resourceHintOrigins: [...hintOrigins],
    srcsetOrigins: [...srcsetOrigins],
  }

  // Forms — from rendered markup only (no comments/scripts).
  const forms: PageForm[] = [...text.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)].slice(0, 20).map((m) => {
    const open = m[0].match(/<form\b[^>]*>/i)?.[0] ?? ''
    const actionRaw = attr(open, 'action') ?? ''
    let actionUrl: URL | null = null
    try {
      actionUrl = new URL(actionRaw || pageUrl.toString(), base)
    } catch {
      /* keep null → treated as same-page */
    }
    const method = (attr(open, 'method') ?? 'get').toUpperCase()
    const fields: FormField[] = [...m[1].matchAll(/<(input|select|textarea)\b[^>]*>/gi)].slice(0, 60).map((f) => ({
      name: clean(attr(f[0], 'name') ?? '', 80),
      type: clean((attr(f[0], 'type') ?? f[1]).toLowerCase(), 30),
      required: /(?:^|[\s"'])required(?:[\s>"']|$)/i.test(f[0]),
    }))
    // Security flags computed from the PARSED url; the stored string is cleaned.
    const insecureTarget = pageUrl.protocol === 'https:' && actionUrl?.protocol === 'http:'
    const crossOrigin = actionUrl ? actionUrl.origin !== pageUrl.origin : false
    const sensitive = fields.some((f) => f.type === 'password' || SENSITIVE_FIELD.test(f.name))
    const hasCsrfToken = fields.some((f) => f.type === 'hidden' && /csrf|xsrf|token|authenticity|_token|nonce/i.test(f.name))
    return { action: clean((actionUrl ?? pageUrl).toString(), 300), method, insecureTarget, crossOrigin, fields, sensitive, hasCsrfToken }
  })

  // Links — from rendered markup only.
  const links: PageLink[] = [...text.matchAll(/<a\b[^>]*>/gi)].slice(0, 500).map((m) => {
    const hrefRaw = attr(m[0], 'href') ?? ''
    let external = false
    try {
      external = new URL(hrefRaw, base).origin !== pageUrl.origin
    } catch {
      /* relative/malformed → internal */
    }
    const targetBlank = (attr(m[0], 'target') ?? '').toLowerCase() === '_blank'
    const rel = (attr(m[0], 'rel') ?? '').toLowerCase()
    const unsafeBlank = targetBlank && external && !/noopener|noreferrer/.test(rel)
    return { href: clean(hrefRaw, 300), external, unsafeBlank }
  })

  return { structure, forms, links }
}

function nz(s: string): string | null {
  return s ? s : null
}
