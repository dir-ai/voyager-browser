import { stripInjection } from '@dir-ai/voyager'
import type { Framed, FormField, PageForm, PageLink, PageStructure } from './types.js'

/** Frame owner/third-party page text as UNTRUSTED: strip injection payloads and
 *  record whether anything was neutralized. The agent must treat `text` as data. */
export function frame(raw: string): Framed {
  const collapsed = decodeEntities(raw).replace(/\s+/g, ' ').trim().slice(0, 400)
  const cleaned = stripInjection(collapsed)
  return { text: cleaned, stripped: cleaned !== collapsed ? 1 : 0 }
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

function attr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'))
  return m ? (m[2] ?? m[3] ?? m[4] ?? '') : null
}

function stripScriptsAndStyles(html: string): string {
  return html.replace(/<script\b[\s\S]*?<\/script>/gi, ' ').replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
}

const SENSITIVE_FIELD = /pass|pwd|card|cvv|cvc|ssn|iban|account|secret|token|otp|pin\b/i

/** Extract the structural signals we reason over — dependency-free, best-effort,
 *  honest. It parses static HTML; it does NOT execute JavaScript or render SPAs. */
export function extractStructure(html: string, pageUrl: URL): {
  structure: PageStructure
  forms: PageForm[]
  links: PageLink[]
} {
  const text = stripScriptsAndStyles(html)

  const titleM = text.match(/<title[^>]*>([\s\S]*?)<\/title>/i)
  const title = titleM ? frame(titleM[1]) : null
  const htmlTag = html.match(/<html\b[^>]*>/i)?.[0] ?? ''
  const lang = htmlTag ? attr(htmlTag, 'lang') : null

  const metas = [...html.matchAll(/<meta\b[^>]*>/gi)].map((m) => m[0])
  const descTag = metas.find((t) => (attr(t, 'name') ?? '').toLowerCase() === 'description')
  const metaDescription = descTag ? frame(attr(descTag, 'content') ?? '') : null
  const viewportTag = metas.find((t) => (attr(t, 'name') ?? '').toLowerCase() === 'viewport')
  const viewport = viewportTag ? attr(viewportTag, 'content') : null

  const headings = [...text.matchAll(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi)]
    .slice(0, 40)
    .map((m) => ({ level: Number(m[1]), text: frame(m[2].replace(/<[^>]+>/g, ' ')) }))

  const scripts = [...html.matchAll(/<script\b[^>]*>/gi)].map((m) => m[0])
  const scriptOrigins = new Set<string>()
  let inlineScripts = 0
  for (const s of scripts) {
    const src = attr(s, 'src')
    if (src) {
      try {
        scriptOrigins.add(new URL(src, pageUrl).origin)
      } catch {
        /* ignore malformed src */
      }
    } else inlineScripts++
  }

  const imgs = [...html.matchAll(/<img\b[^>]*>/gi)].map((m) => m[0])
  const imgCount = imgs.length
  const imgMissingAlt = imgs.filter((t) => attr(t, 'alt') === null).length

  const structure: PageStructure = {
    title,
    lang,
    headings,
    scriptOrigins: [...scriptOrigins],
    inlineScripts,
    imgCount,
    imgMissingAlt,
    metaDescription,
    viewport,
  }

  // Forms
  const forms: PageForm[] = [...html.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)].slice(0, 20).map((m) => {
    const open = m[0].match(/<form\b[^>]*>/i)?.[0] ?? ''
    const actionRaw = attr(open, 'action') ?? ''
    let action = pageUrl.toString()
    try {
      action = new URL(actionRaw || pageUrl.toString(), pageUrl).toString()
    } catch {
      /* keep page url */
    }
    const method = (attr(open, 'method') ?? 'get').toUpperCase()
    const fields: FormField[] = [...m[1].matchAll(/<(input|select|textarea)\b[^>]*>/gi)].slice(0, 60).map((f) => ({
      name: attr(f[0], 'name') ?? '',
      type: (attr(f[0], 'type') ?? f[1].toLowerCase()).toLowerCase(),
      required: /\brequired\b/i.test(f[0]),
    }))
    let actionUrl: URL | null = null
    try {
      actionUrl = new URL(action)
    } catch {
      /* ignore */
    }
    const insecureTarget = pageUrl.protocol === 'https:' && actionUrl?.protocol === 'http:'
    const crossOrigin = actionUrl ? actionUrl.origin !== pageUrl.origin : false
    const sensitive = fields.some((f) => f.type === 'password' || SENSITIVE_FIELD.test(f.name))
    return { action, method, insecureTarget, crossOrigin, fields, sensitive }
  })

  // Links
  const links: PageLink[] = [...html.matchAll(/<a\b[^>]*>/gi)].slice(0, 500).map((m) => {
    const hrefRaw = attr(m[0], 'href') ?? ''
    let external = false
    try {
      external = new URL(hrefRaw, pageUrl).origin !== pageUrl.origin
    } catch {
      /* relative/malformed → internal */
    }
    const targetBlank = (attr(m[0], 'target') ?? '') === '_blank'
    const rel = (attr(m[0], 'rel') ?? '').toLowerCase()
    const unsafeBlank = targetBlank && external && !/noopener|noreferrer/.test(rel)
    return { href: hrefRaw.slice(0, 300), external, unsafeBlank }
  })

  return { structure, forms, links }
}
