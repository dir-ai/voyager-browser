import net from 'node:net'

export interface UrlDecision {
  ok: boolean
  url: string | null
  host: string | null
  origin: string | null
  scope: 'loopback' | 'private' | 'public' | 'unknown'
  reason?: string
}

// Cloud instance-metadata endpoints — fetching these is an SSRF/credential-theft
// vector, never a legitimate page observation. Hard-blocked.
const METADATA_HOSTS = new Set(['169.254.169.254', 'fd00:ec2::254', 'metadata.google.internal', '100.100.100.200'])

/**
 * Parse and vet a SINGLE page URL. voyager-browser refuses anything but one
 * http(s) URL: no file://, data:, javascript:, ftp:, no lists. The host is
 * additionally screened so a literal metadata/loopback target is rejected up
 * front (resolved IPs are re-screened after DNS in observe()).
 */
export function parseUrl(input: string): UrlDecision {
  const raw = (input ?? '').trim()
  if (!raw) return { ok: false, url: null, host: null, origin: null, scope: 'unknown', reason: 'empty URL' }
  if (/[,\s]/.test(raw)) return { ok: false, url: null, host: null, origin: null, scope: 'unknown', reason: 'only a single URL is allowed (no lists or whitespace)' }

  let u: URL
  try {
    u = new URL(raw)
  } catch {
    // allow a bare host/domain by assuming https
    try {
      u = new URL(`https://${raw}`)
    } catch {
      return { ok: false, url: null, host: null, origin: null, scope: 'unknown', reason: `not a valid URL: ${raw}` }
    }
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return { ok: false, url: null, host: null, origin: null, scope: 'unknown', reason: `only http(s) is allowed, not ${u.protocol}` }
  }
  if (u.username || u.password) {
    return { ok: false, url: null, host: null, origin: null, scope: 'unknown', reason: 'credentials in the URL are not allowed' }
  }
  const host = u.hostname.replace(/^\[|\]$/g, '')
  if (METADATA_HOSTS.has(host.toLowerCase())) {
    return { ok: false, url: null, host, origin: u.origin, scope: 'unknown', reason: 'cloud metadata endpoints are blocked (SSRF/credential-theft surface)' }
  }
  const ipVer = net.isIP(host)
  const scope: UrlDecision['scope'] = ipVer ? ipScope(host, ipVer) : 'unknown'
  return { ok: true, url: u.toString(), host, origin: u.origin, scope }
}

// A metadata/link-local/loopback IP that a hostname RESOLVES to → an SSRF /
// DNS-rebinding attempt. Screened AFTER DNS resolution, not just on the literal.
const BLOCKED_IPS = new Set(['169.254.169.254', 'fd00:ec2::254', '100.100.100.200'])
export function blockedIpReason(ip: string): string | null {
  if (BLOCKED_IPS.has(ip)) return 'resolves to a cloud metadata endpoint (SSRF/DNS-rebinding blocked)'
  if (/^169\.254\./.test(ip) || /^fe80:/i.test(ip)) return 'resolves to a link-local address'
  if (ip === '127.0.0.1' || ip.startsWith('127.') || ip === '::1') return 'resolves to loopback'
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || /^(fc|fd)/i.test(ip)) return 'resolves to a private address'
  return null
}

function ipScope(ip: string, ver: number): UrlDecision['scope'] {
  if (ver === 4) {
    if (ip === '127.0.0.1' || ip.startsWith('127.')) return 'loopback'
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || ip.startsWith('169.254.')) return 'private'
    return 'public'
  }
  if (ip === '::1') return 'loopback'
  if (/^(fe80|fc|fd)/i.test(ip)) return 'private'
  return 'public'
}
