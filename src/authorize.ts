import net from 'node:net'
import ipaddr from 'ipaddr.js'

export interface UrlDecision {
  ok: boolean
  url: string | null
  host: string | null
  origin: string | null
  scope: 'loopback' | 'private' | 'public' | 'unknown'
  reason?: string
}

// Cloud instance-metadata endpoints that live in otherwise-routable ranges (so a
// pure range check wouldn't catch them). Hard-blocked by name/address. Most cloud
// metadata (169.254.169.254 link-local, fd00:ec2::254 ULA, 100.100.100.200 CGNAT)
// is already covered by the range classifier below; this set is defense-in-depth.
const METADATA_HOSTS = new Set(['169.254.169.254', 'fd00:ec2::254', 'metadata.google.internal', '100.100.100.200'])

/**
 * Classify a resolved IP and return a reason if it must not be fetched. Parses
 * the address canonically (via ipaddr.js), unwraps IPv4-mapped/compat IPv6 to the
 * embedded IPv4, and refuses anything that is not a normal PUBLIC unicast address.
 * This closes IPv4-mapped-IPv6 bypasses (::ffff:169.254.169.254), the unspecified
 * addresses (0.0.0.0, ::), CGNAT (100.64/10), NAT64, benchmark/reserved/multicast
 * and every private/loopback/link-local range in one rule.
 */
// Ranges an AUTHORIZED internal audit may reach (allowPrivate): the operator's own
// private/loopback space. linkLocal is deliberately EXCLUDED (169.254 = metadata
// surface), as are multicast/broadcast/unspecified/reserved.
const AUDIT_ALLOWED_RANGES = new Set<string>(['loopback', 'private', 'uniqueLocal', 'carrierGradeNat'])

export function blockedIpReason(ipStr: string, allowPrivate = false): string | null {
  let addr: ipaddr.IPv4 | ipaddr.IPv6
  try {
    addr = ipaddr.parse(ipStr)
  } catch {
    return `unparseable IP (${ipStr})`
  }
  // Unwrap IPv4-mapped / -compatible IPv6 so the embedded IPv4 is classified.
  if (addr.kind() === 'ipv6') {
    const v6 = addr as ipaddr.IPv6
    if (v6.isIPv4MappedAddress()) addr = v6.toIPv4Address()
  }
  if (METADATA_HOSTS.has(addr.toString())) return 'is a cloud metadata endpoint (SSRF/credential-theft surface)'
  const range = addr.range()
  // 'unicast' is the only public, routable-to-the-internet category.
  if (range === 'unicast') return null
  // AUTHORIZED internal audit (Kimi web-audit P0 — without this, voyager-browser
  // cannot even POINT at your own staging/intranet/loopback app). When allowPrivate,
  // permit the operator's own private ranges but STILL refuse cloud-metadata (above)
  // and link-local + multicast/broadcast/unspecified/reserved. Mirrors voyager-net's
  // authorized posture.
  if (allowPrivate && AUDIT_ALLOWED_RANGES.has(range)) return null
  return `resolves to a non-public address (${range})`
}

/** Scope of a literal IP, for the UrlDecision. */
function scopeOf(ipStr: string): UrlDecision['scope'] {
  try {
    let a: ipaddr.IPv4 | ipaddr.IPv6 = ipaddr.parse(ipStr)
    if (a.kind() === 'ipv6') { const v6 = a as ipaddr.IPv6; if (v6.isIPv4MappedAddress()) a = v6.toIPv4Address() }
    const r = a.range()
    if (r === 'loopback') return 'loopback'
    if (r === 'unicast') return 'public'
    return 'private'
  } catch { return 'unknown' }
}

/**
 * Parse and vet a SINGLE page URL. voyager-browser refuses anything but one
 * http(s) URL: no file://, data:, javascript:, ftp:, no lists, no credentials.
 * A literal IP is classified immediately; hostnames are re-screened after DNS in
 * observe() (and the resolved IP is pinned to the socket to defeat rebinding).
 */
export function parseUrl(input: string, opts: { allowPrivate?: boolean } = {}): UrlDecision {
  const allowPrivate = opts.allowPrivate === true
  const raw = (input ?? '').trim()
  if (!raw) return { ok: false, url: null, host: null, origin: null, scope: 'unknown', reason: 'empty URL' }
  if (/[,\s]/.test(raw)) return { ok: false, url: null, host: null, origin: null, scope: 'unknown', reason: 'only a single URL is allowed (no lists or whitespace)' }

  let u: URL
  try {
    u = new URL(raw)
  } catch {
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
  const host = u.hostname.replace(/^\[|\]$/g, '') // strip IPv6 brackets
  if (METADATA_HOSTS.has(host.toLowerCase())) {
    return { ok: false, url: null, host, origin: u.origin, scope: 'unknown', reason: 'cloud metadata endpoints are blocked (SSRF/credential-theft surface)' }
  }
  // A literal IP target is classified now — reject non-public immediately.
  if (net.isIP(host)) {
    const blocked = blockedIpReason(host, allowPrivate)
    if (blocked) return { ok: false, url: null, host, origin: u.origin, scope: 'unknown', reason: `${host} ${blocked}` }
    return { ok: true, url: u.toString(), host, origin: u.origin, scope: scopeOf(host) }
  }
  return { ok: true, url: u.toString(), host, origin: u.origin, scope: 'unknown' }
}
