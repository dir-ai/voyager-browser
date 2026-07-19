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
export function blockedIpReason(ipStr: string): string | null {
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
  // 'unicast' is the only public, routable-to-the-internet category. Everything
  // else — private, loopback, linkLocal, uniqueLocal, unspecified, broadcast,
  // multicast, carrierGradeNat, reserved, rfc6145/rfc6052 (NAT64), etc. — is out.
  if (range !== 'unicast') return `resolves to a non-public address (${range})`
  return null
}

/**
 * Parse and vet a SINGLE page URL. voyager-browser refuses anything but one
 * http(s) URL: no file://, data:, javascript:, ftp:, no lists, no credentials.
 * A literal IP is classified immediately; hostnames are re-screened after DNS in
 * observe() (and the resolved IP is pinned to the socket to defeat rebinding).
 */
export function parseUrl(input: string): UrlDecision {
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
    const blocked = blockedIpReason(host)
    if (blocked) return { ok: false, url: null, host, origin: u.origin, scope: 'unknown', reason: `${host} ${blocked}` }
    return { ok: true, url: u.toString(), host, origin: u.origin, scope: 'public' }
  }
  return { ok: true, url: u.toString(), host, origin: u.origin, scope: 'unknown' }
}
