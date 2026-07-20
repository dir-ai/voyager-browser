import http from 'node:http'
import https from 'node:https'
import type { LookupFunction } from 'node:net'
import { blockedIpReason } from './authorize.js'

export interface SafeGetResult {
  status: number
  headers: http.IncomingHttpHeaders
  /** Raw Set-Cookie lines, each evaluated individually (undici/http joins them otherwise). */
  setCookies: string[]
  body: string
  truncated: boolean
}

export interface SafeGetOptions {
  /** The already-vetted IP to PIN the connection to (defeats DNS rebinding). */
  pinnedIp: string
  timeoutMs: number
  maxBytes: number
  /** Authorized internal audit: permit private/loopback pins (still refuses
   *  cloud-metadata + link-local). Mirrors the observe() `authorized` posture. */
  allowPrivate?: boolean
}

/**
 * A GET that PINS the socket to a pre-vetted IP. The custom lookup ignores the
 * hostname and returns only `pinnedIp` (re-screened here so a race can't slip
 * another address in), while `servername`/Host stay the original hostname so TLS
 * SNI and certificate validation are unaffected. A single deadline bounds headers
 * AND body, and the body is capped — a slow-drip server cannot hang the tool.
 * Redirects are NOT followed here (the caller re-vets each hop).
 */
export function safeGet(urlStr: string, opts: SafeGetOptions): Promise<SafeGetResult> {
  const url = new URL(urlStr)
  const isHttps = url.protocol === 'https:'
  const mod = isHttps ? https : http
  const family = opts.pinnedIp.includes(':') ? 6 : 4

  // Pin every connection attempt to the vetted IP; refuse if it's somehow blocked.
  // Node calls lookup either as (err, address, family) or, when options.all is
  // set, as (err, [{address, family}]) — handle BOTH so the socket never gets an
  // undefined address.
  const lookup = ((hostname: string, options: { all?: boolean } | number, cb: (...a: unknown[]) => void) => {
    const reason = blockedIpReason(opts.pinnedIp, opts.allowPrivate)
    if (reason) {
      cb(new Error(`pinned IP ${opts.pinnedIp} ${reason}`))
      return
    }
    const all = typeof options === 'object' && options?.all === true
    if (all) cb(null, [{ address: opts.pinnedIp, family }])
    else cb(null, opts.pinnedIp, family)
  }) as unknown as LookupFunction

  return new Promise<SafeGetResult>((resolve, reject) => {
    let settled = false
    const done = (fn: () => void) => {
      if (settled) return
      settled = true
      clearTimeout(deadline)
      fn()
    }

    const req = mod.request(
      {
        protocol: url.protocol,
        hostname: url.hostname.replace(/^\[|\]$/g, ''),
        port: url.port || (isHttps ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method: 'GET',
        lookup,
        servername: isHttps ? url.hostname.replace(/^\[|\]$/g, '') : undefined,
        headers: { accept: 'text/html,*/*', 'user-agent': 'voyager-browser (read-only page sense)', host: url.host },
      },
      (res) => {
        const chunks: Buffer[] = []
        let total = 0
        let truncated = false
        res.on('data', (c: Buffer) => {
          if (settled) return
          total += c.byteLength
          if (total > opts.maxBytes) {
            truncated = true
            chunks.push(c.subarray(0, Math.max(0, c.byteLength - (total - opts.maxBytes))))
            res.destroy()
            finish()
            return
          }
          chunks.push(c)
        })
        res.on('end', finish)
        res.on('error', (e) => done(() => reject(e)))
        function finish(): void {
          done(() =>
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              setCookies: res.headers['set-cookie'] ?? [],
              body: Buffer.concat(chunks).toString('utf-8'),
              truncated,
            }),
          )
        }
      },
    )
    // ONE deadline for the whole exchange (headers + body), unlike a header-only timeout.
    const deadline = setTimeout(() => {
      req.destroy()
      done(() => reject(new Error(`timed out after ${opts.timeoutMs}ms`)))
    }, opts.timeoutMs)
    req.on('error', (e) => done(() => reject(e)))
    req.end()
  })
}
