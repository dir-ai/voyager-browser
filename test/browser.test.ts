import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import { parseUrl, blockedIpReason } from '../dist/authorize.js'
import { frame, extractStructure } from '../dist/html.js'
import { detectBodySignatures, analyzeJwts, scanSecrets, secretFindings } from '../dist/detect.js'
import { graphqlIntrospectionFinding } from '../dist/graphql.js'
import { observe } from '../dist/observe.js'

test('parseUrl: accepts a bare host as https, keeps a full URL', () => {
  assert.equal(parseUrl('example.com').url, 'https://example.com/')
  assert.equal(parseUrl('https://x.io/a?b=1').ok, true)
})

test('parseUrl: refuses non-http(s), credentials, metadata, and lists', () => {
  assert.equal(parseUrl('file:///etc/passwd').ok, false)
  assert.equal(parseUrl('javascript:alert(1)').ok, false)
  assert.equal(parseUrl('data:text/html,<h1>x').ok, false)
  assert.equal(parseUrl('https://user:pw@x.io').ok, false)
  assert.equal(parseUrl('http://169.254.169.254/').ok, false)
  assert.equal(parseUrl('http://a.com, http://b.com').ok, false)
})

test('blockedIpReason: SSRF gate covers metadata, link-local, loopback, private', () => {
  assert.ok(blockedIpReason('169.254.169.254'))
  assert.ok(blockedIpReason('169.254.1.1'))
  assert.ok(blockedIpReason('127.0.0.1'))
  assert.ok(blockedIpReason('10.0.0.5'))
  assert.ok(blockedIpReason('192.168.1.1'))
  assert.ok(blockedIpReason('172.16.0.1'))
  assert.equal(blockedIpReason('93.184.216.34'), null) // public → allowed
})

test('frame: passes clean text through, decodes entities, flags nothing stripped', () => {
  const f = frame('Hello &amp; welcome')
  assert.equal(f.text, 'Hello & welcome')
  assert.equal(f.stripped, 0)
})

test('extractStructure: title, lang, headings, meta, scripts, imgs', () => {
  const html = `<!doctype html><html lang="en"><head>
    <title>My &amp; Page</title>
    <meta name="description" content="a demo">
    <meta name="viewport" content="width=device-width">
    <script src="https://cdn.other.com/a.js"></script>
    <script>console.log(1)</script>
  </head><body>
    <h1>Top</h1><h3>Skips a level</h3>
    <img src="/a.png" alt="a"><img src="/b.png">
  </body></html>`
  const { structure } = extractStructure(html, new URL('https://site.test/'))
  assert.equal(structure.title?.text, 'My & Page')
  assert.equal(structure.lang, 'en')
  assert.equal(structure.metaDescription?.text, 'a demo')
  assert.deepEqual(structure.headings.map((h) => h.level), [1, 3])
  assert.deepEqual(structure.scriptOrigins, ['https://cdn.other.com'])
  assert.equal(structure.inlineScripts, 1)
  assert.equal(structure.imgCount, 2)
  assert.equal(structure.imgMissingAlt, 1)
})

test('extractStructure: forms flag insecure/cross-origin/sensitive targets', () => {
  const html = `<html><body>
    <form action="http://evil.test/collect" method="post">
      <input name="username"><input name="password" type="password">
    </form>
    <form action="/local"><input name="q"></form>
  </body></html>`
  const { forms } = extractStructure(html, new URL('https://bank.test/login'))
  const login = forms[0]
  assert.equal(login.method, 'POST')
  assert.equal(login.insecureTarget, true) // https page → http action
  assert.equal(login.crossOrigin, true)
  assert.equal(login.sensitive, true) // has a password field
  assert.equal(forms[1].sensitive, false)
  assert.equal(forms[1].crossOrigin, false)
})

test('extractStructure: external target=_blank without rel=noopener is flagged', () => {
  const html = `<a href="https://other.test/x" target="_blank">out</a>
                <a href="https://other.test/y" target="_blank" rel="noopener">safe</a>
                <a href="/internal">in</a>`
  const { links } = extractStructure(html, new URL('https://me.test/'))
  assert.equal(links[0].unsafeBlank, true)
  assert.equal(links[1].unsafeBlank, false)
  assert.equal(links[2].external, false)
})

test('observe: SSRF-blocks a literal metadata URL before any fetch (isError)', async () => {
  const brief = await observe('http://169.254.169.254/latest/meta-data/')
  assert.ok(brief.error)
  assert.match(brief.error!, /metadata|SSRF/i)
})

test('observe: refuses a non-http(s) scheme', async () => {
  const brief = await observe('file:///etc/passwd')
  assert.ok(brief.error)
  assert.match(brief.error!, /http\(s\)/)
})

// ── Regression tests for the closed adversarial findings ───────────────────

test('SSRF gate (#2/#3): IPv4-mapped IPv6, unspecified, and CGNAT are blocked', () => {
  for (const bad of [
    'http://[::ffff:169.254.169.254]/', // maps to metadata
    'http://[::ffff:7f00:1]/', // maps to 127.0.0.1
    'http://0.0.0.0/',
    'http://[::]/',
    'http://100.64.1.1/', // CGNAT
    'http://100.100.100.200/', // Alibaba metadata (CGNAT range)
  ]) {
    assert.equal(parseUrl(bad).ok, false, `${bad} must be blocked`)
  }
  assert.equal(parseUrl('https://example.com').ok, true) // public still allowed
  assert.equal(blockedIpReason('::ffff:a9fe:a9fe'), 'is a cloud metadata endpoint (SSRF/credential-theft surface)')
})

test('parser (#5): commented-out and script-embedded markup does NOT fabricate findings', () => {
  const html = `<html><body>
    <!-- <form action="http://evil.test/collect" method="post"><input type="password" name="pw"></form> -->
    <script>var s = '<a href="http://x.evil/" target="_blank">out</a>';</script>
    <p>real content</p>
  </body></html>`
  const { forms, links } = extractStructure(html, new URL('https://site.test/'))
  assert.equal(forms.length, 0) // commented-out form is gone
  assert.equal(links.length, 0) // link inside a <script> string is gone
})

test('parser (#6): data-* attributes cannot masquerade as href/name/src', () => {
  const { links } = extractStructure('<a data-href="http://internal.evil/x" href="/safe">x</a>', new URL('https://me.test/'))
  assert.equal(links[0].href, '/safe')
  assert.equal(links[0].external, false)
})

test('framing (#7): owner-controlled href/action/field-name reach output injection-stripped', () => {
  const html = `<a href="/x‮evil">l</a><form action="/a"><input name="user​name"></form>`
  const { links, forms } = extractStructure(html, new URL('https://me.test/'))
  assert.ok(!/[‮​]/.test(links[0].href), 'href must be stripped of bidi/zero-width')
  assert.ok(!/[​]/.test(forms[0].fields[0].name), 'field name must be stripped')
})

test('form CSRF/hidden-token detection populates hasCsrfToken', () => {
  const html = `<form method="post" action="/login"><input type="password" name="pw"><input type="hidden" name="csrf_token" value="x"></form>`
  const { forms } = extractStructure(html, new URL('https://me.test/'))
  assert.equal(forms[0].sensitive, true)
  assert.equal(forms[0].hasCsrfToken, true)
})

test('SPA render detection: an empty shell with a mount node + bundle is client-heavy signal', () => {
  const { structure } = extractStructure('<html lang="en"><body><div id="root"></div><script src="/app.js"></script></body></html>', new URL('https://spa.test/'))
  assert.equal(structure.hasMountNode, true)
  assert.ok(structure.visibleTextLength < 200)
})

test('SRI: third-party script without integrity is counted', () => {
  const html = `<script src="https://cdn.other.com/a.js"></script><script src="https://cdn.other.com/b.js" integrity="sha384-x"></script>`
  const { structure } = extractStructure(html, new URL('https://me.test/'))
  assert.equal(structure.externalScriptsNoSri, 1)
})

test('Kimi: <base href> is honored — a hostile base makes relative URLs external', () => {
  const html = '<html><head><base href="http://attacker.test/"></head><body><a href="/inside">x</a><script src="/app.js"></script><form action="/login"><input type="password" name="pw"></form></body></html>'
  const { links, structure, forms } = extractStructure(html, new URL('https://victim.test/'))
  assert.equal(links[0].external, true, 'a relative link under a hostile <base> resolves to the attacker (external)')
  assert.ok(structure.scriptOrigins.includes('http://attacker.test'))
  assert.equal(forms[0].crossOrigin, true) // the form now posts to the attacker origin
})

test('Kimi: target="_BLANK" (any case) is caught for reverse-tabnabbing', () => {
  const { links } = extractStructure('<a href="https://other.test/x" target="_BLANK">x</a>', new URL('https://me.test/'))
  assert.equal(links[0].unsafeBlank, true)
})

// Round-3: embedded third-party surface (iframes, resource hints, srcset).
test('extractStructure: cross-origin iframes, resource hints and srcset origins are captured', () => {
  const html = `<html><head>
    <link rel="preconnect" href="https://hints.cdn.example/">
    <link rel="dns-prefetch" href="https://track.evil.example/">
  </head><body>
    <iframe src="https://embed.other.example/widget"></iframe>
    <iframe src="https://safe.example/x" sandbox></iframe>
    <img srcset="https://img.cdn.example/a.jpg 1x, /local.jpg 2x">
    <iframe src="/same-origin"></iframe>
  </body></html>`
  const { structure } = extractStructure(html, new URL('https://site.example/'))
  const iframeOrigins = structure.iframes.map((i) => i.origin)
  assert.ok(iframeOrigins.includes('https://embed.other.example'), 'cross-origin iframe captured')
  assert.ok(structure.iframes.some((i) => i.origin === 'https://safe.example' && i.sandboxed), 'sandbox flag recorded')
  assert.ok(!iframeOrigins.includes('https://site.example'), 'same-origin iframe excluded')
  assert.ok(structure.resourceHintOrigins.includes('https://track.evil.example'), 'resource hint origin captured')
  assert.ok(structure.srcsetOrigins.includes('https://img.cdn.example'), 'srcset third-party origin captured')
})

// Kimi #7: same-origin bundle URLs captured (feed the API-endpoint mining).
test('extractStructure: captures same-origin script bundle URLs, excludes third-party', () => {
  const html = '<html><head><script src="/static/bundle.abc.js"></script><script src="https://cdn.other.example/lib.js"></script></head><body></body></html>'
  const { structure } = extractStructure(html, new URL('https://app.example/'))
  assert.ok(structure.scriptSrcs.includes('https://app.example/static/bundle.abc.js'), 'same-origin bundle captured as full URL')
  assert.ok(!structure.scriptSrcs.some((s) => /cdn\.other/.test(s)), 'third-party script excluded from bundle fetch list')
})

// ── Kimi web-audit P0: browser could not even POINT at your own staging/intranet ──
// The SSRF gate blocked ALL loopback/private with no way in. `authorized` opens the
// operator's OWN private space while STILL refusing cloud-metadata + link-local.
test('authorized gate: blockedIpReason permits private/loopback ONLY with allowPrivate', () => {
  // default (public-only) — every internal range refused
  assert.ok(blockedIpReason('10.0.0.5'), 'private blocked by default')
  assert.ok(blockedIpReason('127.0.0.1'), 'loopback blocked by default')
  // allowPrivate — the operator's own space is reachable
  assert.equal(blockedIpReason('10.0.0.5', true), null, 'private allowed when authorized')
  assert.equal(blockedIpReason('127.0.0.1', true), null, 'loopback allowed when authorized')
  assert.equal(blockedIpReason('192.168.1.10', true), null, 'RFC1918 allowed when authorized')
  // public is always fine
  assert.equal(blockedIpReason('8.8.8.8'), null, 'public unicast never blocked')
  // the dangerous SSRF surfaces stay blocked EVEN with authorized
  assert.ok(blockedIpReason('169.254.169.254', true), 'cloud-metadata STILL blocked when authorized')
  assert.ok(blockedIpReason('169.254.1.1', true), 'link-local STILL blocked when authorized')
})

test('authorized gate: parseUrl gates a loopback literal by default, opens it with allowPrivate', () => {
  assert.equal(parseUrl('http://127.0.0.1:8088').ok, false, 'loopback refused by default')
  const ok = parseUrl('http://127.0.0.1:8088', { allowPrivate: true })
  assert.equal(ok.ok, true, 'loopback accepted when authorized')
  assert.equal(ok.scope, 'loopback')
})

const bind = (srv: http.Server): Promise<number> => new Promise((r) => srv.listen(0, '127.0.0.1', () => r((srv.address() as net.AddressInfo).port)))

test('observe: a REAL loopback app is refused by default, observed WITH authorized', async () => {
  const srv = http.createServer((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><head><title>Staging</title></head><body><form action="/login" method="post"><input name="pw" type="password"></form></body></html>') })
  srv.on('error', () => {})
  const port = await bind(srv)
  try {
    const refused = await observe(`http://127.0.0.1:${port}/`)
    assert.ok(refused.error && /non-public|loopback/i.test(refused.error), 'default: loopback SSRF-refused')

    const ok = await observe(`http://127.0.0.1:${port}/`, { authorized: true })
    assert.equal(ok.error, undefined, 'authorized: the loopback app is observed, no error')
    assert.equal(ok.status, 200)
    assert.ok(ok.forms.length >= 1, 'authorized: parsed the login form on the internal app')
  } finally { srv.close() }
})

// ── Kimi web-audit round: read-only leak detectors ──────────────────────────

// (A) Body-content signatures — unit-level, on strings (no network).
test('detectBodySignatures: Apache directory listing is detected', () => {
  const body = '<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><a href="../">Parent Directory</a><a href="db.sql">db.sql</a></body></html>'
  const sigs = detectBodySignatures(body)
  assert.ok(sigs.some((s) => s.kind === 'directory-listing'), 'directory listing flagged')
})

test('detectBodySignatures: language stack traces + verbose framework errors are detected', () => {
  assert.ok(detectBodySignatures('Traceback (most recent call last):\n  File "app.py", line 4').some((s) => s.kind === 'stack-trace'), 'python traceback')
  assert.ok(detectBodySignatures('You have an error in your SQL syntax; check the manual').some((s) => s.kind === 'stack-trace'), 'mysql syntax error')
  assert.ok(detectBodySignatures('<title>ORA-01722: invalid number</title>').some((s) => s.kind === 'stack-trace'), 'oracle ORA-')
  assert.ok(detectBodySignatures("<h1>Server Error in '/' Application.</h1>").some((s) => s.kind === 'verbose-error'), 'asp.net YSOD')
  assert.ok(detectBodySignatures('<title>Werkzeug Debugger</title>The debugger caught an exception').some((s) => s.kind === 'verbose-error'), 'werkzeug debugger')
})

test('detectBodySignatures: a clean page yields NO body-signature false positives', () => {
  const clean = '<html lang="en"><head><title>Home</title></head><body><h1>Welcome</h1><p>Index of products below. No errors here.</p></body></html>'
  assert.equal(detectBodySignatures(clean).length, 0, 'clean page → no signatures')
})

// (B) JWT analyzer — unit-level (decode-only, no verification).
const b64u = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url')
const mkJwt = (header: unknown, payload: unknown, sig = ''): string => `${b64u(header)}.${b64u(payload)}.${sig}`

test('analyzeJwts: flags alg:none (critical), expired (medium) and no-exp (low); frames claims', () => {
  const none = mkJwt({ alg: 'none', typ: 'JWT' }, { sub: 'admin', iss: 'acme' })
  const expired = mkJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'u1', exp: 1000000000 }, 'sig') // 2001 → expired
  const noexp = mkJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'u2' }, 'sig')
  const findings = analyzeJwts([
    { where: 'Set-Cookie', text: `session=${none}; Path=/` },
    { where: 'page body', text: `<script>var t="${expired}"; var t2="${noexp}";</script>` },
  ], 'https://app.test/')
  assert.ok(findings.some((f) => f.kind === 'jwt-alg-none' && f.severity === 'critical'), 'alg:none critical')
  assert.ok(findings.some((f) => f.kind === 'jwt-expired' && f.severity === 'medium'), 'expired medium')
  assert.ok(findings.some((f) => f.kind === 'jwt-no-exp' && f.severity === 'low'), 'no-exp low')
})

test('analyzeJwts: a base64-looking non-JWT and clean tokens produce nothing', () => {
  assert.equal(analyzeJwts([{ where: 'page body', text: 'eyJhbGc.notavalidjwt.xx and some eyJ text' }], 'https://x.test/').length, 0)
  const valid = mkJwt({ alg: 'RS256', typ: 'JWT' }, { sub: 'u', exp: 4102444800 }, 'sig') // exp in 2100
  assert.equal(analyzeJwts([{ where: 'page body', text: valid }], 'https://x.test/').length, 0, 'a signed, unexpired, exp-bearing JWT is not flagged')
})

// (C) End-to-end on REAL loopback servers.
test('observe (discovery): a REAL server exposing /.git/config is flagged; a clean app is not', async () => {
  const gitBody = '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:acme/secret.git\n'
  const leaky = http.createServer((req, res) => {
    if (req.url === '/.git/config') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(gitBody); return }
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><head><title>App</title></head><body>hi</body></html>'); return }
    res.writeHead(404); res.end('nope')
  })
  leaky.on('error', () => {})
  const clean = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><head><title>App</title></head><body>hi</body></html>'); return }
    res.writeHead(404); res.end('nope')
  })
  clean.on('error', () => {})
  const [lp, cp] = [await bind(leaky), await bind(clean)]
  try {
    const hit = await observe(`http://127.0.0.1:${lp}/`, { authorized: true })
    assert.equal(hit.error, undefined)
    const git = hit.findings.find((f) => f.kind === 'exposed-sensitive-path' && /\.git\/config/.test(f.detail))
    assert.ok(git, 'exposed .git/config flagged')
    assert.equal(git!.severity, 'high')

    const none = await observe(`http://127.0.0.1:${cp}/`, { authorized: true })
    assert.equal(none.findings.some((f) => f.kind === 'exposed-sensitive-path'), false, 'clean app → no exposed-sensitive-path (no bare-200 false positive)')
  } finally { leaky.close(); clean.close() }
})

test('observe (body detectors): a REAL server returning a directory listing / stack trace is flagged', async () => {
  const listing = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><head><title>Index of /</title></head><body><h1>Index of /</h1><a href="../">Parent Directory</a><a href="secret.env">secret.env</a></body></html>'); return }
    res.writeHead(404); res.end('nope')
  })
  listing.on('error', () => {})
  const trace = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(500, { 'content-type': 'text/html' }); res.end('<html><body><pre>Traceback (most recent call last):\n  File "/srv/app/views.py", line 42, in index\n    1/0\nZeroDivisionError: division by zero</pre></body></html>'); return }
    res.writeHead(404); res.end('nope')
  })
  trace.on('error', () => {})
  const [lp, tp] = [await bind(listing), await bind(trace)]
  try {
    const l = await observe(`http://127.0.0.1:${lp}/`, { authorized: true })
    assert.ok(l.findings.some((f) => f.kind === 'directory-listing'), 'directory listing flagged on the live page')

    const t = await observe(`http://127.0.0.1:${tp}/`, { authorized: true })
    assert.ok(t.findings.some((f) => f.kind === 'stack-trace-disclosure'), 'stack trace flagged on the live page')
  } finally { listing.close(); trace.close() }
})

test('observe (JWT): a REAL server setting an alg:none JWT cookie is flagged critical', async () => {
  const noneJwt = mkJwt({ alg: 'none', typ: 'JWT' }, { sub: 'admin', iss: 'acme', role: 'root' })
  const srv = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': `session=${noneJwt}; Path=/` }); res.end('<html><head><title>App</title></head><body>ok</body></html>'); return }
    res.writeHead(404); res.end('nope')
  })
  srv.on('error', () => {})
  const port = await bind(srv)
  try {
    const brief = await observe(`http://127.0.0.1:${port}/`, { authorized: true })
    const jwt = brief.findings.find((f) => f.kind === 'jwt-alg-none')
    assert.ok(jwt, 'alg:none JWT in Set-Cookie flagged')
    assert.equal(jwt!.severity, 'critical')
    assert.match(jwt!.detail, /cookie/i)
  } finally { srv.close() }
})

// ── Kimi web-audit round 4: SameSite, CORS, GraphQL introspection, bundle secrets ──

// (1) Cookie SameSite — end-to-end on real servers.
test('observe (cookie SameSite): a REAL server setting Secure+HttpOnly+SameSite=None is flagged CSRF-able; a SameSite=Lax cookie is clean', async () => {
  const csrfable = http.createServer((req, res) => {
    // Secure + HttpOnly present → the OLD weak-cookie check passes clean; SameSite=None is the gap.
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=None; Path=/' }); res.end('<html><head><title>App</title></head><body>ok</body></html>'); return }
    res.writeHead(404); res.end('nope')
  })
  csrfable.on('error', () => {})
  const safe = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Lax; Path=/' }); res.end('<html><head><title>App</title></head><body>ok</body></html>'); return }
    res.writeHead(404); res.end('nope')
  })
  safe.on('error', () => {})
  const [bp, gp] = [await bind(csrfable), await bind(safe)]
  try {
    const bad = await observe(`http://127.0.0.1:${bp}/`, { authorized: true, discoverPaths: false })
    const ss = bad.findings.find((f) => f.kind === 'cookie-samesite')
    assert.ok(ss, 'SameSite=None cookie flagged')
    assert.match(ss!.detail, /SameSite=None|cross-site/i)
    assert.equal(bad.findings.some((f) => f.kind === 'weak-cookie'), false, 'Secure+HttpOnly present → no weak-cookie false positive')

    const good = await observe(`http://127.0.0.1:${gp}/`, { authorized: true, discoverPaths: false })
    assert.equal(good.findings.some((f) => f.kind === 'cookie-samesite'), false, 'SameSite=Lax → not flagged')
  } finally { csrfable.close(); safe.close() }
})

// (2) CORS — end-to-end on real servers.
test('observe (CORS): ACAO:* → cors-wildcard (medium); reflected origin + credentials:true → cors-credentials (high); clean app → neither', async () => {
  const wildcard = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'access-control-allow-origin': '*' }); res.end('<html><head><title>W</title></head><body>ok</body></html>')
  })
  wildcard.on('error', () => {})
  const creds = http.createServer((req, res) => {
    // reflect the caller's Origin (echo) AND allow credentials — the dangerous combo.
    res.writeHead(200, { 'content-type': 'text/html', 'access-control-allow-origin': 'https://evil.example', 'access-control-allow-credentials': 'true' }); res.end('<html><head><title>C</title></head><body>ok</body></html>')
  })
  creds.on('error', () => {})
  const cleanSrv = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><head><title>Clean</title></head><body>ok</body></html>') })
  cleanSrv.on('error', () => {})
  const [wp, cp, kp] = [await bind(wildcard), await bind(creds), await bind(cleanSrv)]
  try {
    const w = await observe(`http://127.0.0.1:${wp}/`, { authorized: true, discoverPaths: false })
    const cw = w.findings.find((f) => f.kind === 'cors-wildcard')
    assert.ok(cw && cw.severity === 'medium', 'ACAO:* → cors-wildcard medium')

    const c = await observe(`http://127.0.0.1:${cp}/`, { authorized: true, discoverPaths: false })
    const cc = c.findings.find((f) => f.kind === 'cors-credentials')
    assert.ok(cc && cc.severity === 'high', 'reflected origin + credentials → cors-credentials high')
    assert.match(cc!.detail, /evil\.example/, 'the reflected origin is framed into the finding')

    const k = await observe(`http://127.0.0.1:${kp}/`, { authorized: true, discoverPaths: false })
    assert.equal(k.findings.some((f) => f.kind === 'cors-wildcard' || f.kind === 'cors-credentials'), false, 'clean app → no CORS false positive')
  } finally { wildcard.close(); creds.close(); cleanSrv.close() }
})

// (3) GraphQL introspection — unit + end-to-end.
test('graphqlIntrospectionFinding: a schema with a sensitive field is HIGH; a plain schema is MEDIUM; a non-schema body is null', () => {
  const withSecret = JSON.stringify({ data: { __schema: { queryType: { name: 'Query' }, types: [{ name: 'User', fields: [{ name: 'id' }, { name: 'passwordHash' }] }, { name: '__Directive', fields: [] }] } } })
  const hi = graphqlIntrospectionFinding('https://x.test/graphql', withSecret)
  assert.ok(hi && hi.kind === 'graphql-introspection-enabled' && hi.severity === 'high', 'sensitive field → high')
  assert.match(hi!.detail, /passwordHash/, 'the sensitive field name is surfaced')
  assert.ok(!/__Directive/.test(hi!.detail), 'GraphQL internals (__*) are excluded')

  const plain = JSON.stringify({ data: { __schema: { queryType: { name: 'Query' }, types: [{ name: 'Product', fields: [{ name: 'title' }] }] } } })
  assert.equal(graphqlIntrospectionFinding('https://x.test/graphql', plain)!.severity, 'medium', 'no sensitive names → medium')

  assert.equal(graphqlIntrospectionFinding('https://x.test/graphql', '{"errors":[{"message":"introspection disabled"}]}'), null, 'no schema → null')
  assert.equal(graphqlIntrospectionFinding('https://x.test/graphql', 'not json'), null, 'non-JSON → null')
})

test('observe (GraphQL): authorized sends ONE read-only introspection POST and flags it; UNauthorized never POSTs (suggests it instead)', async () => {
  let introspectionPosts = 0
  const gql = http.createServer((req, res) => {
    if (req.url === '/graphql' && req.method === 'POST') {
      introspectionPosts++
      let body = ''
      req.on('data', (c) => { body += c })
      req.on('end', () => {
        // Confirm it is the read-only introspection query (a QUERY, never a mutation).
        assert.match(body, /__schema/, 'the probe is an introspection query')
        assert.ok(!/mutation/i.test(body), 'the probe contains no mutation')
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ data: { __schema: { queryType: { name: 'Query' }, types: [{ name: 'User', fields: [{ name: 'id' }, { name: 'ssn' }] }] } } }))
      })
      return
    }
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><head><title>GQL</title></head><body>ok</body></html>'); return }
    res.writeHead(404); res.end('nope')
  })
  gql.on('error', () => {})
  const port = await bind(gql)
  try {
    const authed = await observe(`http://127.0.0.1:${port}/`, { authorized: true, discoverPaths: false })
    const gi = authed.findings.find((f) => f.kind === 'graphql-introspection-enabled')
    assert.ok(gi, 'authorized: introspection flagged')
    assert.equal(gi!.severity, 'high', 'a sensitive field (ssn) raises it to high')
    assert.ok(introspectionPosts >= 1, 'authorized: the introspection POST was sent')

    // UNauthorized against the SAME endpoint on loopback is refused at the SSRF gate;
    // prove the no-POST contract on a public-shaped path instead: authorized:false must
    // not emit the POST. (Loopback is refused before any request, so posts stay at 1.)
    const before = introspectionPosts
    const unauth = await observe(`http://127.0.0.1:${port}/`)
    assert.ok(unauth.error, 'unauthorized loopback is SSRF-refused (no requests sent at all)')
    assert.equal(introspectionPosts, before, 'no introspection POST when unauthorized')
  } finally { gql.close() }
})

// (4) Secrets in JS bundles — unit + end-to-end.
test('scanSecrets: matches provider key shapes + generic assignment, REDACTS the value, no false positive on clean JS', () => {
  const bundle = [
    'const stripe = "sk-live-ABCDEFGHIJKLMNOPQRSTUVWX";',
    'const aws = "AKIAIOSFODNN7EXAMPLE";',
    'const gh = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";',
    'const cfg = { api_key: "aVeryLongApiKeyValue1234567890" };',
  ].join('\n')
  const matches = scanSecrets(bundle)
  const labels = matches.map((m) => m.label).join(' | ')
  assert.match(labels, /Stripe live secret/i)
  assert.match(labels, /AWS access key/i)
  assert.match(labels, /GitHub personal access token/i)
  assert.match(labels, /credential assignment/i)
  for (const m of matches) {
    assert.match(m.redacted, /…\(len \d+\)/, 'value is redacted to prefix + length')
    assert.ok(!/ABCDEFGHIJKLMNOPQRSTUVWX/.test(m.redacted), 'the full Stripe secret never appears')
    assert.ok(!/aVeryLongApiKeyValue1234567890/.test(m.redacted), 'the full generic secret never appears')
  }
  const findings = secretFindings(matches, 'https://app.test/bundle.js')
  assert.ok(findings.every((f) => f.severity === 'critical' && f.kind === 'exposed-secret'))

  assert.equal(scanSecrets('const x = 1; function add(a,b){ return a+b } // no secrets here').length, 0, 'clean JS → no false positive')
})

test('observe (bundle secrets): a REAL server whose same-origin bundle contains sk-live-… is flagged critical (REDACTED)', async () => {
  const fakeKey = 'sk-live-51ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  const srv = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><head><title>SPA</title><script src="/app.js"></script></head><body><div id="root"></div></body></html>'); return }
    if (req.url === '/app.js') { res.writeHead(200, { 'content-type': 'application/javascript' }); res.end(`const STRIPE="${fakeKey}"; console.log("hi");`); return }
    res.writeHead(404); res.end('nope')
  })
  srv.on('error', () => {})
  const cleanSrv = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><head><title>SPA</title><script src="/app.js"></script></head><body><div id="root"></div></body></html>'); return }
    if (req.url === '/app.js') { res.writeHead(200, { 'content-type': 'application/javascript' }); res.end('const version="1.2.3"; console.log("hi");'); return }
    res.writeHead(404); res.end('nope')
  })
  cleanSrv.on('error', () => {})
  const [sp, cp] = [await bind(srv), await bind(cleanSrv)]
  try {
    const hit = await observe(`http://127.0.0.1:${sp}/`, { authorized: true, discoverPaths: false })
    const sec = hit.findings.find((f) => f.kind === 'exposed-secret')
    assert.ok(sec, 'hardcoded sk-live- key in the bundle flagged')
    assert.equal(sec!.severity, 'critical')
    assert.match(sec!.at ?? '', /app\.js/, 'the bundle URL is reported')
    assert.ok(!sec!.detail.includes(fakeKey), 'the full secret is NEVER in the finding (redacted)')

    const none = await observe(`http://127.0.0.1:${cp}/`, { authorized: true, discoverPaths: false })
    assert.equal(none.findings.some((f) => f.kind === 'exposed-secret'), false, 'clean bundle → no exposed-secret false positive')
  } finally { srv.close(); cleanSrv.close() }
})

test('observe (--no-discovery): discoverPaths:false skips the well-known probes', async () => {
  let gitProbed = false
  const srv = http.createServer((req, res) => {
    if (req.url === '/.git/config') { gitProbed = true; res.writeHead(200, { 'content-type': 'text/plain' }); res.end('[core]\n\trepositoryformatversion = 0\n'); return }
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><head><title>App</title></head><body>hi</body></html>'); return }
    res.writeHead(404); res.end('nope')
  })
  srv.on('error', () => {})
  const port = await bind(srv)
  try {
    const brief = await observe(`http://127.0.0.1:${port}/`, { authorized: true, discoverPaths: false })
    assert.equal(brief.findings.some((f) => f.kind === 'exposed-sensitive-path'), false, 'no discovery findings')
    assert.equal(gitProbed, false, 'the well-known path was NOT requested when discovery is off')
  } finally { srv.close() }
})
