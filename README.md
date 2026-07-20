# @dir-ai/voyager-browser

**Voyager's web-page sense.** A safe, **read-only** observation of one live URL:
its structure, forms, links, script origins, **security posture** (HTTPS / HSTS /
CSP / mixed-content / cookies) and **accessibility signals** (lang, image alt
coverage, heading order) — each with a *described, never applied* fix.

It parses **static HTML** — **no JavaScript execution, no headless browser** — so
it's honest about what it can and cannot see (it will not render a client-side
SPA's runtime state). Every piece of page text is returned **framed as
untrusted**. It is **SSRF-gated**: it refuses non-`http(s)` URLs and anything
resolving to private, loopback, or cloud-metadata addresses.

> One sense in the [Voyager family](#the-voyager-family). Read-only, like all the
> senses — it never submits a form, clicks, or mutates anything.

## Install

```bash
npm i -g @dir-ai/voyager-browser
```

## Use

```bash
voyager-browser observe https://example.com
voyager-browser observe https://example.com --json
```

```
https://example.com/
https://example.com — 200; 3 finding(s), worst: medium. 0 form(s), 1 link(s).

  title: Example Domain
  security: https  ·  a11y lang:yes alt:n/a

  med   HTTPS without HSTS
        ↳ add Strict-Transport-Security: max-age=63072000; includeSubDomains
  med   no Content-Security-Policy
        ↳ add a Content-Security-Policy to constrain scripts/resources
  low   no X-Content-Type-Options: nosniff
        ↳ add X-Content-Type-Options: nosniff
```

## As an MCP server

One tool, `observe_page`.

```json
{ "command": "voyager-browser", "args": ["mcp"] }
```

## As a library

```ts
import { observe } from '@dir-ai/voyager-browser'

const brief = await observe('https://example.com')
console.log(brief.summary)
console.log(brief.security)   // { https, hsts, csp, mixedContent, thirdPartyScripts, … }
console.log(brief.forms)      // insecure / cross-origin / sensitive flags
console.log(brief.findings)   // severity + described fix
```

## What it looks for

- **Security posture (quality, not just presence)** — plain HTTP; missing/**weak** HSTS; missing CSP or a CSP graded weak (`unsafe-inline`/`unsafe-eval`/wildcard/no `object-src`/no `base-uri`); missing clickjacking protection (X-Frame-Options / `frame-ancestors`); missing `nosniff`, Referrer-Policy, Permissions-Policy; version-leaking `Server`/`X-Powered-By`; mixed content on an HTTPS page (origin-compared, not prefix); **per-cookie** Secure/HttpOnly; third-party scripts without **Subresource Integrity**.
- **Forms** — a form on HTTPS posting to plain HTTP (`critical`); a sensitive form (password/payment) posting cross-origin or over HTTP; a sensitive `POST` with no anti-CSRF token; sensitive data on `GET`.
- **Links** — external `target="_blank"` without `rel="noopener"` (reverse-tabnabbing).
- **Body-content leaks** — directory listings (Apache/nginx autoindex), language-specific **stack traces** (Python/Java/PHP/Node/Oracle/SQLSTATE/MySQL) and **verbose framework debug pages** (Werkzeug/Flask, Rails, Symfony/Whoops, ASP.NET YSOD) disclosed in the response body — each with the matched signature (framed).
- **Exposed JWTs** — JWT-shaped tokens found in the HTML, response headers, `Set-Cookie`, and same-origin bundles are **decoded** (header+payload, base64url, **no signature verification, no secret cracking**) and flagged for `alg:none` (`critical`), expired (`exp` in the past), or missing `exp`. Claim values are framed as untrusted.
- **Passive discovery of well-known sensitive paths** — bounded, same-origin, read-only `GET`s to a **short fixed list** (`/.git/config`, `/.env`, `/.svn/entries`, `/.DS_Store`, `/config.json`, `/wp-config.php~`, `/backup/`, `/uploads/`), flagging only a **confirmed body signature** — never a bare `200`. Pinned to the vetted IP; honours `--authorized`. Disable with `--no-discovery`.
- **Accessibility** — missing `<html lang>`, images without `alt`, skipped heading levels, unlabeled form fields.
- **Render honesty** — a `render: static | hybrid | client-heavy` field: if a page's content is JavaScript-rendered, the brief says so and marks itself PARTIAL rather than reporting a shell as clean.
- **Composition hints** — third-party script origins to vet with `@dir-ai/voyager` / `@dir-ai/voyager-net`.

## Safety

- **Read-only.** Fetches the page with a single GET; never submits, clicks, or mutates.
- **No code execution.** Static HTML parsing only — the page's JavaScript is never run.
- **SSRF-gated, with IP pinning.** Only `http(s)`; a single URL (no lists/credentials). The host is resolved, every address is classified canonically (IPv4-mapped IPv6, unspecified, CGNAT, NAT64, link-local, private, loopback, metadata all refused), and the connection is **pinned to the vetted IP** so DNS rebinding cannot swap in an internal address between the check and the fetch. **Every redirect hop is re-vetted and re-pinned.**
- **Untrusted by construction.** Every owner-controlled string that reaches the brief — title, headings, meta, links, form actions, field names — is injection-stripped and framed; the agent must treat it as data, not instructions.
- **Bounded.** One deadline covers headers **and** body; the body is byte-capped; a truncated read downgrades confidence and is never reported as "clean".
- **Honest limits.** It reads what the server sends. It does not see client-rendered state — and the `render` field says exactly how much it saw.

## Roadmap

- **v0.3** — same-origin JS-bundle static scan (exposed secrets/endpoints/source-maps), third-party/tracker/cookie inventory + tech fingerprinting, WCAG-mapped a11y depth, and a `CognitiveClaim` adapter so a page observation drops into a `@dir-ai/voyager-agent` mission (page → host → dependency chain).
- **v1.0** — an opt-in, consent-gated `--render` sandboxed headless pass (network-isolated, resource-capped) for true SPA/rendered-DOM coverage, always labeled as render-mode output; a stable finding-`kind` taxonomy and a full posture score.

The line stays fixed: voyager-browser expands by **reading more of what's already served**, never by *doing more to the server*. Anything active (submitting, fuzzing, probing) belongs to a separate consent-gated organ.

## The Voyager family

| Package | Sense |
| --- | --- |
| [`@dir-ai/voyager`](https://www.npmjs.com/package/@dir-ai/voyager) | web — verified-internet retrieval |
| **`@dir-ai/voyager-browser`** | **web page — observe one live URL** |
| [`@dir-ai/voyager-repo`](https://www.npmjs.com/package/@dir-ai/voyager-repo) | code — orient in a repository |
| [`@dir-ai/voyager-net`](https://www.npmjs.com/package/@dir-ai/voyager-net) | hosts — authorized host audit |
| [`@dir-ai/voyager-contract`](https://www.npmjs.com/package/@dir-ai/voyager-contract) | the cognitive contract the senses speak |
| [`@dir-ai/voyager-agent`](https://www.npmjs.com/package/@dir-ai/voyager-agent) | the one agent that composes them |

## License

MIT © dir-ai
