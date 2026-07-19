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

- **Security** — plain HTTP, missing HSTS / CSP / `nosniff`, mixed content on an HTTPS page, insecure cookies.
- **Forms** — a form on HTTPS posting to plain HTTP (`critical`), a sensitive form (password/payment) posting cross-origin or over HTTP.
- **Links** — external `target="_blank"` without `rel="noopener"` (reverse-tabnabbing).
- **Accessibility** — missing `<html lang>`, images without `alt`, skipped heading levels, unlabeled form fields.
- **Composition hints** — third-party script origins to vet with `@dir-ai/voyager` / `@dir-ai/voyager-net`.

## Safety

- **Read-only.** Fetches the page with a single GET; never submits, clicks, or mutates.
- **No code execution.** Static HTML parsing only — the page's JavaScript is never run.
- **SSRF-gated.** Only `http(s)`; a single URL (no lists/credentials); the resolved IP is screened, and **every redirect hop is re-vetted** — a redirect to a private/metadata address is refused.
- **Untrusted by construction.** All page text is injection-stripped and framed; the agent must treat it as data, not instructions.
- **Honest limits.** It reads what the server sends. It does not see client-rendered state, and it says so.

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
