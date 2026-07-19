#!/usr/bin/env node
/**
 * voyager-browser CLI. Observe ONE live web page, read-only.
 *   voyager-browser observe https://example.com
 *   voyager-browser observe https://example.com --json
 */
import { observe } from './observe.js'
import { VERSION } from './version.js'

const SEV: Record<string, string> = { critical: '\x1b[41m crit \x1b[0m', high: '\x1b[31mhigh\x1b[0m', medium: '\x1b[33mmed \x1b[0m', low: '\x1b[36mlow \x1b[0m', info: '\x1b[2minfo\x1b[0m' }

const HELP = `voyager-browser v${VERSION} — Voyager's web-page sense (read-only)

USAGE
  voyager-browser observe <url> [--json] [--timeout <ms>] [--max-bytes <n>]
        Observe ONE live page: structure, forms, links, security posture
        (CSP/HSTS/mixed-content) and accessibility signals → findings with
        DESCRIBED (never applied) fixes.

  voyager-browser mcp
        Run as an MCP server (stdio) exposing one tool: observe_page.

  voyager-browser help | --version

Static HTML only — no JavaScript execution, no headless browser. All page text
is framed as untrusted. Refuses non-http(s) URLs and anything resolving to
private/loopback/cloud-metadata addresses (SSRF-gated). Read-only: it never
submits a form, clicks, or mutates anything.`

function parseArgs(argv: string[]): { flags: Record<string, string | boolean>; positionals: string[] } {
  const boolean = new Set(['json'])
  const flags: Record<string, string | boolean> = {}
  const positionals: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const key = a.slice(2)
      const next = argv[i + 1]
      if (!boolean.has(key) && next !== undefined && !next.startsWith('--')) { flags[key] = next; i++ }
      else flags[key] = true
    } else positionals.push(a)
  }
  return { flags, positionals }
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2)
  if (cmd === '--version' || cmd === 'version') { console.log(VERSION); return 0 }
  if (cmd === 'mcp') {
    const { startMcpServer } = await import('./mcp.js')
    await startMcpServer()
    return new Promise<number>(() => {}) // stdio server runs until the transport closes
  }
  if (cmd !== 'observe') { console.log(HELP); return 0 }

  const { flags, positionals } = parseArgs(rest)
  const url = positionals[0]
  if (!url) { console.error('observe needs a URL'); return 2 }
  const json = flags.json === true

  const brief = await observe(url, {
    timeoutMs: typeof flags.timeout === 'string' ? Number(flags.timeout) || undefined : undefined,
    maxBytes: typeof flags['max-bytes'] === 'string' ? Number(flags['max-bytes']) || undefined : undefined,
    onLog: (l) => { if (!json) console.error(`  · ${l}`) },
  })

  if (json) { console.log(JSON.stringify(brief, null, 2)); return brief.error ? 2 : brief.findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 1 : 0 }

  if (brief.error) { console.error(`\x1b[31m✗\x1b[0m ${brief.error}`); return 2 }
  console.log(`\n\x1b[1m${brief.target.url}\x1b[0m`)
  console.log(`\x1b[2m${brief.summary}\x1b[0m\n`)
  if (brief.structure?.title) console.log(`  title: ${brief.structure.title.text}`)
  console.log(`  security: ${brief.security?.https ? 'https' : 'HTTP'}${brief.security?.hsts ? ' +hsts' : ''}${brief.security?.csp ? ' +csp' : ''}  ·  a11y lang:${brief.a11y.lang ? 'yes' : 'no'} alt:${brief.a11y.imgAltCoverage ?? 'n/a'}`)
  if (brief.findings.length) {
    console.log('')
    for (const f of brief.findings) console.log(`  ${SEV[f.severity] ?? f.severity}  ${f.detail}\n        \x1b[2m↳ ${f.suggestedFix}\x1b[0m`)
  }
  if (brief.suggestedNextProbes.length) { console.log('\n  \x1b[1mnext probes:\x1b[0m'); for (const p of brief.suggestedNextProbes) console.log(`    · ${p}`) }
  console.log('')
  return brief.findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 1 : 0
}

main().then((c) => process.exit(c)).catch((e) => { console.error(e instanceof Error ? (e.stack ?? e.message) : String(e)); process.exit(2) })
