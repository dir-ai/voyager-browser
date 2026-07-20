import { safeGet } from './fetch.js'
import { clean } from './html.js'
import { detectBodySignatures, bodySignatureFindings } from './detect.js'
import type { PageFinding } from './types.js'

/**
 * PASSIVE DISCOVERY of well-known sensitive paths. After the page is observed, do
 * bounded SAME-ORIGIN GETs to a SHORT, high-signal fixed list and flag ONLY a
 * CONFIRMED signature — never a bare 200. Read-only: a GET can never mutate. Each
 * request is pinned to the page's already-vetted IP (SSRF-safe), honours the
 * `allowPrivate` posture (so an authorized internal audit works), is same-origin
 * only, and is bounded by a small body cap + the shared timeout.
 */

interface Hit {
  signature: string
  severity: PageFinding['severity']
  detail: string
}
interface Probe {
  path: string
  fix: string
  confirm: (body: string) => Hit | null
}

// ── Confirmations (a bare 200 is NEVER a hit — the body must match) ──────────
function envHit(body: string): Hit | null {
  const secretKey = /(SECRET|PASSWORD|PASSWD|API[_-]?KEY|APIKEY|TOKEN|PRIVATE[_-]?KEY|AWS_|DB_|DATABASE_URL|ACCESS[_-]?KEY|CLIENT_SECRET)/i
  const kv = /^\s*(?:export\s+)?[A-Z0-9_]{2,40}\s*=/
  let hits = 0
  let sample = ''
  for (const line of body.split(/\r?\n/).slice(0, 300)) {
    if (kv.test(line) && secretKey.test(line)) {
      hits++
      if (!sample) sample = line.split('=')[0].replace(/^\s*export\s+/, '').trim()
    }
  }
  return hits ? { signature: `${hits} secret-ish KEY=VALUE line(s) (e.g. ${clean(sample, 40)}=…)`, severity: 'high', detail: 'exposed .env — application secrets/credentials are downloadable' } : null
}

function svnHit(body: string): Hit | null {
  const first = body.split(/\r?\n/)[0]?.trim() ?? ''
  if (/^\d+$/.test(first) && /(^|\n)dir(\r?\n|$)|svn:|has-props/.test(body)) {
    return { signature: `SVN entries (format ${first})`, severity: 'high', detail: 'exposed .svn/entries — the repository source/history is recoverable' }
  }
  return null
}

function collectKeys(obj: unknown, out: string[], depth = 0): void {
  if (depth > 4 || out.length > 200 || !obj || typeof obj !== 'object') return
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    out.push(k)
    if (v && typeof v === 'object') collectKeys(v, out, depth + 1)
  }
}
function configJsonHit(body: string): Hit | null {
  if (body.length > 200_000) return null
  let obj: unknown
  try {
    obj = JSON.parse(body)
  } catch {
    return null
  }
  if (!obj || typeof obj !== 'object') return null
  const keys: string[] = []
  collectKeys(obj, keys)
  const secret = keys.find((k) => /(password|passwd|secret|api[_-]?key|apikey|token|private[_-]?key|access[_-]?key|connection[_-]?string|db[_-]?pass|credential)/i.test(k))
  return secret ? { signature: `JSON config exposing a secret-ish key "${clean(secret, 40)}"`, severity: 'high', detail: 'exposed config.json contains secret-looking keys' } : null
}

function dirListHit(body: string): Hit | null {
  const dl = detectBodySignatures(body).find((s) => s.kind === 'directory-listing')
  return dl ? { signature: dl.signature, severity: 'medium', detail: 'directory listing is enabled — files are browsable' } : null
}

const PROBES: Probe[] = [
  {
    path: '/.git/config',
    fix: 'block dotfiles/.git at the web server; never deploy the .git directory into the web root',
    confirm: (b) => (/\[core\]/.test(b) && /repositoryformatversion/i.test(b) ? { signature: '[core] + repositoryformatversion', severity: 'high', detail: 'exposed .git/config — the full repository (source + history) is downloadable' } : null),
  },
  { path: '/.env', fix: 'move .env outside the web root and block dotfiles; rotate every exposed secret', confirm: envHit },
  { path: '/.svn/entries', fix: 'block .svn at the web server; never deploy VCS metadata into the web root', confirm: svnHit },
  {
    path: '/.DS_Store',
    fix: 'block .DS_Store at the web server and stop committing it (it leaks the directory tree)',
    confirm: (b) => (/\bBud1\b/.test(b.slice(0, 64)) ? { signature: 'DS_Store "Bud1" magic', severity: 'medium', detail: 'exposed .DS_Store — leaks the directory/file listing' } : null),
  },
  { path: '/config.json', fix: 'never serve config with secrets from the web root; load config from env/secret store', confirm: configJsonHit },
  {
    path: '/wp-config.php~',
    fix: 'remove editor backup files (*~, *.bak, *.save) from the web root and block them; rotate DB creds',
    confirm: (b) => ((/DB_PASSWORD|DB_NAME|DB_USER/.test(b) && /<\?php|define\s*\(/.test(b)) ? { signature: 'wp-config backup with DB_* defines', severity: 'high', detail: 'exposed wp-config backup — database credentials/salts are in the raw PHP source' } : null),
  },
  { path: '/backup/', fix: 'disable directory indexing and keep backups out of the web root', confirm: dirListHit },
  { path: '/uploads/', fix: 'disable directory indexing on the uploads directory', confirm: dirListHit },
]

export interface DiscoverOptions {
  timeoutMs: number
  allowPrivate: boolean
  onLog?: (line: string) => void
}

/**
 * Probe the well-known paths against `origin`, pinned to `pinnedIp`. Returns a
 * finding per CONFIRMED hit, plus any stack-trace/verbose-error the probe response
 * itself disclosed. Never throws — a path that won't fetch is simply skipped.
 */
export async function discoverWellKnown(origin: string, pinnedIp: string, opts: DiscoverOptions): Promise<PageFinding[]> {
  const findings: PageFinding[] = []
  const log = opts.onLog ?? (() => {})
  for (const probe of PROBES) {
    let url: string
    try {
      url = new URL(probe.path, origin).toString()
    } catch {
      continue
    }
    log(`probing ${probe.path}…`)
    try {
      const res = await safeGet(url, { pinnedIp, timeoutMs: opts.timeoutMs, maxBytes: 65_536, allowPrivate: opts.allowPrivate })
      if (res.status < 200 || res.status >= 300) continue
      const hit = probe.confirm(res.body)
      if (hit) {
        findings.push({ severity: hit.severity, kind: 'exposed-sensitive-path', detail: `${probe.path} — ${hit.detail} (signature: ${clean(hit.signature, 120)})`, at: url, suggestedFix: probe.fix, confidence: 'strong' })
      }
      // A well-known response can ALSO disclose a stack trace / verbose error.
      for (const bf of bodySignatureFindings(detectBodySignatures(res.body).filter((s) => s.kind !== 'directory-listing'), url)) findings.push(bf)
    } catch {
      /* a path that won't fetch is skipped — the rest still run */
    }
  }
  return findings
}
