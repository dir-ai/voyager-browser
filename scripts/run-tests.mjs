// Deterministic, cross-platform test entry: import every compiled test in
// dist-test so node:test (net organ) collects them — no shell globs (cmd.exe can't expand
// them) and no auto-discovery of the TypeScript sources (Node ≥24 would try to
// run test/*.ts directly and fail to resolve the sibling .js imports).
import { readdirSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist-test')
for (const f of readdirSync(dir)) {
  if (f.endsWith('.test.js')) await import(pathToFileURL(join(dir, f)).href)
}
