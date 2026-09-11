/**
 * Local read-only data bridge for the MicroAPI Guard console.
 *
 * The gateway publishes exactly three admin endpoints (/__guard/health,
 * /__guard/stats, /__guard/reload) and proxies everything else to the backend.
 * It does NOT serve the event log or the model artefacts over HTTP, and this
 * project must not grow a backend endpoint just to feed a dashboard.
 *
 * So the Vite dev/preview server - which is frontend tooling, not part of the
 * deployed gateway - reads those files straight off disk and exposes them under
 * /__dash/*. Nothing here writes, and nothing here invents a value: every field
 * returned is either a line from src/data/events.jsonl, a key from
 * src/ml_pipeline/models/*.json, or a literal parsed out of src/common/*.py.
 */
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import path from 'node:path'
import type { Connect, Plugin, PreviewServer, ViteDevServer } from 'vite'

const MAX_READ_BYTES = 12 * 1024 * 1024
const BYTES_PER_EVENT_ESTIMATE = 2_600

export interface MicroapiDataOptions {
  /** Absolute path to the repository's `src/` directory. */
  srcDir: string
}

function json(res: import('node:http').ServerResponse, status: number, body: unknown) {
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('cache-control', 'no-store')
  res.end(JSON.stringify(body))
}

// -- event log ---------------------------------------------------------------

interface TailResult {
  events: unknown[]
  malformed: number
  nextOffset: number
  fileSize: number
  mtimeMs: number
  truncatedRead: boolean
}

/**
 * Read complete JSONL records from `file`.
 *
 * `after >= 0` reads forward from that byte offset (an incremental poll);
 * `after < 0` reads a tail sized for `limit` records. Either way only whole
 * lines are parsed, so a record the gateway is part-way through appending
 * never arrives half-written.
 */
async function readEvents(file: string, limit: number, after: number): Promise<TailResult> {
  const stat = await fsp.stat(file)
  const size = stat.size

  let start: number
  let truncatedRead = false
  // A cursor handed back from a previous call is already a line boundary, so
  // the first line it addresses is a whole record and must be kept. Every
  // other entry point lands at an arbitrary byte and needs its leading
  // fragment discarded. Conflating the two silently drops one record per poll.
  let alignToNextLine: boolean

  if (after >= 0 && after <= size) {
    start = after
    alignToNextLine = false
    if (size - start > MAX_READ_BYTES) {
      start = size - MAX_READ_BYTES
      alignToNextLine = true
      truncatedRead = true
    }
  } else {
    // Either a tail read, or a cursor past the end of a file that was rotated
    // or truncated underneath us. Both start mid-record.
    const want = Math.min(MAX_READ_BYTES, limit * BYTES_PER_EVENT_ESTIMATE)
    start = Math.max(0, size - want)
    alignToNextLine = start > 0
    truncatedRead = start > 0
  }

  if (start >= size) {
    return {
      events: [],
      malformed: 0,
      nextOffset: size,
      fileSize: size,
      mtimeMs: stat.mtimeMs,
      truncatedRead: false,
    }
  }

  const fh = await fsp.open(file, 'r')
  let text: string
  try {
    const buf = Buffer.allocUnsafe(size - start)
    await fh.read(buf, 0, buf.length, start)
    text = buf.toString('utf8')
  } finally {
    await fh.close()
  }

  if (alignToNextLine) {
    const nl = text.indexOf('\n')
    if (nl === -1) {
      return {
        events: [],
        malformed: 0,
        nextOffset: size,
        fileSize: size,
        mtimeMs: stat.mtimeMs,
        truncatedRead,
      }
    }
    start += Buffer.byteLength(text.slice(0, nl + 1), 'utf8')
    text = text.slice(nl + 1)
  }

  const events: unknown[] = []
  let malformed = 0
  let offset = start
  let consumed = start
  let cursor = 0

  while (cursor < text.length) {
    const nl = text.indexOf('\n', cursor)
    if (nl === -1) break // trailing partial line - the writer has not finished it
    const line = text.slice(cursor, nl)
    const lineBytes = Buffer.byteLength(line, 'utf8') + 1
    if (line.trim()) {
      try {
        const rec = JSON.parse(line) as Record<string, unknown>
        rec._offset = offset
        events.push(rec)
      } catch {
        malformed += 1
      }
    }
    offset += lineBytes
    consumed = offset
    cursor = nl + 1
  }

  const trimmed = events.length > limit ? events.slice(events.length - limit) : events
  return {
    events: trimmed,
    malformed,
    nextOffset: consumed,
    fileSize: size,
    mtimeMs: stat.mtimeMs,
    truncatedRead,
  }
}

// -- model artefacts ---------------------------------------------------------

async function readJsonIfPresent(file: string) {
  try {
    return JSON.parse(await fsp.readFile(file, 'utf8'))
  } catch {
    return null
  }
}

// -- source-file parsing (rules + config defaults) ---------------------------

const SEVERITY_TOKENS: Record<string, string> = { BLOCK: 'block', FLAG: 'flag' }
const TARGET_TOKENS: Record<string, string> = { PATH: 'path', BODY: 'body', ANY: 'any' }

/**
 * Extract the Layer-1 signature table from common/rules.py.
 *
 * Every entry is written as `_r("id", "category", SEVERITY, TARGET, r"...",
 * "why")`, so the header is a fixed shape and the human-readable reason is the
 * last quoted string in the call. The regex source itself is deliberately not
 * returned: it is long, unreadable in a table, and publishing it in a browser
 * page tells an attacker exactly what to encode around.
 */
function parseRules(source: string) {
  const header = /_r\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*(BLOCK|FLAG)\s*,\s*(PATH|BODY|ANY)\s*,/g
  const headers = [...source.matchAll(header)]

  // Each rule's body runs from the end of its own header to the start of the
  // next one, so no closing-paren heuristic is needed. That matters: an
  // indexOf("),\n") terminator silently over-reads on a CRLF checkout and
  // attaches the following rule's text to this one.
  const listEnd = source.indexOf('\n]', headers.length ? (headers[headers.length - 1].index ?? 0) : 0)

  return headers.map((m, i) => {
    const from = (m.index ?? 0) + m[0].length
    const next = i + 1 < headers.length ? (headers[i + 1].index ?? source.length) : listEnd === -1 ? source.length : listEnd
    const block = source.slice(from, next)
    // The pattern comes first and the human-readable reason last, so the final
    // string literal in the call is the `why`. Escaped quotes inside a raw
    // pattern are consumed by the \\. alternative rather than ending a match.
    const strings = [...block.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((s) => s[1])
    return {
      id: m[1],
      category: m[2],
      severity: SEVERITY_TOKENS[m[3]],
      target: TARGET_TOKENS[m[4]],
      why: (strings.length ? strings[strings.length - 1] : '').replace(/\\(.)/g, '$1'),
    }
  })
}

/**
 * Extract the env-var defaults from common/config.py.
 *
 * These are the values the gateway falls back to when the environment does not
 * override them - the SOURCE defaults, not a readback of the running process.
 * Only /__guard/health reports live values, and it reports just the mode and
 * the threshold, so the UI labels everything else accordingly.
 */
function parseConfigDefaults(source: string) {
  const out: Array<{ name: string; env: string; default: string; kind: string }> = []
  const re =
    /^([A-Z_][A-Z0-9_]*)\s*=\s*(?:_([bif])\(\s*"([^"]+)"\s*,\s*([^)]+?)\s*\)|os\.getenv\(\s*"([^"]+)"\s*,\s*"([^"]*)"\s*\))/gm
  let m: RegExpExecArray | null
  while ((m = re.exec(source)) !== null) {
    if (m[3]) {
      out.push({
        name: m[1],
        env: m[3],
        default: m[4].replace(/_/g, ''),
        kind: m[2] === 'b' ? 'boolean' : m[2] === 'i' ? 'integer' : 'float',
      })
    } else if (m[5]) {
      out.push({ name: m[1], env: m[5], default: m[6], kind: 'string' })
    }
  }
  return out
}

function countFeatureNames(source: string): number {
  const block = source.match(/^FEATURE_NAMES = \[([\s\S]*?)^\]/m)
  if (!block) return 0
  return block[1]
    .split('\n')
    .filter((line) => !line.trim().startsWith('#'))
    .reduce((n, line) => n + [...line.matchAll(/"[a-z0-9_]+"/g)].length, 0)
}

// -- middleware --------------------------------------------------------------

export function microapiData(options: MicroapiDataOptions): Plugin {
  const srcDir = options.srcDir
  const eventLog = process.env.MICROAPI_EVENT_LOG || path.join(srcDir, 'data', 'events.jsonl')
  const modelsDir = process.env.MICROAPI_MODELS_DIR || path.join(srcDir, 'ml_pipeline', 'models')
  const commonDir = path.join(srcDir, 'common')

  const middleware: Connect.NextHandleFunction = (req, res, next) => {
    const url = req.url || ''
    if (!url.startsWith('/__dash/')) return next()

    const route = new URL(url, 'http://local').pathname
    const params = new URL(url, 'http://local').searchParams

    void (async () => {
      try {
        if (route === '/__dash/events') {
          const limit = Math.min(5000, Math.max(1, Number(params.get('limit')) || 500))
          const afterRaw = params.get('after')
          const after = afterRaw === null ? -1 : Number(afterRaw)
          if (!fs.existsSync(eventLog)) {
            return json(res, 200, {
              ok: false,
              reason: 'missing',
              source: eventLog,
              events: [],
              message: 'Event log not found. The gateway creates it on its first proxied request.',
            })
          }
          const result = await readEvents(eventLog, limit, Number.isFinite(after) ? after : -1)
          return json(res, 200, { ok: true, source: eventLog, ...result })
        }

        if (route === '/__dash/artifacts') {
          const [decision, calibration, validation, comparison, tuning] = await Promise.all([
            readJsonIfPresent(path.join(modelsDir, 'decision.json')),
            readJsonIfPresent(path.join(modelsDir, 'calibration.json')),
            readJsonIfPresent(path.join(modelsDir, 'validation.json')),
            readJsonIfPresent(path.join(modelsDir, 'comparison.json')),
            readJsonIfPresent(path.join(modelsDir, 'tuning.json')),
          ])
          return json(res, 200, {
            ok: true,
            source: modelsDir,
            decision,
            calibration,
            validation,
            comparison,
            tuning,
          })
        }

        if (route === '/__dash/rules') {
          const file = path.join(commonDir, 'rules.py')
          const rules = parseRules(await fsp.readFile(file, 'utf8'))
          return json(res, 200, { ok: true, source: file, count: rules.length, rules })
        }

        if (route === '/__dash/config-defaults') {
          const file = path.join(commonDir, 'config.py')
          const featuresSrc = await fsp
            .readFile(path.join(commonDir, 'features.py'), 'utf8')
            .catch(() => '')
          return json(res, 200, {
            ok: true,
            source: file,
            defaults: parseConfigDefaults(await fsp.readFile(file, 'utf8')),
            featureCount: countFeatureNames(featuresSrc),
          })
        }

        return json(res, 404, { ok: false, error: `unknown console route ${route}` })
      } catch (err) {
        return json(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) })
      }
    })()
  }

  return {
    name: 'microapi-data',
    configureServer(server: ViteDevServer) {
      server.middlewares.use(middleware)
    },
    configurePreviewServer(server: PreviewServer) {
      server.middlewares.use(middleware)
    },
  }
}
