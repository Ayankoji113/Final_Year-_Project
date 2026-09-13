import type { GuardEvent } from '../types'

/**
 * Everything the console charts is computed here, from real log records.
 *
 * The one rule this file exists to enforce: a block is attributed to the layer
 * the gateway itself recorded in `layer`, never inferred from an HTTP status.
 * A 403 in the log can be the backend's own 403 relayed through the proxy; a
 * guard block is the one where `action === "block"`.
 */

export type Outcome = 'blocked' | 'observed' | 'allowed'

/**
 * `enforced` is the gateway's own record of whether the block was acted on.
 * Under GUARD_MODE=enforce-l1 an L4 verdict has action="block" but
 * enforced=false: the request was forwarded and only the verdict was logged.
 */
export function outcomeOf(e: GuardEvent): Outcome {
  if (e.action !== 'block') return 'allowed'
  return e.enforced ? 'blocked' : 'observed'
}

export const OUTCOME_LABEL: Record<Outcome, string> = {
  blocked: 'Blocked',
  observed: 'Would block (not enforced)',
  allowed: 'Allowed',
}

export interface LayerMeta {
  key: string
  label: string
  short: string
  kind: 'rule' | 'rate' | 'ml' | 'error' | 'degraded' | 'clean'
  description: string
}

/** The exact `layer` strings the gateway writes, from gateway/detector.py. */
export const LAYER_META: Record<string, LayerMeta> = {
  'L1-rules': {
    key: 'L1-rules',
    label: 'L1 Security Rule',
    short: 'L1 rule',
    kind: 'rule',
    description:
      'A BLOCK-severity signature matched the normalised path or body. Deterministic, and it short-circuits before any model runs.',
  },
  'L1-rate': {
    key: 'L1-rate',
    label: 'L1 Rate Limit',
    short: 'L1 rate',
    kind: 'rate',
    description:
      'The client exceeded the configured sliding-window or burst limit in Redis. A policy decision, not a model prediction.',
  },
  'L4-meta': {
    key: 'L4-meta',
    label: 'ML Detection (L4)',
    short: 'L4 ML',
    kind: 'ml',
    description:
      'The L4 meta-learner combined the L1 rate score with the Isolation Forest and autoencoder scores and crossed the calibrated threshold.',
  },
  'L-error': {
    key: 'L-error',
    label: 'Inference Failure',
    short: 'error',
    kind: 'error',
    description:
      'Feature extraction or inference raised. With GUARD_FAIL_CLOSED=true the request is treated as hostile rather than waved through.',
  },
  'L1-only': {
    key: 'L1-only',
    label: 'L1 only (models absent)',
    short: 'L1 only',
    kind: 'degraded',
    description:
      'The anomaly models were not loaded, so only the signature and rate layers ran. Anomaly coverage was not available for this request.',
  },
  '': {
    key: '',
    label: 'Passed all layers',
    short: 'allowed',
    kind: 'clean',
    description: 'No signature matched, the rate was within policy, and L4 stayed below the threshold.',
  },
}

export function layerMeta(layer: string): LayerMeta {
  return (
    LAYER_META[layer] ?? {
      key: layer,
      label: layer,
      short: layer,
      kind: 'clean',
      description: 'Layer string recorded by the gateway but not known to this console.',
    }
  )
}

export interface TrafficSummary {
  total: number
  allowed: number
  blocked: number
  observed: number
  l1RuleBlocks: number
  l1RateBlocks: number
  mlDetections: number
  inferenceErrors: number
  degraded: number
  firstTs: number | null
  lastTs: number | null
}

export function summarise(events: GuardEvent[]): TrafficSummary {
  const s: TrafficSummary = {
    total: events.length,
    allowed: 0,
    blocked: 0,
    observed: 0,
    l1RuleBlocks: 0,
    l1RateBlocks: 0,
    mlDetections: 0,
    inferenceErrors: 0,
    degraded: 0,
    firstTs: null,
    lastTs: null,
  }
  for (const e of events) {
    const outcome = outcomeOf(e)
    if (outcome === 'allowed') s.allowed += 1
    else if (outcome === 'blocked') s.blocked += 1
    else s.observed += 1

    if (e.action === 'block') {
      if (e.layer === 'L1-rules') s.l1RuleBlocks += 1
      else if (e.layer === 'L1-rate') s.l1RateBlocks += 1
      else if (e.layer === 'L4-meta') s.mlDetections += 1
      else if (e.layer === 'L-error') s.inferenceErrors += 1
    }
    if (e.degraded) s.degraded += 1
    if (s.firstTs === null || e.ts < s.firstTs) s.firstTs = e.ts
    if (s.lastTs === null || e.ts > s.lastTs) s.lastTs = e.ts
  }
  return s
}

export interface Tally {
  key: string
  count: number
}

function tally(map: Map<string, number>): Tally[] {
  return [...map.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
}

/** Which layer decided, across every event including the allowed ones. */
export function layerCounts(events: GuardEvent[]): Tally[] {
  const m = new Map<string, number>()
  for (const e of events) {
    const key = e.action === 'block' ? e.layer : e.layer === 'L1-only' ? 'L1-only' : ''
    m.set(key, (m.get(key) ?? 0) + 1)
  }
  return tally(m)
}

/**
 * Attack categories. These come from the rule table's own `category` field via
 * the event's `categories` array - they are not guessed from status codes, and
 * an event with no rule hit contributes nothing.
 */
export function categoryCounts(events: GuardEvent[]): Tally[] {
  const m = new Map<string, number>()
  for (const e of events) for (const c of e.categories) m.set(c, (m.get(c) ?? 0) + 1)
  return tally(m)
}

export function ruleHitCounts(events: GuardEvent[]): Tally[] {
  const m = new Map<string, number>()
  for (const e of events) for (const r of e.rule_hits) m.set(r, (m.get(r) ?? 0) + 1)
  return tally(m)
}

export function templateCounts(events: GuardEvent[]): Tally[] {
  const m = new Map<string, number>()
  for (const e of events) m.set(e.template, (m.get(e.template) ?? 0) + 1)
  return tally(m)
}

export function clientCounts(events: GuardEvent[]): Tally[] {
  const m = new Map<string, number>()
  for (const e of events) m.set(e.client, (m.get(e.client) ?? 0) + 1)
  return tally(m)
}

export function statusClassCounts(events: GuardEvent[]): Tally[] {
  const m = new Map<string, number>()
  for (const e of events) {
    const key = `${Math.floor(e.status / 100)}xx`
    m.set(key, (m.get(key) ?? 0) + 1)
  }
  return tally(m).sort((a, b) => a.key.localeCompare(b.key))
}

export interface TimeBucket {
  t: number
  label: string
  allowed: number
  blocked: number
  observed: number
  total: number
}

/**
 * Bucket events into a fixed number of equal time slices spanning the data.
 *
 * Empty slices are kept so a gap in traffic reads as a gap rather than being
 * silently closed up, which would imply activity that did not happen.
 */
export function timeSeries(events: GuardEvent[], buckets = 40): TimeBucket[] {
  if (events.length === 0) return []
  let lo = Infinity
  let hi = -Infinity
  for (const e of events) {
    if (e.ts < lo) lo = e.ts
    if (e.ts > hi) hi = e.ts
  }
  const span = Math.max(hi - lo, 1e-3)
  const width = span / buckets
  const out: TimeBucket[] = Array.from({ length: buckets }, (_, i) => ({
    t: lo + i * width,
    label: new Date((lo + i * width) * 1000).toLocaleTimeString(undefined, { hour12: false }),
    allowed: 0,
    blocked: 0,
    observed: 0,
    total: 0,
  }))
  for (const e of events) {
    const idx = Math.min(buckets - 1, Math.max(0, Math.floor((e.ts - lo) / width)))
    const b = out[idx]
    b[outcomeOf(e)] += 1
    b.total += 1
  }
  return out
}

export function percentile(sorted: number[], p: number): number | null {
  if (sorted.length === 0) return null
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))
  return sorted[idx]
}

export interface LatencyProfile {
  n: number
  p50: number | null
  p95: number | null
  p99: number | null
  max: number | null
  mean: number | null
}

export function latencyProfile(events: GuardEvent[], field: 'detect_ms' | 'latency_ms'): LatencyProfile {
  const values = events.map((e) => e[field]).filter((v) => Number.isFinite(v)).sort((a, b) => a - b)
  if (values.length === 0) return { n: 0, p50: null, p95: null, p99: null, max: null, mean: null }
  const sum = values.reduce((a, b) => a + b, 0)
  return {
    n: values.length,
    p50: percentile(values, 50),
    p95: percentile(values, 95),
    p99: percentile(values, 99),
    max: values[values.length - 1],
    mean: sum / values.length,
  }
}

/** Stable identity for a log record. The byte offset is unique and ordered. */
export function eventKey(e: GuardEvent): string {
  return String(e._offset)
}

/**
 * Events the Threats view treats as security-relevant: anything the gateway
 * called a block, enforced or not, plus requests that tripped a FLAG-severity
 * rule without being blocked. A 4xx from the backend is not a threat.
 */
export function threatEvents(events: GuardEvent[]): GuardEvent[] {
  return events.filter((e) => e.action === 'block' || e.rule_hits.length > 0)
}

export interface BackendState {
  tone: 'ok' | 'bad' | 'warn' | 'mute'
  state: string
  detail: string
}

/**
 * The upstream backend's reachability, inferred from the log.
 *
 * There is no side channel to the backend: the gateway's only route to it is
 * the catch-all proxy, and polling that would put the console's own probes
 * into the very traffic it is reporting on. So this reads the evidence already
 * in the log - the gateway writes 502 when the upstream connection fails and
 * 504 when it times out - and says plainly that it is an inference.
 */
export function backendStateFromEvents(events: GuardEvent[], sample = 60): BackendState {
  // Only forwarded requests carry evidence. A request the gateway blocked never
  // reached the backend, so its status says nothing about the backend.
  const forwarded = events.filter((e) => !(e.action === 'block' && e.enforced)).slice(-sample)
  if (forwarded.length === 0) {
    return {
      tone: 'mute',
      state: 'Unknown',
      detail: 'No forwarded request in the loaded log window. Probe it from System Health.',
    }
  }
  const failures = forwarded.filter((e) => e.status === 502 || e.status === 504)
  if (failures.length === 0) {
    return {
      tone: 'ok',
      state: 'Responding',
      detail: `Last ${forwarded.length} forwarded requests all reached the upstream.`,
    }
  }
  if (failures[failures.length - 1] === forwarded[forwarded.length - 1]) {
    return {
      tone: 'bad',
      state: 'Not responding',
      detail: `Most recent forwarded request returned ${failures[failures.length - 1].status} from the gateway.`,
    }
  }
  return {
    tone: 'warn',
    state: 'Intermittent',
    detail: `${failures.length} of the last ${forwarded.length} forwarded requests returned 502 or 504.`,
  }
}

/**
 * Why an ML verdict was or was not enforced.
 *
 * The gateway records this per request, so the console never has to infer it.
 * Each reason is separately actionable: "below threshold" means tighten or
 * loosen the bar, "not in canary" means widen the rollout, and "brake" means
 * the safety latch fired and an operator has to look before anything resumes.
 */
export const GATE_META: Record<string, { label: string; why: string }> = {
  enforce: { label: 'Enforced', why: 'The verdict was acted on: this request received 403.' },
  l1: { label: 'Layer 1', why: 'A deterministic layer decided. The ML gate was never consulted.' },
  mode: {
    label: 'Rollout off',
    why: 'ML enforcement is at 0% of clients, so every ML verdict is recorded only.',
  },
  degraded: {
    label: 'Degraded input',
    why: 'Redis was unavailable, so the rate features read zero and the probability came from knowingly degraded input. Detect on it, do not block on it.',
  },
  brake: {
    label: 'Brake engaged',
    why: 'The automatic brake disabled ML enforcement after the would-block rate crossed its ceiling. Layer 1 is still enforcing.',
  },
  'below-threshold': {
    label: 'Below enforce threshold',
    why: 'Detected, but the probability did not reach the separate enforcement threshold.',
  },
  'endpoint-not-enabled': {
    label: 'Endpoint not enabled',
    why: 'This endpoint is not in the list ML is allowed to block on. False-positive rates differ per endpoint, so enforcement is enabled per endpoint.',
  },
  'not-in-canary': {
    label: 'Outside canary',
    why: 'This client falls outside the percentage of clients ML enforcement is rolled out to.',
  },
  error: {
    label: 'Gate error',
    why: 'The enforcement gate raised. It is wrapped to resolve to "do not enforce", so a fault here can never cause over-blocking.',
  },
}

export function gateMeta(gate: string | undefined) {
  if (!gate) return null
  return GATE_META[gate] ?? { label: gate, why: 'Gate reason not known to this console.' }
}
