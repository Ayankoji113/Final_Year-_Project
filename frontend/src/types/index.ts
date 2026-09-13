/**
 * Every shape here was read off the running code, not guessed:
 *
 *   GuardHealth / GuardStats  -> src/gateway/main.py, the two admin handlers
 *   GuardEvent                -> the `enqueue({...})` call in src/gateway/main.py
 *   Decision* artefacts       -> src/ml_pipeline/models/*.json
 *
 * If a field is not in one of those places it is not in this file, and the UI
 * renders "not exposed" rather than inventing it.
 */

// -- GET /__guard/health -----------------------------------------------------

export interface GuardHealth {
  /** "healthy" or "degraded". Degraded still returns HTTP 200: the process is
   *  alive and L1 is still enforcing, it just cannot deliver everything. */
  status: string
  /** Plain-language reasons the gateway is degraded. Empty when healthy. */
  degraded_reasons?: string[]
  /** "enforce" | "enforce-l1" | "monitor" - free-form, read from GUARD_MODE. */
  mode: string
  enforcing_rules: boolean
  enforcing_ml: boolean
  models_loaded: boolean
  calibrated: boolean
  calibration_samples: number
  redis: boolean
  threshold: number
  uptime_s: number
  /** Enforcement rollout state. Absent on a gateway built before Phase E. */
  ml?: MlEnforcement
}

/** Detection and enforcement are separate decisions; this reports both. */
export interface MlEnforcement {
  /** Percentage of clients whose ML verdicts are enforced. 0 means none. */
  rollout_percent: number
  /** What counts as a detection, i.e. what the console shows. */
  threshold_detect: number
  /** How sure before a 403. Never below the detection threshold. */
  threshold_enforce: number
  /** Path templates ML may block. Empty means every endpoint is eligible. */
  enforce_endpoints: string[]
  /** Whether a degraded rate signal suppresses enforcement. */
  require_rate_state: boolean
  /** False means canary membership is publicly computable. */
  salted: boolean
  /** Whether ML verdicts can block anything at all right now. */
  enforcing: boolean
  brake: MlBrake
}

/**
 * The automatic brake. It measures the would-block rate across everything that
 * reached the models, so the figure is meaningful even at 0% rollout - which is
 * how an operator sees whether enforcement would be safe before enabling it.
 */
export interface MlBrake {
  enabled: boolean
  engaged: boolean
  tripped_at: number | null
  tripped_rate: number
  tripped_samples: number
  tripped_clients: number
  window_secs: number
  live_would_block_rate: number
  live_samples: number
  live_clients: number
  max_rate: number
}

// -- GET /__guard/stats ------------------------------------------------------

export interface GuardStats {
  total: number
  allowed: number
  blocked: number
  /** ML verdicts recorded, whether or not they were acted on. */
  ml_detected?: number
  /** ML verdicts that actually returned 403. */
  ml_enforced?: number
  /** Counts per gate reason, e.g. how many were outside the canary. */
  ml_gate?: Record<string, number>
  ml?: MlEnforcement
  /** Counts ENFORCED blocks only, keyed by the layer that decided. */
  by_layer: Record<string, number>
  trained_at: string | null
}

// -- POST /__guard/reload ----------------------------------------------------

export interface GuardReload {
  reloaded: boolean
  calibrated: boolean
}

// -- one line of src/data/events.jsonl ---------------------------------------

/**
 * Base-detector scores. Present only for requests that reached L2/L3/L4: an
 * L1 rule block carries `{rule: 1}` and a rate block carries `{rate: 1}`.
 */
export interface EventScores {
  rate?: number
  isolation_forest?: number
  autoencoder?: number
  meta_lr?: number
  rule?: number
}

export interface GuardEvent {
  /** Byte offset of this record in the log. Added by the console's file reader. */
  _offset: number
  /** Unix seconds, 3dp. */
  ts: number
  /** SHA-256 prefix of the client address. The raw address never reaches disk. */
  client: string
  method: string
  /** Normalised path template, e.g. /api/products/{id}. The raw URL is not logged. */
  template: string
  path_len: number
  body_size: number
  status: number
  window_count: number
  burst_count: number
  latency_ms: number
  detect_ms: number
  action: 'allow' | 'block'
  /** False for a block the current GUARD_MODE only observed. */
  enforced: boolean
  layer: string
  reason: string
  probability: number
  scores: EventScores
  rule_hits: string[]
  categories: string[]
  degraded: boolean
  features: Record<string, number>
  label: string | null
  /**
   * Why an ML verdict was or was not enforced. Absent on events logged before
   * Phase E, so every consumer must tolerate undefined.
   */
  enforce_gate?: string
  /** The enforcement threshold in force for THIS request. */
  enforce_threshold?: number
  /** Canary membership, or null when the gate never needed to compute it. */
  canary?: boolean | null
}

export interface EventsResponse {
  ok: boolean
  reason?: string
  message?: string
  source: string
  events: GuardEvent[]
  malformed: number
  nextOffset: number
  fileSize: number
  mtimeMs: number
  truncatedRead: boolean
}

// -- src/ml_pipeline/models/*.json -------------------------------------------

export interface TestMetrics {
  accuracy: number
  precision: number
  recall: number
  f1: number
  fpr: number
  fnr: number
  tp: number
  tn: number
  fp: number
  fn: number
}

export interface DecisionArtifact {
  version: number
  trained_at: string
  seed: number
  feature_names: string[]
  threshold: number
  if_lo: number
  if_hi: number
  ae_lo: number
  ae_hi: number
  meta_inputs: string[]
  pool_sizes: Record<string, number>
  novel_families: string[]
  hyperparams: {
    ae_noise: number
    ae_hidden: number
    ae_bottleneck: number
    if_trees: number
    meta: string
  }
  val_f1: number
  test_metrics: TestMetrics
  test_roc_auc: number
  test_pr_auc: number
  zero_day_recall: number
  unique_feature_ratio: number
}

export interface CalibrationArtifact {
  endpoints: Record<string, { body_mean: number; body_std: number; count: number }>
  rate: { mean: number; std: number }
  n_samples: number
}

export interface SeedSummary {
  mean: number
  ci95: [number, number]
  min: number
  max: number
  n: number
}

export interface ValidationArtifact {
  seeds: number[]
  runs: Array<Record<string, number>>
  summary: Record<string, SeedSummary>
}

export interface ComparisonArtifact {
  metrics: Record<string, TestMetrics>
  mcnemar: Record<
    string,
    { n01: number; n10: number; p: number; method: string; significant: boolean }
  >
}

export interface TuningArtifact {
  search_seeds: number[]
  pseudo_novel: string
  objective: string
  results: Array<Record<string, unknown>>
  best: Record<string, string>
}

export interface ArtifactsResponse {
  ok: boolean
  source: string
  decision: DecisionArtifact | null
  calibration: CalibrationArtifact | null
  validation: ValidationArtifact | null
  comparison: ComparisonArtifact | null
  tuning: TuningArtifact | null
}

// -- parsed out of src/common/*.py -------------------------------------------

export interface GuardRule {
  id: string
  category: string
  severity: 'block' | 'flag'
  target: 'path' | 'body' | 'any'
  why: string
}

export interface RulesResponse {
  ok: boolean
  source: string
  count: number
  rules: GuardRule[]
}

export interface ConfigDefault {
  name: string
  env: string
  default: string
  kind: string
}

export interface ConfigDefaultsResponse {
  ok: boolean
  source: string
  defaults: ConfigDefault[]
  featureCount: number
}

// -- client-side request state ----------------------------------------------

export type LoadState = 'idle' | 'loading' | 'ok' | 'error'

export interface Async<T> {
  state: LoadState
  data: T | null
  error: string | null
  /** Wall-clock time of the last successful response. */
  updatedAt: number | null
}
