import { getJson } from './api'
import type { ArtifactsResponse, ConfigDefaultsResponse, RulesResponse } from '../types'

/** The committed training artefacts in src/ml_pipeline/models/. */
export function fetchArtifacts(signal?: AbortSignal) {
  return getJson<ArtifactsResponse>('/__dash/artifacts', signal, 15000)
}

/** The Layer-1 signature table, parsed from src/common/rules.py. */
export function fetchRules(signal?: AbortSignal) {
  return getJson<RulesResponse>('/__dash/rules', signal)
}

/** Env-var fallbacks declared in src/common/config.py. NOT a live readback. */
export function fetchConfigDefaults(signal?: AbortSignal) {
  return getJson<ConfigDefaultsResponse>('/__dash/config-defaults', signal)
}
