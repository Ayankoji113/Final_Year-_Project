import { getJson, postJson } from './api'
import type { GuardHealth, GuardReload } from '../types'

/** GET /__guard/health - the gateway's own liveness, mode and model state. */
export function fetchHealth(signal?: AbortSignal) {
  return getJson<GuardHealth>('/__guard/health', signal)
}

/**
 * POST /__guard/reload - hot-reloads the model files and the calibration
 * baseline. This endpoint already exists on the gateway; the console does not
 * add it. It is the only write the console can perform.
 */
export function reloadModels(signal?: AbortSignal) {
  return postJson<GuardReload>('/__guard/reload', signal, 20000)
}

export interface BackendProbe {
  reachable: boolean
  status: number
  body: string
  at: number
}

/**
 * Deliberate, operator-triggered probe of the upstream backend.
 *
 * There is no out-of-band backend health channel: the gateway's only route to
 * the backend is the catch-all proxy. So this sends one real GET /health
 * THROUGH the full detection pipeline. It is a genuine request - it increments
 * the gateway's counters and appends one line to the event log - which is why
 * it is a button and not a poll.
 */
export async function probeBackend(signal?: AbortSignal): Promise<BackendProbe> {
  try {
    const res = await fetch('/__probe/health', { signal, headers: { accept: 'application/json' } })
    const body = await res.text()
    return { reachable: res.ok, status: res.status, body: body.slice(0, 500), at: Date.now() }
  } catch (err) {
    return {
      reachable: false,
      status: 0,
      body: err instanceof Error ? err.message : String(err),
      at: Date.now(),
    }
  }
}
