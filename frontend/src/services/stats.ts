import { getJson } from './api'
import type { GuardStats } from '../types'

/**
 * GET /__guard/stats - in-process counters.
 *
 * Two properties the UI has to be honest about:
 *   - they are held in a plain dict in the gateway process, so they reset to
 *     zero every time the container restarts;
 *   - `by_layer` counts only blocks that were actually ENFORCED, so under
 *     GUARD_MODE=enforce-l1 an ML verdict never appears here even though the
 *     event log records it.
 */
export function fetchStats(signal?: AbortSignal) {
  return getJson<GuardStats>('/__guard/stats', signal)
}
