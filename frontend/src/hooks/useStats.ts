import { useGuardData } from './useGuardData'

/** In-process counters from GET /__guard/stats, re-polled every 5 s. */
export function useStats() {
  return useGuardData().stats
}
