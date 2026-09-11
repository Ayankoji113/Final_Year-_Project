import { useGuardData } from './useGuardData'

/** Live gateway state from GET /__guard/health, re-polled every 5 s. */
export function useHealth() {
  return useGuardData().health
}
