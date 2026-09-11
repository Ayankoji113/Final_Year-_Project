import { useGuardData } from './useGuardData'

/** The shared event-log feed. One poller backs every page that reads traffic. */
export function useTraffic() {
  return useGuardData().traffic
}
