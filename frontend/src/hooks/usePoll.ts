import { useCallback, useEffect, useRef, useState } from 'react'
import type { Async } from '../types'

const IDLE: Async<never> = { state: 'idle', data: null, error: null, updatedAt: null }

export interface PollResult<T> extends Async<T> {
  /** Fetch now, outside the interval. */
  refresh: () => void
  /** True while a fetch is in flight over data that is already on screen. */
  refreshing: boolean
}

/**
 * Poll `fetcher` on an interval.
 *
 * There is no WebSocket or SSE channel on the gateway and this project must not
 * add one, so everything live in this console is polling. The UI says so.
 *
 * A failed poll keeps the last good `data` on screen and sets `error`
 * alongside it - blanking a security console the moment one request times out
 * is worse than showing slightly stale numbers next to a clear staleness
 * warning.
 */
export function usePoll<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  intervalMs: number,
  enabled = true,
): PollResult<T> {
  const [result, setResult] = useState<Async<T>>(IDLE as Async<T>)
  const [refreshing, setRefreshing] = useState(false)
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher
  const inFlight = useRef<AbortController | null>(null)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      inFlight.current?.abort()
    }
  }, [])

  const run = useCallback(async () => {
    inFlight.current?.abort()
    const ctl = new AbortController()
    inFlight.current = ctl
    setRefreshing(true)
    try {
      const data = await fetcherRef.current(ctl.signal)
      if (!mounted.current || ctl.signal.aborted) return
      setResult({ state: 'ok', data, error: null, updatedAt: Date.now() })
    } catch (err) {
      if (!mounted.current || ctl.signal.aborted) return
      setResult((prev) => ({
        state: 'error',
        data: prev.data,
        error: err instanceof Error ? err.message : String(err),
        updatedAt: prev.updatedAt,
      }))
    } finally {
      if (mounted.current && !ctl.signal.aborted) setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    if (!enabled) return
    setResult((prev) => (prev.state === 'idle' ? { ...prev, state: 'loading' } : prev))
    void run()
    if (intervalMs <= 0) return
    const id = setInterval(() => void run(), intervalMs)
    return () => clearInterval(id)
  }, [run, intervalMs, enabled])

  return { ...result, refresh: () => void run(), refreshing }
}
