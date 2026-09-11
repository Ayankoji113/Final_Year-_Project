import {
  createContext,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { fetchHealth } from '../services/health'
import { fetchStats } from '../services/stats'
import { fetchEvents } from '../services/logs'
import { usePoll, type PollResult } from './usePoll'
import type { EventsResponse, GuardEvent, GuardHealth, GuardStats } from '../types'

/** How many records the console keeps in memory. Roughly 30 MB of JSON at worst. */
export const EVENT_BUFFER = 4000
/** Records pulled on the first load. */
const INITIAL_TAIL = 1500

export const HEALTH_INTERVAL_MS = 5000
export const STATS_INTERVAL_MS = 5000
export const EVENTS_INTERVAL_MS = 4000

export interface TrafficFeed {
  events: GuardEvent[]
  state: 'idle' | 'loading' | 'ok' | 'error'
  error: string | null
  updatedAt: number | null
  /** Lines in the log the reader could not parse as JSON. */
  malformed: number
  /** True when the log is longer than the console chose to read. */
  windowed: boolean
  fileSize: number
  source: string
  /** Set when the log file does not exist yet. */
  missingMessage: string | null
  paused: boolean
  setPaused: (paused: boolean) => void
  refresh: () => void
}

export interface GuardData {
  health: PollResult<GuardHealth>
  stats: PollResult<GuardStats>
  traffic: TrafficFeed
}

export const GuardDataContext = createContext<GuardData | null>(null)

export function GuardDataProvider({ children }: { children: ReactNode }) {
  const health = usePoll(fetchHealth, HEALTH_INTERVAL_MS)
  const stats = usePoll(fetchStats, STATS_INTERVAL_MS)

  const [events, setEvents] = useState<GuardEvent[]>([])
  const [meta, setMeta] = useState({
    malformed: 0,
    windowed: false,
    fileSize: 0,
    source: '',
    missingMessage: null as string | null,
  })
  const [paused, setPaused] = useState(false)
  const cursor = useRef<number | null>(null)

  const pull = useCallback(async (signal: AbortSignal): Promise<EventsResponse> => {
    const at = cursor.current
    const res = await fetchEvents(at === null ? INITIAL_TAIL : EVENT_BUFFER, at ?? undefined, signal)

    if (!res.ok) {
      cursor.current = null
      setEvents([])
      setMeta({
        malformed: 0,
        windowed: false,
        fileSize: 0,
        source: res.source,
        missingMessage: res.message ?? 'Event log unavailable.',
      })
      return res
    }

    // The gateway only ever appends, so a file that shrank was rotated or
    // cleared. Drop the cursor and re-read a tail rather than splicing new
    // records onto stale ones.
    const rotated = at !== null && res.fileSize < at
    cursor.current = res.nextOffset

    setEvents((prev) => {
      const base = at === null || rotated ? [] : prev
      if (res.events.length === 0) return base
      const merged = base.concat(res.events)
      return merged.length > EVENT_BUFFER ? merged.slice(merged.length - EVENT_BUFFER) : merged
    })
    setMeta((prev) => ({
      malformed: at === null || rotated ? res.malformed : prev.malformed + res.malformed,
      windowed: at === null ? res.truncatedRead : prev.windowed,
      fileSize: res.fileSize,
      source: res.source,
      missingMessage: null,
    }))
    return res
  }, [])

  const feed = usePoll(pull, EVENTS_INTERVAL_MS, !paused)

  // Coming back from a pause, catch up immediately instead of waiting out the
  // next tick - an operator who un-pauses expects to see the gap close.
  const wasPaused = useRef(paused)
  useEffect(() => {
    if (wasPaused.current && !paused) feed.refresh()
    wasPaused.current = paused
  }, [paused, feed])

  const traffic = useMemo<TrafficFeed>(
    () => ({
      events,
      state: feed.state,
      error: feed.error,
      updatedAt: feed.updatedAt,
      malformed: meta.malformed,
      windowed: meta.windowed,
      fileSize: meta.fileSize,
      source: meta.source,
      missingMessage: meta.missingMessage,
      paused,
      setPaused,
      refresh: feed.refresh,
    }),
    [events, feed.state, feed.error, feed.updatedAt, feed.refresh, meta, paused],
  )

  const value = useMemo<GuardData>(() => ({ health, stats, traffic }), [health, stats, traffic])

  return <GuardDataContext.Provider value={value}>{children}</GuardDataContext.Provider>
}
