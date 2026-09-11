import { useMemo, useState } from 'react'
import type { GuardEvent } from '../types'
import { outcomeOf, type Outcome } from '../utils/derive'

export interface EventFilterState {
  search: string
  method: string
  statusClass: string
  layer: string
  outcome: string
  /** Seconds back from the newest record in the window; 0 means no limit. */
  windowSecs: number
}

export const TIME_WINDOWS: Array<{ label: string; secs: number }> = [
  { label: 'All loaded', secs: 0 },
  { label: 'Last 1 min', secs: 60 },
  { label: 'Last 5 min', secs: 300 },
  { label: 'Last 15 min', secs: 900 },
  { label: 'Last hour', secs: 3600 },
]

export const EMPTY_FILTER: EventFilterState = {
  search: '',
  method: 'all',
  statusClass: 'all',
  layer: 'all',
  outcome: 'all',
  windowSecs: 0,
}

/**
 * Match free text against the fields the log actually carries.
 *
 * Note what is absent: there is no raw URL, query string or body to search,
 * because the gateway never writes them. Searching `template`, `reason`,
 * `rule_hits`, `categories` and `client` is the whole of what exists.
 */
function matchesSearch(e: GuardEvent, needle: string): boolean {
  if (!needle) return true
  const q = needle.toLowerCase()
  return (
    e.template.toLowerCase().includes(q) ||
    e.method.toLowerCase().includes(q) ||
    e.reason.toLowerCase().includes(q) ||
    e.layer.toLowerCase().includes(q) ||
    e.client.toLowerCase().includes(q) ||
    String(e.status).includes(q) ||
    e.rule_hits.some((r) => r.toLowerCase().includes(q)) ||
    e.categories.some((c) => c.toLowerCase().includes(q))
  )
}

export function applyFilter(events: GuardEvent[], f: EventFilterState): GuardEvent[] {
  // The window is measured from the newest record present, not from wall-clock
  // now, so a log that stopped an hour ago still shows its final minutes
  // instead of rendering empty.
  let cutoff = -Infinity
  if (f.windowSecs > 0 && events.length > 0) {
    const newest = events.reduce((max, e) => (e.ts > max ? e.ts : max), -Infinity)
    cutoff = newest - f.windowSecs
  }

  return events.filter((e) => {
    if (e.ts < cutoff) return false
    if (f.method !== 'all' && e.method !== f.method) return false
    if (f.statusClass !== 'all' && `${Math.floor(e.status / 100)}xx` !== f.statusClass) return false
    if (f.layer !== 'all') {
      const layer = e.action === 'block' ? e.layer : e.layer || ''
      if (layer !== f.layer) return false
    }
    if (f.outcome !== 'all' && outcomeOf(e) !== (f.outcome as Outcome)) return false
    return matchesSearch(e, f.search)
  })
}

export function useEventFilter(events: GuardEvent[], initial: Partial<EventFilterState> = {}) {
  const [filter, setFilter] = useState<EventFilterState>({ ...EMPTY_FILTER, ...initial })

  const filtered = useMemo(() => applyFilter(events, filter), [events, filter])

  const options = useMemo(() => {
    const methods = new Set<string>()
    const statuses = new Set<string>()
    const layers = new Set<string>()
    for (const e of events) {
      methods.add(e.method)
      statuses.add(`${Math.floor(e.status / 100)}xx`)
      layers.add(e.action === 'block' ? e.layer : e.layer || '')
    }
    return {
      methods: [...methods].sort(),
      statuses: [...statuses].sort(),
      layers: [...layers].sort(),
    }
  }, [events])

  const active =
    filter.search !== '' ||
    filter.method !== 'all' ||
    filter.statusClass !== 'all' ||
    filter.layer !== 'all' ||
    filter.outcome !== 'all' ||
    filter.windowSecs !== 0

  return {
    filter,
    setFilter,
    filtered,
    options,
    active,
    reset: () => setFilter({ ...EMPTY_FILTER, ...initial }),
  }
}
