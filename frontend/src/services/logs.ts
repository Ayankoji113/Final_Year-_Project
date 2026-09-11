import { getJson } from './api'
import type { EventsResponse } from '../types'

/**
 * Read the gateway's append-only event log.
 *
 * Served by the console's own dev/preview server from src/data/events.jsonl.
 * The gateway does not expose the log over HTTP and this project must not grow
 * an endpoint that does, so the file is read locally instead.
 *
 * `after` is a byte offset returned as `nextOffset` by the previous call; pass
 * it to fetch only the records appended since. Omit it for a tail of the last
 * `limit` records.
 */
export function fetchEvents(limit: number, after?: number, signal?: AbortSignal) {
  const q = new URLSearchParams({ limit: String(limit) })
  if (after !== undefined) q.set('after', String(after))
  return getJson<EventsResponse>(`/__dash/events?${q}`, signal, 15000)
}
