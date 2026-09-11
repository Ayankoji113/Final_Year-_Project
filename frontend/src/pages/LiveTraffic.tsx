import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Pause, Play, RefreshCw } from 'lucide-react'
import { useTraffic } from '../hooks/useTraffic'
import { useEventFilter } from '../hooks/useEventFilter'
import { EventTable, type EventColumn } from '../components/tables/EventTable'
import { FilterBar } from '../components/tables/FilterBar'
import { ErrorState, Panel, SourceNote, Unavailable } from '../components/common/Panel'
import { Pill } from '../components/status/Badges'
import { EVENTS_INTERVAL_MS, EVENT_BUFFER } from '../hooks/GuardDataProvider'
import { eventKey, summarise } from '../utils/derive'
import { formatInt, relativeAge } from '../utils/format'

/**
 * Every column here maps to a key the gateway actually writes.
 *
 * There is no raw-path column because there is no raw path in the log: the
 * gateway records the normalised `template` and the path's length, and nothing
 * else about the URL.
 */
const COLUMNS: EventColumn[] = [
  'time',
  'method',
  'template',
  'status',
  'decision',
  'layer',
  'probability',
  'rate',
  'detect_ms',
  'latency_ms',
  'client',
]

export function LiveTraffic() {
  const traffic = useTraffic()
  const navigate = useNavigate()
  const { filter, setFilter, filtered, options, active, reset } = useEventFilter(traffic.events)

  const newestFirst = useMemo(() => [...filtered].reverse(), [filtered])
  const summary = useMemo(() => summarise(filtered), [filtered])

  const controlClass =
    'inline-flex h-8 items-center gap-1.5 rounded-md border border-ink-600 px-2.5 text-xs text-slate-b transition-colors hover:border-ink-500 hover:text-slate-hi'

  return (
    <div className="space-y-4">
      <Panel
        title="Live request feed"
        subtitle={`Auto-refreshing every ${EVENTS_INTERVAL_MS / 1000} seconds by polling the gateway's event log. This is not a push stream.`}
        actions={
          <>
            <Pill tone={traffic.paused ? 'warn' : 'ok'}>{traffic.paused ? 'Paused' : 'Live'}</Pill>
            <button
              type="button"
              onClick={() => traffic.setPaused(!traffic.paused)}
              className={controlClass}
              aria-pressed={traffic.paused}
            >
              {traffic.paused ? <Play className="h-3.5 w-3.5" aria-hidden /> : <Pause className="h-3.5 w-3.5" aria-hidden />}
              {traffic.paused ? 'Resume' : 'Pause'}
            </button>
            <button type="button" onClick={traffic.refresh} className={controlClass}>
              <RefreshCw className="h-3.5 w-3.5" aria-hidden />
              Refresh
            </button>
          </>
        }
      >
        <FilterBar
          filter={filter}
          setFilter={setFilter}
          options={options}
          active={active}
          reset={reset}
          resultCount={filtered.length}
          totalCount={traffic.events.length}
        />

        <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-slate-t">
          <span>
            Allowed <span className="num text-ok-400">{formatInt(summary.allowed)}</span>
          </span>
          <span>
            Blocked <span className="num text-bad-400">{formatInt(summary.blocked)}</span>
          </span>
          <span>
            Would block <span className="num text-warn-400">{formatInt(summary.observed)}</span>
          </span>
          {summary.degraded > 0 && (
            <span>
              Degraded <span className="num text-warn-400">{formatInt(summary.degraded)}</span>
            </span>
          )}
          <span className="ml-auto">Log read {relativeAge(traffic.updatedAt)}</span>
        </div>

        {traffic.error && (
          <div className="mt-3">
            <ErrorState message={traffic.error} hint="Showing the last records that were read successfully." />
          </div>
        )}
      </Panel>

      <Panel bodyClassName="" className="overflow-hidden">
        {traffic.missingMessage ? (
          <div className="p-4">
            <Unavailable what="Event log not readable" why={traffic.missingMessage} />
          </div>
        ) : (
          <EventTable
            events={newestFirst}
            columns={COLUMNS}
            onSelect={(e) => navigate(`/investigate/${eventKey(e)}`)}
            emptyTitle={active ? 'No events match these filters' : 'No requests in the loaded window'}
            emptyHint={
              active
                ? 'Clear the filters to see the full feed.'
                : 'Send a request through the gateway on port 5000 and it will appear on the next refresh.'
            }
            maxHeight="max-h-[62vh]"
          />
        )}
      </Panel>

      <SourceNote>
        The console keeps the most recent {formatInt(EVENT_BUFFER)} records in memory and polls only the bytes appended
        since the last read. {traffic.windowed && 'The log on disk is longer than this window. '}
        {traffic.malformed > 0 && `${formatInt(traffic.malformed)} line(s) could not be parsed as JSON and were skipped. `}
        Source: <code>{traffic.source || 'src/data/events.jsonl'}</code>
      </SourceNote>
    </div>
  )
}
