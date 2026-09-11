import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Download, FileJson } from 'lucide-react'
import { useTraffic } from '../hooks/useTraffic'
import { useEventFilter } from '../hooks/useEventFilter'
import { EventTable, type EventColumn } from '../components/tables/EventTable'
import { FilterBar } from '../components/tables/FilterBar'
import { EmptyState, Panel, SourceNote, Unavailable } from '../components/common/Panel'
import { eventKey } from '../utils/derive'
import { formatBytes, formatInt, formatEventDateTime } from '../utils/format'
import type { GuardEvent } from '../types'

const COLUMNS: EventColumn[] = [
  'time',
  'method',
  'template',
  'status',
  'decision',
  'layer',
  'probability',
  'body_size',
  'rate',
  'detect_ms',
  'latency_ms',
  'client',
]

export function RequestLogs() {
  const traffic = useTraffic()
  const navigate = useNavigate()
  const [selected, setSelected] = useState<GuardEvent | null>(null)
  const { filter, setFilter, filtered, options, active, reset } = useEventFilter(traffic.events)

  const newestFirst = useMemo(() => [...filtered].reverse(), [filtered])
  const raw = selected ? JSON.stringify(selected, null, 2) : ''

  const exportFiltered = () => {
    // Re-serialise one JSON object per line, exactly the shape that was read.
    const body = filtered.map((e) => JSON.stringify(e)).join('\n')
    const url = URL.createObjectURL(new Blob([body], { type: 'application/x-ndjson' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `microapi-events-${Date.now()}.jsonl`
    a.click()
    URL.revokeObjectURL(url)
  }

  const controlClass =
    'inline-flex h-8 items-center gap-1.5 rounded-md border border-ink-600 px-2.5 text-xs text-slate-b transition-colors hover:border-ink-500 hover:text-slate-hi'

  return (
    <div className="space-y-4">
      <Panel
        title="Event log viewer"
        subtitle={
          <>
            Reading <code className="font-mono">{traffic.source || 'src/data/events.jsonl'}</code> directly. The console
            never writes to it and the record format is untouched.
          </>
        }
        actions={
          <button type="button" onClick={exportFiltered} className={controlClass} disabled={filtered.length === 0}>
            <Download className="h-3.5 w-3.5" aria-hidden />
            Export view
          </button>
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
        <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-slate-t">
          <span>
            Log size on disk <span className="num text-slate-b">{formatBytes(traffic.fileSize)}</span>
          </span>
          <span>
            Records held <span className="num text-slate-b">{formatInt(traffic.events.length)}</span>
          </span>
          {traffic.windowed && <span className="text-warn-400">Showing the most recent portion of a longer log</span>}
          {traffic.malformed > 0 && (
            <span className="text-warn-400">{formatInt(traffic.malformed)} unparseable line(s) skipped</span>
          )}
        </div>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <Panel bodyClassName="" className="overflow-hidden">
          {traffic.missingMessage ? (
            <div className="p-4">
              <Unavailable what="Event log not readable" why={traffic.missingMessage} />
            </div>
          ) : (
            <EventTable
              events={newestFirst}
              columns={COLUMNS}
              selectedKey={selected ? eventKey(selected) : null}
              onSelect={setSelected}
              emptyTitle={active ? 'No records match these filters' : 'The log window is empty'}
              maxHeight="max-h-[68vh]"
            />
          )}
        </Panel>

        <Panel
          title={
            <span className="flex items-center gap-2">
              <FileJson className="h-4 w-4 text-slate-t" aria-hidden />
              Raw record
            </span>
          }
          subtitle={selected ? formatEventDateTime(selected.ts) : 'Select a row to see its complete JSON'}
          actions={
            selected && (
              <button
                type="button"
                onClick={() => navigate(`/investigate/${eventKey(selected)}`)}
                className={controlClass}
              >
                Investigate
              </button>
            )
          }
        >
          {selected ? (
            <pre className="scroll-x max-h-[62vh] overflow-y-auto rounded-lg bg-ink-950/70 p-3 font-mono text-[11px] leading-relaxed text-slate-b">
              {raw}
            </pre>
          ) : (
            <EmptyState
              title="No record selected"
              hint="Every field shown is written by the gateway. Raw URLs, query strings, bodies and headers are deliberately absent from the log."
            />
          )}
        </Panel>
      </div>

      <SourceNote>
        The log is append-only and the gateway writes it in batches from a background task, so a record can appear a
        second or two after the request it describes. The console only reads bytes appended since its last poll.
      </SourceNote>
    </div>
  )
}
