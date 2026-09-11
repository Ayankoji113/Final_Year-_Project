import { AlertTriangle } from 'lucide-react'
import type { GuardEvent } from '../../types'
import { eventKey } from '../../utils/derive'
import { formatEventTime, formatInt, formatProbability } from '../../utils/format'
import { DecisionBadge, LayerBadge, MethodBadge, StatusBadge } from '../status/Badges'
import { EmptyState } from '../common/Panel'

/**
 * Columns are named after the exact JSONL keys the gateway writes.
 *
 * There is no `path` column and there never can be: the log records the
 * normalised `template` and `path_len` only, because writing raw URLs and
 * bodies to disk is what leaks credentials out of a security log.
 */
export type EventColumn =
  | 'time'
  | 'method'
  | 'template'
  | 'status'
  | 'decision'
  | 'layer'
  | 'probability'
  | 'detect_ms'
  | 'latency_ms'
  | 'client'
  | 'body_size'
  | 'rate'
  | 'reason'

const HEAD: Record<EventColumn, { label: string; title: string; align?: string }> = {
  time: { label: 'Time', title: 'ts - Unix seconds when the gateway handled the request' },
  method: { label: 'Method', title: 'method' },
  template: { label: 'Endpoint', title: 'template - normalised path. The raw URL is deliberately not logged.' },
  status: { label: 'Status', title: 'status - the response code the client received' },
  decision: { label: 'Decision', title: 'action + enforced' },
  layer: { label: 'Layer', title: 'layer - which detection layer decided' },
  probability: { label: 'Score', title: 'probability - the L4 meta-learner output, 1.000 for a deterministic L1 verdict', align: 'text-right' },
  detect_ms: { label: 'Detect', title: 'detect_ms - time spent in the detection pipeline', align: 'text-right' },
  latency_ms: { label: 'Total', title: 'latency_ms - end-to-end time including the upstream call', align: 'text-right' },
  client: { label: 'Client', title: 'client - SHA-256 prefix of the address. The raw address never reaches disk.' },
  body_size: { label: 'Body', title: 'body_size in bytes', align: 'text-right' },
  rate: { label: 'Win/Burst', title: 'window_count / burst_count - the client rate counters at decision time', align: 'text-right' },
  reason: { label: 'Reason', title: 'reason - the gateway explanation string, empty for an allowed request' },
}

export const DEFAULT_COLUMNS: EventColumn[] = [
  'time',
  'method',
  'template',
  'status',
  'decision',
  'layer',
  'probability',
  'detect_ms',
]

function Cell({ column, event }: { column: EventColumn; event: GuardEvent }) {
  switch (column) {
    case 'time':
      return <span className="font-mono text-[11px] text-slate-b">{formatEventTime(event.ts)}</span>
    case 'method':
      return <MethodBadge method={event.method} />
    case 'template':
      return (
        <span className="flex items-center gap-1.5">
          <span className="truncate font-mono text-[11px] text-slate-hi" title={event.template}>
            {event.template}
          </span>
          {event.degraded && (
            <AlertTriangle
              className="h-3 w-3 shrink-0 text-warn-400"
              aria-label="degraded"
              // degraded=true means Redis was down or inference failed, so the
              // rate counters and scores on this row are not trustworthy.
            />
          )}
        </span>
      )
    case 'status':
      return <StatusBadge status={event.status} />
    case 'decision':
      return <DecisionBadge event={event} />
    case 'layer':
      return <LayerBadge layer={event.action === 'block' ? event.layer : event.layer || ''} />
    case 'probability':
      return <span className="num text-[11px] text-slate-b">{formatProbability(event.probability)}</span>
    case 'detect_ms':
      return <span className="num text-[11px] text-slate-b">{event.detect_ms.toFixed(1)}</span>
    case 'latency_ms':
      return <span className="num text-[11px] text-slate-b">{event.latency_ms.toFixed(1)}</span>
    case 'client':
      return <span className="font-mono text-[11px] text-slate-t">{event.client.slice(0, 10)}</span>
    case 'body_size':
      return <span className="num text-[11px] text-slate-b">{formatInt(event.body_size)}</span>
    case 'rate':
      return (
        <span className="num text-[11px] text-slate-b">
          {event.window_count}/{event.burst_count}
        </span>
      )
    case 'reason':
      return (
        <span className="block truncate text-[11px] text-slate-t" title={event.reason}>
          {event.reason || '--'}
        </span>
      )
  }
}

export function EventTable({
  events,
  columns = DEFAULT_COLUMNS,
  selectedKey,
  onSelect,
  emptyTitle = 'No matching events',
  emptyHint,
  maxHeight = '',
}: {
  events: GuardEvent[]
  columns?: EventColumn[]
  selectedKey?: string | null
  onSelect?: (event: GuardEvent) => void
  emptyTitle?: string
  emptyHint?: string
  maxHeight?: string
}) {
  if (events.length === 0) return <EmptyState title={emptyTitle} hint={emptyHint} />

  return (
    <div className={`scroll-x ${maxHeight ? `overflow-y-auto ${maxHeight}` : ''}`}>
      <table className="w-full min-w-[720px] border-collapse text-left">
        <thead className="sticky top-0 z-10 bg-ink-850">
          <tr className="border-b border-ink-700">
            {columns.map((c) => (
              <th
                key={c}
                scope="col"
                title={HEAD[c].title}
                className={`px-3 py-2 text-[10px] font-semibold tracking-wide text-slate-t uppercase ${HEAD[c].align ?? ''}`}
              >
                {HEAD[c].label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((e) => {
            const key = eventKey(e)
            const selected = key === selectedKey
            return (
              <tr
                key={key}
                onClick={onSelect ? () => onSelect(e) : undefined}
                onKeyDown={
                  onSelect
                    ? (ev) => {
                        if (ev.key === 'Enter' || ev.key === ' ') {
                          ev.preventDefault()
                          onSelect(e)
                        }
                      }
                    : undefined
                }
                tabIndex={onSelect ? 0 : undefined}
                role={onSelect ? 'button' : undefined}
                aria-label={onSelect ? `Investigate ${e.method} ${e.template}` : undefined}
                className={`row-hover border-b border-ink-800/70 ${onSelect ? 'cursor-pointer' : ''} ${
                  selected ? 'bg-accent-500/10 ring-1 ring-accent-500/30 ring-inset' : ''
                }`}
              >
                {columns.map((c) => (
                  <td key={c} className={`max-w-[280px] px-3 py-1.5 ${HEAD[c].align ?? ''}`}>
                    <Cell column={c} event={e} />
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
