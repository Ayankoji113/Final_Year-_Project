import { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import type { GuardEvent } from '../../types'
import { Unavailable } from '../common/Panel'

/**
 * The feature vector the gateway logged for this request.
 *
 * These names and values are verbatim from the record's `features` object,
 * which the gateway produces by calling the same common/features.extract() the
 * trainer uses. The groups below mirror the comment blocks in FEATURE_NAMES.
 */
const GROUPS: Array<{ title: string; prefixes: string[]; note: string }> = [
  { title: 'Body shape', prefixes: ['body_', 'has_body', 'ct_json'], note: 'size, entropy and character mix of the request body' },
  { title: 'Path shape', prefixes: ['path_'], note: 'depth, length, entropy and encoding delta of the path' },
  { title: 'Query shape', prefixes: ['q_'], note: 'parameter count and value length of the query string' },
  { title: 'Behaviour', prefixes: ['win_'], note: 'how many distinct endpoints this client touched. Rate magnitude is Layer 1 policy and is deliberately not a model feature.' },
  { title: 'Method', prefixes: ['m_', 'is_write'], note: 'the six HTTP method buckets that exist on every API' },
  { title: 'Layer-1 evidence', prefixes: ['n_flags'], note: 'count of FLAG-severity signature hits. BLOCK hits never reach the model.' },
]

function groupOf(name: string): string {
  for (const g of GROUPS) if (g.prefixes.some((p) => name.startsWith(p))) return g.title
  return 'Other'
}

export function FeatureVector({ event }: { event: GuardEvent }) {
  const [open, setOpen] = useState(false)
  const entries = Object.entries(event.features)

  if (entries.length === 0) {
    return (
      <Unavailable
        what="No feature vector recorded"
        why="The gateway writes an empty features object when extraction raised for this request. The raw request is not retained, so it cannot be recomputed."
      />
    )
  }

  const grouped = new Map<string, Array<[string, number]>>()
  for (const entry of entries) {
    const g = groupOf(entry[0])
    if (!grouped.has(g)) grouped.set(g, [])
    grouped.get(g)!.push(entry)
  }
  const order = [...GROUPS.map((g) => g.title), 'Other'].filter((t) => grouped.has(t))

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-1.5 rounded-md px-1 py-1 text-xs text-slate-b hover:text-slate-hi"
      >
        {open ? <ChevronDown className="h-3.5 w-3.5" aria-hidden /> : <ChevronRight className="h-3.5 w-3.5" aria-hidden />}
        {entries.length} behavioural features logged for this request
      </button>

      {open && (
        <div className="mt-2 space-y-3">
          {order.map((title) => {
            const note = GROUPS.find((g) => g.title === title)?.note
            return (
              <div key={title}>
                <p className="text-[11px] font-semibold text-slate-b">{title}</p>
                {note && <p className="mb-1.5 text-[10px] text-slate-t">{note}</p>}
                <div className="grid grid-cols-1 gap-x-4 gap-y-0.5 sm:grid-cols-2 xl:grid-cols-3">
                  {grouped.get(title)!.map(([name, value]) => (
                    <div key={name} className="flex items-baseline justify-between gap-2 border-b border-ink-800/60 py-0.5">
                      <span className="truncate font-mono text-[10px] text-slate-t" title={name}>
                        {name}
                      </span>
                      <span className="num shrink-0 font-mono text-[10px] text-slate-hi">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
