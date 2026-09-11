import { Search, X } from 'lucide-react'
import { layerMeta } from '../../utils/derive'
import { TIME_WINDOWS, type EventFilterState } from '../../hooks/useEventFilter'

const control =
  'h-8 rounded-md border border-ink-600 bg-ink-900/80 px-2 text-xs text-slate-hi transition-colors hover:border-ink-500 focus:border-accent-500'

function Select({
  label,
  value,
  onChange,
  children,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  children: React.ReactNode
}) {
  return (
    <label className="flex items-center gap-1.5">
      <span className="text-[10px] tracking-wide text-slate-t uppercase">{label}</span>
      <select className={control} value={value} onChange={(e) => onChange(e.target.value)}>
        {children}
      </select>
    </label>
  )
}

export function FilterBar({
  filter,
  setFilter,
  options,
  active,
  reset,
  resultCount,
  totalCount,
  showTimeWindow = true,
}: {
  filter: EventFilterState
  setFilter: (updater: (prev: EventFilterState) => EventFilterState) => void
  options: { methods: string[]; statuses: string[]; layers: string[] }
  active: boolean
  reset: () => void
  resultCount: number
  totalCount: number
  showTimeWindow?: boolean
}) {
  const set = <K extends keyof EventFilterState>(key: K, value: EventFilterState[K]) =>
    setFilter((prev) => ({ ...prev, [key]: value }))

  return (
    <div className="flex flex-wrap items-center gap-2.5">
      <div className="relative min-w-[180px] flex-1">
        <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-t" aria-hidden />
        <input
          type="search"
          value={filter.search}
          onChange={(e) => set('search', e.target.value)}
          placeholder="Search endpoint, reason, rule id, category, client hash"
          aria-label="Search events"
          className={`${control} w-full pl-8`}
        />
      </div>

      <Select label="Method" value={filter.method} onChange={(v) => set('method', v)}>
        <option value="all">All</option>
        {options.methods.map((m) => (
          <option key={m} value={m}>
            {m}
          </option>
        ))}
      </Select>

      <Select label="Status" value={filter.statusClass} onChange={(v) => set('statusClass', v)}>
        <option value="all">All</option>
        {options.statuses.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </Select>

      <Select label="Layer" value={filter.layer} onChange={(v) => set('layer', v)}>
        <option value="all">All</option>
        {options.layers.map((l) => (
          <option key={l} value={l}>
            {layerMeta(l).label}
          </option>
        ))}
      </Select>

      <Select label="Decision" value={filter.outcome} onChange={(v) => set('outcome', v)}>
        <option value="all">All</option>
        <option value="allowed">Allowed</option>
        <option value="blocked">Blocked</option>
        <option value="observed">Would block</option>
      </Select>

      {showTimeWindow && (
        <Select label="Window" value={String(filter.windowSecs)} onChange={(v) => set('windowSecs', Number(v))}>
          {TIME_WINDOWS.map((w) => (
            <option key={w.secs} value={w.secs}>
              {w.label}
            </option>
          ))}
        </Select>
      )}

      <span className="num ml-auto text-[11px] text-slate-t">
        {resultCount.toLocaleString()} of {totalCount.toLocaleString()}
      </span>

      {active && (
        <button type="button" onClick={reset} className={`${control} inline-flex items-center gap-1 text-slate-b`}>
          <X className="h-3 w-3" aria-hidden />
          Clear
        </button>
      )}
    </div>
  )
}
