import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { BrainCircuit, Gauge, ShieldAlert, ShieldBan, TriangleAlert } from 'lucide-react'
import { useTraffic } from '../hooks/useTraffic'
import { useRules } from '../hooks/useArtifacts'
import { useEventFilter } from '../hooks/useEventFilter'
import { MetricCard } from '../components/cards/MetricCard'
import { EventTable } from '../components/tables/EventTable'
import { FilterBar } from '../components/tables/FilterBar'
import { EmptyState, Panel, SourceNote, Unavailable } from '../components/common/Panel'
import { CategoryBreakdown } from '../components/charts/TrafficCharts'
import { Pill } from '../components/status/Badges'
import { categoryCounts, eventKey, ruleHitCounts, summarise, threatEvents } from '../utils/derive'
import { formatInt } from '../utils/format'

function TallyList({
  rows,
  describe,
  emptyTitle,
}: {
  rows: Array<{ key: string; count: number }>
  describe?: (key: string) => { label: string; note: string; severity?: string } | null
  emptyTitle: string
}) {
  if (rows.length === 0) return <EmptyState title={emptyTitle} />
  const max = rows[0].count
  return (
    <ul className="space-y-1.5">
      {rows.map((r) => {
        const d = describe?.(r.key) ?? null
        return (
          <li key={r.key} className="border-b border-ink-800/60 pb-1.5 last:border-0">
            <div className="flex items-baseline justify-between gap-2">
              <span className="flex min-w-0 items-center gap-1.5">
                <code className="truncate font-mono text-[11px] text-slate-hi" title={r.key}>
                  {r.key}
                </code>
                {d?.severity && <Pill tone={d.severity === 'block' ? 'bad' : 'warn'}>{d.severity}</Pill>}
              </span>
              <span className="num shrink-0 text-[11px] text-slate-b">{formatInt(r.count)}</span>
            </div>
            <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-ink-800">
              <div className="h-full rounded-full bg-accent-500/70" style={{ width: `${(r.count / max) * 100}%` }} />
            </div>
            {d?.note && <p className="mt-1 text-[10px] text-slate-t">{d.note}</p>}
          </li>
        )
      })}
    </ul>
  )
}

export function Threats() {
  const traffic = useTraffic()
  const rules = useRules()
  const navigate = useNavigate()

  const threats = useMemo(() => threatEvents(traffic.events), [traffic.events])
  const summary = useMemo(() => summarise(traffic.events), [traffic.events])
  const categories = useMemo(() => categoryCounts(threats), [threats])
  const ruleHits = useMemo(() => ruleHitCounts(threats).slice(0, 12), [threats])

  const { filter, setFilter, filtered, options, active, reset } = useEventFilter(threats)
  const newestFirst = useMemo(() => [...filtered].reverse(), [filtered])

  const ruleById = useMemo(() => new Map((rules.data?.rules ?? []).map((r) => [r.id, r])), [rules.data])

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Blocked (enforced)"
          value={formatInt(summary.blocked)}
          icon={ShieldBan}
          tone="bad"
          source="action == block and enforced == true"
          detail="returned 403; never reached the backend"
        />
        <MetricCard
          label="L1 rule blocks"
          value={formatInt(summary.l1RuleBlocks)}
          icon={ShieldAlert}
          tone="bad"
          source="layer == L1-rules"
          detail="a BLOCK-severity signature matched"
        />
        <MetricCard
          label="L1 rate blocks"
          value={formatInt(summary.l1RateBlocks)}
          icon={Gauge}
          tone="warn"
          source="layer == L1-rate"
          detail="policy limit, not a model prediction"
        />
        <MetricCard
          label="ML detections"
          value={formatInt(summary.mlDetections)}
          icon={BrainCircuit}
          tone="ml"
          source="layer == L4-meta"
          detail={
            summary.observed > 0
              ? `${formatInt(summary.observed)} recorded but not enforced`
              : 'meta-learner crossed the threshold'
          }
        />
      </div>

      {summary.observed > 0 && (
        <div className="flex items-start gap-2.5 rounded-lg border border-warn-500/25 bg-warn-500/5 p-3.5">
          <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-warn-400" aria-hidden />
          <p className="text-xs text-slate-b">
            <span className="font-semibold text-warn-400">{formatInt(summary.observed)} verdicts were recorded but not
            enforced.</span>{' '}
            The gateway decided these requests were hostile and still forwarded them, because the mode in force does not
            enforce that layer. They are shown as "Would block", never as blocks.
          </p>
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel className="xl:col-span-2" title="Attack categories" subtitle="Category field of the Layer-1 rules that matched">
          <CategoryBreakdown tallies={categories} height={240} />
          <SourceNote>
            Only requests that matched a signature carry a category. A block from the rate limiter or from L4 alone has
            none, and none is assigned to it. HTTP status codes are never used to classify an attack.
          </SourceNote>
        </Panel>

        <Panel title="Most-hit signatures" subtitle={rules.data ? `${rules.data.count} rules in the table` : 'rule table loading'}>
          <TallyList
            rows={ruleHits}
            emptyTitle="No signature matched in this window"
            describe={(id) => {
              const r = ruleById.get(id)
              return r ? { label: r.id, note: r.why, severity: r.severity } : null
            }}
          />
        </Panel>
      </div>

      <Panel
        title="Security events"
        subtitle="Blocked, would-block, and requests that tripped a FLAG-severity signature without being blocked"
        bodyClassName="p-4 pb-0"
      >
        <FilterBar
          filter={filter}
          setFilter={setFilter}
          options={options}
          active={active}
          reset={reset}
          resultCount={filtered.length}
          totalCount={threats.length}
        />
      </Panel>

      <Panel bodyClassName="" className="overflow-hidden">
        {traffic.missingMessage ? (
          <div className="p-4">
            <Unavailable what="Event log not readable" why={traffic.missingMessage} />
          </div>
        ) : (
          <EventTable
            events={newestFirst}
            columns={['time', 'method', 'template', 'status', 'decision', 'layer', 'probability', 'reason']}
            onSelect={(e) => navigate(`/investigate/${eventKey(e)}`)}
            emptyTitle={active ? 'No security events match these filters' : 'No security events in the loaded window'}
            emptyHint="Every loaded request passed Layer 1 and stayed below the L4 threshold."
            maxHeight="max-h-[55vh]"
          />
        )}
      </Panel>
    </div>
  )
}
