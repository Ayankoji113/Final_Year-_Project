import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { AXIS, C, CATEGORICAL, TOOLTIP_STYLE } from './chartTheme'
import { EmptyState } from '../common/Panel'
import { layerMeta, type Tally, type TimeBucket } from '../../utils/derive'

const LEGEND_STYLE = { fontSize: 11, color: C.axis }

/** Request volume over the span covered by the loaded log window. */
export function TrafficOverTime({ buckets, height = 220 }: { buckets: TimeBucket[]; height?: number }) {
  if (buckets.length === 0) {
    return <EmptyState title="No traffic in the loaded log window" hint="Send a request through the gateway on port 5000 and it will appear here." />
  }
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={buckets} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <defs>
          {(['allowed', 'observed', 'blocked'] as const).map((k) => (
            <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={C[k]} stopOpacity={0.45} />
              <stop offset="100%" stopColor={C[k]} stopOpacity={0.02} />
            </linearGradient>
          ))}
        </defs>
        <XAxis dataKey="label" {...AXIS} minTickGap={48} />
        <YAxis {...AXIS} width={56} allowDecimals={false} />
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ stroke: C.border }} />
        <Legend wrapperStyle={LEGEND_STYLE} iconSize={8} />
        <Area type="monotone" dataKey="allowed" name="Allowed" stackId="1" stroke={C.allowed} fill="url(#g-allowed)" strokeWidth={1.5} />
        <Area type="monotone" dataKey="observed" name="Would block" stackId="1" stroke={C.observed} fill="url(#g-observed)" strokeWidth={1.5} />
        <Area type="monotone" dataKey="blocked" name="Blocked" stackId="1" stroke={C.blocked} fill="url(#g-blocked)" strokeWidth={1.5} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export interface DonutSlice {
  name: string
  value: number
  color: string
}

export function OutcomeDonut({ slices, height = 220 }: { slices: DonutSlice[]; height?: number }) {
  const nonZero = slices.filter((s) => s.value > 0)
  if (nonZero.length === 0) return <EmptyState title="No decisions recorded yet" />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie data={nonZero} dataKey="value" nameKey="name" innerRadius="55%" outerRadius="82%" paddingAngle={2} stroke={C.surface} strokeWidth={2}>
          {nonZero.map((s) => (
            <Cell key={s.name} fill={s.color} />
          ))}
        </Pie>
        <Tooltip contentStyle={TOOLTIP_STYLE} />
        <Legend wrapperStyle={LEGEND_STYLE} iconSize={8} />
      </PieChart>
    </ResponsiveContainer>
  )
}

/**
 * Which layer decided, using the gateway's own `layer` string.
 *
 * This is the chart that stops the console from claiming every block was the
 * model's doing: L1 signature blocks, L1 rate blocks and L4 ML detections are
 * three separate bars with three separate colours.
 */
export function LayerBreakdown({ tallies, height = 220 }: { tallies: Tally[]; height?: number }) {
  if (tallies.length === 0) return <EmptyState title="No decisions in the loaded log window" />
  const data = tallies.map((t) => {
    const meta = layerMeta(t.key)
    const color =
      meta.kind === 'rule'
        ? C.rule
        : meta.kind === 'rate'
          ? C.rate
          : meta.kind === 'ml'
            ? C.ml
            : meta.kind === 'error'
              ? C.blocked
              : meta.kind === 'degraded'
                ? C.observed
                : C.allowed
    return { name: meta.label, count: t.count, color }
  })
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 4, bottom: 4 }}>
        <XAxis type="number" {...AXIS} allowDecimals={false} />
        <YAxis type="category" dataKey="name" {...AXIS} width={132} />
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(59,130,246,0.06)' }} />
        <Bar dataKey="count" name="Requests" radius={[0, 4, 4, 0]} barSize={16}>
          {data.map((d) => (
            <Cell key={d.name} fill={d.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

/** Attack categories, straight from the rule table's own category field. */
export function CategoryBreakdown({ tallies, height = 220 }: { tallies: Tally[]; height?: number }) {
  if (tallies.length === 0) {
    return (
      <EmptyState
        title="No categorised rule hits in this window"
        hint="Categories come from the Layer-1 rule table. A request that matched no signature has no category, and none is invented for it."
      />
    )
  }
  const data = tallies.slice(0, 10).map((t, i) => ({ name: t.key, count: t.count, color: CATEGORICAL[i % CATEGORICAL.length] }))
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <XAxis dataKey="name" {...AXIS} interval={0} angle={-25} textAnchor="end" height={52} />
        <YAxis {...AXIS} width={56} allowDecimals={false} />
        <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(59,130,246,0.06)' }} />
        <Bar dataKey="count" name="Events" radius={[4, 4, 0, 0]} barSize={28}>
          {data.map((d) => (
            <Cell key={d.name} fill={d.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
