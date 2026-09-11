import type { Tally } from '../../utils/derive'
import { formatInt } from '../../utils/format'

/**
 * The detection pipeline, drawn as it is actually implemented.
 *
 * Two things the picture has to get right, because they are the parts people
 * get wrong about this system:
 *
 *   - a BLOCK-severity L1 signature or a rate-limit trip short-circuits, so
 *     L2/L3/L4 never see that request. Those exits leave the spine early.
 *   - L4 is the only thing that decides. L2 and L3 produce features for it,
 *     they do not vote.
 *
 * Counts, when supplied, come from the loaded log window.
 */
export interface StageCount {
  l1Rules: number
  l1Rate: number
  ml: number
  allowed: number
  reachedModels: number
  total: number
}

function Stage({
  index,
  title,
  subtitle,
  tone,
  detail,
}: {
  index: string
  title: string
  subtitle: string
  tone: 'neutral' | 'rule' | 'rate' | 'ml' | 'decide'
  detail?: string
}) {
  const ring = {
    neutral: 'border-ink-600',
    rule: 'border-bad-500/35',
    rate: 'border-warn-500/35',
    ml: 'border-ml-500/35',
    decide: 'border-accent-500/40',
  }[tone]
  const tag = {
    neutral: 'text-slate-t',
    rule: 'text-bad-400',
    rate: 'text-warn-400',
    ml: 'text-ml-400',
    decide: 'text-accent-300',
  }[tone]
  return (
    <div className={`rounded-lg border bg-ink-900/60 px-3.5 py-2.5 ${ring}`}>
      <div className="flex items-baseline gap-2">
        <span className={`font-mono text-[10px] font-semibold ${tag}`}>{index}</span>
        <span className="text-xs font-semibold text-slate-hi">{title}</span>
      </div>
      <p className="mt-0.5 text-[11px] text-slate-t">{subtitle}</p>
      {detail && <p className="num mt-1 text-[11px] text-slate-b">{detail}</p>}
    </div>
  )
}

function Exit({ label, count, tone }: { label: string; count: string; tone: 'rule' | 'rate' | 'ml' }) {
  const color = tone === 'rule' ? 'text-bad-400 border-bad-500/30' : tone === 'rate' ? 'text-warn-400 border-warn-500/30' : 'text-ml-400 border-ml-500/30'
  return (
    <div className={`flex items-center gap-2 rounded-lg border bg-ink-900/40 px-3 py-2 ${color}`}>
      <span aria-hidden className="text-sm">
        &#8600;
      </span>
      <div className="min-w-0">
        <p className="text-[11px] font-semibold">{label}</p>
        <p className="num text-[11px] text-slate-t">{count}</p>
      </div>
    </div>
  )
}

function Connector() {
  return (
    <div className="flex justify-center py-1" aria-hidden>
      <span className="text-slate-t">&#8595;</span>
    </div>
  )
}

export function PipelineDiagram({ counts, featureCount }: { counts: StageCount | null; featureCount: number }) {
  const n = (v: number | undefined) => (counts ? `${formatInt(v ?? 0)} requests` : 'no log window loaded')

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_220px]">
      <div>
        <Stage index="in" title="Client request" tone="neutral" subtitle="Any HTTP method, any path. The gateway knows nothing about the backend's routes." detail={counts ? `${formatInt(counts.total)} in the loaded window` : undefined} />
        <Connector />
        <Stage index="0" title="Normalisation" subtitle="Percent-, double-percent-, entity- and unicode-decoding collapse onto one canonical form, plus a path template." tone="neutral" />
        <Connector />
        <Stage index="L1" title="Signature rules and rate limiting" subtitle="26 deterministic patterns, plus Redis sliding-window and burst counters. A BLOCK hit or a rate trip returns 403 here and stops." tone="rule" />
        <Connector />
        <Stage index="FE" title="Feature engineering" subtitle={`${featureCount || 34} behavioural features: body shape, path shape, query shape, endpoint breadth, method, FLAG count. No endpoint identity, no client headers.`} tone="neutral" detail={counts ? `${formatInt(counts.reachedModels)} requests reached this stage` : undefined} />
        <Connector />
        <Stage index="L2" title="Isolation Forest" subtitle="Unsupervised, fitted on normal traffic only. Produces a normalised anomaly score." tone="ml" />
        <Connector />
        <Stage index="L3" title="NumPy autoencoder" subtitle="Unsupervised, fitted on normal traffic only. Produces a normalised reconstruction error." tone="ml" />
        <Connector />
        <Stage index="L4" title="HistGradientBoosting meta-learner" subtitle="Consumes exactly three inputs: the L1 rate score, the L2 score, the L3 score. This is the only layer that decides." tone="decide" />
        <Connector />
        <Stage index="out" title="Allow or block, then JSONL logging" subtitle="Allowed requests are proxied upstream. Every request is appended to the event log as a numeric feature vector, never a raw body." tone="neutral" detail={counts ? `${formatInt(counts.allowed)} allowed` : undefined} />
      </div>

      <div className="flex flex-col gap-2 lg:pt-24">
        <p className="text-[10px] tracking-wide text-slate-t uppercase">Early exits</p>
        <Exit label="403 - L1 signature" count={n(counts?.l1Rules)} tone="rule" />
        <Exit label="403 - L1 rate limit" count={n(counts?.l1Rate)} tone="rate" />
        <Exit label="L4 verdict" count={n(counts?.ml)} tone="ml" />
        <p className="mt-1 text-[10px] leading-relaxed text-slate-t">
          The two L1 exits short-circuit: those requests never reach a model. Sending a confirmed UNION SELECT to a
          statistical model to ask its opinion adds latency and a chance of being wrong about something already certain.
        </p>
      </div>
    </div>
  )
}

export function stageCounts(tallies: Tally[], total: number, allowed: number): StageCount {
  const get = (k: string) => tallies.find((t) => t.key === k)?.count ?? 0
  const l1Rules = get('L1-rules')
  const l1Rate = get('L1-rate')
  return {
    l1Rules,
    l1Rate,
    ml: get('L4-meta'),
    allowed,
    reachedModels: Math.max(0, total - l1Rules - l1Rate),
    total,
  }
}
