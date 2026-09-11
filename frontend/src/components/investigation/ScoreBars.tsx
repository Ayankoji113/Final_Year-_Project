import type { GuardEvent } from '../../types'
import { Pill } from '../status/Badges'
import { Unavailable } from '../common/Panel'
import { formatProbability } from '../../utils/format'

interface Row {
  key: string
  label: string
  note: string
  value: number | undefined
  color: string
}

/**
 * The three base-detector scores that L4 consumes, plus L4's own output.
 *
 * `meta_inputs` in decision.json is exactly ["rate", "isolation_forest",
 * "autoencoder"], so these are the real inputs to the meta-learner and not a
 * decorative breakdown. The Isolation Forest and autoencoder values are the
 * min-max normalised forms the gateway computed with if_lo/if_hi and
 * ae_lo/ae_hi; the raw decision_function and reconstruction-error values are
 * not written to the log.
 */
export function ScoreBars({ event, threshold }: { event: GuardEvent; threshold: number | null }) {
  const s = event.scores

  if (event.layer === 'L1-rules') {
    return (
      <Unavailable
        what="No model scores for this request"
        why="A BLOCK-severity signature matched, and the pipeline short-circuits at L1 before the Isolation Forest, the autoencoder or the meta-learner run. The gateway recorded scores = {rule: 1.0}."
      />
    )
  }
  if (event.layer === 'L1-rate') {
    return (
      <Unavailable
        what="No model scores for this request"
        why="The client exceeded the configured rate limit, and the pipeline short-circuits at L1 before any model runs. The gateway recorded scores = {rate: 1.0}."
      />
    )
  }
  if (event.layer === 'L1-only') {
    return (
      <Unavailable
        what="No model scores for this request"
        why="The anomaly models were not loaded when this request was handled, so only the signature and rate layers ran."
      />
    )
  }
  if (s.meta_lr === undefined && s.isolation_forest === undefined && s.autoencoder === undefined) {
    return (
      <Unavailable
        what="No model scores recorded"
        why="This log record carries no scores object. That happens when inference raised before producing one."
      />
    )
  }

  const rows: Row[] = [
    {
      key: 'rate',
      label: 'L1 rate score',
      note: 'max(window/limit, burst/burst-limit), clipped to 1',
      value: s.rate,
      color: 'bg-warn-500',
    },
    {
      key: 'isolation_forest',
      label: 'L2 Isolation Forest',
      note: 'normalised path-length anomaly score',
      value: s.isolation_forest,
      color: 'bg-accent-500',
    },
    {
      key: 'autoencoder',
      label: 'L3 Autoencoder',
      note: 'normalised reconstruction error',
      value: s.autoencoder,
      color: 'bg-ml-500',
    },
  ]

  const p = s.meta_lr ?? event.probability
  const crossed = threshold !== null && p >= threshold

  return (
    <div className="space-y-3">
      {rows.map((r) => (
        <div key={r.key}>
          <div className="flex items-baseline justify-between gap-2">
            <span className="text-xs text-slate-b">{r.label}</span>
            <span className="num text-xs text-slate-hi">{r.value === undefined ? 'not recorded' : r.value.toFixed(4)}</span>
          </div>
          <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-ink-800">
            <div
              className={`h-full rounded-full ${r.color}`}
              style={{ width: `${Math.max(0, Math.min(1, r.value ?? 0)) * 100}%` }}
            />
          </div>
          <p className="mt-0.5 text-[10px] text-slate-t">{r.note}</p>
        </div>
      ))}

      <div className="rounded-lg border border-ink-600 bg-ink-900/60 p-3">
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-xs font-semibold text-slate-hi">L4 meta-learner output</span>
          <span className={`num text-sm font-semibold ${crossed ? 'text-bad-400' : 'text-ok-400'}`}>
            {formatProbability(p)}
          </span>
        </div>
        <div className="relative mt-2 h-2 w-full overflow-hidden rounded-full bg-ink-800">
          <div
            className={`h-full rounded-full ${crossed ? 'bg-bad-500' : 'bg-ok-500'}`}
            style={{ width: `${Math.max(0, Math.min(1, p)) * 100}%` }}
          />
          {threshold !== null && (
            <div
              className="absolute inset-y-0 w-0.5 bg-slate-hi"
              style={{ left: `${Math.max(0, Math.min(1, threshold)) * 100}%` }}
              title={`Decision threshold ${threshold.toFixed(4)}`}
            />
          )}
        </div>
        <p className="mt-1.5 text-[11px] text-slate-t">
          {threshold === null ? (
            'Threshold unknown: the gateway is unreachable and no decision.json was readable.'
          ) : (
            <>
              Decision threshold <span className="num text-slate-b">{threshold.toFixed(4)}</span>.{' '}
              {crossed ? 'This request crossed it.' : 'This request stayed below it.'}
            </>
          )}
        </p>
        {crossed && !event.enforced && (
          <Pill tone="warn" className="mt-2">
            Recorded only - the mode in force did not enforce this ML verdict
          </Pill>
        )}
      </div>
    </div>
  )
}
