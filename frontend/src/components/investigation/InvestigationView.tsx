import { useState } from 'react'
import { Check, Copy, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import type { GuardEvent, GuardRule } from '../../types'
import { layerMeta, outcomeOf } from '../../utils/derive'
import { formatEventDateTime, formatInt, formatMs } from '../../utils/format'
import { DecisionBadge, LayerBadge, MethodBadge, Pill, StatusBadge } from '../status/Badges'
import { Panel, SourceNote, Unavailable } from '../common/Panel'
import { ScoreBars } from './ScoreBars'
import { FeatureVector } from './FeatureVector'

function Field({ label, children, mono = false }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="border-b border-ink-800/70 py-1.5">
      <dt className="text-[10px] tracking-wide text-slate-t uppercase">{label}</dt>
      <dd className={`mt-0.5 text-xs break-words text-slate-hi ${mono ? 'font-mono' : ''}`}>{children}</dd>
    </div>
  )
}

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setDone(true)
          setTimeout(() => setDone(false), 1500)
        })
      }}
      className="inline-flex h-7 items-center gap-1.5 rounded-md border border-ink-600 px-2 text-[11px] text-slate-b hover:border-ink-500 hover:text-slate-hi"
    >
      {done ? <Check className="h-3 w-3 text-ok-400" aria-hidden /> : <Copy className="h-3 w-3" aria-hidden />}
      {done ? 'Copied' : 'Copy JSON'}
    </button>
  )
}

/** The verdict banner. Its wording is driven entirely by `layer` and `enforced`. */
function VerdictHeader({ event }: { event: GuardEvent }) {
  const outcome = outcomeOf(event)
  const meta = layerMeta(event.layer)

  const Icon = outcome === 'allowed' ? ShieldCheck : outcome === 'blocked' ? ShieldAlert : ShieldQuestion
  const tint =
    outcome === 'allowed'
      ? 'border-ok-500/25 bg-ok-500/5'
      : outcome === 'blocked'
        ? 'border-bad-500/25 bg-bad-500/5'
        : 'border-warn-500/25 bg-warn-500/5'
  const iconColor = outcome === 'allowed' ? 'text-ok-400' : outcome === 'blocked' ? 'text-bad-400' : 'text-warn-400'

  const headline =
    outcome === 'allowed'
      ? 'Request allowed'
      : outcome === 'blocked'
        ? `Blocked by ${meta.label}`
        : `${meta.label} verdict recorded, request forwarded`

  return (
    <div className={`rounded-lg border p-4 ${tint}`}>
      <div className="flex items-start gap-3">
        <Icon className={`mt-0.5 h-5 w-5 shrink-0 ${iconColor}`} aria-hidden />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-slate-hi">{headline}</p>
          <p className="mt-1 text-xs text-slate-b">
            {event.reason || 'The gateway recorded no reason string, which is what it writes for a request that passed every layer.'}
          </p>
          <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
            <DecisionBadge event={event} />
            <LayerBadge layer={event.layer} full />
            <StatusBadge status={event.status} />
            {event.degraded && (
              <Pill tone="warn" title="Redis was unavailable or inference failed, so the rate counters and scores on this record are not trustworthy.">
                Degraded
              </Pill>
            )}
            {event.label && <Pill tone="info">ground-truth label: {event.label}</Pill>}
          </div>
          <p className="mt-2.5 text-[11px] text-slate-t">{meta.description}</p>
        </div>
      </div>
    </div>
  )
}

/** Rule evidence, cross-referenced against the live rule table where available. */
function RuleEvidence({ event, rules }: { event: GuardEvent; rules: GuardRule[] | null }) {
  if (event.rule_hits.length === 0) {
    return (
      <Unavailable
        what="No signature matched"
        why="rule_hits is empty for this request. No Layer-1 pattern fired against the normalised path or body."
      />
    )
  }
  const byId = new Map((rules ?? []).map((r) => [r.id, r]))
  return (
    <div className="space-y-2">
      {event.rule_hits.map((id) => {
        const rule = byId.get(id)
        return (
          <div key={id} className="rounded-lg border border-ink-700 bg-ink-900/50 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <code className="font-mono text-xs text-slate-hi">{id}</code>
              {rule ? (
                <>
                  <Pill tone={rule.severity === 'block' ? 'bad' : 'warn'}>{rule.severity}</Pill>
                  <Pill tone="mute">{rule.category}</Pill>
                  <Pill tone="mute">matches: {rule.target}</Pill>
                </>
              ) : (
                <Pill tone="mute">rule table unavailable</Pill>
              )}
            </div>
            <p className="mt-1.5 text-[11px] text-slate-b">
              {rule ? rule.why : 'This rule id is not in the parsed rule table, so no description is shown rather than one being invented.'}
            </p>
          </div>
        )
      })}
      {event.categories.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <span className="text-[10px] tracking-wide text-slate-t uppercase">Categories</span>
          {event.categories.map((c) => (
            <Pill key={c} tone="info">
              {c}
            </Pill>
          ))}
        </div>
      )}
      <SourceNote>
        A FLAG-severity hit does not block. It is handed to the model as the <code>n_flags</code> feature and weighed
        alongside everything else. Only a BLOCK-severity hit short-circuits the pipeline.
      </SourceNote>
    </div>
  )
}

export function InvestigationView({
  event,
  threshold,
  rules,
}: {
  event: GuardEvent
  threshold: number | null
  rules: GuardRule[] | null
}) {
  const raw = JSON.stringify(event, null, 2)

  return (
    <div className="space-y-4">
      <VerdictHeader event={event} />

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Request" subtitle="Fields the gateway records. Raw URL, query, body and headers are deliberately not logged.">
          <dl>
            <Field label="Timestamp">
              {formatEventDateTime(event.ts)}{' '}
              <span className="font-mono text-[11px] text-slate-t">(ts {event.ts})</span>
            </Field>
            <Field label="Method">
              <MethodBadge method={event.method} />
            </Field>
            <Field label="Endpoint template" mono>
              {event.template}
            </Field>
            <Field label="Path length">{formatInt(event.path_len)} characters</Field>
            <Field label="Body size">{formatInt(event.body_size)} bytes</Field>
            <Field label="Client" mono>
              {event.client}
              <span className="ml-2 font-sans text-[10px] text-slate-t">SHA-256 prefix, pseudonymised at the gateway</span>
            </Field>
            <Field label="Response status">
              <StatusBadge status={event.status} />
            </Field>
            <Field label="Rate counters at decision time">
              {formatInt(event.window_count)} in the sliding window, {formatInt(event.burst_count)} in the burst window
            </Field>
            <Field label="Detection time">{formatMs(event.detect_ms, 3)}</Field>
            <Field label="End-to-end latency">
              {formatMs(event.latency_ms, 3)}
              {event.action === 'block' && event.enforced && (
                <span className="ml-2 text-[10px] text-slate-t">equals detect time: the request never reached the backend</span>
              )}
            </Field>
          </dl>
        </Panel>

        <div className="space-y-4">
          <Panel title="Rule evidence" subtitle="Layer 1 signature matches recorded on this request">
            <RuleEvidence event={event} rules={rules} />
          </Panel>

          <Panel title="ML evidence" subtitle="Base-detector scores and the L4 decision">
            <ScoreBars event={event} threshold={threshold} />
          </Panel>
        </div>
      </div>

      <Panel title="Feature vector" subtitle="Logged by common/features.extract(), the same function the trainer calls">
        <FeatureVector event={event} />
      </Panel>

      <Panel title="Raw event record" subtitle="One verbatim line from src/data/events.jsonl" actions={<CopyButton text={raw} />}>
        <pre className="scroll-x max-h-96 overflow-y-auto rounded-lg bg-ink-950/70 p-3 font-mono text-[11px] leading-relaxed text-slate-b">
          {raw}
        </pre>
        <SourceNote>
          <code>_offset</code> is the record's byte position in the log. The console adds it as a stable identifier; it is
          not written by the gateway.
        </SourceNote>
      </Panel>
    </div>
  )
}
