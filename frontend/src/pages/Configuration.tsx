import { useMemo, useState } from 'react'
import { Lock, RefreshCw, ShieldAlert } from 'lucide-react'
import { useHealth } from '../hooks/useHealth'
import { useArtifacts, useConfigDefaults, useRules } from '../hooks/useArtifacts'
import { reloadModels } from '../services/health'
import { Loading, Panel, SourceNote } from '../components/common/Panel'
import { ModeBadge, Pill } from '../components/status/Badges'
import { formatInt } from '../utils/format'

/**
 * Read-only, with one exception.
 *
 * The gateway exposes exactly one mutating admin endpoint, POST
 * /__guard/reload, which re-reads the model files and the calibration
 * baseline. It already exists; the console surfaces it behind a confirmation
 * rather than inventing settings the backend has no way to accept.
 */

function Row({
  label,
  value,
  source,
  note,
  tone,
}: {
  label: string
  value: React.ReactNode
  source: string
  note?: string
  tone?: 'live' | 'default'
}) {
  return (
    <tr className="border-b border-ink-800/70">
      <td className="px-3 py-2 align-top">
        <p className="font-mono text-[11px] text-slate-hi">{label}</p>
        {note && <p className="mt-0.5 max-w-md text-[10px] text-slate-t">{note}</p>}
      </td>
      <td className="num px-3 py-2 align-top text-xs text-slate-hi">{value}</td>
      <td className="px-3 py-2 align-top">
        <Pill tone={tone === 'live' ? 'ok' : 'mute'}>{tone === 'live' ? 'live' : 'source default'}</Pill>
      </td>
      <td className="px-3 py-2 align-top font-mono text-[10px] text-slate-t">{source}</td>
    </tr>
  )
}

function Table({ children }: { children: React.ReactNode }) {
  return (
    <div className="scroll-x">
      <table className="w-full min-w-[640px] text-left">
        <thead>
          <tr className="border-b border-ink-700">
            {['Setting', 'Value', 'Reading', 'Source'].map((th) => (
              <th key={th} className="px-3 py-2 text-[10px] font-semibold tracking-wide text-slate-t uppercase">
                {th}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

const LIMIT_KEYS = new Set(['MAX_BODY_BYTES', 'BODY_INSPECT_BYTES', 'UPSTREAM_TIMEOUT'])
const SAFETY_KEYS = new Set([
  'FAIL_CLOSED',
  'TRUST_LABEL_HEADER',
  'TRUSTED_PROXY_HOPS',
  'CALIBRATION_MIN_SAMPLES',
  'CALIBRATION_TARGET_FPR',
])

export function Configuration() {
  const health = useHealth()
  const config = useConfigDefaults()
  const rules = useRules()
  const artifacts = useArtifacts()
  const [reloadState, setReloadState] = useState<{ busy: boolean; message: string | null }>({
    busy: false,
    message: null,
  })
  const [confirming, setConfirming] = useState(false)

  const h = health.data
  const defaults = config.data?.defaults ?? []
  const byName = useMemo(() => new Map(defaults.map((d) => [d.name, d])), [defaults])
  const get = (name: string) => byName.get(name)?.default ?? '--'

  const ruleGroups = useMemo(() => {
    const m = new Map<string, { block: number; flag: number }>()
    for (const r of rules.data?.rules ?? []) {
      const g = m.get(r.category) ?? { block: 0, flag: 0 }
      g[r.severity] += 1
      m.set(r.category, g)
    }
    return [...m.entries()].sort((a, b) => b[1].block + b[1].flag - (a[1].block + a[1].flag))
  }, [rules.data])

  const doReload = async () => {
    setReloadState({ busy: true, message: null })
    try {
      const res = await reloadModels()
      setReloadState({
        busy: false,
        message: res.reloaded
          ? `Models reloaded. Calibration baseline ${res.calibrated ? 'is ready' : 'is not ready'}.`
          : 'The gateway reported that the reload failed. Check its logs.',
      })
      health.refresh()
    } catch (err) {
      setReloadState({ busy: false, message: err instanceof Error ? err.message : String(err) })
    } finally {
      setConfirming(false)
    }
  }

  const controlClass =
    'inline-flex h-8 items-center gap-1.5 rounded-md border border-ink-600 px-2.5 text-xs text-slate-b transition-colors hover:border-ink-500 hover:text-slate-hi disabled:opacity-50'

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2.5 rounded-lg border border-accent-500/25 bg-accent-500/5 p-3.5">
        <Lock className="mt-0.5 h-4 w-4 shrink-0 text-accent-300" aria-hidden />
        <p className="text-xs text-slate-b">
          This page is read-only. The gateway exposes no configuration-write API, so nothing here can be edited from the
          browser. Values marked <span className="font-semibold text-ok-400">live</span> are reported by the running
          gateway; values marked <span className="font-semibold">source default</span> are the fallbacks declared in{' '}
          <code className="font-mono">common/config.py</code> and may be overridden by the environment the container was
          started with.
        </p>
      </div>

      <Panel
        title="Operating mode"
        subtitle="Read from the gateway on every poll"
        actions={h ? <ModeBadge mode={h.mode} enforcingMl={h.enforcing_ml} /> : undefined}
      >
        <Table>
          <Row
            label="GUARD_MODE"
            value={h ? h.mode : '--'}
            tone={h ? 'live' : 'default'}
            source="health.mode"
            note="enforce blocks on rules, rate limits and ML anomalies. enforce-l1 blocks on the first two and logs the third. monitor blocks nothing."
          />
          <Row label="enforcing_rules" value={h ? String(h.enforcing_rules) : '--'} tone={h ? 'live' : 'default'} source="health.enforcing_rules" />
          <Row label="enforcing_ml" value={h ? String(h.enforcing_ml) : '--'} tone={h ? 'live' : 'default'} source="health.enforcing_ml" />
          <Row
            label="GUARD_ML_THRESHOLD"
            value={h ? h.threshold.toFixed(6) : '--'}
            tone={h ? 'live' : 'default'}
            source="health.threshold"
            note={`The trained threshold in decision.json wins over the env fallback (${get('ML_THRESHOLD')}). It is picked on the validation pool under the configured false-positive budget.`}
          />
          <Row label="models_loaded" value={h ? String(h.models_loaded) : '--'} tone={h ? 'live' : 'default'} source="health.models_loaded" />
          <Row
            label="calibrated"
            value={h ? `${h.calibrated} (${formatInt(h.calibration_samples)} samples)` : '--'}
            tone={h ? 'live' : 'default'}
            source="health.calibrated"
          />
          <Row label="redis" value={h ? String(h.redis) : '--'} tone={h ? 'live' : 'default'} source="health.redis" />
        </Table>
      </Panel>

      {config.state === 'loading' && <Loading label="Reading config.py" />}

      <Panel
        title="Rate limiting (Layer 1)"
        subtitle="Not reported by any gateway endpoint. These are the source defaults."
      >
        <Table>
          <Row label="GUARD_RATE_WINDOW_SECS" value={`${get('RATE_WINDOW_SECS')} s`} source="common/config.py" note="Length of the sliding window, per client." />
          <Row label="GUARD_RATE_LIMIT" value={`${get('RATE_LIMIT')} requests`} source="common/config.py" note="Sustained-abuse limit per window per client." />
          <Row label="GUARD_RATE_BURST_SECS" value={`${get('RATE_BURST_SECS')} s`} source="common/config.py" note="Short window that catches spikes a 60-second window would hide." />
          <Row label="GUARD_RATE_BURST_LIMIT" value={`${get('RATE_BURST_LIMIT')} requests`} source="common/config.py" note="Burst limit per client." />
        </Table>
        <SourceNote>
          These four are the values the gateway falls back to. It does not report the live numbers, so the console does
          not claim them as live. A rate-limit block in the event log spells out the limit that actually fired in its{' '}
          <code>reason</code> string, which is the one place the running value is observable.
        </SourceNote>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Request limits" subtitle="Source defaults from common/config.py">
          <Table>
            {defaults
              .filter((d) => LIMIT_KEYS.has(d.name))
              .map((d) => (
                <Row key={d.name} label={d.env} value={d.default} source="common/config.py" />
              ))}
          </Table>
        </Panel>

        <Panel title="Safety and calibration" subtitle="Source defaults from common/config.py">
          <Table>
            {defaults
              .filter((d) => SAFETY_KEYS.has(d.name))
              .map((d) => (
                <Row
                  key={d.name}
                  label={d.env}
                  value={d.default}
                  source="common/config.py"
                  note={
                    d.name === 'TRUST_LABEL_HEADER'
                      ? 'Must stay false in production: whoever can set the header can hand-label the corpus the next model trains on.'
                      : d.name === 'FAIL_CLOSED'
                        ? 'A request whose feature extraction or inference raises is treated as hostile, so a crash is not a bypass.'
                        : d.name === 'TRUSTED_PROXY_HOPS'
                          ? '0 means X-Forwarded-For is ignored entirely, because a client can set it and spoof every per-IP control.'
                          : undefined
                  }
                />
              ))}
          </Table>
        </Panel>
      </div>

      <Panel
        title="Layer-1 rule table"
        subtitle={rules.data ? `${rules.data.count} signatures parsed from ${rules.data.source}` : 'reading rules.py'}
      >
        {rules.data ? (
          <>
            <div className="mb-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              {ruleGroups.map(([category, g]) => (
                <div key={category} className="rounded-lg border border-ink-700 bg-ink-900/50 p-2.5">
                  <p className="font-mono text-xs text-slate-hi">{category}</p>
                  <p className="mt-1 flex gap-1.5">
                    {g.block > 0 && <Pill tone="bad">{g.block} block</Pill>}
                    {g.flag > 0 && <Pill tone="warn">{g.flag} flag</Pill>}
                  </p>
                </div>
              ))}
            </div>
            <div className="scroll-x max-h-96 overflow-y-auto">
              <table className="w-full min-w-[620px] text-left">
                <thead className="sticky top-0 bg-ink-850">
                  <tr className="border-b border-ink-700">
                    {['Rule id', 'Category', 'Severity', 'Matches', 'Why it fires'].map((th) => (
                      <th key={th} className="px-3 py-1.5 text-[10px] font-semibold tracking-wide text-slate-t uppercase">
                        {th}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rules.data.rules.map((r) => (
                    <tr key={r.id} className="border-b border-ink-800/70">
                      <td className="px-3 py-1.5 font-mono text-[11px] text-slate-hi">{r.id}</td>
                      <td className="px-3 py-1.5 text-[11px] text-slate-b">{r.category}</td>
                      <td className="px-3 py-1.5">
                        <Pill tone={r.severity === 'block' ? 'bad' : 'warn'}>{r.severity}</Pill>
                      </td>
                      <td className="px-3 py-1.5 text-[11px] text-slate-t">{r.target}</td>
                      <td className="px-3 py-1.5 text-[11px] text-slate-b">{r.why}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <SourceNote>
              Only a <span className="text-bad-400">block</span> rule returns a 403 on its own. A{' '}
              <span className="text-warn-400">flag</span> rule is evidence: it increments the <code>n_flags</code>{' '}
              feature and the model weighs it. The regular expressions themselves are not published here, because doing
              so tells an attacker exactly what to encode around.
            </SourceNote>
          </>
        ) : (
          <p className="text-xs text-slate-t">{rules.error ?? 'Loading...'}</p>
        )}
      </Panel>

      <Panel
        title="Model reload"
        subtitle="POST /__guard/reload - the gateway's own hot-reload endpoint"
        actions={
          <ShieldAlert className="h-4 w-4 text-warn-400" aria-hidden />
        }
      >
        <p className="text-xs text-slate-b">
          Re-reads the model files and calibration baseline from{' '}
          <code className="font-mono">{artifacts.data?.source ?? 'the models directory'}</code> without restarting the
          gateway. Use it after retraining or recalibrating. It does not retrain anything.
        </p>

        {!confirming ? (
          <button type="button" onClick={() => setConfirming(true)} className={`${controlClass} mt-3`} disabled={!h}>
            <RefreshCw className="h-3.5 w-3.5" aria-hidden />
            Reload models
          </button>
        ) : (
          <div className="mt-3 rounded-lg border border-warn-500/25 bg-warn-500/5 p-3">
            <p className="text-xs text-slate-b">
              This takes effect immediately on the running gateway and changes how live traffic is scored. Continue?
            </p>
            <div className="mt-2.5 flex gap-2">
              <button
                type="button"
                onClick={() => void doReload()}
                disabled={reloadState.busy}
                className="inline-flex h-8 items-center gap-1.5 rounded-md border border-warn-500/40 bg-warn-500/10 px-2.5 text-xs text-warn-400 disabled:opacity-50"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${reloadState.busy ? 'animate-spin' : ''}`} aria-hidden />
                {reloadState.busy ? 'Reloading' : 'Yes, reload'}
              </button>
              <button type="button" onClick={() => setConfirming(false)} className={controlClass}>
                Cancel
              </button>
            </div>
          </div>
        )}

        {reloadState.message && <p className="mt-3 text-xs text-slate-b">{reloadState.message}</p>}

        {!h && (
          <SourceNote>The gateway is unreachable, so the reload endpoint cannot be called.</SourceNote>
        )}
      </Panel>

      <Panel title="Deployment topology" subtitle="From src/docker-compose.yml">
        <ul className="space-y-1.5 text-xs text-slate-b">
          <li>
            Port <span className="num text-slate-hi">5000</span> is the only published port. The backend and Redis sit on
            an internal bridge network with no host mapping, so a client cannot bypass the gateway.
          </li>
          <li>
            The models directory is mounted <code className="font-mono">read-only</code> into the gateway. Model files
            are pickles, which is executable content, and a writable mount would let anything with container access swap
            in a payload that runs on the next load.
          </li>
          <li>
            The gateway runs as an unprivileged user with <code className="font-mono">no-new-privileges</code>.
          </li>
          <li>
            The lab override relaxes three things and must never be deployed: it sets monitor mode, trusts one
            X-Forwarded-For hop, and accepts the ground-truth label header.
          </li>
        </ul>
        <SourceNote>
          This panel describes the committed compose file. It is not a readback of the container the gateway is actually
          running in, and the console has no way to inspect that.
        </SourceNote>
      </Panel>
    </div>
  )
}
