import { useState } from 'react'
import { useMemo } from 'react'
import {
  BrainCircuit,
  Database,
  FileText,
  RefreshCw,
  ServerCog,
  ShieldHalf,
  Stethoscope,
} from 'lucide-react'
import { useHealth } from '../hooks/useHealth'
import { useStats } from '../hooks/useStats'
import { useTraffic } from '../hooks/useTraffic'
import { useArtifacts } from '../hooks/useArtifacts'
import { probeBackend, type BackendProbe } from '../services/health'
import { HealthTile } from '../components/status/HealthTile'
import { ErrorState, Panel, SourceNote } from '../components/common/Panel'
import { ModeBadge, Pill } from '../components/status/Badges'
import { backendStateFromEvents } from '../utils/derive'
import { formatBytes, formatClock, formatInt, formatUptime, relativeAge } from '../utils/format'

function KV({ label, value, note }: { label: string; value: React.ReactNode; note?: string }) {
  return (
    <div className="border-b border-ink-800/70 py-1.5">
      <dt className="text-[10px] tracking-wide text-slate-t uppercase">{label}</dt>
      <dd className="num mt-0.5 text-xs text-slate-hi">{value}</dd>
      {note && <p className="mt-0.5 text-[10px] text-slate-t">{note}</p>}
    </div>
  )
}

export function SystemHealth() {
  const health = useHealth()
  const stats = useStats()
  const traffic = useTraffic()
  const artifacts = useArtifacts()
  const [probe, setProbe] = useState<BackendProbe | null>(null)
  const [probing, setProbing] = useState(false)

  const h = health.data
  const backend = useMemo(() => backendStateFromEvents(traffic.events), [traffic.events])

  const runProbe = async () => {
    setProbing(true)
    try {
      setProbe(await probeBackend())
    } finally {
      setProbing(false)
    }
  }

  const controlClass =
    'inline-flex h-8 items-center gap-1.5 rounded-md border border-ink-600 px-2.5 text-xs text-slate-b transition-colors hover:border-ink-500 hover:text-slate-hi disabled:opacity-50'

  return (
    <div className="space-y-4">
      {health.state === 'error' && !h && (
        <ErrorState
          message={health.error ?? 'unknown error'}
          hint="The console proxies /__guard to the gateway on port 5000. Start it with: cd src && docker compose up -d"
        />
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <HealthTile
          icon={ShieldHalf}
          name="Gateway"
          state={h ? 'Healthy' : health.state === 'loading' ? 'Checking' : 'Unreachable'}
          tone={h ? 'ok' : health.state === 'loading' ? 'mute' : 'bad'}
          detail={h ? `status "${h.status}" · up ${formatUptime(h.uptime_s)}` : (health.error ?? 'no response')}
          source="GET /__guard/health"
        />
        <HealthTile
          icon={Database}
          name="Redis"
          state={!h ? 'Unknown' : h.redis ? 'Connected' : 'Unavailable'}
          tone={!h ? 'mute' : h.redis ? 'ok' : 'bad'}
          detail={
            !h
              ? 'gateway unreachable'
              : h.redis
                ? 'sliding-window, burst and endpoint-breadth counters are live'
                : 'rate limiting degraded: counters read zero and requests keep flowing'
          }
          source="health.redis (PING each poll)"
        />
        <HealthTile
          icon={BrainCircuit}
          name="ML models"
          state={!h ? 'Unknown' : h.models_loaded ? 'Loaded' : 'Not loaded'}
          tone={!h ? 'mute' : h.models_loaded ? 'ok' : 'bad'}
          detail={h ? `threshold ${h.threshold.toFixed(4)}` : 'gateway unreachable'}
          source="health.models_loaded"
        />
        <HealthTile
          icon={ServerCog}
          name="Backend"
          state={probe ? (probe.reachable ? 'Responding' : 'Not responding') : backend.state}
          tone={probe ? (probe.reachable ? 'ok' : 'bad') : backend.tone}
          detail={probe ? `probe returned HTTP ${probe.status} at ${formatClock(probe.at)}` : backend.detail}
          source={probe ? 'manual probe through the gateway' : 'inferred from 502/504 in the log'}
        />
        <HealthTile
          icon={FileText}
          name="Event logging"
          state={traffic.missingMessage ? 'No log file' : traffic.state === 'error' ? 'Read failing' : 'Writing'}
          tone={traffic.missingMessage ? 'warn' : traffic.state === 'error' ? 'bad' : 'ok'}
          detail={
            traffic.missingMessage
              ? traffic.missingMessage
              : `${formatBytes(traffic.fileSize)} on disk · read ${relativeAge(traffic.updatedAt)}`
          }
          source={traffic.source || 'src/data/events.jsonl'}
        />
        <HealthTile
          icon={Stethoscope}
          name="Calibration"
          state={!h ? 'Unknown' : h.calibrated ? 'Ready' : 'Uncalibrated'}
          tone={!h ? 'mute' : h.calibrated ? 'ok' : 'warn'}
          detail={
            !h
              ? 'gateway unreachable'
              : h.calibrated
                ? `${formatInt(h.calibration_samples)} baseline samples`
                : 'baseline-relative features fall back to zero'
          }
          source="health.calibrated / calibration_samples"
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Protection mode" subtitle="What the gateway is currently enforcing">
          {h ? (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <ModeBadge mode={h.mode} enforcingMl={h.enforcing_ml} />
                <Pill tone={h.enforcing_rules ? 'ok' : 'warn'}>
                  L1 rules and rate limits: {h.enforcing_rules ? 'blocking' : 'observing'}
                </Pill>
                <Pill tone={h.enforcing_ml ? 'ok' : 'warn'}>
                  L4 ML verdicts: {h.enforcing_ml ? 'blocking' : 'observing'}
                </Pill>
              </div>
              <dl>
                <KV label="GUARD_MODE" value={h.mode} />
                <KV
                  label="enforcing_rules"
                  value={String(h.enforcing_rules)}
                  note="True for both enforce and enforce-l1. Deterministic layers block."
                />
                <KV
                  label="enforcing_ml"
                  value={String(h.enforcing_ml)}
                  note="True only for full enforce. Under enforce-l1 an ML verdict is recorded and the request is forwarded."
                />
                <KV label="Decision threshold" value={h.threshold.toFixed(6)} />
                <KV label="Uptime" value={formatUptime(h.uptime_s)} note={`${formatInt(Math.round(h.uptime_s))} seconds`} />
              </dl>
            </>
          ) : (
            <p className="text-xs text-slate-t">Gateway unreachable, so the live mode cannot be read.</p>
          )}
        </Panel>

        <Panel
          title="Backend probe"
          subtitle="The gateway has no side channel to the backend, so this sends one real request through the full pipeline"
          actions={
            <button type="button" onClick={() => void runProbe()} disabled={probing} className={controlClass}>
              <RefreshCw className={`h-3.5 w-3.5 ${probing ? 'animate-spin' : ''}`} aria-hidden />
              {probing ? 'Probing' : 'Probe GET /health'}
            </button>
          }
        >
          <div className="rounded-lg border border-warn-500/25 bg-warn-500/5 p-3">
            <p className="text-[11px] text-slate-b">
              This probe is a genuine proxied request. It increments the gateway's counters and appends one line to the
              event log, which is exactly why it is a button rather than a poll: a dashboard that silently probes its own
              subject corrupts the traffic it is reporting on.
            </p>
          </div>

          {probe ? (
            <dl className="mt-3">
              <KV label="Result" value={probe.reachable ? `HTTP ${probe.status}` : `failed (${probe.status || 'no response'})`} />
              <KV label="At" value={formatClock(probe.at)} />
              <KV label="Response body" value={<span className="font-mono break-all">{probe.body || '(empty)'}</span>} />
            </dl>
          ) : (
            <p className="mt-3 text-xs text-slate-t">
              Not probed this session. The Backend tile above is showing the inference from the log instead.
            </p>
          )}
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Gateway counters" subtitle="In-process, and reset whenever the gateway restarts">
          {stats.data ? (
            <>
              <dl>
                <KV label="Total requests" value={formatInt(stats.data.total)} />
                <KV label="Allowed" value={formatInt(stats.data.allowed)} />
                <KV label="Blocked (enforced)" value={formatInt(stats.data.blocked)} />
                <KV
                  label="Model trained at"
                  value={stats.data.trained_at ?? 'not reported'}
                  note="From the loaded decision.json, relayed by /__guard/stats."
                />
              </dl>
              <div className="mt-3">
                <p className="mb-1.5 text-[10px] tracking-wide text-slate-t uppercase">Enforced blocks by layer</p>
                {Object.keys(stats.data.by_layer).length === 0 ? (
                  <p className="text-xs text-slate-t">No enforced block since the gateway started.</p>
                ) : (
                  <ul className="space-y-1">
                    {Object.entries(stats.data.by_layer).map(([layer, n]) => (
                      <li key={layer} className="flex justify-between border-b border-ink-800/60 py-1 text-xs">
                        <code className="font-mono text-slate-b">{layer}</code>
                        <span className="num text-slate-hi">{formatInt(n)}</span>
                      </li>
                    ))}
                  </ul>
                )}
                <SourceNote>
                  This map counts enforced blocks only. Under enforce-l1 an L4 verdict never appears here even though
                  the event log records it, which is why the Threats page counts from the log instead.
                </SourceNote>
              </div>
            </>
          ) : (
            <p className="text-xs text-slate-t">{stats.error ?? 'Loading counters...'}</p>
          )}
        </Panel>

        <Panel title="Artefacts on disk" subtitle="Read from src/ml_pipeline/models/">
          <dl>
            <KV
              label="decision.json"
              value={artifacts.data?.decision ? `present · seed ${artifacts.data.decision.seed} · ${artifacts.data.decision.trained_at}` : 'not readable'}
            />
            <KV
              label="calibration.json"
              value={
                artifacts.data?.calibration
                  ? `present · ${formatInt(artifacts.data.calibration.n_samples)} samples · ${formatInt(Object.keys(artifacts.data.calibration.endpoints).length)} endpoints`
                  : 'not readable'
              }
            />
            <KV
              label="validation.json"
              value={artifacts.data?.validation ? `present · seeds ${artifacts.data.validation.seeds.join(', ')}` : 'not readable'}
            />
            <KV
              label="comparison.json"
              value={artifacts.data?.comparison ? `present · ${Object.keys(artifacts.data.comparison.metrics).length} models compared` : 'not readable'}
            />
            <KV
              label="tuning.json"
              value={artifacts.data?.tuning ? `present · search seeds ${artifacts.data.tuning.search_seeds.join(', ')}` : 'not readable'}
            />
          </dl>
          <SourceNote>
            The binary model files themselves (scaler, forest, autoencoder, meta-learner) are pickles loaded by the
            gateway. Whether they loaded successfully is reported by <code>health.models_loaded</code> above; their
            contents are not read by this console.
          </SourceNote>
        </Panel>
      </div>
    </div>
  )
}
