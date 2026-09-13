import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Activity, BrainCircuit, CheckCircle2, Database, Gauge, ServerCog, ShieldAlert, ShieldBan, ShieldHalf } from 'lucide-react'
import { useHealth } from '../hooks/useHealth'
import { useStats } from '../hooks/useStats'
import { useTraffic } from '../hooks/useTraffic'
import { MetricCard } from '../components/cards/MetricCard'
import { HealthTile } from '../components/status/HealthTile'
import { ErrorState, Panel, SourceNote, Unavailable } from '../components/common/Panel'
import { CategoryBreakdown, LayerBreakdown, OutcomeDonut, TrafficOverTime } from '../components/charts/TrafficCharts'
import { EventTable } from '../components/tables/EventTable'
import { C } from '../components/charts/chartTheme'
import {
  backendStateFromEvents,
  categoryCounts,
  eventKey,
  layerCounts,
  latencyProfile,
  summarise,
  threatEvents,
  timeSeries,
} from '../utils/derive'
import { formatInt, formatMs, formatUptime } from '../utils/format'

export function Overview() {
  const health = useHealth()
  const stats = useStats()
  const traffic = useTraffic()
  const navigate = useNavigate()

  const events = traffic.events
  const summary = useMemo(() => summarise(events), [events])
  const series = useMemo(() => timeSeries(events, 40), [events])
  const layers = useMemo(() => layerCounts(events), [events])
  const categories = useMemo(() => categoryCounts(events), [events])
  const detect = useMemo(() => latencyProfile(events, 'detect_ms'), [events])
  const recentThreats = useMemo(() => threatEvents(events).slice(-12).reverse(), [events])
  const backend = useMemo(() => backendStateFromEvents(events), [events])

  const h = health.data
  const s = stats.data

  return (
    <div className="space-y-5">
      {health.state === 'error' && !h && (
        <ErrorState
          message={health.error ?? 'unknown error'}
          hint="Start the stack with: cd src && docker compose up -d. The console proxies /__guard to port 5000."
        />
      )}

      {/* ---- component health ------------------------------------------- */}
      <section>
        <h2 className="mb-2 text-xs font-semibold tracking-wide text-slate-t uppercase">Component health</h2>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <HealthTile
            icon={ShieldHalf}
            name="Gateway"
            state={h ? 'Healthy' : health.state === 'loading' ? 'Checking' : 'Unreachable'}
            tone={h ? 'ok' : health.state === 'loading' ? 'mute' : 'bad'}
            detail={h ? `up ${formatUptime(h.uptime_s)} · mode ${h.mode}` : (health.error ?? 'no response')}
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
                  ? 'rate limiting active'
                  : 'rate limiting degraded; counters read zero'
            }
            source="health.redis"
          />
          <HealthTile
            icon={BrainCircuit}
            name="ML Models"
            state={!h ? 'Unknown' : h.models_loaded ? (h.calibrated ? 'Loaded' : 'Uncalibrated') : 'Not loaded'}
            tone={!h ? 'mute' : !h.models_loaded ? 'bad' : h.calibrated ? 'ok' : 'warn'}
            detail={
              !h
                ? 'gateway unreachable'
                : h.models_loaded
                  ? `threshold ${h.threshold.toFixed(4)} · baseline ${formatInt(h.calibration_samples)} samples`
                  : 'L2/L3/L4 are not running; only L1 applies'
            }
            source="health.models_loaded / calibrated"
          />
          <HealthTile
            icon={ServerCog}
            name="Backend"
            state={backend.state}
            tone={backend.tone}
            detail={backend.detail}
            source="inferred from 502/504 in the event log"
          />
        </div>
      </section>

      {/* ---- counters ---------------------------------------------------- */}
      <section>
        <h2 className="mb-2 text-xs font-semibold tracking-wide text-slate-t uppercase">
          Since gateway start
          <span className="ml-2 font-normal normal-case">
            in-process counters, reset whenever the gateway restarts
          </span>
        </h2>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          <MetricCard
            label="Total requests"
            value={formatInt(s?.total)}
            icon={Activity}
            source="GET /__guard/stats -> total"
            detail={h ? `gateway up ${formatUptime(h.uptime_s)}` : undefined}
          />
          <MetricCard
            label="Allowed"
            value={formatInt(s?.allowed)}
            icon={CheckCircle2}
            tone="ok"
            source="stats.allowed"
            detail="forwarded to the backend"
          />
          <MetricCard
            label="ML detected / enforced"
            value={`${formatInt(s?.ml_detected ?? 0)} / ${formatInt(s?.ml_enforced ?? 0)}`}
            icon={BrainCircuit}
            tone={(s?.ml_enforced ?? 0) > 0 ? 'ml' : 'warn'}
            source="stats.ml_detected / stats.ml_enforced"
            detail={
              (s?.ml_enforced ?? 0) === 0 && (s?.ml_detected ?? 0) > 0
                ? 'recorded only; no ML verdict returned 403'
                : 'ML verdicts recorded and acted on'
            }
          />
          <MetricCard
            label="Blocked (enforced)"
            value={formatInt(s?.blocked)}
            icon={ShieldBan}
            tone="bad"
            source="stats.blocked"
            detail="returned 403 without reaching the backend"
          />
        </div>
        {stats.state === 'error' && (
          <SourceNote>Counters are stale: the last poll failed with "{stats.error}".</SourceNote>
        )}
      </section>

      {/* ---- log-derived counters ---------------------------------------- */}
      <section>
        <h2 className="mb-2 text-xs font-semibold tracking-wide text-slate-t uppercase">
          From the event log
          <span className="ml-2 font-normal normal-case">
            {formatInt(events.length)} records currently loaded{traffic.windowed ? ', the most recent portion of a longer log' : ''}
          </span>
        </h2>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="L1 rule blocks"
            value={formatInt(summary.l1RuleBlocks)}
            icon={ShieldAlert}
            tone="bad"
            source="layer == L1-rules"
            detail="deterministic signature matches"
          />
          <MetricCard
            label="L1 rate blocks"
            value={formatInt(summary.l1RateBlocks)}
            icon={Gauge}
            tone="warn"
            source="layer == L1-rate"
            detail="sliding-window or burst limit exceeded"
          />
          <MetricCard
            label="ML detections"
            value={formatInt(summary.mlDetections)}
            icon={BrainCircuit}
            tone="ml"
            source="layer == L4-meta"
            detail={
              summary.mlDetections > 0 && summary.observed > 0
                ? `${formatInt(summary.observed)} recorded without being enforced`
                : 'meta-learner crossed the threshold'
            }
          />
          <MetricCard
            label="Detection latency p95"
            value={detect.p95 === null ? '--' : formatMs(detect.p95, 2)}
            icon={Gauge}
            tone="info"
            source="detect_ms over loaded records"
            detail={
              detect.p50 === null
                ? 'no records loaded'
                : `p50 ${formatMs(detect.p50, 2)} · max ${formatMs(detect.max, 2)}`
            }
          />
        </div>
      </section>

      {/* ---- charts ------------------------------------------------------ */}
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel
          className="xl:col-span-2"
          title="Request traffic over time"
          subtitle="Stacked by verdict, bucketed across the span of the loaded log window"
        >
          <TrafficOverTime buckets={series} />
        </Panel>

        <Panel title="Allowed vs blocked" subtitle="Every loaded record, by what the gateway actually did">
          <OutcomeDonut
            slices={[
              { name: 'Allowed', value: summary.allowed, color: C.allowed },
              { name: 'Blocked', value: summary.blocked, color: C.blocked },
              { name: 'Would block', value: summary.observed, color: C.observed },
            ]}
          />
          {summary.observed > 0 && (
            <SourceNote>
              "Would block" is a verdict the gateway recorded but did not act on, because the mode in force does not
              enforce that layer. Those requests reached the backend.
            </SourceNote>
          )}
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Decisions by detection layer" subtitle="Attributed from the layer the gateway recorded, not from status codes">
          <LayerBreakdown tallies={layers} />
          <SourceNote>
            A block here is not automatically an ML detection. L1 signature hits and rate limits are deterministic and
            short-circuit before any model runs.
          </SourceNote>
        </Panel>

        <Panel title="Threat categories" subtitle="From the categories the Layer-1 rule table assigns">
          <CategoryBreakdown tallies={categories} />
        </Panel>
      </div>

      {/* ---- recent security events -------------------------------------- */}
      <Panel
        title="Recent security events"
        subtitle="Blocked, would-block, and requests that tripped a FLAG-severity signature. Click a row to investigate."
        bodyClassName=""
      >
        {traffic.missingMessage ? (
          <div className="p-4">
            <Unavailable what="Event log not readable" why={traffic.missingMessage} />
          </div>
        ) : (
          <EventTable
            events={recentThreats}
            columns={['time', 'method', 'template', 'status', 'decision', 'layer', 'probability', 'reason']}
            onSelect={(e) => navigate(`/investigate/${eventKey(e)}`)}
            emptyTitle="No security events in the loaded window"
            emptyHint="Every loaded request passed Layer 1 and stayed below the L4 threshold."
          />
        )}
      </Panel>
    </div>
  )
}
