import { useMemo } from 'react'
import { BrainCircuit, GitCompare, Layers, Ruler, Sigma, Trees } from 'lucide-react'
import { useHealth } from '../hooks/useHealth'
import { useArtifacts, useConfigDefaults } from '../hooks/useArtifacts'
import { useTraffic } from '../hooks/useTraffic'
import { Panel, SourceNote, Unavailable, Loading, ErrorState } from '../components/common/Panel'
import { MetricCard } from '../components/cards/MetricCard'
import { Pill } from '../components/status/Badges'
import { PipelineDiagram, stageCounts } from '../components/charts/PipelineDiagram'
import { layerCounts, latencyProfile, summarise } from '../utils/derive'
import { formatInt, formatInterval, formatMs, formatPct, formatScientific } from '../utils/format'

function KV({ label, value, note }: { label: string; value: React.ReactNode; note?: string }) {
  return (
    <div className="border-b border-ink-800/70 py-1.5">
      <dt className="text-[10px] tracking-wide text-slate-t uppercase">{label}</dt>
      <dd className="num mt-0.5 text-xs text-slate-hi">{value}</dd>
      {note && <p className="mt-0.5 text-[10px] text-slate-t">{note}</p>}
    </div>
  )
}

const LAYER_EXPLAINERS = [
  {
    icon: Trees,
    tag: 'L2',
    title: 'Isolation Forest',
    what: 'An ensemble of random trees that isolates each request by repeatedly splitting on a random feature at a random value.',
    why: 'A point that sits away from the bulk of the data needs fewer splits to isolate, so the average path length across the forest is itself an anomaly score. It needs no attack labels.',
    here: 'Fitted on the `base` pool only, which contains normal traffic, so its score on any attack is out-of-sample by construction. Its output is min-max normalised with the if_lo/if_hi bounds stored in decision.json before it reaches L4.',
  },
  {
    icon: Layers,
    tag: 'L3',
    title: 'Denoising autoencoder',
    what: 'A small neural network, written directly in NumPy, that compresses the feature vector through a bottleneck and reconstructs it.',
    why: 'Trained only on normal traffic, it learns to reconstruct normal shapes well and unfamiliar ones badly. The reconstruction error is the anomaly score, which is what makes it able to flag an attack family it has never seen.',
    here: 'Its error is normalised with the ae_lo/ae_hi bounds from decision.json. Because it is baseline-relative, the calibration step - not a full retrain - is what adapts it to a new backend.',
  },
  {
    icon: Sigma,
    tag: 'L4',
    title: 'HistGradientBoosting meta-learner',
    what: 'A gradient-boosted tree classifier over exactly three numbers: the L1 rate score, the L2 score and the L3 score.',
    why: 'The base detectors disagree in structured ways. A supervised learner over their outputs can weight them per-region, which is what lifts the stack above every individual detector.',
    here: 'This is the only layer that produces a verdict. L2 and L3 do not vote; they produce features. Its probability is compared against a threshold picked on the validation pool under a 1% false-positive budget.',
  },
]

export function MLIntelligence() {
  const health = useHealth()
  const artifacts = useArtifacts()
  const config = useConfigDefaults()
  const traffic = useTraffic()

  const h = health.data
  const d = artifacts.data?.decision ?? null
  const v = artifacts.data?.validation ?? null
  const cmp = artifacts.data?.comparison ?? null
  const cal = artifacts.data?.calibration ?? null

  const summary = useMemo(() => summarise(traffic.events), [traffic.events])
  const layers = useMemo(() => layerCounts(traffic.events), [traffic.events])
  const detect = useMemo(() => latencyProfile(traffic.events, 'detect_ms'), [traffic.events])
  const counts = traffic.events.length > 0 ? stageCounts(layers, summary.total, summary.allowed) : null

  // Only requests that actually reached L4 carry a meta-learner probability.
  const scored = useMemo(
    () => traffic.events.filter((e) => e.scores.meta_lr !== undefined),
    [traffic.events],
  )

  return (
    <div className="space-y-5">
      {/* ---- live model status ------------------------------------------ */}
      <section>
        <h2 className="mb-2 text-xs font-semibold tracking-wide text-slate-t uppercase">Live model status</h2>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="Models loaded"
            value={!h ? '--' : h.models_loaded ? 'Yes' : 'No'}
            icon={BrainCircuit}
            tone={!h ? 'mute' : h.models_loaded ? 'ok' : 'bad'}
            source="health.models_loaded"
            detail={!h ? 'gateway unreachable' : h.models_loaded ? 'scaler, forest, autoencoder, meta-learner' : 'only L1 is running'}
          />
          <MetricCard
            label="Decision threshold"
            value={h ? h.threshold.toFixed(4) : d ? d.threshold.toFixed(4) : '--'}
            icon={Ruler}
            tone="info"
            source={h ? 'health.threshold (live)' : 'decision.json (gateway unreachable)'}
            detail="picked on the validation pool under a 1% FPR budget"
          />
          <MetricCard
            label="Calibration"
            value={!h ? '--' : h.calibrated ? 'Ready' : 'Uncalibrated'}
            icon={Ruler}
            tone={!h ? 'mute' : h.calibrated ? 'ok' : 'warn'}
            source="health.calibrated"
            detail={h ? `${formatInt(h.calibration_samples)} baseline samples` : 'gateway unreachable'}
          />
          <MetricCard
            label="ML enforcement"
            value={!h ? '--' : h.enforcing_ml ? 'Blocking' : 'Observing'}
            icon={BrainCircuit}
            tone={!h ? 'mute' : h.enforcing_ml ? 'ok' : 'warn'}
            source="health.enforcing_ml"
            detail={
              !h
                ? 'gateway unreachable'
                : h.enforcing_ml
                  ? 'an L4 verdict returns 403'
                  : 'an L4 verdict is logged only; the request is still forwarded'
            }
          />
        </div>
      </section>

      {/* ---- architecture ------------------------------------------------ */}
      <Panel title="Detection pipeline" subtitle="The path a request takes, with counts from the loaded log window">
        <PipelineDiagram counts={counts} featureCount={config.data?.featureCount ?? d?.feature_names.length ?? 34} />
      </Panel>

      {/* ---- layer explainers -------------------------------------------- */}
      <div className="grid gap-4 xl:grid-cols-3">
        {LAYER_EXPLAINERS.map(({ icon: Icon, tag, title, what, why, here }) => (
          <Panel
            key={tag}
            title={
              <span className="flex items-center gap-2">
                <Icon className="h-4 w-4 text-ml-400" aria-hidden />
                <span className="font-mono text-[10px] text-ml-400">{tag}</span>
                {title}
              </span>
            }
          >
            <p className="text-xs text-slate-b">{what}</p>
            <p className="mt-2 text-xs text-slate-b">
              <span className="font-semibold text-slate-hi">Why it works: </span>
              {why}
            </p>
            <p className="mt-2 text-[11px] text-slate-t">
              <span className="font-semibold text-slate-b">In this system: </span>
              {here}
            </p>
          </Panel>
        ))}
      </div>

      {/* ---- runtime inference ------------------------------------------- */}
      <Panel title="Runtime inference" subtitle="Measured from the loaded log window, not from the training report">
        <div className="grid gap-4 lg:grid-cols-2">
          <dl>
            <KV
              label="Requests that reached the models"
              value={formatInt(scored.length)}
              note="Only these carry a meta-learner probability. L1 short-circuits the rest."
            />
            <KV
              label="Detection time p50 / p95 / p99"
              value={
                detect.n === 0
                  ? '--'
                  : `${formatMs(detect.p50, 2)} / ${formatMs(detect.p95, 2)} / ${formatMs(detect.p99, 2)}`
              }
              note="detect_ms, the time spent inside the pipeline before forwarding"
            />
            <KV
              label="L4 verdicts in this window"
              value={formatInt(summary.mlDetections)}
              note={summary.observed > 0 ? `${formatInt(summary.observed)} were recorded without being enforced` : undefined}
            />
            <KV
              label="Inference failures"
              value={formatInt(summary.inferenceErrors)}
              note="layer == L-error. With GUARD_FAIL_CLOSED=true these are treated as hostile."
            />
          </dl>

          <div>
            <p className="mb-2 text-[10px] tracking-wide text-slate-t uppercase">Per-model scores</p>
            <p className="text-xs text-slate-b">
              The gateway does expose the individual base-detector scores: every log record that reached the models
              carries <code className="font-mono text-[11px]">scores.rate</code>,{' '}
              <code className="font-mono text-[11px]">scores.isolation_forest</code>,{' '}
              <code className="font-mono text-[11px]">scores.autoencoder</code> and{' '}
              <code className="font-mono text-[11px]">scores.meta_lr</code>. Open any request in Threat Investigation to
              see them broken out against the threshold.
            </p>
            <SourceNote>
              What is <em>not</em> exposed is the raw, un-normalised output of each detector: the log stores the min-max
              normalised forms the gateway computed using the if_lo/if_hi and ae_lo/ae_hi bounds. The raw
              decision_function and reconstruction-error values are not written anywhere, and this console does not
              back-compute them.
            </SourceNote>
          </div>
        </div>
      </Panel>

      {/* ---- reportable metrics ------------------------------------------ */}
      {artifacts.state === 'loading' && <Loading label="Reading training artefacts" />}
      {artifacts.state === 'error' && (
        <ErrorState
          message={artifacts.error ?? 'unknown error'}
          hint="Artefacts are read from src/ml_pipeline/models/. Run the training pipeline if they are missing."
        />
      )}

      {v && (
        <Panel
          title="Reportable performance"
          subtitle="Ten-seed intervals from validation.json. These are the figures that should be quoted."
        >
          <div className="scroll-x">
            <table className="w-full min-w-[560px] text-left">
              <thead>
                <tr className="border-b border-ink-700">
                  {['Metric', 'Mean', '95% interval', 'Min', 'Max'].map((th) => (
                    <th key={th} className="px-3 py-2 text-[10px] font-semibold tracking-wide text-slate-t uppercase">
                      {th}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Object.entries(v.summary).map(([metric, s]) => (
                  <tr key={metric} className="border-b border-ink-800/70">
                    <td className="px-3 py-1.5 font-mono text-[11px] text-slate-hi">{metric}</td>
                    <td className="num px-3 py-1.5 text-xs text-slate-hi">{s.mean.toFixed(4)}</td>
                    <td className="num px-3 py-1.5 text-xs text-slate-b">
                      [{s.ci95[0].toFixed(4)}, {s.ci95[1].toFixed(4)}]
                    </td>
                    <td className="num px-3 py-1.5 text-xs text-slate-t">{s.min.toFixed(4)}</td>
                    <td className="num px-3 py-1.5 text-xs text-slate-t">{s.max.toFixed(4)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <SourceNote>
            Seeds {v.seeds.join(', ')}. Each seed re-partitions sessions, not rows, so a whole client's traffic lands on
            one side of the split. Zero-day recall is measured only on the withheld families.
          </SourceNote>
        </Panel>
      )}

      {d && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Panel
            title="Trained model in production"
            subtitle="decision.json - the artefact the gateway loaded"
            actions={<Pill tone="info">seed {d.seed}</Pill>}
          >
            <dl>
              <KV label="Trained at" value={d.trained_at} />
              <KV label="Artefact version" value={d.version} />
              <KV label="Features" value={`${d.feature_names.length} in a fixed order`} note="The gateway refuses to load a model whose feature list differs from the running build." />
              <KV label="Meta-learner" value={d.hyperparams.meta === 'hgb' ? 'HistGradientBoosting' : d.hyperparams.meta} />
              <KV label="Meta inputs" value={d.meta_inputs.join(', ')} />
              <KV label="Isolation Forest trees" value={formatInt(d.hyperparams.if_trees)} />
              <KV
                label="Autoencoder"
                value={`hidden ${d.hyperparams.ae_hidden}, bottleneck ${d.hyperparams.ae_bottleneck}, noise ${d.hyperparams.ae_noise}`}
              />
              <KV
                label="Withheld zero-day families"
                value={d.novel_families.join(', ')}
                note="Absent from the meta and validation pools, so they appear only in the final test."
              />
              <KV
                label="Session pools"
                value={Object.entries(d.pool_sizes).map(([k, n]) => `${k} ${formatInt(n)}`).join(' · ')}
              />
            </dl>
          </Panel>

          <Panel title="Single-seed test result" subtitle="The same decision.json, read with the caution it needs">
            <div className="rounded-lg border border-warn-500/25 bg-warn-500/5 p-3">
              <p className="text-[11px] text-slate-b">
                These numbers come from one seed. Seed {d.seed} is the strongest of the ten validation runs, so quoting
                it on its own overstates the system. The interval table above is the honest figure.
              </p>
            </div>
            <dl className="mt-3">
              <KV
                label="F1"
                value={
                  v?.summary.f1
                    ? `${d.test_metrics.f1.toFixed(4)} single seed · ${formatInterval(v.summary.f1.mean, v.summary.f1.ci95, 4)} across ten`
                    : d.test_metrics.f1.toFixed(4)
                }
              />
              <KV
                label="Zero-day recall"
                value={
                  v?.summary.zero_day_recall
                    ? `${d.zero_day_recall.toFixed(4)} single seed · ${formatInterval(v.summary.zero_day_recall.mean, v.summary.zero_day_recall.ci95, 4)} across ten`
                    : d.zero_day_recall.toFixed(4)
                }
              />
              <KV label="Precision / Recall" value={`${d.test_metrics.precision.toFixed(4)} / ${d.test_metrics.recall.toFixed(4)}`} />
              <KV label="False-positive rate" value={formatPct(d.test_metrics.fpr, 2)} note="budget is 1%" />
              <KV label="ROC AUC / PR AUC" value={`${d.test_roc_auc.toFixed(4)} / ${d.test_pr_auc.toFixed(4)}`} />
              <KV
                label="Confusion matrix"
                value={`TP ${formatInt(d.test_metrics.tp)} · TN ${formatInt(d.test_metrics.tn)} · FP ${formatInt(d.test_metrics.fp)} · FN ${formatInt(d.test_metrics.fn)}`}
              />
            </dl>
          </Panel>
        </div>
      )}

      {cmp && (
        <Panel
          title="Stack versus each base detector"
          subtitle="comparison.json - every model scored on the same test rows, under the same false-positive budget"
          actions={<GitCompare className="h-4 w-4 text-slate-t" aria-hidden />}
        >
          <div className="scroll-x">
            <table className="w-full min-w-[620px] text-left">
              <thead>
                <tr className="border-b border-ink-700">
                  {['Model', 'F1', 'Precision', 'Recall', 'FPR', 'vs stack (McNemar)'].map((th) => (
                    <th key={th} className="px-3 py-2 text-[10px] font-semibold tracking-wide text-slate-t uppercase">
                      {th}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Object.entries(cmp.metrics).map(([name, m]) => {
                  const test = cmp.mcnemar[`stack_vs_${name}`]
                  return (
                    <tr key={name} className={`border-b border-ink-800/70 ${name === 'stack' ? 'bg-accent-500/5' : ''}`}>
                      <td className="px-3 py-1.5 font-mono text-[11px] text-slate-hi">
                        {name === 'stack' ? 'Full stack (L1+L2+L3+L4)' : name}
                      </td>
                      <td className="num px-3 py-1.5 text-xs text-slate-hi">{m.f1.toFixed(4)}</td>
                      <td className="num px-3 py-1.5 text-xs text-slate-b">{m.precision.toFixed(4)}</td>
                      <td className="num px-3 py-1.5 text-xs text-slate-b">{m.recall.toFixed(4)}</td>
                      <td className="num px-3 py-1.5 text-xs text-slate-b">{formatPct(m.fpr, 2)}</td>
                      <td className="px-3 py-1.5 text-xs">
                        {test ? (
                          <span className="num text-slate-b">
                            p = {formatScientific(test.p)}{' '}
                            <Pill tone={test.significant ? 'ok' : 'mute'}>{test.significant ? 'significant' : 'n.s.'}</Pill>
                          </span>
                        ) : (
                          <span className="text-slate-t">--</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          <SourceNote>
            McNemar's test pairs the two models on the same rows, which is why compare.py rebuilds the whole pipeline
            rather than reusing the trained artefacts. Every row here was scored under the same 1% false-positive budget,
            so no model is rewarded for being allowed to be looser.
          </SourceNote>
        </Panel>
      )}

      {cal ? (
        <Panel title="Calibration baseline" subtitle="calibration.json - what normal looks like for this deployment">
          <div className="grid gap-4 lg:grid-cols-[220px_minmax(0,1fr)]">
            <dl>
              <KV label="Samples" value={formatInt(cal.n_samples)} />
              <KV label="Endpoints known" value={formatInt(Object.keys(cal.endpoints).length)} />
              <KV
                label="Client rate"
                value={`mean ${cal.rate.mean.toFixed(2)} · sd ${cal.rate.std.toFixed(2)} req/window`}
              />
            </dl>
            <div className="scroll-x max-h-64 overflow-y-auto">
              <table className="w-full min-w-[420px] text-left">
                <thead className="sticky top-0 bg-ink-850">
                  <tr className="border-b border-ink-700">
                    {['Endpoint template', 'Requests', 'Body mean', 'Body sd'].map((th) => (
                      <th key={th} className="px-3 py-1.5 text-[10px] font-semibold tracking-wide text-slate-t uppercase">
                        {th}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(cal.endpoints)
                    .sort((a, b) => b[1].count - a[1].count)
                    .map(([tmpl, e]) => (
                      <tr key={tmpl} className="border-b border-ink-800/70">
                        <td className="px-3 py-1 font-mono text-[11px] text-slate-hi">{tmpl}</td>
                        <td className="num px-3 py-1 text-[11px] text-slate-b">{formatInt(e.count)}</td>
                        <td className="num px-3 py-1 text-[11px] text-slate-b">{e.body_mean.toFixed(1)}</td>
                        <td className="num px-3 py-1 text-[11px] text-slate-b">{e.body_std.toFixed(1)}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
          <SourceNote>
            An endpoint absent from this table sets the <code>path_known</code> feature to zero. This baseline is what
            lets a trained model serve a backend it has never seen: recalibration re-derives it without retraining the
            forest or the network.
          </SourceNote>
        </Panel>
      ) : (
        artifacts.state === 'ok' && (
          <Unavailable
            what="Calibration baseline not readable"
            why="No calibration.json was found in src/ml_pipeline/models/. The gateway reports this state as 'uncalibrated'."
          />
        )
      )}
    </div>
  )
}
