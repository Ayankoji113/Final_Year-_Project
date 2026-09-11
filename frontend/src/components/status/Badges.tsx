import type { ReactNode } from 'react'
import { layerMeta, outcomeOf } from '../../utils/derive'
import type { GuardEvent } from '../../types'

const TONES = {
  ok: 'border-ok-500/35 bg-ok-500/10 text-ok-400',
  bad: 'border-bad-500/35 bg-bad-500/10 text-bad-400',
  warn: 'border-warn-500/35 bg-warn-500/10 text-warn-400',
  ml: 'border-ml-500/35 bg-ml-500/10 text-ml-400',
  info: 'border-accent-500/35 bg-accent-500/10 text-accent-300',
  mute: 'border-ink-600 bg-ink-800/60 text-slate-b',
} as const

export type Tone = keyof typeof TONES

export function Pill({
  tone = 'mute',
  children,
  title,
  className = '',
}: {
  tone?: Tone
  children: ReactNode
  title?: string
  className?: string
}) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-0.5 text-[11px] font-medium ${TONES[tone]} ${className}`}
    >
      {children}
    </span>
  )
}

export function StatusDot({ tone, pulse = false }: { tone: Tone; pulse?: boolean }) {
  const fill =
    tone === 'ok'
      ? 'bg-ok-500'
      : tone === 'bad'
        ? 'bg-bad-500'
        : tone === 'warn'
          ? 'bg-warn-500'
          : tone === 'ml'
            ? 'bg-ml-500'
            : tone === 'info'
              ? 'bg-accent-500'
              : 'bg-slate-t'
  return (
    <span className="relative inline-flex h-2 w-2 shrink-0">
      {pulse && <span className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-60 ${fill}`} />}
      <span className={`relative inline-flex h-2 w-2 rounded-full ${fill}`} />
    </span>
  )
}

/**
 * The verdict badge.
 *
 * "Would block" is its own state on purpose: under GUARD_MODE=enforce-l1 an ML
 * verdict is recorded but the request is still forwarded, and showing that as
 * "Blocked" would claim protection the gateway did not apply.
 */
export function DecisionBadge({ event }: { event: GuardEvent }) {
  const outcome = outcomeOf(event)
  if (outcome === 'allowed') return <Pill tone="ok">Allowed</Pill>
  if (outcome === 'blocked') return <Pill tone="bad">Blocked</Pill>
  return (
    <Pill tone="warn" title="The gateway recorded a block verdict but the current GUARD_MODE did not enforce it, so the request was forwarded.">
      Would block
    </Pill>
  )
}

const LAYER_TONE: Record<string, Tone> = {
  rule: 'bad',
  rate: 'warn',
  ml: 'ml',
  error: 'bad',
  degraded: 'warn',
  clean: 'mute',
}

export function LayerBadge({ layer, full = false }: { layer: string; full?: boolean }) {
  const meta = layerMeta(layer)
  return (
    <Pill tone={LAYER_TONE[meta.kind] ?? 'mute'} title={meta.description}>
      {full ? meta.label : meta.short}
    </Pill>
  )
}

export function StatusBadge({ status }: { status: number }) {
  const tone: Tone = status >= 500 ? 'bad' : status >= 400 ? 'warn' : status >= 300 ? 'info' : 'ok'
  return <Pill tone={tone}>{status}</Pill>
}

export function MethodBadge({ method }: { method: string }) {
  const tone: Tone = method === 'GET' ? 'info' : method === 'DELETE' ? 'bad' : method === 'POST' ? 'ml' : 'mute'
  return (
    <span className={`inline-block w-[52px] rounded border px-1 py-0.5 text-center font-mono text-[10px] font-semibold ${TONES[tone]}`}>
      {method}
    </span>
  )
}

/** GUARD_MODE, with the enforcement split spelled out rather than implied. */
export function ModeBadge({ mode, enforcingMl }: { mode: string; enforcingMl: boolean }) {
  const tone: Tone = mode === 'enforce' ? 'ok' : mode === 'enforce-l1' ? 'info' : 'warn'
  const title =
    mode === 'enforce'
      ? 'Signature hits, rate limits and ML anomalies all block.'
      : mode === 'enforce-l1'
        ? 'Signature hits and rate limits block. ML anomalies are logged only.'
        : mode === 'monitor'
          ? 'Nothing is blocked. Every verdict is recorded only.'
          : 'Mode string reported by the gateway.'
  return (
    <Pill tone={tone} title={title} className="uppercase tracking-wide">
      {mode}
      {!enforcingMl && mode !== 'monitor' ? ' · ML observe' : ''}
    </Pill>
  )
}
