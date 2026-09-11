import type { LucideIcon } from 'lucide-react'
import { StatusDot, type Tone } from './Badges'

export interface HealthTileProps {
  icon: LucideIcon
  name: string
  /** One or two words. The state itself, never a sentence. */
  state: string
  tone: Tone
  /** Where this reading came from, so nobody has to guess. */
  detail: string
  source: string
}

export function HealthTile({ icon: Icon, name, state, tone, detail, source }: HealthTileProps) {
  const ring =
    tone === 'ok'
      ? 'border-ok-500/25'
      : tone === 'bad'
        ? 'border-bad-500/30'
        : tone === 'warn'
          ? 'border-warn-500/30'
          : 'border-ink-700'
  return (
    <div className={`panel ${ring} p-3.5`}>
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4 shrink-0 text-slate-t" aria-hidden />
        <span className="truncate text-xs font-medium text-slate-b">{name}</span>
        <span className="ml-auto">
          <StatusDot tone={tone} pulse={tone === 'ok'} />
        </span>
      </div>
      <p className="mt-2 truncate text-base font-semibold text-slate-hi">{state}</p>
      <p className="mt-0.5 truncate text-[11px] text-slate-t" title={detail}>
        {detail}
      </p>
      <p className="mt-2 truncate font-mono text-[10px] text-slate-t/70" title={source}>
        {source}
      </p>
    </div>
  )
}
