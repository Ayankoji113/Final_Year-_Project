import type { LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import type { Tone } from '../status/Badges'

const ACCENT: Record<Tone, string> = {
  ok: 'text-ok-400',
  bad: 'text-bad-400',
  warn: 'text-warn-400',
  ml: 'text-ml-400',
  info: 'text-accent-300',
  mute: 'text-slate-hi',
}

export function MetricCard({
  label,
  value,
  unit,
  icon: Icon,
  tone = 'mute',
  detail,
  source,
}: {
  label: string
  /** Already formatted. Pass "--" for a value that genuinely has no reading. */
  value: ReactNode
  unit?: string
  icon?: LucideIcon
  tone?: Tone
  detail?: ReactNode
  /** Which endpoint or file produced this number. Always rendered. */
  source: string
}) {
  return (
    <div className="panel p-4">
      <div className="flex items-center gap-2">
        {Icon && <Icon className="h-3.5 w-3.5 shrink-0 text-slate-t" aria-hidden />}
        <span className="truncate text-[11px] font-medium tracking-wide text-slate-t uppercase">{label}</span>
      </div>
      <p className={`num mt-2 text-2xl leading-none font-semibold ${ACCENT[tone]}`}>
        {value}
        {unit && <span className="ml-1 text-sm font-normal text-slate-t">{unit}</span>}
      </p>
      {detail && <p className="mt-1.5 text-[11px] text-slate-b">{detail}</p>}
      <p className="mt-2 truncate font-mono text-[10px] text-slate-t/70" title={source}>
        {source}
      </p>
    </div>
  )
}
