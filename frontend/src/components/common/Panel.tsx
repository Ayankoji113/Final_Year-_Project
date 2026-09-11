import type { ReactNode } from 'react'

export function Panel({
  title,
  subtitle,
  actions,
  children,
  className = '',
  bodyClassName = 'p-4',
}: {
  title?: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-head flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold text-slate-hi">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-slate-t">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  )
}

/**
 * The standard "this value does not exist" tile.
 *
 * The brief for this console is explicit that a missing metric must say so
 * rather than be filled with a plausible number, so every gap routes here and
 * names the reason it is a gap.
 */
export function Unavailable({ what, why }: { what: string; why: string }) {
  return (
    <div className="flex h-full min-h-24 flex-col justify-center rounded-lg border border-dashed border-ink-600 bg-ink-900/40 px-4 py-3">
      <p className="text-xs font-medium text-slate-b">{what}</p>
      <p className="mt-1 text-xs text-slate-t">{why}</p>
    </div>
  )
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 px-6 py-12 text-center">
      <p className="text-sm text-slate-b">{title}</p>
      {hint && <p className="max-w-md text-xs text-slate-t">{hint}</p>}
    </div>
  )
}

export function ErrorState({ message, hint }: { message: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-bad-500/30 bg-bad-500/5 px-4 py-3">
      <p className="text-xs font-semibold text-bad-400">Could not load</p>
      <p className="mt-1 font-mono text-xs break-words text-slate-b">{message}</p>
      {hint && <p className="mt-1 text-xs text-slate-t">{hint}</p>}
    </div>
  )
}

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 px-4 py-8 text-xs text-slate-t">
      <span className="h-2 w-2 animate-pulse rounded-full bg-accent-400" />
      {label}...
    </div>
  )
}

/** Small grey caption naming where a number came from. Used relentlessly. */
export function SourceNote({ children }: { children: ReactNode }) {
  return <p className="mt-2 text-[11px] leading-relaxed text-slate-t">{children}</p>
}
