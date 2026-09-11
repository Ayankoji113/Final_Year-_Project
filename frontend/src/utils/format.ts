export function formatInt(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '--'
  return n.toLocaleString()
}

export function formatMs(n: number | null | undefined, digits = 2): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '--'
  return `${n.toFixed(digits)} ms`
}

export function formatPct(fraction: number | null | undefined, digits = 1): string {
  if (fraction === null || fraction === undefined || !Number.isFinite(fraction)) return '--'
  return `${(fraction * 100).toFixed(digits)}%`
}

export function formatProbability(p: number | null | undefined): string {
  if (p === null || p === undefined || !Number.isFinite(p)) return '--'
  return p.toFixed(4)
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return '--'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/** Event timestamps are Unix seconds with 3 decimal places. */
export function formatEventTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString(undefined, { hour12: false })
}

export function formatEventDateTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString(undefined, { hour12: false })
}

export function formatClock(epochMs: number | null): string {
  if (!epochMs) return 'never'
  return new Date(epochMs).toLocaleTimeString(undefined, { hour12: false })
}

export function formatUptime(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return '--'
  const s = Math.floor(seconds)
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m ${s % 60}s`
  return `${s}s`
}

export function relativeAge(epochMs: number | null): string {
  if (!epochMs) return 'never'
  const secs = Math.max(0, Math.round((Date.now() - epochMs) / 1000))
  if (secs < 2) return 'just now'
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  return `${Math.floor(secs / 3600)}h ago`
}

/**
 * Confidence intervals in validation.json are stored as a [lo, hi] pair.
 * Rendering a mean without its interval is exactly the misreporting the
 * project's own evaluation notes warn about, so they always travel together.
 */
export function formatInterval(mean: number, ci: [number, number], digits = 3): string {
  return `${mean.toFixed(digits)} [${ci[0].toFixed(digits)}-${ci[1].toFixed(digits)}]`
}

export function formatScientific(p: number): string {
  if (!Number.isFinite(p)) return '--'
  if (p === 0) return '0'
  if (p < 1e-4) return p.toExponential(2)
  return p.toFixed(4)
}
