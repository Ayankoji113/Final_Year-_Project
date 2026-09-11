/**
 * Chart palette.
 *
 * Verdict colours are fixed across every chart in the console - green is
 * always allowed, red always an enforced block, amber always a verdict that
 * was recorded but not acted on, indigo always the ML layer. A reader should
 * never have to check a legend twice.
 */
export const C = {
  allowed: '#22c55e',
  blocked: '#ef4444',
  observed: '#f59e0b',
  ml: '#818cf8',
  rule: '#f472b6',
  rate: '#fbbf24',
  accent: '#3b82f6',
  grid: '#16233a',
  axis: '#7c8db0',
  surface: '#0b1220',
  border: '#1e3050',
}

/** Categorical ramp for tallies that have no fixed semantic colour. */
export const CATEGORICAL = ['#3b82f6', '#818cf8', '#f472b6', '#22c55e', '#f59e0b', '#06b6d4', '#a78bfa', '#ef4444']

export const AXIS = {
  stroke: C.axis,
  fontSize: 11,
  tickLine: false,
  axisLine: false,
}

export const TOOLTIP_STYLE = {
  background: C.surface,
  border: `1px solid ${C.border}`,
  borderRadius: 8,
  fontSize: 12,
  color: '#e6ecf7',
  boxShadow: '0 10px 30px -12px rgba(0,0,0,0.8)',
}
