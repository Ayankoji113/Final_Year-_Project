import { useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import {
  Activity,
  BrainCircuit,
  HeartPulse,
  Menu,
  ScrollText,
  Search,
  Settings2,
  ShieldAlert,
  ShieldHalf,
  LayoutDashboard,
  X,
} from 'lucide-react'
import type { ReactNode } from 'react'
import { useHealth } from '../../hooks/useHealth'
import { useTraffic } from '../../hooks/useTraffic'
import { ModeBadge, Pill, StatusDot } from '../status/Badges'
import { EVENTS_INTERVAL_MS, HEALTH_INTERVAL_MS } from '../../hooks/GuardDataProvider'
import { formatClock, relativeAge } from '../../utils/format'

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/live', label: 'Live Traffic', icon: Activity },
  { to: '/threats', label: 'Threats', icon: ShieldAlert },
  { to: '/investigate', label: 'Investigation', icon: Search },
  { to: '/ml', label: 'ML Intelligence', icon: BrainCircuit },
  { to: '/logs', label: 'Request Logs', icon: ScrollText },
  { to: '/health', label: 'System Health', icon: HeartPulse },
  { to: '/config', label: 'Configuration', icon: Settings2 },
]

function ProtectionStatus() {
  const health = useHealth()

  if (health.state === 'loading' && !health.data) {
    return <Pill tone="mute">Contacting gateway...</Pill>
  }
  if (!health.data) {
    return (
      <Pill tone="bad" title={health.error ?? undefined}>
        <StatusDot tone="bad" /> Gateway unreachable
      </Pill>
    )
  }

  const h = health.data
  // "Protected" is claimed only when the gateway says it is enforcing. Under
  // monitor mode nothing is blocked, and saying otherwise on a security console
  // is the most damaging thing this page could do.
  const tone = !h.enforcing_rules ? 'warn' : h.enforcing_ml ? 'ok' : 'info'
  const label = !h.enforcing_rules
    ? 'Observing only'
    : h.enforcing_ml
      ? 'Fully enforcing'
      : 'Enforcing L1'

  return (
    <>
      <Pill tone={tone}>
        <StatusDot tone={tone} pulse /> {label}
      </Pill>
      <ModeBadge mode={h.mode} enforcingMl={h.enforcing_ml} />
      {health.state === 'error' && (
        <Pill tone="warn" title={health.error ?? undefined}>
          stale
        </Pill>
      )}
    </>
  )
}

function LastUpdated() {
  const health = useHealth()
  const traffic = useTraffic()
  const newest = Math.max(health.updatedAt ?? 0, traffic.updatedAt ?? 0) || null

  return (
    <div className="text-right">
      <p className="text-[11px] text-slate-b">
        Last updated <span className="num">{formatClock(newest)}</span>
      </p>
      <p className="text-[10px] text-slate-t">
        {traffic.paused
          ? 'Live feed paused'
          : `Auto-refreshing: health every ${HEALTH_INTERVAL_MS / 1000}s, events every ${EVENTS_INTERVAL_MS / 1000}s`}
      </p>
    </div>
  )
}

function SideNav({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="flex flex-col gap-0.5 p-3" aria-label="Console sections">
      {NAV.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          onClick={onNavigate}
          className={({ isActive }) =>
            `flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
              isActive
                ? 'bg-accent-500/12 text-accent-300 ring-1 ring-accent-500/25 ring-inset'
                : 'text-slate-b hover:bg-ink-800/70 hover:text-slate-hi'
            }`
          }
        >
          <Icon className="h-4 w-4 shrink-0" aria-hidden />
          {label}
        </NavLink>
      ))}
    </nav>
  )
}

function FeedFooter() {
  const traffic = useTraffic()
  return (
    <div className="border-t border-ink-700 p-3">
      <p className="text-[10px] tracking-wide text-slate-t uppercase">Event log</p>
      <p className="mt-1 text-[11px] text-slate-b">
        {traffic.missingMessage
          ? 'not found'
          : `${traffic.events.length.toLocaleString()} records in view`}
      </p>
      <p className="text-[10px] text-slate-t">read {relativeAge(traffic.updatedAt)}</p>
    </div>
  )
}

export function AppShell({ children }: { children: ReactNode }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const location = useLocation()
  const current = NAV.find((n) => (n.end ? location.pathname === n.to : location.pathname.startsWith(n.to)))

  return (
    <div className="flex min-h-screen">
      {/* Desktop rail */}
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-ink-700 bg-ink-900/60 backdrop-blur-sm lg:flex">
        <div className="flex items-center gap-2.5 border-b border-ink-700 px-4 py-4">
          <ShieldHalf className="h-5 w-5 text-accent-400" aria-hidden />
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-slate-hi">MicroAPI Guard</p>
            <p className="text-[10px] text-slate-t">Security Console</p>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          <SideNav />
        </div>
        <FeedFooter />
      </aside>

      {/* Mobile / tablet drawer */}
      {menuOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <button
            type="button"
            aria-label="Close navigation"
            onClick={() => setMenuOpen(false)}
            className="absolute inset-0 bg-ink-950/80"
          />
          <div className="relative h-full w-64 border-r border-ink-700 bg-ink-900">
            <div className="flex items-center justify-between border-b border-ink-700 px-4 py-3.5">
              <span className="text-sm font-semibold text-slate-hi">MicroAPI Guard</span>
              <button type="button" onClick={() => setMenuOpen(false)} aria-label="Close navigation">
                <X className="h-4 w-4 text-slate-b" />
              </button>
            </div>
            <SideNav onNavigate={() => setMenuOpen(false)} />
          </div>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b border-ink-700 bg-ink-900/85 backdrop-blur-md">
          <div className="flex flex-wrap items-center gap-3 px-4 py-3 sm:px-6">
            <button
              type="button"
              onClick={() => setMenuOpen(true)}
              aria-label="Open navigation"
              className="rounded-md border border-ink-600 p-1.5 text-slate-b lg:hidden"
            >
              <Menu className="h-4 w-4" />
            </button>
            <h1 className="text-sm font-semibold text-slate-hi">{current?.label ?? 'Console'}</h1>
            <div className="flex flex-wrap items-center gap-1.5">
              <ProtectionStatus />
            </div>
            <div className="ml-auto">
              <LastUpdated />
            </div>
          </div>
        </header>

        <main className="min-w-0 flex-1 px-4 py-5 sm:px-6">{children}</main>

        <footer className="border-t border-ink-700 px-4 py-3 text-[10px] text-slate-t sm:px-6">
          Read-only console. Live values come from the gateway's <code>/__guard/health</code> and{' '}
          <code>/__guard/stats</code> endpoints and from its append-only event log. Nothing on any page is simulated.
        </footer>
      </div>
    </div>
  )
}
