import { HashRouter, Navigate, Route, Routes } from 'react-router-dom'
import { GuardDataProvider } from './hooks/GuardDataProvider'
import { AppShell } from './components/layout/AppShell'
import { Overview } from './pages/Overview'
import { LiveTraffic } from './pages/LiveTraffic'
import { Threats } from './pages/Threats'
import { ThreatInvestigation } from './pages/ThreatInvestigation'
import { MLIntelligence } from './pages/MLIntelligence'
import { RequestLogs } from './pages/RequestLogs'
import { SystemHealth } from './pages/SystemHealth'
import { Configuration } from './pages/Configuration'

/**
 * HashRouter rather than BrowserRouter: the built bundle is meant to be served
 * by anything that can hand out static files, including `vite preview` and a
 * plain file server, neither of which rewrites unknown paths to index.html.
 */
export function App() {
  return (
    <GuardDataProvider>
      <HashRouter>
        <AppShell>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/live" element={<LiveTraffic />} />
            <Route path="/threats" element={<Threats />} />
            <Route path="/investigate" element={<ThreatInvestigation />} />
            <Route path="/investigate/:offset" element={<ThreatInvestigation />} />
            <Route path="/ml" element={<MLIntelligence />} />
            <Route path="/logs" element={<RequestLogs />} />
            <Route path="/health" element={<SystemHealth />} />
            <Route path="/config" element={<Configuration />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </AppShell>
      </HashRouter>
    </GuardDataProvider>
  )
}
