import { useMemo } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { useTraffic } from '../hooks/useTraffic'
import { useHealth } from '../hooks/useHealth'
import { useArtifacts, useRules } from '../hooks/useArtifacts'
import { InvestigationView } from '../components/investigation/InvestigationView'
import { EventTable } from '../components/tables/EventTable'
import { EmptyState, Panel, SourceNote } from '../components/common/Panel'
import { eventKey, threatEvents } from '../utils/derive'

/**
 * Investigation for one log record.
 *
 * The record is looked up in the in-memory window by its byte offset. An event
 * that has scrolled out of that window cannot be recovered without re-reading
 * the log from the start, so the page says so rather than showing a blank
 * detail panel.
 */
export function ThreatInvestigation() {
  const { offset } = useParams<{ offset: string }>()
  const navigate = useNavigate()
  const traffic = useTraffic()
  const health = useHealth()
  const artifacts = useArtifacts()
  const rules = useRules()

  const event = useMemo(
    () => (offset ? (traffic.events.find((e) => eventKey(e) === offset) ?? null) : null),
    [traffic.events, offset],
  )

  // Live threshold first - it is what the gateway is deciding with right now.
  // decision.json is the fallback when the gateway cannot be reached.
  const threshold = health.data?.threshold ?? artifacts.data?.decision?.threshold ?? null

  if (!offset) {
    const candidates = [...threatEvents(traffic.events)].reverse().slice(0, 60)
    return (
      <div className="space-y-4">
        <Panel
          title="Select an event to investigate"
          subtitle="Security events from the loaded log window. Any row in Live Traffic, Threats or Request Logs opens here too."
          bodyClassName=""
        >
          <EventTable
            events={candidates}
            columns={['time', 'method', 'template', 'status', 'decision', 'layer', 'probability', 'reason']}
            onSelect={(e) => navigate(`/investigate/${eventKey(e)}`)}
            emptyTitle="No security events in the loaded window"
            emptyHint="Nothing was blocked and no signature fired across the records currently loaded."
            maxHeight="max-h-[70vh]"
          />
        </Panel>
      </div>
    )
  }

  if (!event) {
    return (
      <Panel title="Event not in the loaded window">
        <EmptyState
          title={`No record at offset ${offset} is currently held in memory`}
          hint="The console keeps a rolling window of the most recent records. Open the event again from Live Traffic or Request Logs, or widen the window by reloading the page."
        />
        <button
          type="button"
          onClick={() => navigate('/live')}
          className="mx-auto mt-2 flex items-center gap-1.5 rounded-md border border-ink-600 px-3 py-1.5 text-xs text-slate-b hover:text-slate-hi"
        >
          <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Back to live traffic
        </button>
      </Panel>
    )
  }

  return (
    <div className="space-y-4">
      <button
        type="button"
        onClick={() => navigate(-1)}
        className="inline-flex items-center gap-1.5 rounded-md border border-ink-600 px-2.5 py-1.5 text-xs text-slate-b hover:border-ink-500 hover:text-slate-hi"
      >
        <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Back
      </button>

      <InvestigationView event={event} threshold={threshold} rules={rules.data?.rules ?? null} />

      <SourceNote>
        Threshold shown is {health.data ? "the live value from the gateway's /__guard/health" : 'from decision.json, because the gateway is unreachable'}.
        {rules.state === 'error' && ' The rule table could not be read, so signature descriptions are omitted rather than guessed.'}
      </SourceNote>
    </div>
  )
}
