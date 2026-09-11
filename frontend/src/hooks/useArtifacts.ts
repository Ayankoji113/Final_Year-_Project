import { fetchArtifacts, fetchConfigDefaults, fetchRules } from '../services/artifacts'
import { usePoll } from './usePoll'

/**
 * Training artefacts and static source tables.
 *
 * These only change when someone retrains or edits the rule file, so they are
 * fetched once per mount (interval 0) rather than polled.
 */
export function useArtifacts() {
  return usePoll(fetchArtifacts, 0)
}

export function useRules() {
  return usePoll(fetchRules, 0)
}

export function useConfigDefaults() {
  return usePoll(fetchConfigDefaults, 0)
}
