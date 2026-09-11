import { useContext } from 'react'
import { GuardDataContext, type GuardData } from './GuardDataProvider'

export function useGuardData(): GuardData {
  const ctx = useContext(GuardDataContext)
  if (!ctx) throw new Error('useGuardData must be used inside <GuardDataProvider>')
  return ctx
}
