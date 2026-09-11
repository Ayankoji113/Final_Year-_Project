/**
 * Thin fetch wrapper.
 *
 * Two things it must get right, because the whole console leans on them:
 * every request is abortable (polling that cannot be cancelled leaks a timer
 * per page change), and every failure comes back as a sentence a human can act
 * on rather than a bare "Failed to fetch".
 */

export class ApiError extends Error {
  readonly status: number
  readonly hint: string

  constructor(message: string, status: number, hint: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.hint = hint
  }
}

const DEFAULT_TIMEOUT_MS = 8000

export async function getJson<T>(url: string, signal?: AbortSignal, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<T> {
  return request<T>(url, { method: 'GET' }, signal, timeoutMs)
}

export async function postJson<T>(url: string, signal?: AbortSignal, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<T> {
  return request<T>(url, { method: 'POST' }, signal, timeoutMs)
}

async function request<T>(
  url: string,
  init: RequestInit,
  signal: AbortSignal | undefined,
  timeoutMs: number,
): Promise<T> {
  const timer = new AbortController()
  const timeout = setTimeout(() => timer.abort(new DOMException('timeout', 'TimeoutError')), timeoutMs)
  const onOuterAbort = () => timer.abort(signal?.reason)
  signal?.addEventListener('abort', onOuterAbort)

  try {
    const res = await fetch(url, { ...init, signal: timer.signal, headers: { accept: 'application/json' } })
    if (!res.ok) {
      throw new ApiError(
        `${init.method} ${url} returned HTTP ${res.status}`,
        res.status,
        // The dev/preview proxy reports a dead upstream as 500, not 502, so
        // all three mean "nothing answered on port 5000" rather than "the
        // gateway answered and refused".
        res.status === 500 || res.status === 502 || res.status === 504
          ? 'The gateway did not answer. Check that it is running on port 5000.'
          : 'The gateway answered, but rejected the request.',
      )
    }
    return (await res.json()) as T
  } catch (err) {
    if (err instanceof ApiError) throw err
    if (signal?.aborted) throw err
    if (err instanceof DOMException && err.name === 'TimeoutError') {
      throw new ApiError(`${url} timed out after ${timeoutMs} ms`, 0, 'The gateway is reachable but slow, or wedged.')
    }
    throw new ApiError(
      err instanceof Error ? err.message : String(err),
      0,
      'Could not reach the gateway. Start it with "docker compose up -d" from src/.',
    )
  } finally {
    clearTimeout(timeout)
    signal?.removeEventListener('abort', onOuterAbort)
  }
}
