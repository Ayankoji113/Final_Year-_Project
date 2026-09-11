# MicroAPI Guard — Security Console

A read-only operations console for the MicroAPI Guard gateway. React + TypeScript +
Vite + Tailwind + Recharts + Lucide.

It adds nothing to the gateway. Every number on every page comes from one of four
places, and each page says which:

| Source | What it gives | How it is reached |
| --- | --- | --- |
| `GET /__guard/health` | mode, enforcement split, model + calibration state, Redis, threshold, uptime | proxied by Vite to port 5000 |
| `GET /__guard/stats` | in-process request counters and enforced-blocks-by-layer | proxied by Vite to port 5000 |
| `POST /__guard/reload` | hot-reload of models and baseline (the only write) | proxied, behind a confirmation |
| `src/data/events.jsonl` | every logged request: verdict, layer, scores, 34-feature vector | read from disk by a Vite plugin |
| `src/ml_pipeline/models/*.json` | training, validation, comparison and calibration artefacts | read from disk by a Vite plugin |
| `src/common/rules.py`, `config.py` | the 26-rule signature table and the env-var defaults | parsed from source by a Vite plugin |

## Why a Vite plugin reads files

The gateway publishes exactly three admin endpoints and proxies everything else
upstream. It does not serve its event log or its model artefacts over HTTP, and this
project must not grow an endpoint that does just to feed a dashboard. So the dev and
preview server — frontend tooling, not part of the deployed gateway — reads those
files directly and exposes them under `/__dash/*`. It never writes.

See `plugins/microapiData.ts`.

## Why a proxy rather than CORS

The gateway sends no CORS headers, deliberately: it is a reverse proxy for an API,
not for a browser app. Rather than modify it, the console is served same-origin and
Vite proxies `/__guard` to port 5000. The deployed gateway stays byte-for-byte the
one that was audited.

## Running it

Start the stack first:

```bash
cd src
docker compose up -d          # gateway on :5000
```

Then the console:

```bash
cd frontend
npm install
npm run dev                   # http://localhost:5173
```

Production build:

```bash
npm run build
npm run preview               # http://localhost:4173, same proxy and file reader
```

The build is a static bundle, but the `/__dash/*` file reader and the `/__guard`
proxy only exist in the dev and preview servers. Serving `dist/` from a plain static
host gives you a page that cannot reach any data.

### Environment overrides

| Variable | Default | Purpose |
| --- | --- | --- |
| `GATEWAY_URL` | `http://127.0.0.1:5000` | where to proxy `/__guard` |
| `MICROAPI_SRC` | `../src` | repository `src/` directory |
| `MICROAPI_EVENT_LOG` | `<src>/data/events.jsonl` | event log path |
| `MICROAPI_MODELS_DIR` | `<src>/ml_pipeline/models` | artefacts directory |

## Refresh behaviour

Everything live is **polling**, and the UI says so rather than claiming to stream:

- health and stats every 5 s
- the event log every 4 s, reading only the bytes appended since the last read
- artefacts, rules and config defaults once per mount

There is no WebSocket or SSE channel on the gateway, and adding one purely for a
dashboard is out of scope.

## Rules the UI holds itself to

- **A block is attributed to the layer the gateway recorded**, never inferred from an
  HTTP status. A 403 in the log can be the backend's own 403 relayed through the
  proxy.
- **Not every block is ML.** L1 signature hits and rate-limit trips are deterministic
  and short-circuit before any model runs. They get their own colour and their own
  counters everywhere.
- **"Would block" is its own state.** Under `GUARD_MODE=enforce-l1` an L4 verdict is
  recorded and the request is still forwarded. Showing that as a block would claim
  protection the gateway did not apply.
- **Missing data says it is missing.** No metric is filled with a plausible number.
- **Reported metrics carry their intervals.** The ML page leads with the ten-seed
  confidence intervals from `validation.json` and marks the single-seed figures in
  `decision.json` as the best of ten.

## What the log does not contain

The gateway writes a numeric feature vector, never a raw request, so no page can show
a raw URL, query string, body, header or client IP — a login password cannot leak
through the log. What exists is the normalised path template, the path length, the
body size, and a pseudonymised client hash. The console shows exactly that.
