# Brag Plan: MicroAPI Guard

## What is this app?
A backend-agnostic API security gateway that reverse-proxies any HTTP backend and pushes every request through a four-layer detection pipeline — deterministic signatures and Redis rate limits (L1), an Isolation Forest (L2), a NumPy autoencoder (L3) and a gradient-boosted meta-learner (L4) — blocking malicious traffic inline with no change to the protected service.

## The angle
A calm, cinematic engineering documentary on black. The video walks the path of a single request through the gateway, layer by layer, then goes live: real console recordings and real gateway responses captured from the running system. The emotional turn is the project's own honesty — the 0.99 F1 that turned out to be a lie, the independent-traffic finding that became the main contribution, and the brake that keeps an unready model from blocking anyone. Closing line comes straight from the README: **Enforce what is certain. Observe what is learned.**

## Hook (first 2-3 seconds)
Pure black. A cursor types a real attack — `GET /api/search?q=' UNION SELECT password FROM users --` — key by key. It hits the gateway and a red `403 · L1-rules · sqli.union` verdict slams in. Narration: "Every API is a door…"

## Key moments (the middle)
- The double-encoded traversal `%252e%252e%252f` visibly collapsing to `../` through the decode loop.
- `O'Brien` sailing through a rule that blocks `' OR '1'='1' --` (structure, not characters).
- The 34-feature vector assembling, with endpoint identity and User-Agent crossed out.
- The autoencoder 34→32→16→32→34 hourglass reconstructing normal traffic cleanly and failing on an anomaly.
- Live console recordings: Overview, Live Traffic, Threats, Investigation (1.258 ms block, no model ran), System Health brake.
- The honesty reveal: F1 0.99 → ROC-AUC 0.56 on independent traffic; models_b4 61.3% → 17.0% false positives.

## Outro / punchline
"Enforce what is certain. Observe what is learned." → MicroAPI Guard lockup + repo URL.

## User flow worth showing
1. Normal request `GET /api/products/1` → `200 OK`, `x-guard-action: allow`.
2. Attacks (SQLi, double-encoded traversal, XSS, SSRF) → `403` with deciding layer + reason, and `O'Brien` → `200`.
3. Console shows the verdicts land live: Allowed / Blocked / Would block, then an Investigation drill-down of one blocked request.

## Tone
- Preset: cinematic (with polished restraint)
- Creative direction: user-provided — "a full explanation of the project, using black; images, animation, sound effects and AI-generated narration; include the live demo; explain the implementation with a beautiful touch."
- Interpretation: long-form documentary pacing; each chapter gets room to breathe under narration; black canvas with the console's own blue/green/red/amber/indigo verdict colours as the only colour; motion is precise and calm, never busy.

## Format: landscape — 1920x1080, 30fps
## Duration: ~6.5–7 minutes (user requested a minimum of 5 minutes)
Deliberate override of brag's 15–25 s creative law, requested explicitly by the user. Scene lengths flex to the generated narration.

## Visual identity (from the project — frontend/src/index.css)
- Background: pure black #000000 (user request), with the console's ink-950 #05080f for panels and subtle accent-500 radial glows
- Accent: #3b82f6 (accent-500), #60a5fa (accent-400)
- Verdict colours: ok #22c55e, bad #ef4444, warn #f59e0b, ml #818cf8
- Text: #e6ecf7 (slate-hi), secondary #aebcd6 (slate-b), muted #7c8db0 (slate-t)
- Display/body font: Inter (console font) · Mono: JetBrains Mono
- Strongest visual element: the console's verdict pills (Allowed / Blocked / Would block) and the "Detection pipeline" stack from ML Intelligence

## Share copy (draft)
MicroAPI Guard: a four-layer API security gateway — 26 signatures, Redis rate limits, an Isolation Forest, a NumPy autoencoder and a gradient-boosted meta-learner — that enforces what is certain and only observes what is learned.

## Audio direction
- Role: cinematic support under narration
- Music: happy-beats-business-moves-vol-12 (steady and clean), looped to cover the full length
- Music treatment: fades in over the cold open, sits at ~0.10–0.12 under narration, lifts briefly in chapter gaps and the outro, fades out under the final lockup
- Music cue guidance: bundled preset read at composition time; only 1–3 locks (hook verdict slam, title reveal, outro lockup)
- Audio-reactive treatment: subtle — background glow breathes with music RMS if extraction is available; otherwise skipped
- SFX posture: sparse, motion-matched; key ticks for typed requests, a soft impact for 403 verdicts, gentle drops for cards, one bell for the title and one for the outro
- Restraint rule: never compete with the narration; no SFX on every list item

## Voiceover script
Voice: Kokoro `af_heart`. Generated per scene; scene durations follow the audio.

1. **Cold open** — Every API is a door. Most requests knock politely. Some arrive with a crowbar. This one asks the database for every password it holds. It never gets there.
2. **Title** — This is MicroAPI Guard: a real-time API security gateway built on a learned stacking ensemble. It sits in front of any HTTP backend, inspects every request through four layers of detection, and blocks malicious traffic inline, without a single change to the service it protects.
3. **The problem** — Microservices turned REST APIs into the front line. The usual defences, web application firewalls and static rate limiters, only catch what they already have a signature for, and during traffic spikes they often block the very users they're meant to protect. MicroAPI Guard combines both worlds: deterministic rules for what is certain, and unsupervised models, trained only on normal traffic, for what no signature anticipates.
4. **Architecture** — Here is the shape of it. Clients reach the gateway on port five thousand, the only port that is published. Behind it, on an internal network, sit the backend and Redis, deliberately unreachable from the host, so the gateway cannot be bypassed. Every request flows down one pipeline: normalization, layer one rules and rate limits, feature extraction, an Isolation Forest, an autoencoder, and finally a gradient-boosted meta-learner. FastAPI, Redis, scikit-learn and NumPy, all running in Docker.
5. **Normalization** — Before any rule runs, the payload is normalized, because attackers hide inside encodings. The gateway percent-decodes up to four times, unescapes HTML entities, folds Unicode with NFKC, and strips null bytes. Watch a double-encoded path traversal collapse. Percent two five two E becomes percent two E, which becomes a plain dot dot slash. Now the signature can see it.
6. **Layer 1 rules** — Layer one is twenty-six deterministic signatures, covering SQL injection, cross-site scripting, path traversal, command injection, server-side request forgery, scanner probes and deserialization. Every rule is either block or flag. A pattern only earns block if a legitimate client would essentially never send it, like UNION SELECT. Weaker patterns become flags: evidence for the model, not an instant 403. And rules match structure, not single characters, so a customer named O'Brien goes straight through.
7. **Rate limiting** — The other half of layer one is rate limiting, backed by Redis sorted sets. Each client gets a sixty-second sliding window of two hundred and forty requests, and a five-second burst window of forty. A HyperLogLog counts how many distinct endpoints a client touches, in constant memory, which is the fingerprint of scanning and enumeration. All three counters update in a single pipelined round trip.
8. **Short-circuit** — A block hit or a rate breach ends the request right there, with a 403. Sending a confirmed UNION SELECT to a statistical model to ask its opinion would only add latency, and a chance of being wrong about something already certain.
9. **Features** — Everything that survives layer one becomes a vector of thirty-four behavioural features: the shape of the body, the path and the query, their length, depth, entropy and special characters, and how much decoding changed them, plus endpoint breadth, the HTTP method, and the number of flag hits. Just as important is what is missing. There is no endpoint identity, so the model learns what a request looks like, not where it went, and that is what lets it sit in front of a different backend. And there are no client headers like the User-Agent. An attacker copies those for free, and they were the single biggest source of false positives.
10. **L2 and L3** — Layers two and three are unsupervised. They are trained only on normal traffic, so they never need attack labels. The Isolation Forest, three hundred trees, measures how easily a request can be isolated from the crowd. The autoencoder, written in pure NumPy with no PyTorch, squeezes the thirty-four features through a narrow bottleneck and tries to rebuild them. Normal traffic reconstructs cleanly. Anomalies do not, and the reconstruction error becomes a score.
11. **L4 meta-learner** — Layer four makes the call. A gradient-boosted meta-learner takes exactly three inputs: the rate score from layer one, the forest score, and the autoencoder score. It returns one probability. Above the threshold of zero point four three, chosen on a validation pool under a one percent false-positive budget, the request is judged hostile. This is the only component that decides.
12. **Engineering safeguards** — The gateway and the trainer import the same feature code, so serving can never drift from training, and the gateway refuses to load a model whose feature contract does not match. The event log stores a numeric feature vector and a hashed client id, never a raw request body. Inference errors fail closed. Bodies are capped at one mebibyte, and the containers run as non-root.
13. **Live: console** — Now let's see it running. This is the security console: eight pages built with React, TypeScript and Recharts, reading live from the gateway's health and stats endpoints and its event log. Nothing on screen is simulated. The gateway is healthy, Redis is connected, the models are loaded, and the backend is responding.
14. **Live: attacks** — Let's send some traffic. A normal product request goes straight through: 200 OK. A SQL injection is blocked at layer one, with the rule and the reason. A double-encoded path traversal is still blocked. A script tag, blocked. A request for the cloud metadata endpoint, the classic SSRF credential grab, blocked. And the name O'Brien? 200 OK.
15. **Live: traffic feed** — In the live feed, every request lands with its verdict. Green is allowed. Red was blocked by a rule. Amber is different: would block. The machine-learning layer judged that request hostile, but in the default mode it only records the verdict and forwards the request anyway.
16. **Live: threats and investigation** — The Threats page keeps enforced rule blocks and machine-learning detections strictly apart. And any event can be investigated. This path traversal matched two signatures and was blocked in one point two six milliseconds, before any model ran. The request itself was never stored raw: just its features, and a pseudonymised client hash.
17. **Live: ML and health** — ML Intelligence shows the live pipeline and its threshold. System Health shows something more important: the would-block rate. In this demo, the model would have blocked far too much legitimate traffic. Which brings us to the most honest part of this project.
18. **The honest finding** — Early on, the ensemble scored an F1 of zero point nine nine. It looked perfect. But the test data came from the same traffic generator used for training, and that generator always called each endpoint the same way. The model had learned how each endpoint is normally called, not what an attack is. A bare GET on the products endpoint scored zero point nine nine: attack. On traffic from a second, independent client, it was close to chance, with a ROC AUC of zero point five six. Finding that, and fixing it, became the main contribution of this work.
19. **The real numbers** — The live model, models b4, was chosen only on independent traffic. It cut legitimate requests wrongly flagged from sixty-one point three percent to seventeen. ROC AUC rose from zero point five six to zero point eight seven, and it still catches ninety-two point eight percent of the attacks that layer one missed. Layer one itself wrongly blocked zero of five hundred and eight legitimate requests.
20. **Enforcement and the brake** — Seventeen percent is a long way from the one percent goal, so the model does not block by default. The gateway runs in enforce L1 mode. When an operator is ready, machine-learning blocking can be switched on per endpoint, for a small canary of clients, behind an automatic brake. If the would-block rate passes five percent, the brake turns machine-learning blocking off by itself, while layer one keeps blocking. And a single client can never trip it alone, so an attacker cannot switch the model off with volume.
21. **Verification** — All of it is covered by a suite of one hundred and thirty-seven tests, with tooling for ten-seed statistical validation and McNemar comparisons against single-model baselines, and a Docker deployment that starts with one command.
22. **Outro** — MicroAPI Guard. Enforce what is certain. Observe what is learned.

## Storyboard
Durations are set from the generated narration (≈ narration + 1.2–2 s of air). Every scene is a sub-composition on black.

### Scene 1 — Cold open
Black. Terminal prompt types the real SQLi request character by character, then a red 403 card slams in with the real JSON reason. Sequential: typed request with key ticks. Audio: music fades in; key ticks; soft impact on 403. Transition: dip to black.

### Scene 2 — Title
Shield mark draws on, "MicroAPI Guard" in Inter 700, subtitle "Real-Time API Anomaly Detection Using a Learned Stacking Ensemble", then the README client→Guard→backend line animates with a packet. Audio: bell on title. Transition: soft fade.

### Scene 3 — The problem
Three cards: "REST APIs are primary targets", "Signatures only catch what they know", "Static limits block real users during spikes" → resolve into two columns "Deterministic rules — what is certain" / "Unsupervised models — what no signature anticipates". Sequential: cards one by one with drop SFX.

### Scene 4 — Architecture
Diagram: Client → :5000 Gateway → internal network (Backend :8000, Redis :6379) with a dashed "internal network" boundary and a crossed-out bypass arrow; then the 6-stage pipeline stack lights up top to bottom; tech chips FastAPI · Redis · scikit-learn · NumPy · Docker.

### Scene 5 — Normalization
Big mono string `/api/files/%252e%252e%252f%252e%252e%252fetc%252fpasswd` decodes in rounds: round 1 → `%2e%2e%2f…`, round 2 → `../../etc/passwd`; step chips: percent-decode ×4 · HTML unescape · NFKC fold · strip nulls.

### Scene 6 — Layer 1 rules
Category grid (sqli, xss, traversal, cmdi, ssti, scan, deser, ssrf) with "26 signatures" counter; BLOCK vs FLAG split with real rule ids and reasons; `O'Brien` → 200 vs `' OR '1'='1' --` → 403.

### Scene 7 — Rate limiting
Sliding-window bar filling with request ticks: 240 / 60 s, 40 / 5 s, HyperLogLog distinct-endpoints counter; "1 pipelined Redis round trip".

### Scene 8 — Short-circuit
Fork: BLOCK hit → 403 exit; everything else → down to the models. Quote card.

### Scene 9 — Features
34 feature names assemble as a grid in groups (body 9, path 11, query 5, behaviour 1, method 7, L1 evidence 1); then struck-through ghosts: `http_path one-hot`, `user_agent`, `referer`, `header_count`.

### Scene 10 — L2 + L3
Left: Isolation Forest — points, one outlier isolated by few splits, "300 trees". Right: autoencoder hourglass 34→32→16→32→34; normal input reconstructs (green), anomaly fails (red), "reconstruction error = score".

### Scene 11 — L4
Three score bars (rate, isolation_forest, autoencoder) flow into a "HistGradientBoosting" node → probability gauge crossing threshold 0.43.

### Scene 12 — Engineering safeguards
Checklist of six safeguards appearing one by one with shield ticks.

### Scene 13 — Live: console overview (recording)
overview-rec.mp4 in a floating browser frame, chapter tag "LIVE DEMO".

### Scene 14 — Live: attacks (terminal)
Terminal window replays the real captured responses line by line (200 / 403 ×4 / 200).

### Scene 15 — Live: traffic feed (recording)
live-rec.mp4 framed; legend pills Allowed / Blocked / Would block fade in on cue.

### Scene 16 — Live: threats + investigation
threats-rec.mp4, then inv-block.png with a slow push toward "1.258 ms" and "No model scores for this request".

### Scene 17 — Live: ML + health
ml-view.png pipeline, then health-view.png with the "Live would-block rate" panel highlighted.

### Scene 18 — The honest finding
Big "F1 0.991" that cracks; the bare-GET vs `?page=2&limit=20` comparison (0.99 vs 0.0003); "ROC-AUC 0.56 — near chance".

### Scene 19 — The real numbers
Before/after table with animated bars: FPR 61.3% → 17.0%, ROC-AUC 0.56 → 0.87, recall 92.8%, F1 0.32 → 0.58; L1 0 / 508.

### Scene 20 — Enforcement + brake
Mode switch: monitor / enforce-l1 / enforce; canary dial 5%; brake gauge crossing 5% → ML off, L1 still blocking.

### Scene 21 — Verification
Counters: 137 tests · 10 seeds · McNemar · `docker compose up -d`.

### Scene 22 — Outro
"Enforce what is certain." / "Observe what is learned." then lockup + github.com/Ayankoji113/Final_Year-_Project. Bell; music fades.

**Music mood for this video:** cinematic, steady
**Audio summary:** a quiet steady bed under clear narration, with precise motion-matched accents at verdicts and reveals, opening and closing on music.
