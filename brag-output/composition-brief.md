# Hyperframes Composition Brief: MicroAPI Guard

## Objective
A long-form (user-requested, ≥ 5 min) narrated explainer of MicroAPI Guard on black: what it is, how every layer is implemented, a live demo of the running system, the honest results, and how enforcement is kept safe.

## Output
- Composition directory: `brag-output/composition/`
- Rendered video: `brag-output/brag.mp4`
- Format: landscape — 1920x1080, 30 fps
- Duration: 552.2 s (9:12) — scene lengths follow the generated narration (`work/build.py`)

## Source Material
- Project root: `C:\Final_year Project`
- Primary files read: README.md, HANDOVER.md, CLAUDE.md, src/common/{rules,normalize,features}.py, src/gateway/{detector,enforcement,ratelimit,main}.py, src/ml_pipeline/models/{decision.json,MODEL_SELECTION.md}, src/docker-compose.yml, frontend/src/index.css, frontend/README.md
- Product name: MicroAPI Guard
- Tagline: "Real-Time API Anomaly Detection Using a Learned Stacking Ensemble"
- Live material captured from the running stack (gateway + console + `traffic_simulator/live_demo.py`):
  - `assets/demo/{overview,live,threats}-rec.mp4` — frame-accurate console recordings
  - `assets/demo/*-view.png`, `inv-block.png` — console stills (Overview, Live Traffic, Threats, Investigation, ML Intelligence, System Health)
  - Real gateway responses for /api/products/1, SQLi, double-encoded traversal, XSS, SSRF and O'Brien (scene 14)
- Copy used verbatim: "sqli.union: UNION SELECT is never emitted by a legitimate API client"; the detector.py short-circuit quote; "Enforce what is certain. Observe what is learned." (README)

## Creative Direction
- Tone preset: cinematic, with polished restraint
- Creative direction: full explanation on black, images + animation + SFX + AI narration, live demo, implementation detail, beautiful touch
- Angle: walk one request through the gateway layer by layer, go live, then tell the honest story (F1 0.99 in-distribution → ROC-AUC 0.56 on independent traffic → models_b4 and the brake)
- Hook: a real UNION SELECT typed key by key, then a red 403 verdict
- Outro: "Enforce what is certain. Observe what is learned." + repo URL

## Visual Identity
- Background: #000 with slow blue/indigo glows and a faint masked grid (`compositions/bg.html`)
- Text: #e6ecf7 / #aebcd6 / #8796b8
- Accent: #3b82f6 / #60a5fa; verdicts: ok #22c55e, bad #ef4444, warn #f59e0b, ml #818cf8 (from the console's index.css)
- Fonts: Inter (display/body), JetBrains Mono (code) — local woff2 in `assets/fonts/`

## Storyboard
22 scenes, one sub-composition each (`compositions/s01–s22.html`), plus `bg.html` and `chrome.html` (chapter label + progress hairline). See `brag-plan.md` for the scene-by-scene contract.

## Audio
- Narration: Kokoro `af_heart`, one WAV per scene (`assets/vo/`), aligned to clauses via pause detection (`work/align.json`); every visual cue is a clause start
- Music: chapter-based bed (vol-12 → vol-9 → vol-11 → vol-12) with crossfades, loudness-normalised, at 0.13 under narration (`assets/music/bed.m4a`)
- SFX: ~70 motion-matched CC0 cues (key ticks for typing, soft impacts on 403s, card slides for screen changes, bells on title/finding/outro)
- Audio-reactive treatment: not used — the narration runs nearly continuously, so the bed stays quiet and steady by design
- Beat sync: not used — narration timing drives every reveal

## Hyperframes Instructions
Built with hyperframes-core conventions (templated sub-compositions, one paused timeline per scene, seek-safe fromTo tweens, scene-local media timing). `npx hyperframes check` passes: 0 errors, 58/58 WCAG AA text checks.
