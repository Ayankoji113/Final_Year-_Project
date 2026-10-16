"""Estimate when each clause of the narration is spoken.

Kokoro pauses at punctuation, so speech segments (between silences) map onto
clauses. When the counts match we use the measured segment starts; otherwise we
fall back to a punctuation-weighted character estimate. Output: per scene, a
list of [clause_text, start_s].
"""
import json, re, sys, pathlib
import numpy as np
import soundfile as sf

vo = pathlib.Path(sys.argv[1]); txt = pathlib.Path(sys.argv[2]); out = sys.argv[3]

def clauses(text):
    parts = re.split(r"(?<=[.,:;?!])\s+", text.strip())
    return [p for p in parts if p]

def segments(path, min_gap=0.16, thresh_db=-38):
    a, sr = sf.read(path)
    if a.ndim > 1: a = a.mean(1)
    hop = int(sr * 0.01)
    rms = np.sqrt(np.convolve(a ** 2, np.ones(hop) / hop, mode="same"))[::hop]
    db = 20 * np.log10(rms + 1e-9)
    voiced = db > thresh_db
    starts, i, n = [], 0, len(voiced)
    while i < n:
        if voiced[i]:
            starts.append(i * 0.01)
            while i < n:
                j = i
                while j < n and not voiced[j]: j += 1
                if j - i >= min_gap / 0.01 and j > i: break
                i = j + 1 if j == i else j
            continue
        i += 1
    return starts, len(a) / sr

def weighted(cls, dur, first):
    w = [len(c) + (6 if c[-1] in ".?!" else 3) for c in cls]
    tot = sum(w); t = first; res = []
    for c, wi in zip(cls, w):
        res.append(round(t, 2)); t += (dur - first) * wi / tot
    return res

result = {}
for f in sorted(txt.glob("s*.txt")):
    n = f.stem; cls = clauses(f.read_text(encoding="utf-8"))
    starts, dur = segments(vo / f"{n}.wav")
    if len(starts) == len(cls):
        times, how = [round(s, 2) for s in starts], "exact"
    else:
        est = weighted(cls, dur, starts[0] if starts else 0.0)
        times, snapped, prev = [], 0, -1.0
        for k, e in enumerate(est):
            near = [s for s in starts if abs(s - e) <= 0.8 and s > prev]
            t = min(near, key=lambda s: abs(s - e)) if near else max(e, prev + 0.3)
            snapped += bool(near); times.append(round(t, 2)); prev = t
        how = f"snap {snapped}/{len(cls)}"
    result[n] = {"dur": round(dur, 3), "how": how, "clauses": [[c, t] for c, t in zip(cls, times)]}
    print(n, how)
json.dump(result, open(out, "w"), indent=1)
