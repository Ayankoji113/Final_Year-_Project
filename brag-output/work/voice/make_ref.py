"""Build a clean cloning reference from the fluent phrases of the user's sample.

Hesitations, restarts and stuck moments (short fragments in phrases.json) are
dropped; kept phrases are joined with short, even gaps.
"""
import json
import numpy as np
import soundfile as sf

KEEP = [2, 3, 5, 11, 17, 18, 23, 24, 31, 35]   # fluent phrases (see phrases.json)
a, sr = sf.read("raw.wav")
ph = {p["i"]: p for p in json.load(open("phrases.json"))}
gap = np.zeros(int(0.28 * sr))
fade = int(0.02 * sr)
out = []
for i in KEEP:
    s, e = ph[i]["start"] - 0.06, ph[i]["end"] + 0.10
    seg = a[int(s * sr): int(e * sr)].copy()
    seg[:fade] *= np.linspace(0, 1, fade)
    seg[-fade:] *= np.linspace(1, 0, fade)
    out += [seg, gap]
ref = np.concatenate(out)
sf.write("ref_cut.wav", ref, sr)
print(f"kept {len(KEEP)} phrases, {len(ref) / sr:.1f}s")
