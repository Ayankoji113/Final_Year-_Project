"""Split the sample at pauses and transcribe each phrase on its own.

Output phrases.json: [{i, start, end, text}] so clean phrases can be chosen
by exact boundaries (long-form Whisper timestamps drift).
"""
import json, sys
import numpy as np
import soundfile as sf
from transformers import pipeline

wav, out = sys.argv[1], sys.argv[2]
a, sr = sf.read(wav)
hop = int(sr * 0.01)
rms = np.sqrt(np.convolve(a ** 2, np.ones(hop) / hop, mode="same"))[::hop]
voiced = 20 * np.log10(rms + 1e-9) > -36

# speech runs separated by >= 0.35 s of silence
runs, i, n = [], 0, len(voiced)
while i < n:
    if not voiced[i]:
        i += 1; continue
    j = i
    while j < n:
        k = j
        while k < n and not voiced[k]: k += 1
        if k - j >= 35 or k >= n: break
        j = k + 1 if k == j else k
    runs.append([i * 0.01, j * 0.01]); i = j
runs = [r for r in runs if r[1] - r[0] > 0.25]

asr = pipeline("automatic-speech-recognition", model="openai/whisper-small.en", device="cpu")
res = []
for idx, (s, e) in enumerate(runs):
    seg = a[int(max(0, s - 0.05) * sr): int((e + 0.05) * sr)].astype("float32")
    text = asr({"raw": seg, "sampling_rate": sr})["text"].strip()
    res.append({"i": idx, "start": round(s, 2), "end": round(e, 2), "text": text})
    print(f"{idx:2d} {s:6.2f}-{e:6.2f} ({e - s:4.1f}s)  {text}", flush=True)
json.dump(res, open(out, "w"), indent=1)
