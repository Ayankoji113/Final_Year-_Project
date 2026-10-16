"""Word-level transcript of the voice sample, to find hesitations and repeats."""
import json, sys
import soundfile as sf
from transformers import pipeline

wav, out = sys.argv[1], sys.argv[2]
audio, sr = sf.read(wav)
asr = pipeline("automatic-speech-recognition", model="openai/whisper-small.en", device="cpu")
res = asr({"raw": audio.astype("float32"), "sampling_rate": sr}, return_timestamps="word", chunk_length_s=30)
words = [[c["text"].strip(), round(c["timestamp"][0], 2), round(c["timestamp"][1] or c["timestamp"][0], 2)] for c in res["chunks"]]
json.dump(words, open(out, "w"), indent=0)
line, t0 = [], None
for w, s, e in words:
    if t0 is None: t0 = s
    line.append(w)
    if len(line) >= 12:
        print(f"{t0:6.2f}  {' '.join(line)}"); line, t0 = [], None
if line: print(f"{t0:6.2f}  {' '.join(line)}")
