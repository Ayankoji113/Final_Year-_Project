"""Narrate every scene in the user's cloned voice (variant A, chosen by the user).

Variant A = fluent-phrase reference (ref_cut.wav), English, 30 s conditioning,
temperature 0.8. Spelled acronyms ("A P I") are rewritten as "A.P.I." because
XTTS read "A P I" as "a PI". Resumable: scenes with an existing WAV are skipped.

usage: python clone_all.py <narration_dir> <text_out_dir> <wav_out_dir>
"""
import os, re, sys, time, pathlib
os.environ["COQUI_TOS_AGREED"] = "1"
import numpy as np
import soundfile as sf
import torch
from TTS.api import TTS

src, txt_out, wav_out = (pathlib.Path(p) for p in sys.argv[1:4])
txt_out.mkdir(parents=True, exist_ok=True)
wav_out.mkdir(parents=True, exist_ok=True)


def fix(text):
    # Cases the general rule gets wrong: an article before an acronym, and two acronyms in a row.
    text = text.replace("A S Q L", "An S.Q.L.").replace("R O C A U C", "R.O.C. A.U.C.")
    # "A P I" -> "A.P.I." (runs of 2-4 single capitals)
    text = re.sub(r"\b(?:[A-Z] ){1,3}[A-Z]\b", lambda m: ".".join(m.group(0).split()) + ".", text)
    return re.sub(r"\.\.", ".", text)


torch.set_num_threads(os.cpu_count() or 4)
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
print("device:", DEVICE, flush=True)
m = TTS("tts_models/multilingual/multi-dataset/xtts_v2").to(DEVICE).synthesizer.tts_model
here = pathlib.Path(__file__).resolve().parent
lat, emb = m.get_conditioning_latents(audio_path=str(here / "ref_cut.wav"), gpt_cond_len=30, max_ref_length=60)

for f in sorted(src.glob("s*.txt")):
    text = fix(f.read_text(encoding="utf-8"))
    (txt_out / f.name).write_text(text, encoding="utf-8")
    out = wav_out / f"{f.stem}.wav"
    if out.exists():
        print(f.stem, "exists, skipped", flush=True)
        continue
    t = time.time()
    torch.manual_seed(7)
    # XTTS degrades past ~250 chars per call; speak sentence by sentence.
    parts, gap = [], np.zeros(int(0.22 * 24000), dtype=np.float32)
    # split only after a word ending, never inside an acronym like "A.P.I."
    for s in re.split(r"(?<=[a-z0-9')\]][.?!])\s+", text.strip()):
        parts += [np.asarray(m.inference(s, "en", lat, emb, temperature=0.8, repetition_penalty=5.0,
                                         top_p=0.9)["wav"], dtype=np.float32), gap]
    wav = np.concatenate(parts[:-1])
    sf.write(str(out) + ".tmp.wav", wav, 24000)
    os.replace(str(out) + ".tmp.wav", out)
    print(f.stem, f"{len(wav) / 24000:.1f}s audio in {time.time() - t:.0f}s", flush=True)
