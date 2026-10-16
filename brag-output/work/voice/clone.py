"""Speak narration scenes in the user's cloned voice (XTTS-v2, CPU).

usage: python clone.py <out_dir> s02 [s05 ...]   (or "all")
Reads the scene text from ../narration/sNN.txt and the reference from ref.wav.
"""
import os, sys, time, pathlib
os.environ["COQUI_TOS_AGREED"] = "1"
import torch
from TTS.api import TTS

out = pathlib.Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
nar = pathlib.Path(__file__).resolve().parent.parent / "narration"
ids = sorted(p.stem for p in nar.glob("s*.txt")) if sys.argv[2:] == ["all"] else sys.argv[2:]

torch.set_num_threads(os.cpu_count() or 4)
tts = TTS("tts_models/multilingual/multi-dataset/xtts_v2").to("cpu")
for sid in ids:
    t = time.time()
    text = (nar / f"{sid}.txt").read_text(encoding="utf-8")
    tts.tts_to_file(text=text, speaker_wav="ref.wav", language="en", file_path=str(out / f"{sid}.wav"),
                    temperature=0.6, repetition_penalty=5.0, split_sentences=True)
    print(f"{sid} done in {time.time() - t:.0f}s", flush=True)
