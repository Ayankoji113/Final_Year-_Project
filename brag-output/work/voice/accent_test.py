"""Accent + "API" pronunciation variants of one sentence, to pick the closest to the user."""
import os, time
os.environ["COQUI_TOS_AGREED"] = "1"
import soundfile as sf
import torch
from TTS.api import TTS

torch.set_num_threads(os.cpu_count() or 4)
DOTS = "This is Micro A.P.I. Guard. Every A.P.I. request passes through four layers of detection."
WORDS = "This is Micro ay pee eye Guard. Every ay pee eye request passes through four layers of detection."
tts = TTS("tts_models/multilingual/multi-dataset/xtts_v2").to("cpu")
m = tts.synthesizer.tts_model


def say(name, text, ref, lang, cond_len, temp=0.8):
    t = time.time()
    lat, emb = m.get_conditioning_latents(audio_path=ref, gpt_cond_len=cond_len, max_ref_length=cond_len + 30)
    out = m.inference(text, lang, lat, emb, temperature=temp, repetition_penalty=5.0, top_p=0.9)
    sf.write(f"test/{name}.wav", out["wav"], 24000)
    print(name, f"{time.time() - t:.0f}s", flush=True)


say("A_english_longref", DOTS, "ref_cut.wav", "en", 30)
say("B_hindi_mode", DOTS, "ref_cut.wav", "hi", 30)
say("C_full_recording", DOTS, "raw.wav", "en", 60)
say("D_full_recording_api_words", WORDS, "raw.wav", "en", 60)
