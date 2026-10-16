# Finishing the explainer video on Linux (GPU)

This package holds everything needed to finish the MicroAPI Guard explainer in your cloned voice:

- the Hyperframes composition with all 22 scenes, console recordings and SFX
- your cleaned voice reference (`work/voice/ref_cut.wav`)
- the narration scenes already generated on Windows (`work/voice/scenes_raw/`)
- the music tracks

## 1. Install the tools (once)

Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y ffmpeg python3.11 python3.11-venv curl
# Node.js 18+ (skip if `node -v` already shows 18 or newer)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs
# optional but faster installs:
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Check that the NVIDIA driver works: `nvidia-smi` should list your GPU. If it doesn't, install the
driver first (Ubuntu: `sudo ubuntu-drivers autoinstall`, then reboot).

## 2. Run the pipeline

```bash
unzip brag-linux-package.zip -d ~/brag      # or wherever you copied it
cd ~/brag/brag-output
bash work/linux/pipeline_linux.sh
```

What it does, roughly 1 hour in total:

| Step | Time |
| --- | --- |
| First run only: installs PyTorch with CUDA + XTTS (~3 GB) and downloads the XTTS model (~1.8 GB) | ~10 min |
| Narrates the remaining scenes on the GPU (finished ones are skipped) | ~5–10 min |
| Trims and evens out the audio, re-times every animation to your voice, rebuilds the timeline | ~1 min |
| Renders 1920×1080 at 30 fps | ~20–40 min |
| Sets the title card as the thumbnail and opens `brag.mp4` | — |

If anything stops it, run the same command again. It resumes where it left off.

## Notes

- The render uses parallel workers by default (`WORKERS=auto`). Parallel rendering stores frames on disk
  temporarily (~34 GB). If disk is short, run `WORKERS=1 bash work/linux/pipeline_linux.sh`, which streams
  frames straight into the video and needs no extra space.
- To regenerate one scene (e.g. one sentence sounds wrong), delete `work/voice/scenes_raw/s07.wav` and
  re-run the pipeline.
- The AI-voice version of the video is not in this package (it stays on Windows as `brag_ai_voice.mp4`).
  `composition/assets/vo_kokoro/` and `work/align_kokoro.json` are kept so you can rebuild it.
- The voice model is XTTS-v2 (Coqui Public Model License: non-commercial use, fine for an academic project).
