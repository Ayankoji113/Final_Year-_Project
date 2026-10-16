#!/usr/bin/env bash
# Finish the cloned-voice explainer on Linux with an NVIDIA GPU.
#   bash work/linux/pipeline_linux.sh            (run from anywhere)
# Re-runnable: finished narration scenes are skipped.
set -euo pipefail
B="$(cd "$(dirname "$0")/../.." && pwd)"          # brag-output/
W="$B/work"; C="$B/composition"; VENV="$W/.venv-xtts"
step() { echo; echo "=== $(date '+%H:%M:%S') $*"; }

step "0/7 check tools"
for t in ffmpeg ffprobe node npx python3; do command -v $t >/dev/null || { echo "missing: $t (see README_LINUX.md)"; exit 1; }; done
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader || echo "WARNING: no NVIDIA GPU visible - XTTS will run on CPU (slow)"

step "1/7 XTTS environment (first run only, ~3 GB download)"
if [ ! -x "$VENV/bin/python" ]; then
  if command -v uv >/dev/null; then
    uv venv -q -p 3.11 "$VENV"
    uv pip install -q -p "$VENV/bin/python" --index-url https://download.pytorch.org/whl/cu126 \
      --extra-index-url https://pypi.org/simple --index-strategy unsafe-best-match \
      "torch==2.8.0" "torchaudio==2.8.0" "transformers>=4.52,<4.58" coqui-tts soundfile numpy
  else
    python3.11 -m venv "$VENV"
    "$VENV/bin/pip" install -q "torch==2.8.0" "torchaudio==2.8.0" --index-url https://download.pytorch.org/whl/cu126
    "$VENV/bin/pip" install -q "transformers>=4.52,<4.58" coqui-tts soundfile numpy
  fi
fi
"$VENV/bin/python" -c "import torch; print('torch', torch.__version__, 'cuda:', torch.cuda.is_available())"

step "2/7 narrate remaining scenes in the cloned voice"
cd "$W/voice"
"$VENV/bin/python" clone_all.py "$W/narration" "$W/narration_mine" "$W/voice/scenes_raw" 2>&1 | grep -E "^s[0-9]+ |^device|Error" || true
n=$(ls "$W/voice/scenes_raw"/s??.wav | wc -l)
[ "$n" -eq 22 ] || { echo "narration incomplete ($n/22) - re-run this script"; exit 1; }

step "3/7 trim silence + even loudness"
for f in "$W/voice/scenes_raw"/s??.wav; do
  ffmpeg -y -loglevel error -i "$f" -af "silenceremove=start_periods=1:start_threshold=-45dB,areverse,silenceremove=start_periods=1:start_threshold=-45dB,areverse,loudnorm=I=-18:TP=-2:LRA=9" -ar 24000 -ac 1 "$C/assets/vo/$(basename "$f")"
done

step "4/7 align visuals to the new narration"
"$VENV/bin/python" "$W/narration/align.py" "$C/assets/vo" "$W/narration_mine" "$W/align.json"

step "5/7 rebuild timeline + music bed"
cd "$W" && "$VENV/bin/python" build.py | head -1
cd "$C" && npx -y hyperframes@0.8.162 lint 2>&1 | tail -1

step "6/7 render 1920x1080 @ 30 fps"
npx -y hyperframes@0.8.162 browser ensure >/dev/null
WORKERS="${WORKERS:-auto}"
npx -y hyperframes@0.8.162 render --quality delivery --video-frame-format png --workers "$WORKERS" --output ../brag.new.mp4 > "$W/render.log" 2>&1 \
  || { echo "render failed - see work/render.log (low disk? try WORKERS=1)"; exit 1; }

step "7/7 poster frame"
cd "$B"
T=$("$VENV/bin/python" -c "import json;r={x['id']:x for x in json.load(open('work/timeline.json'))}['s02'];print(round(r['start']+r['dur']-1.0,2))")
ffmpeg -y -loglevel error -ss "$T" -i brag.new.mp4 -frames:v 1 -q:v 2 brag.jpg
ffmpeg -y -loglevel error -i brag.new.mp4 -i brag.jpg -filter_complex "[0:v][1:v]overlay=0:0:enable='eq(n,0)'[v]" \
  -map "[v]" -map "0:a?" -c:v libx264 -crf 18 -preset slow -pix_fmt yuv420p -c:a copy -movflags +faststart brag.mp4
rm -f brag.new.mp4
echo "DONE: $B/brag.mp4 ($(ffprobe -v error -show_entries format=duration -of csv=p=0 brag.mp4)s)"
command -v xdg-open >/dev/null && xdg-open "$B/brag.mp4" >/dev/null 2>&1 &
