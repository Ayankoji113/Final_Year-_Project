#!/usr/bin/env bash
# Unattended: cloned-voice narration -> re-time -> re-render -> poster -> open.
# Safe to re-run: finished scenes are skipped, backups are made only once.
set -euo pipefail
B="/c/Final_year Project/brag-output"
W="$B/work"; C="$B/composition"
PY="C:/Users/tausi/AppData/Local/Temp/claude/C--Final-year-Project/854ee572-4e4a-4605-a149-c1271e55e33f/scratchpad/xttsvenv/Scripts/python.exe"
export PATH="/c/Users/tausi/AppData/Local/Microsoft/WinGet/Packages/Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe/ffmpeg-9.0.2-full_build/bin:/c/Program Files/nodejs:$PATH"
step() { echo; echo "=== $(date '+%H:%M:%S') $*"; }

step "1/7 backups (AI voice kept for rollback)"
[ -d "$C/assets/vo_kokoro" ] || cp -r "$C/assets/vo" "$C/assets/vo_kokoro"
[ -f "$W/align_kokoro.json" ] || cp "$W/align.json" "$W/align_kokoro.json"
[ -f "$B/brag_ai_voice.mp4" ] || { [ -f "$B/brag.mp4" ] && cp "$B/brag.mp4" "$B/brag_ai_voice.mp4"; } || true

step "2/7 narrate 22 scenes in the cloned voice (~2 h on CPU)"
cd "$W/voice"
"$PY" clone_all.py "$W/narration" "$W/narration_mine" "$W/voice/scenes_raw" 2>&1 | grep -E "^s[0-9]+ |Error|error" || true
[ "$(ls "$W/voice/scenes_raw"/s*.wav | grep -vc tmp)" -eq 22 ] || { echo "narration incomplete - re-run this script"; exit 1; }

step "3/7 trim silence + even loudness"
for f in "$W/voice/scenes_raw"/s??.wav; do
  ffmpeg -y -loglevel error -i "$f" -af "silenceremove=start_periods=1:start_threshold=-45dB,areverse,silenceremove=start_periods=1:start_threshold=-45dB,areverse,loudnorm=I=-18:TP=-2:LRA=9" -ar 24000 -ac 1 "$C/assets/vo/$(basename "$f")"
done

step "4/7 align visuals to the new narration"
python "$W/narration/align.py" "$C/assets/vo" "$W/narration_mine" "$W/align.json"

step "5/7 rebuild timeline + music bed"
cd "$W" && python build.py | head -1
cd "$C" && npx -y hyperframes lint 2>&1 | tail -1

step "6/7 render (~40 min, 1 worker streams frames - no temp disk)"
cd "$C" && npx -y hyperframes render --quality delivery --video-frame-format png --workers 1 --output ../brag.new.mp4 > "$W/render.log" 2>&1 \
  || { echo "render failed - see work/render.log"; exit 1; }

step "7/7 poster frame + open"
cd "$B"
T=$(python -c "import json;r={x['id']:x for x in json.load(open('work/timeline.json'))}['s02'];print(round(r['start']+r['dur']-1.0,2))")
ffmpeg -y -loglevel error -ss "$T" -i brag.new.mp4 -frames:v 1 -q:v 2 brag.jpg
ffmpeg -y -loglevel error -i brag.new.mp4 -i brag.jpg -filter_complex "[0:v][1:v]overlay=0:0:enable='eq(n,0)'[v]" \
  -map "[v]" -map "0:a?" -c:v libx264 -crf 18 -preset slow -pix_fmt yuv420p -c:a copy -movflags +faststart brag.mp4
rm -f brag.new.mp4
echo "DONE: $(ffprobe -v error -show_entries format=duration -of csv=p=0 brag.mp4)s"
powershell -c "Start-Process '$(cygpath -w "$B/brag.mp4")'"
