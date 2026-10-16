"""Assemble the MicroAPI Guard explainer composition.

Scene lengths follow the generated narration: each scene = lead + VO + tail.
This script
  1. lays out the 22 scenes on one timeline,
  2. injects each scene's cue times (lead + clause start) and duration into
     compositions/sNN.html (`const C = /*CUES*/[...]`, `const D = /*DUR*/n`),
  3. builds the chapter-based music bed with ffmpeg,
  4. writes index.html: background, scenes, chapter chrome, VO, music, SFX.

Run from anywhere:  python build.py
"""
import json, random, re, subprocess, pathlib

HERE = pathlib.Path(__file__).resolve().parent
COMP = HERE.parent / "composition"
# Music/SFX source: the /brag skill if installed, else the copy shipped in work/brag-assets.
SKILL = pathlib.Path.home() / ".claude/skills/brag/assets"
if not (SKILL / "music").exists():
    SKILL = HERE / "brag-assets"
ALIGN = json.loads((HERE / "align.json").read_text())

# id, lead, tail, chapter label (None = chrome hidden)
SCENES = [
    ("s01", 0.8, 1.6, None),
    ("s02", 0.5, 1.2, None),
    ("s03", 0.5, 1.0, "The problem"),
    ("s04", 0.5, 1.8, "Architecture"),
    ("s05", 0.6, 1.0, "Layer 1 · Normalization"),
    ("s06", 0.5, 1.0, "Layer 1 · Signatures"),
    ("s07", 0.5, 1.0, "Layer 1 · Rate limiting"),
    ("s08", 0.5, 1.8, "Layer 1 · Short-circuit"),
    ("s09", 0.6, 1.0, "Feature extraction"),
    ("s10", 0.5, 1.0, "Layers 2 + 3"),
    ("s11", 0.5, 1.0, "Layer 4 · Meta-learner"),
    ("s12", 0.5, 1.8, "Engineering safeguards"),
    ("s13", 0.8, 1.4, "Live demo · Console"),
    ("s14", 0.6, 1.6, "Live demo · Attacks"),
    ("s15", 0.5, 1.4, "Live demo · Traffic"),
    ("s16", 0.5, 1.4, "Live demo · Investigation"),
    ("s17", 0.5, 1.8, "Live demo · Health"),
    ("s18", 0.8, 1.0, "The honest finding"),
    ("s19", 0.5, 1.2, "Results"),
    ("s20", 0.5, 1.2, "Enforcement"),
    ("s21", 0.5, 1.8, "Verification"),
    ("s22", 1.2, 6.0, None),
]

# Music bed: chapter -> (track, first scene, last scene, offset into track)
MUSIC = [
    ("happy-beats-business-moves-vol-12-by-ende-dot-app.mp3", "s01", "s04", 0.0),
    ("happy-beats-business-moves-vol-9-by-ende-dot-app.mp3", "s05", "s12", 0.0),
    ("happy-beats-business-moves-vol-11-by-ende-dot-app.mp3", "s13", "s17", 0.0),
    ("happy-beats-business-moves-vol-12-by-ende-dot-app.mp3", "s18", "s22", 40.0),
]

# SFX: (scene, cue index or None, offset seconds, file under assets/sfx, volume)
# Times are scene-local: cue time (lead + clause start) + offset.
SFX = [
    ("s01", 4, -0.05, "impact/impactSoft_heavy_001.ogg", 0.75),
    ("s02", 0, 0.25, "impact/impactBell_heavy_000.ogg", 0.45),
    ("s02", 5, 0.4, "interface/error_006.ogg", 0.3),
    ("s03", 1, 0.0, "interface/drop_001.ogg", 0.5),
    ("s03", 2, 0.5, "interface/drop_002.ogg", 0.5),
    ("s03", 6, 0.0, "impact/impactSoft_medium_001.ogg", 0.5),
    ("s04", 7, 0.0, "interface/error_005.ogg", 0.35),
    ("s04", 8, 0.0, "interface/switch_004.ogg", 0.4),
    ("s04", 15, 0.0, "impact/impactSoft_medium_002.ogg", 0.45),
    ("s05", 8, 1.2, "interface/glitch_004.ogg", 0.3),
    ("s05", 9, 0.6, "interface/glitch_002.ogg", 0.3),
    ("s05", 10, 0.0, "impact/impactSoft_medium_000.ogg", 0.55),
    ("s06", 8, 0.0, "interface/switch_005.ogg", 0.4),
    ("s06", 17, 0.2, "interface/drop_003.ogg", 0.5),
    ("s07", 7, 0.0, "interface/switch_006.ogg", 0.4),
    ("s08", 3, -0.1, "impact/impactSoft_heavy_002.ogg", 0.65),
    ("s09", 12, 0.0, "interface/switch_007.ogg", 0.35),
    ("s09", 13, 0.0, "interface/error_005.ogg", 0.3),
    ("s09", 17, 0.0, "interface/error_005.ogg", 0.3),
    ("s10", 12, 0.0, "interface/error_006.ogg", 0.3),
    ("s11", 8, 0.0, "impact/impactSoft_medium_003.ogg", 0.55),
    ("s13", 0, 0.0, "casino/card-slide-1.ogg", 0.45),
    ("s15", 0, 0.0, "casino/card-slide-2.ogg", 0.45),
    ("s16", 1, 0.0, "casino/card-slide-3.ogg", 0.45),
    ("s17", 1, 0.0, "casino/card-slide-4.ogg", 0.45),
    ("s18", 1, 0.2, "impact/impactBell_heavy_003.ogg", 0.4),
    ("s18", 9, 0.0, "interface/error_006.ogg", 0.35),
    ("s18", 14, 0.3, "impact/impactSoft_heavy_003.ogg", 0.6),
    ("s19", 5, 0.0, "interface/drop_002.ogg", 0.5),
    ("s19", 9, 0.4, "impact/impactBell_heavy_004.ogg", 0.4),
    ("s20", 8, 0.0, "interface/switch_001.ogg", 0.5),
    ("s21", 3, 0.3, "interface/select_008.ogg", 0.45),
    ("s22", 2, 1.4, "impact/impactBell_heavy_000.ogg", 0.5),
]
# Terminal rows in s14 land with a soft key; 403 rows with a dull hit.
for c in (2, 14):
    SFX.append(("s14", c, 0.0, "ui/click3.ogg", 0.45))
for c in (5, 7, 9, 12):
    SFX.append(("s14", c, -0.1, "impact/impactSoft_medium_004.ogg", 0.4))

def cues(sid, lead):
    return [round(lead + t, 3) for _, t in ALIGN[sid]["clauses"]]


def layout():
    t, rows = 0.0, []
    for sid, lead, tail, chap in SCENES:
        vo = ALIGN[sid]["dur"]
        dur = round(lead + vo + tail, 3)
        rows.append(dict(id=sid, start=round(t, 3), dur=dur, lead=lead, vo=vo,
                         chap=chap, cues=cues(sid, lead)))
        t += dur
    return rows, round(t, 3)


def inject(rows):
    for r in rows:
        f = COMP / "compositions" / f"{r['id']}.html"
        if not f.exists():
            print("missing scene", f.name)
            continue
        s = f.read_text(encoding="utf-8")
        s = re.sub(r"const C = /\*CUES\*/\[[^\]]*\];", lambda m: f"const C = /*CUES*/{json.dumps(r['cues'])};", s)
        s = re.sub(r"const D = /\*DUR\*/[\d.]+;", lambda m: f"const D = /*DUR*/{r['dur']};", s)
        f.write_text(s, encoding="utf-8")


def music_bed(rows, total):
    by = {r["id"]: r for r in rows}
    out = COMP / "assets/music/bed.m4a"
    out.parent.mkdir(parents=True, exist_ok=True)
    inputs, chains = [], []
    for i, (track, a, b, off) in enumerate(MUSIC):
        start = by[a]["start"]
        end = by[b]["start"] + by[b]["dur"]
        ln = end - start + (2.5 if i < len(MUSIC) - 1 else 0)   # overlap = crossfade
        inputs += ["-stream_loop", "-1", "-ss", str(off), "-i", str(SKILL / "music" / track)]
        fade_out = 2.5 if i < len(MUSIC) - 1 else 5.0
        chains.append(
            f"[{i}:a]atrim=0:{ln:.3f},asetpts=PTS-STARTPTS,loudnorm=I=-18:TP=-2:LRA=11,"
            f"aresample=48000,afade=t=in:d={1.5 if i == 0 else 2.5},"
            f"afade=t=out:st={ln - fade_out:.3f}:d={fade_out},"
            f"adelay={int(start * 1000)}|{int(start * 1000)}[m{i}]")
    mix = "".join(f"[m{i}]" for i in range(len(MUSIC)))
    fc = ";".join(chains) + f";{mix}amix=inputs={len(MUSIC)}:normalize=0,atrim=0:{total:.3f}[out]"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", *inputs, "-filter_complex", fc,
                    "-map", "[out]", "-c:a", "aac", "-b:a", "192k", str(out)], check=True)


def copy_sfx():
    used = {f for _, _, _, f, _ in SFX} | {f"keyboard/keypress-{i:03d}.wav" for i in range(1, 33)}
    for f in used:
        dst = COMP / "assets/sfx" / f
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists():
            dst.write_bytes((SKILL / "sfx" / f).read_bytes())


def typing_sfx(rows):
    """Keystrokes for scenes that type text, read from `typing` markers in the scene."""
    out = []
    rng = random.Random(7)
    for r in rows:
        f = COMP / "compositions" / f"{r['id']}.html"
        if not f.exists():
            continue
        s = f.read_text(encoding="utf-8")
        for m in re.finditer(r"/\*TYPE (\d+) ([\d.-]+) ([\d.]+)\*/", s):
            ci, off, ln = int(m.group(1)), float(m.group(2)), float(m.group(3))
            t, end = r["cues"][ci] + off, r["cues"][ci] + off + ln
            while t < end:
                out.append((r["start"] + t, f"keyboard/keypress-{rng.randint(1, 32):03d}.wav", 0.32))
                t += rng.uniform(0.085, 0.15)
    return out


_LEN = {}


def media_len(path):
    """Clip slots must not outrun the media (check: clip_media_fit)."""
    if path not in _LEN:
        out = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                              "-of", "csv=p=0", str(path)], capture_output=True, text=True, check=True)
        _LEN[path] = float(out.stdout.strip())
    return _LEN[path]


def write_index(rows, total):
    by = {r["id"]: r for r in rows}
    hosts, audio = [], []
    for r in rows:
        if not (COMP / "compositions" / f"{r['id']}.html").exists():
            continue
        hosts.append(
            f'      <div id="el-{r["id"]}" data-composition-id="{r["id"]}" '
            f'data-composition-src="compositions/{r["id"]}.html" data-start="{r["start"]}" '
            f'data-duration="{r["dur"]}" data-track-index="1" data-width="1920" data-height="1080"></div>')
        audio.append(
            f'      <audio id="vo-{r["id"]}" src="assets/vo/{r["id"]}.wav" data-start="{round(r["start"] + r["lead"], 3)}" '
            f'data-duration="{r["vo"]}" data-track-index="3" data-volume="1"></audio>')
    events = []
    for sid, ci, off, f, vol in SFX:
        r = by[sid]
        t = r["start"] + (r["cues"][ci] if ci is not None else 0) + off
        events.append((t, f, vol))
    events += typing_sfx(rows)
    events.sort()
    lanes = [-1.0] * 16
    for i, (t, f, vol) in enumerate(events):
        ln = round(min(1.8, media_len(COMP / "assets/sfx" / f)), 3)
        lane = next(k for k in range(16) if lanes[k] <= t)
        lanes[lane] = t + ln + 0.05
        audio.append(
            f'      <audio id="sfx-{i:03d}" src="assets/sfx/{f}" data-start="{t:.3f}" data-duration="{ln}" '
            f'data-track-index="{11 + lane}" data-volume="{vol}"></audio>')
    chapters = [{"t": r["start"], "d": r["dur"], "label": r["chap"]} for r in rows]
    html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=1920, height=1080" />
    <title>MicroAPI Guard — Explainer</title>
    <script src="assets/vendor/gsap.min.js"></script>
    <link rel="stylesheet" href="assets/theme.css" />
    <script>window.HF_CHAPTERS = {json.dumps(chapters)}; window.HF_TOTAL = {total};</script>
    <style>
      html, body {{ margin: 0; width: 1920px; height: 1080px; overflow: hidden; background: #000; }}
      #root {{ position: relative; width: 100%; height: 100%; overflow: hidden; background: #000; }}
      [data-composition-id="main"] > div[data-composition-src] {{ position: absolute; inset: 0; }}
    </style>
  </head>
  <body>
    <div id="root" data-composition-id="main" data-start="0" data-width="1920" data-height="1080" data-duration="{total}">
      <div id="el-bg" data-composition-id="bg" data-composition-src="compositions/bg.html" data-start="0" data-duration="{total}" data-track-index="0" data-width="1920" data-height="1080"></div>
{chr(10).join(hosts)}
      <div id="el-chrome" data-composition-id="chrome" data-composition-src="compositions/chrome.html" data-start="0" data-duration="{total}" data-track-index="2" data-width="1920" data-height="1080"></div>
      <audio id="bgm" src="assets/music/bed.m4a" data-start="0" data-duration="{total}" data-track-index="4" data-volume="0.13"></audio>
{chr(10).join(audio)}
    </div>
    <script>
      const tl = gsap.timeline({{ paused: true }});
      window.__timelines["main"] = tl;
    </script>
  </body>
</html>
"""
    (COMP / "index.html").write_text(html, encoding="utf-8")


def inject_globals(rows, total):
    """bg/chrome need the chapter table and total length."""
    chapters = [{"t": r["start"], "d": r["dur"], "label": r["chap"]} for r in rows]
    for name in ("bg", "chrome"):
        f = COMP / "compositions" / f"{name}.html"
        if f.exists():
            s = f.read_text(encoding="utf-8")
            s = re.sub(r"const CH = /\*CHAPTERS\*/\[.*?\];", lambda m: f"const CH = /*CHAPTERS*/{json.dumps(chapters, ensure_ascii=False)};", s, flags=re.S)
            s = re.sub(r"const T = /\*TOTAL\*/[\d.]+;", lambda m: f"const T = /*TOTAL*/{total};", s)
            f.write_text(s, encoding="utf-8")


if __name__ == "__main__":
    import sys
    rows, total = layout()
    inject(rows)
    inject_globals(rows, total)
    copy_sfx()
    if "--no-music" not in sys.argv:
        music_bed(rows, total)
    write_index(rows, total)
    (HERE / "timeline.json").write_text(json.dumps(rows, indent=1))
    print(f"{len(rows)} scenes, total {total:.1f}s ({int(total // 60)}:{total % 60:04.1f})")
    for r in rows:
        print(f"  {r['id']} start {r['start']:7.2f}  dur {r['dur']:6.2f}  {r['chap'] or ''}")
