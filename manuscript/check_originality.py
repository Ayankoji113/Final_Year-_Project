"""Text-overlap check for the manuscript against the papers in ../Paper/.

    python paper/check_originality.py

Reports 6- and 8-word windows of the manuscript that also appear in any
reference paper. Requires `pdftotext` (poppler) on PATH.

NOT a plagiarism score. It compares against the local reference PDFs only --
not the web, not publisher databases, not student-work repositories. Run the
manuscript through the institution's real plagiarism system before submitting.
"""
import re, glob, os, io, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PAPERS = os.path.join(HERE, os.pardir, "Paper")
CACHE = os.path.join(tempfile.gettempdir(), "microapi_refcorpus")
TEX = os.path.join(HERE, "microapi_guard.tex")
BS = chr(92) * 2          # an escaped backslash, for the LaTeX-stripping regexes


def norm(t):
    t = t.lower()
    t = re.sub(r"[^a-z0-9 ]", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def reference_text():
    """Extract every reference PDF to text once, then cache it."""
    os.makedirs(CACHE, exist_ok=True)
    for pdf in sorted(glob.glob(os.path.join(PAPERS, "*.pdf"))):
        out = os.path.join(CACHE, os.path.basename(pdf)[:40] + ".txt")
        if not os.path.exists(out):
            # long paths make pdftotext fail silently, hence the truncated name
            subprocess.run(["pdftotext", "-layout", pdf, out], check=False)
    return sorted(glob.glob(os.path.join(CACHE, "*.txt")))


def manuscript_words():
    tex = io.open(TEX, encoding="utf-8").read()
    tex = re.sub(r"%.*", "", tex)
    tex = re.sub(BS + r"begin\{(tabular|table|thebibliography)\}.*?"
                 + BS + r"end\{\1\}", " ", tex, flags=re.S)
    tex = re.sub(BS + r"cite\{[^}]*\}", " ", tex)
    tex = re.sub(BS + r"[a-zA-Z]+\*?(\[[^\]]*\])?(\{[^{}]*\})?", " ", tex)
    tex = re.sub(r"[{}$" + BS + r"]", " ", tex)
    return norm(tex).split()


def main():
    files = reference_text()
    ref = {}
    for fp in files:
        w = norm(io.open(fp, encoding="utf-8", errors="ignore").read()).split()
        name = os.path.basename(fp)
        for n in (6, 8):
            for i in range(len(w) - n + 1):
                ref.setdefault(" ".join(w[i:i + n]), name)

    words = manuscript_words()
    print("reference corpus : %d papers" % len(files))
    print("manuscript prose : %s words" % format(len(words), ","))

    worst = 0
    for n in (8, 6):
        windows = len(words) - n + 1
        hits = []
        for i in range(windows):
            s = " ".join(words[i:i + n])
            if s in ref:
                hits.append((s, ref[s]))
        worst = max(worst, len(hits) if n == 8 else 0)
        print("\n%d-gram overlap: %d of %d windows (%.3f%%)"
              % (n, len(hits), windows, 100.0 * len(hits) / max(1, windows)))
        seen = set()
        for s, src in hits:
            if s not in seen:
                seen.add(s)
                print("  %-62s  <- %s" % (s[:62], src[:38]))

    # An 8-gram match is long enough that it is almost never coincidental.
    return 1 if worst else 0


if __name__ == "__main__":
    raise SystemExit(main())
