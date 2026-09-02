# Paper — MicroAPI Guard (IEEE conference format)

| File | What it is |
|---|---|
| `microapi_guard.tex` | The manuscript. IEEEtran, `conference` class, two-column. |
| `references.bib` | 22 references. Every one was actually read. |
| `architecture_ieee.pdf` | Fig. 1, ready for `\includegraphics`. |
| `architecture_ieee.svg` | Fig. 1 source (vector). Copy of `../diagrams/`. |
| `check_originality.py` | Text-overlap check against `../Paper/`. |
| `ORIGINALITY_AUDIT.md` | Audit results, claim provenance, known discrepancies. |

## Before the first build

`architecture_ieee.pdf` is already built and checked in — nothing to convert.
It is 516 × 216 pt (7.17 × 3.00 in), pure vector, with embedded fonts and no
raster images, so it scales cleanly to `\textwidth` in a `figure*`.

If you edit `architecture_ieee.svg`, regenerate the PDF. Neither
`rsvg-convert` nor Inkscape is installed here, so it was produced with
headless Chrome, which keeps SVG vector:

```powershell
# wrapper HTML pins the page to the SVG's exact size with zero margin
"@page{size:516pt 216pt;margin:0}html,body{margin:0;width:516pt;height:216pt}
 svg{display:block;width:516pt;height:216pt}" |
  Set-Content $env:TEMP\s.css
# see the session log for the full wrapper; or simply:
#   inkscape architecture_ieee.svg --export-filename=architecture_ieee.pdf
```

Verify a regenerated figure with:
```bash
python -c "import pypdf; p=pypdf.PdfReader('architecture_ieee.pdf').pages[0]; \
print(p.mediabox.width, p.mediabox.height, list(p.get('/Resources',{}).get('/XObject',{})))"
```
Expect `516 216 []` — a non-empty XObject list means it got rasterised.

You also need `IEEEtran.cls` and `IEEEtran.bst` — bundled with TeX Live and
MiKTeX, otherwise from
<https://www.ieee.org/conferences/publishing/templates.html>.

## Build

```bash
pdflatex microapi_guard
bibtex   microapi_guard
pdflatex microapi_guard
pdflatex microapi_guard
```

No LaTeX toolchain is installed here, so **the document has never been
compiled**. Structure was validated statically: braces balanced, all
environments paired, all 22 `\cite` keys present in the `.bib` with no unused
entries. Expect to fix minor spacing on the first real build. Overleaf is the
fastest way to get it compiling — upload the four files.

## Checks

```bash
python check_originality.py     # exit 1 if any 8-gram matches a source paper
```

Current result: **0 eight-gram overlaps** in 3,437 windows. One six-gram hit,
`"the owasp api security top 10"`, which is the name of a standard.

This is **not** a plagiarism score — it only compares against the 18 local
PDFs. Run the real institutional check before submitting. See
`ORIGINALITY_AUDIT.md`.

## Read this before submitting

`ORIGINALITY_AUDIT.md` lists four places where existing project documents
contradict the code. The paper follows the code. The most important:

- `synopsis__1_.pdf` still describes a logistic-regression meta-learner,
  Locust, and a Streamlit dashboard — none of which are in the current system.
- `README.md` claims 35,496 labelled events; the corpus actually holds 14,960.

Fix these or the paper and the synopsis will contradict each other in front of
an examiner.
