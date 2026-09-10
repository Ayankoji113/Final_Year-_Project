# Paper - MicroAPI Guard (IEEE conference format)

| File | What it is |
|---|---|
| `microapi_guard.tex` | The manuscript. IEEEtran `conference`, two-column. Self-contained: every figure is drawn inline with TikZ/pgfplots. |
| `refs.bib` | 19 references, all 2020-2026, one per PDF in `../Paper/`. |
| `check_originality.py` | Text-overlap check against `../Paper/`. |
| `ORIGINALITY_AUDIT.md` | Audit results, claim provenance, known discrepancies. |
| `WRITING_SKELETON.md` | Claims and numbers per section, for rewriting in your own words. |
| `alt_figures/` | Superseded standalone figures (PDF/SVG/matplotlib). Not used by the .tex. |

## Before the first build

Nothing to convert. Every figure is drawn inline with TikZ and pgfplots, so
the .tex needs no external image files.

You need `IEEEtran.cls`, `IEEEtran.bst`, and the packages the preamble
declares: `algorithm2e`, `tikz` (with `shapes.geometric`, `shapes.multipart`,
`arrows.meta`, `positioning`, `calc`, `fit`, `backgrounds`), `pgfplots`
(compat 1.18), `tabularx`, `booktabs`, `stfloats`, `placeins`, `enumitem`.
All ship with a full TeX Live or MiKTeX install and are present on Overleaf.

## Build

```bash
pdflatex microapi_guard
bibtex   microapi_guard
pdflatex microapi_guard
pdflatex microapi_guard
```

No LaTeX toolchain is installed here, so **the document has never been
compiled**. Structure was validated statically: braces balanced, all
environments paired, all 19 `\cite` keys present in `refs.bib` with no unused
entries, no dangling `ef`, and every `tabularx` column spec matching its
header. Expect to fix minor float placement on the first real build. Overleaf
is the fastest route — upload `microapi_guard.tex` and `refs.bib`.

## Checks

```bash
python check_originality.py     # exit 1 if any 8-gram matches a source paper
```

Current result: **0 eight-gram overlaps** in 5,414 windows. Two six-gram hits,
both proper nouns: `"the owasp api security top 10"` and the dataset list
`"5g nidd unr idd n baiot"` in the literature table.

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
