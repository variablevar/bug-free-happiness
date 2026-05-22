# LaTeX Dissertation

This folder contains a LaTeX conversion of `../docs.md`.

## Files

- `main.tex` - main compile entry point.
- `chapters/` - front matter, chapters, and appendices.
- `references.bib` - BibTeX reference database converted from the Markdown references.

## Compile

From this folder, run:

```bash
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

The Markdown source `../docs.md` is not changed by this LaTeX project.
