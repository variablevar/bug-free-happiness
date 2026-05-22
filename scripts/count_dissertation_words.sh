#!/usr/bin/env bash
# Approximate word count for dissertation (LaTeX sources + bibliography entries).

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHAPTERS="$ROOT/latex_dissertation/chapters"
BIB="$ROOT/latex_dissertation/references.bib"

count_tex() {
  cat "$CHAPTERS"/*.tex 2>/dev/null | \
    sed 's/\\[a-zA-Z]*{[^}]*}//g; s/\\[a-zA-Z]*\b//g; s/[{}%]//g' | \
    wc -w | tr -d ' '
}

count_bib() {
  sed 's/@[^{]*{[^,]*,//g; s/[^a-zA-Z0-9 ,.-]//g' "$BIB" | wc -w | tr -d ' '
}

TEX=$(count_tex)
BIBW=$(count_bib)
TOTAL=$((TEX + BIBW))

echo "Chapter/front/appendix .tex words (approx): $TEX"
echo "Bibliography .bib words (approx):          $BIBW"
echo "Combined approximate total:                $TOTAL"
echo "Target:                                    15600"
