# Review materials

The audit trail of the systematic literature review behind the thesis
*Assessing Dataset Suitability for Log-Based Security Analytics*.

The thesis reports the aggregate results of the review, and its appendix carries
the quality-assessment scores, the acquisition channels, the source
classification and the six thematic evidence tables. This folder carries the
per-source detail behind them: one appraisal for each of the 95 reviewed
entries, recording

- the acquisition channel, meaning how the source entered the review,
- a summary of what the source contributes,
- the arguments for and against relying on it,
- a usability verdict, and
- the datasets the source evaluates on, where it uses any.

Of the 95 entries, 89 come from the systematic search, four were added in a
final update round used only for the dataset-usage analysis, and the remainder
are companion entries assessed for transparency without counting toward the
review total.

## Files

| File | Contents |
|---|---|
| `appraisals.tex` | the 95 appraisal entries, grouped into ten thematic areas |
| `appraisals_standalone.tex` | a wrapper that makes the entries a self-contained document |
| `references.bib` | the bibliography the entries cite |

## Building the document

```
pdflatex appraisals_standalone
bibtex   appraisals_standalone
pdflatex appraisals_standalone
pdflatex appraisals_standalone
```

In Overleaf, upload the three files and press Recompile. The result is roughly
sixteen pages.

## Relation to the thesis

`appraisals.tex` is generated from the thesis source, so the entries read
exactly as they would if the thesis typeset them. Two differences follow from
making the file stand on its own:

- Cross-references into the thesis are given by name rather than by number,
  because the two documents are numbered independently.
- The section heading of the appraisal section is carried by the document title
  instead.

Nothing else is altered: no entry is added, removed, reworded or reordered.
