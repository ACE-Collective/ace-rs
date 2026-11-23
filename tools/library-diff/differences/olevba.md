# Differences between olevba and its port

`tools/library-diff/run olevba --right rust:ace-mod-oletools/olevba` diffs oletools 0.60.2 with `crates/ace-mod-oletools`. The rows follow `tools/ace3/trees/differences.md` and `docs/acceptance.md`.

## Explained

| Samples | Path | Why | When |
|---|---|---|---|
| `ace-rs/office/vba_excel_bad_biff_formula.xls` | `/output/macros/1/*` | A workbook xlrd2 refuses, with a macro sheet, a LABEL and a FORMULA. olevba's fallback to oledump's `plugin_biff` asks for the LABEL record and the formulas as CSV as well as the sheets, and those need its formula parser, about 5,000 lines of Python that `xlm.rs` doesn't port (PLAN.md 4.12). Checked: Python's macro at this path has one more LABEL line and one more CSV row (`"",A1,1,""`) than the port's, and the sheets and heading are the same. | |
