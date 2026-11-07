# Differences between olevba and its port

`tools/library-diff/run olevba --right rust:ace-mod-oletools/olevba` diffs oletools 0.60.2 with `crates/ace-mod-oletools`. The rows follow `tools/ace3/trees/differences.md` and `docs/acceptance.md`.

## Explained

| Samples | Path | Why | When |
|---|---|---|---|
| `ace4/office/vba_xlm_biff8.xls` | `/output/macros/*` | A macro sheet beside VBA. olevba calls XLMMacroDeobfuscator (`_extract_xlm_xlmdeobf`) and yields its whole text as `xlm_macro`, and PLAN.md 4.12 ports that library. The port flags the sheet and leaves that text out: `XLM macro` is the same on both sides. The `xlmdeobfuscator` module still runs on the Python pool, on the same file, and gives the same text in its own result. Checked: the Python macro at this path is `xlm_macro`, and every VBA macro matches. | |
| `ace4/office/vba_xlm_biff8.xls` | `/output/analysis/*/*` | The same: olevba scans that text for keywords, so `CALL`, `EXEC`, `URLDownloadToFileA` and IOCs from the XLM are in its list, which also shifts every later row of the list. The port's list is what the VBA gives, plus `XLM macro`. | |
| `ace4/office/vba_xlm_obfuscated.xlsm` | `/output/macros/*` | The same as `vba_xlm_biff8.xls`, on an OpenXML workbook. | |
| `ace4/office/vba_xlm_obfuscated.xlsm` | `/output/analysis/*/*` | The same. | |
| `ace4/office/vba_xlm_biff8.xls` | `/output/analysis/*` | The rows past the end of the port's shorter list. | |
| `ace4/office/vba_xlm_obfuscated.xlsm` | `/output/analysis/*` | The same. | |
| `ace4/office/vba_excel_bad_biff.xls` | `/output/macros/1` | A workbook XLMMacroDeobfuscator refuses with an exception, which sends olevba to oledump's `plugin_biff`, whose `Analyze()` lists the workbook's BOUNDSHEET records. olevba yields that list even when, as here, it decides there's no macro sheet it can read. PLAN.md 4.12 owns that library. Checked: Python's macro at this path is the two BOUNDSHEET lines, with the VBA macro at 0 the same on both. | |
