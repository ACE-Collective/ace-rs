# phishkit_analyzer's differences from ace3's reference dumps

`tests/reference.rs` runs `phishkit_analyzer` as `differences.md` describes for both modules; these are its rows.

| Dumps | Path | Why |
|---|---|---|
| `*` | `/details/output_dir` | Where the scan's files were kept: ace3's is a temporary directory on its node (`create_temporary_directory`), `<work>/tmp/tmp<random>` in the dumps, and ace-rs's is the scan's directory in the alert, `phishkit/<job id>`. |
| `*` | `/details/output_files/*` | The same files in another order. ace3 adds them in the order `os.walk` lists its copy of the output directory (`saq/phishkit.py`'s `_copy_files`), which is the order its filesystem keeps, here the dump's `/tmp`, in production the shared volume's; ace-rs walks it top-down with each directory's names sorted (`ace_mod_scanners::read_output`). Checked on each of file_render, url_scan, url_partial and url_script: the two lists hold the same paths. |
| `*` | `/summary` | The summary names the files in that order, and only that differs: checked on the same four. |
| `file_render` | `/analyzed/yara_meta/type=document.html` | file_type's `yara_meta` tag for an HTML page: the dump enabled file_type, which phishkit depends on, and ace3 records what it adds with the module's run. ace-rs's file_type adds it in its own result. |
| `file_render` | `/observables/file:*/yara_meta/type=*` | file_type's tags on the scan's files, `type=document.html` on the DOM and the bodies and `type=image` on the screenshot, the same way: in ace3's run file_type analyzed what phishkit added. |
