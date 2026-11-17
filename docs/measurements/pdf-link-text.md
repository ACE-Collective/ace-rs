# The link text module on crafted PDFs

`pdf_link_text` (ace3 `b4badb2c`, ported on 2026-11-16) reads a PDF's link annotations with libqpdf in its task and runs `pdftotext -bbox` in the sandbox runner. This asks what a crafted PDF can make the two do against the task's limits: a 60 s deadline, 60 s of CPU and 2 GiB of address space (`crates/ace-mod-pdf/src/links.rs`, the PDF module's, whose libqpdf it shares), and for pdftotext 10 s (ace3's `PDFTOTEXT_TIMEOUT_SECONDS`) and the runner's 64 MiB of output.

`tools/samples/make-pdf-link-hostile` writes the set. Measured on 2026-11-16 in ace4's dev container, debug builds, while `tools/ace3/trees/make-trees` ran in ace3's container on the same VM, so the times are upper bounds.

## In a task

`ACE4_CRAFTED=<dir> cargo test -p ace-pool --test hung_tasks crafted -- --ignored --nocapture` gives the test pool one task per file, as `ace4-task`, under Landlock and seccomp, with the module's limits. One run of the set below; four of the files ran twice more in an earlier form of the set, which had no cross-reference tables, and those times are in brackets. The time is from the task's queuing to its root's idle, so it includes the upload.

| File | Size | Ends | Time | Result |
|---|---:|---|---:|---|
| `words_20k_lines_200.pdf`: a page of 19,900 one-letter words and 200 links of one line each | 19 KB | done | 0.4 s | 200 links, 199 with text |
| `words_20k_links_200.pdf`: the same page under 200 links that each cover every line | 18 KB | done | 0.4 s | 200 links, none with text: each box is over more than `max_link_band_words` |
| `words_3x60k.pdf`: three pages of 60,000 one-letter words each, a link on each | 2 KB | done | 0.5 s | 3 links, none with text: each page has more than `max_page_words` |
| `title_100mb.pdf`: a document title of 100 MB | 100 MB | done | 6.6 s (9.8, 10.0) | 1 link, without text |
| `content_2gib.pdf`: a content stream that inflates to 2 GiB of text operators | 5 MB | done | 11.1 s (10.8, 10.9) | 1 link, without text |
| `links_200k.pdf`: 200,000 links, each its own URL and box | 20 MB | done | 12.4 s | 200 links |
| `links_1m.pdf`: a million of them | 100 MB | done | 19.9 s | none |
| `links_1m_no_xref.pdf`: the same with no cross-reference table | 100 MB | done | 19.1 s (20.5, 20.6) | none |
| `repeat_5m.pdf`: one annotation five million times | 30 MB | **failed, SIGABRT** | 13.5 s | none |
| `repeat_5m_no_xref.pdf` | 30 MB | **failed, SIGABRT** | 13.4 s (13.7, 13.6) | none |

The test prints a task's state and its result, not its log, so why a link has no text is read from the module's code and the time: `content_2gib.pdf` ends a second after pdftotext's 10 s, and the link in `title_100mb.pdf` is over the same words as a sample's (`link_text.pdf`) whose text is placed, so pdftotext didn't finish there either. Neither was checked against the runner's own report of the stop.

## By part, with no limit

A probe that opens the file as the module does and then reads the links, once, with `VmHWM` from `/proc/self/status`:

| File | libqpdf opens it | Peak RSS | Reading the links | Growth while reading |
|---|---:|---:|---:|---|
| `repeat_5m.pdf` | 16.7 s | 3.7 GiB | 51.8 s for 5,000,000 annotations | none |

`pikepdf`, the Rust side of `tools/library-diff/run pikepdf`, once each: `links_200k.pdf` 17.9 s and 699 MiB, `links_1m.pdf` 79.4 s and 3.5 GiB. It also builds a JSON reply of every URI, which the task doesn't, so these are upper bounds.

## What this shows

- **pdftotext can't make the task late or large.** A content stream it can't finish is stopped at 10 s, and output past 64 MiB stops it. The links are then kept without their text and the result is marked failed with the reason, as ace3 marks its analysis (`Analysis.error`).
- **A page gives at most about 25,100 words.** poppler 25.03.0 stops a page's text at about 50,000 characters, spaces among them: a page of 30,000 one-letter words comes out as 25,126, of 60,000 as 25,078, of 30,000 two-letter words as 16,723 (50,170 characters), of 20,000 eight-letter words as 5,564 (50,072 characters), each run once with `pdftotext -bbox` in ace3's image. So `max_page_words` (20,000) is reached only by words of one letter, pdftotext writes about 2.4 MB a page and 7 MB over the three pages it is asked for, and what the task parses is bounded by that, not by the file. Only the title and the other fields of the document's information, which `-bbox` writes first, can take the output to the runner's limit.
- **Placing is cheap.** 200 links over 19,900 words took 0.4 s, in both directions of the band rule.
- **Many links cost libqpdf's memory, not the module's.** The module reads one annotation at a time and gives libqpdf's handles back as it goes, so its own memory stays flat: five million annotations added nothing to the peak. But libqpdf itself needs 3.7 GiB to open the 30 MB file that repeats one annotation five million times, and more than 2 GiB for a million annotations of a page. Under the task's 2 GiB the first aborts (an exception inside libqpdf's C API when memory runs out, which the process can't catch) and the second fails cleanly, so the module records nothing. The task fails with a row, or ends with no result, and the supervisor leases the next one. ace3 has no such limit: its worker would hold the gigabytes and record the links. The PDF module opens the same file the same way and meets the same bound (`docs/measurements/pdf-hostile.md`).
- **Nothing reached the 60 s deadline in a task**, but only because memory ended the worst file first. Without a limit, reading five million annotations took 52 s in a debug build after 17 s to open the file, which is past the deadline. A release build wasn't measured.

Not measured: a release build, the sandbox image's own pdftotext (the dev image's is the same Debian package), and more than one run of most files.
