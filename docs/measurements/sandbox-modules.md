# The sandbox modules on crafted files

PLAN.md 7.5 batch 10: `pdftotext`, `exif`, `qrcode`, `ocr` and `pdf_analyzer`'s Ghostscript rewrite on files made to cost them most, contained, as a pool runs them. Measured on 2026-11-10 in ace4's dev container with `ACE4_CRAFTED=<dir> cargo test -p ace-pool --test hung_tasks crafted -- --ignored --nocapture`, which runs `test-pool parsers --task-user ace4-task --concurrency 1` and gives it one task per module and file, the image with the `ocr` directive; one run, debug builds, the time from the task's queuing to its root's idle.

The files, made with Pillow in ace3's container: `huge.png`, a white 20,000 by 20,000 greyscale PNG of 438 KB; `pages_2000.pdf`, 2,000 empty pages; `page_200in.pdf`, one page 200 inches square.

| Module | File | Ends | Time |
|---|---|---|---|
| ocr | huge.png | done, no text | 149.1 s |
| qrcode | huge.png | skipped: zbarimg refuses the image (ImageMagick's size policy), so the scan failed and nothing is recorded, as ace3 | 1.3 s |
| qrcode | page_200in.pdf | skipped the same way: Ghostscript renders its 28,800 by 28,800 page, which zbarimg refuses | 13.5 s |
| qrcode | pages_2000.pdf | done, no code: pdfinfo's count, then the first and last 3 pages | 1.6 s |
| pdftotext | pages_2000.pdf | done | 0.3 s |
| exif | pages_2000.pdf | done, `PageCount=2000` | 0.4 s |
| pdf_analyzer | pages_2000.pdf | done, with the rewrite | 1.6 s |
| pdf_analyzer | page_200in.pdf | done | 0.3 s |

The dearest is ocr on the large image: OpenCV's non-local means denoising of 400 million pixels in the task and tesseract's two passes, 149 s of the module's 300-second deadline. Each tool has its own timeout under that (`ocr`'s `timeout`, 120 s a pass; qrcode's 30 s a run, as ace3), and the task's memory (3 GiB for ocr, 2 GiB for qrcode) holds the decoded image: OpenCV refuses an image of more than 2^30 pixels itself (`CV_IO_MAX_IMAGE_PIXELS`). A file past ace3's `file_size_limit` (100 MB for ocr, 80 MB for exif) isn't read.
