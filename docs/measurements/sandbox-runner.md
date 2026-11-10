# The sandbox runner

PLAN.md 7.5 batch 10 built the runner `docs/modules.md` (*External tools*) describes: a tool a contained task asks for runs as its own process, contained before its exec, allowed threads and no processes (`crates/ace-pool/src/tools.rs`, `containment::contain_tool`, the tool filter in `containment/seccomp.rs`). Measured on 2026-11-10 in ace4's dev container (Rancher Desktop, Linux 6.18, Landlock ABI 7, aarch64, 10 CPUs), debug builds.

## What it refuses

`crates/ace-pool/tests/containment.rs`'s `runner` tests run `containment-test-task` as the tool: its `tool` mode contains itself and execs `containment-test-task --uncontained ACTION`, so each refusal is the runner's and not the test task's. Each must end with a status, never a hang:

| Test | The tool | Ends |
|---|---|---|
| `a_tool_may_start_threads` | starts a thread | exits 0, `a thread ran` |
| `a_tool_that_forks_is_killed` | `fork()` | stopped: `process` (SIGSYS) |
| `a_tool_that_spawns_a_process_is_killed` | `Command::spawn`, glibc's `posix_spawn` (`clone(CLONE_VM \| CLONE_VFORK)`) | stopped: `process` (SIGSYS) |
| `a_tool_that_execs_again_is_killed` | `execv("/bin/true")` after the runner's exec | stopped: `program`, killed by the supervisor at the exec, in under 10 s |
| `a_tool_can_open_no_socket` | a TCP connect, and a UDP datagram to a listening port | refused, EACCES from the tool filter's `socket`, both |
| `a_tool_writes_only_its_working_directory` | writes inside its working directory, then outside it | the first written, the second refused (EACCES) and not there |
| `a_tool_reads_only_what_it_was_given` | reads a task file it was given, another task file, `/etc/passwd`, `/proc/self/status` | the first read, the rest refused (EACCES) |
| `a_task_file_is_opened_with_no_symlink_followed` | is given a task "file" that is a symlink to `/etc/passwd` | the run refused before it starts: `the task's link: Too many levels of symbolic links` |
| `a_tool_past_its_memory_limit_is_refused_the_memory` | allocates 512 MB under a 256 MB `RLIMIT_AS` | the allocation fails: SIGABRT, `memory allocation of 536870912 bytes failed` |
| `a_tool_past_its_cpu_limit_is_killed` | spins for 30 CPU seconds under a 1-second `RLIMIT_CPU` | killed by SIGXCPU |
| `a_tool_that_writes_a_file_past_its_limit_is_stopped` | writes 8 MB under a 1 MB `RLIMIT_FSIZE` | stopped: `file_size` (SIGXFSZ), nothing kept |
| `a_tool_past_its_open_files_is_refused_more` | opens 100 files under `RLIMIT_NOFILE` 32 | refused: `Too many open files` |
| `a_tool_that_writes_too_much_output_is_stopped` | prints 80 MB | stopped: `output`, its first 64 MiB kept |
| `a_tool_past_its_timeout_is_killed` | sleeps 60 s with a 1-second timeout | stopped: `timeout`, in under 10 s |
| `only_plain_files_are_kept` | leaves a file, a symlink to `/etc/passwd` and a file with two links | only the plain file kept |
| `exiftool_reads_what_it_reads_plain` | ExifTool on a DOCX, an ODT and an AES-256 PDF | the same JSON as plain but for the copy's times: the first e2e run of the batch found ExifTool missing Perl's arch-dependent modules (`Compress::Raw::Zlib`, for Archive::Zip) under the runner, so it now reads `/usr/lib/<triplet>/perl` too |
| `tesseract_and_zbarimg_run_their_threads_under_the_runner` | Ghostscript renders the QR sample's pages, zbarimg scans each, tesseract reads the first, all contained | the same stdout as each run plain, the QR code's URL read; zbarimg ran 6 threads and tesseract 4 at most, 3 runs of 3 |

The same through a pool: `crates/ace-pool/tests/hung_tasks.rs`'s `a_task_whose_tool_is_stopped_or_refused_ends_with_the_reason` runs `test-pool parsers --task-user ace4-task`, whose module `test_runs_tool` runs the test task as its tool with the arguments its input holds. Each of a thread, a fork, an exec, a 60-second sleep, 80 MB of output, a read of `/etc/passwd`, a read of its input and a file to keep ends its task `done`, with the run's status in the result (`stopped: Process`, `stopped: Program`, `stopped: Timeout`, `stopped: Output`, `exited 4`, ...), in 5.3 s for all eight. `the_sandbox_modules_run_opencv_contained` runs qrcode on a blank image (zbarimg, OpenCV's decoder in the task, the inverted scan) and ocr on a small screenshot (OpenCV's scaling, sharpening and denoising in the task, tesseract twice) through the same pool: both end `done`, so OpenCV ran on the task's one thread under containment.

`cargo test -p ace-pool --test containment` ran three times in a row: 29 passed each time, in 2.08 to 2.13 s, before `exiftool_reads_what_it_reads_plain` was added; with it, 30 pass in about 9 s, most of it ExifTool decrypting the AES-256 PDF.

## What it costs

`the_runners_cost` (ignored, run by hand): the test task doing nothing, through the runner and plain, 21 runs each. Through the runner: median 2.90 ms, range 2.62 to 3.94 ms; plain: median 1.32 ms, range 1.21 to 1.70 ms. So the runner adds about 1.6 ms a run: the `tool` process's start, its opening of the paths and its containment, and the listener's handshake. The tools' own runs are tens to hundreds of milliseconds (Ghostscript's renders, tesseract), and a module runs at most a few dozen (`MAX_RUNS` is 64).

## What a tool reads

What each tool opened under `strace -f -e trace=%file` on the samples, besides its working directory, `/proc` and `/dev`, is its spec's `reads` in `ace_sdk::tools::SANDBOX_TOOLS`, with the directories its data's symlinks lead to (Ghostscript's `Resource` directory links into poppler's CMaps, the URW fonts and the ICC profiles); the runner adds the dynamic loader's cache, the time zone, the C locale, glibc's character set modules and the random devices, and the libraries the program, its interpreter and the modules in its data need by `DT_NEEDED`. A second strace of the tesseract test under the runner found no open refused. The modules' reference tests run the tools plain and `tests/e2e/run` contained, and both match ace3's dumps and trees.
