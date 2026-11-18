# 0003: What a file is, known when it is added

Status: decided on 2026-11-17, built on 2026-11-18 as PLAN.md decision 25; *As built* at the end says what the build chose where this left it open. The owner chose option 2 (the byte facts as each file's first, contained task) and accepted that `file_type`'s result leaves the tree. The owner kept the distinction this design draws between a file's *type* (what its bytes are, such as `text/plain`) and its *role* (what its producer made it, such as an email's text body); the two are named so from here on. The role is a field of its own on the file, with ace3's values (today's `type=` names); `yara_meta`'s `type=` tag is built from it, so YARA rules and the signatures see what they see today.

## The problem

A module that acts on some kinds of file finds out whether a file is one by looking at it. Since decision 23 a module declares the checks that need only what the core holds (the file's name, size, directives, which module added it), and the core queues nothing those checks decline. What is left is mostly checks on a file's bytes: 98,164 tasks a comparison run are still started only for the module to read a file's first bytes and stop (`docs/measurements/task-start.md`). Several of those modules repeat the same checks: `file_type` already computes `is_pdf_file`, `is_pe_file`, `is_lnk_file` and nine more flags with the same functions (`ace-mod-files`' `checks`), and other modules then compute them again.

The owner wants one way for a module to know what a file is, with no module reading bytes to decide whether to act. Some files' kind is known by whoever made them (an email's HTML body, an attachment); some only by their bytes (a file out of an archive). One mechanism has to cover both, so it is facts on the file rather than observable subtypes.

## The design

**A file carries facts from the moment it is added.** Two kinds, in one place:

- **What its bytes say.** libmagic's description and mime type, and the flags `file_type` computes today: OLE, RTF, PDF, PE, zip, x509, LNK, jar, email, Office, and the rest of `FileTypeAnalysis`. They depend on the bytes alone, so they are kept once per sha256, as the bucket keeps the bytes once (decision 15).
- **What its producer knew.** The role the module that wrote it gave it: today's `yara_meta` `type=` tags already are this vocabulary (`email.attachment`, `email`, `document.pdf.text`, `script.macro`, `archive.dmg`, `document.mhtml.part` and about 20 more, all ace3's). They stay per path, as `yara_meta` is now, since the same bytes can be an attachment in one email and a body part in another.

A few of today's flags depend on the name as well as the bytes (`is_office_ext`, and `is_pdf_file`'s exception for a `.pdfparser` name). Those stay declarations over the path, which decision 23 already supports; they are not facts.

**Who computes the byte facts: one contained step, before anything else sees the file.** Typing a file means libmagic, a zip reader and an x509 parser reading attacker bytes, so it runs in a contained parser task, never in the core. Two places it could run:

1. *In the producer*, as part of writing the file out. No extra task, but every module that writes files would load libmagic's database (1.5 to 2 ms a process, measured in `task-start.md`), a lookup module that fetches a file couldn't (lookups parse nothing hostile), and an API submission has no producer.
2. *As the file's first task*, which the core queues for every new file on the parser pool, and until whose end the core queues no other task on that file. It is today's `file_type` task made mandatory and first, with its output stored as the file's facts instead of as an analysis.

**I recommend 2.** It is one place for every file, submitted or produced, parser or lookup; it costs one task per new file, which is what `file_type` costs today; and since no other task on the file exists until the facts do, no declaration ever waits for a fact that arrives later. The role facts need no parse and are set by the producer as `yara_meta` is now.

**Declarations read the facts.** `Module::takes` gains conditions over them ("the file is a PDF", "the file's role is `email.attachment`"), checked by the core's matcher and again by the pool, with the audit setting proving each module's declaration as it did for decision 23. A module's own byte check then goes, wherever the fact says exactly what the module's check said. Checks that need a real parse stay in the module.

## What it changes

- **The core no longer runs libmagic.** Today `ace-store` computes a mime type for every file the core spools (an API submission, a task's upload) in the core's own process (`crates/ace-store/src/spool.rs`, `mime_type_of`). That is hostile bytes parsed outside containment. The facts replace it: the store records no type, and `store.objects.mime_type`, which decision 23's declarations read, comes from the facts.
- **`file_type` stops being an analysis module** and becomes the facts step. Its result is no longer a result in the tree.
- **The comparison with ace3.** ace3's trees have a `file_type_analysis` result on every file. ace4's normal form builds that result from the file's facts, so the comparison checks the same values, and a difference in a fact shows as it does today.
- **Observable types are unchanged.** A file is still `file`; nothing in a hunt, a signature or the API's types moves.
- **A site** declares on the facts the same way, and adds role values as it adds observable types, through `App`, so the vocabulary is fixed when the binary is built.

## Expected effect, to be measured in the step

Of the 98,164 first-byte tasks, 68,035 compare fixed bytes and about 30,000 more turn on libmagic's answer (`task-start.md`, option 3). Most of both are what the facts say. The step measures how many declarations can cover, as decision 23's did, with the same three runs: HEAD, audit, applied.

## What the owner decides

1. Option 2 (the facts as the file's first task) or option 1 (in the producer).
2. Whether the role vocabulary is `yara_meta`'s `type=` values as they are, or a field of its own that `yara_meta` is then built from.
3. Whether `file_type`'s result leaving the tree, and being rebuilt only for the comparison, is acceptable for the GUI's analysis view and the API, which show it today.

## As built

PLAN.md decision 25 has the whole of it; `docs/measurements/task-start.md` (*The file's type, built*) has the measurements.

- **The type step.** `file_type` is queued first on every file that any module of the root's mode would take, by the core's own rules, and nothing else on the file is queued until it has ended (`ace_core::type_step`). It runs once a file in each root, as `file_type` did, and its facts are kept once a sha256 (`store.file_types`). A binary without `file_type` types nothing and nothing waits.
- **A failed step.** However it fails (the module, its deadline, its lease run out on its last attempt), the file's other tasks are queued in the same transaction. The file then has no type, unless the same bytes were typed in another root, and every declaration's condition on the type is unknown and holds, so the modules whose checks moved run and their own parse decides. A failure can start modules that would have declined the file; it can't keep one off.
- **ace3's result.** Where ace3's `file_type` would have run, by the core's rules for the `file_type` component, the file gets that module's tags and `yara_meta` types from its facts and analysis path, and is marked (`analysis.observables.type_result`). The comparison's normal form, the modules ace3 makes depend on `file_type`, the declarations that read its result and the hooks' tree conditions get ace3's result built the same way.
- **The role** is `analysis.files.role`, from `ace_results::FileRole`: ace3's 37 `type=` values, and a site's through `App::file_roles`. A module gives it with `TaskContext::write_file`, which adds the `type=` tag built from it; a submission's role is its first `type=` tag that names one.
- **The store** reads no bytes: `mime_type_of` and `store.objects.mime_type` are gone, and a lease's mime type is the type's.
