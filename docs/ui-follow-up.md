# GUI follow-up work

What the design pass of 2026-11-15 (commit `4700cb22`) left weak or undone. It was a foundation, meant
to be refined once analysts use it.

## The direction

The owner's direction, which every item here is measured against:

- An analyst should be able to look at an alert and have what they need, faster and with less on the
  page than ace3. ace3's alert page (the tree plus every section added on top) borders on overload.
- Keep all the information reachable, but lead with what decides the alert and put the rest one click
  away.
- What decides an alert depends on its type, so the top of the page is chosen by alert type.
- Don't add an always-visible section to the alert page without saying what it displaces.
- ace4's own CSS only: no framework and no outside assets. The CSP stays as strict as it is. A page gets
  a script of ace4's own only for a behaviour that can't be a link, a form or a Datastar expression, as
  a same-origin file loaded with the nonce: the graph and the alert list's range selection are the two.
  No need to resemble ace3.

## Decisions waiting on the owner

- [ ] **Email body inline.** The email summary names the body part and links to it in the tree. Showing
  it on the page means the GUI reading file bytes, and a file read is audited as a download today.
  Decide whether to show it, and whether each page view is an audited read.
- [ ] **How much a type's summary controls.** A type's summary replaces one block, beside "What fired".
  The rest of the page is the same for every alert. ace3 swaps the whole page template. Decide whether
  a type should be able to reorder or hide the other sections.
- [ ] **More alert types.** Only `mailbox` and `hunter` have summaries. ace3's `brotex`, `bro_smtp`,
  `http`, `virustotal`, `o365_security`, `graph_resource` and `saq_debug` templates were left out by
  decision. a site's integrations add theirs with `App::alert_summary`.

## The alert page

- [ ] **"What fired" shows at most 6 detections.** Check what an alert with many looks like, and how the
  rest are reached.
- [ ] **Disposition from the alert page lands on the bulk result page,** whose link reads "Back to the
  list". It should return to the alert.
- [ ] **Alert Details starts collapsed now.** It was open before. Confirm with analysts that the one-line
  hint is enough.
- [ ] **Panels opened by a link.** A redirect to `#detections` or `#svs` relies on the browser opening a
  `<details>` for a fragment. This wasn't tested in a browser.
- [ ] **The pruned tree.** The tree starts at the branches that carry a detection. Check with real
  alerts that this is the right default, and that an alert whose important context has no detection on
  it (a hunt's host, an email's sender) still reads well.
- [ ] **The email and hunt summaries were built from fixtures.** Check them against real alerts of each
  type: which fields analysts read first, and which are noise.
- [ ] **Ownership-changed notice.** Unassigning shows nothing, as in ace3. Confirm that's wanted.
- [ ] **Failed analyses.** A result whose module said it failed has an `error` badge in the tree, with
  the reason beside it when it has no summary, and its page shows the reason above the details; a
  module whose task failed without a result is listed under its observable (ace3 `2b9fcd2c`). Built
  from fixtures and not looked at in a browser. Three things to check with real alerts: the badge is
  the warning colour, not ace3's red, so a failure doesn't read as a detection; the pruned tree shows
  a failure only on an observable it already draws, so an alert whose modules failed on a branch with
  no detection says nothing until the whole tree is opened; and the top of the page doesn't count
  failures.
- [ ] **The remediation timeline** (PLAN.md decision 38) is the Remediation panel's table: when,
  target, source, action, how long after the message, and a link. Built from fixtures and not looked at
  in a browser. To check with analysts: whether the remediator's message belongs in the row rather
  than its tooltip (it says why an alias was removed through its owner); whether dropping ace3's Event
  Time column for the duration's tooltip loses anything; whether the panel should start open on an
  email alert; and how an alert with hundreds of deliveries reads.
- [ ] **Add Directive is a page of its own** (PLAN.md decision 31), as Add Comment is: the observable's
  Actions menu links to a form of every directive the binary lists, the five built in (those of ace3's `GUI_DIRECTIVES` an ace4 module reads) and the site's, as boxes
  to tick, and the form goes back to the observable in the whole tree. ace3 takes them in its Add
  Observable modal's multiselect. Check with analysts whether 16-plus boxes on a page read well, whether
  the list should be filtered by the observable's type (ace3 offers every one on every type), and whether
  the page should say which modules a directive lets in. It was looked at only in tests, not in a browser.
  A link can tick boxes in advance (PLAN.md decision 60, `?directive=`), so a site's action, such as
  a site's "Upload To VT" or "Collect Browser History", is one click on a ticked form. A name the list
  doesn't offer is named back in a warning. Check with analysts whether the ticked box stands out
  enough among the others, or whether a link that ticks one should show only that one, with the rest
  folded.
- [ ] **Pivot links** (PLAN.md decision 32 part (b)): a result's are small links beside it in the tree,
  an icon when the binary registered one, and an alert's own are an "External links" panel in the
  summary, drawn only when it has some. Check with analysts whether the panel earns its place above the
  type's summary, and whether a result's links should also show on its own page. Looked at only in
  tests, not in a browser.

## Tables and lists

- [ ] **Numeric columns are right-aligned on four lists only:** SVS runs, batches, tests and coverage.
  Samples, validations, monitoring and worklist counts are still left-aligned.
- [ ] **Long values are truncated with a `title` on the SVS runs list only.** Apply it to the other
  lists.
- [ ] **The alert list's bulk bar takes two rows at 1280 px.**
- [ ] **The SVS runs date wraps to two lines** so its 13 columns fit at 1280 px. Consider a shorter date
  or fewer default columns.
- [ ] **Sticky header against horizontal scroll.** Tables scroll in their own container below 1200 px
  and get a sticky header at 1200 px and above. At that width a table wider than the window would
  scroll the page. None does on the fixture data at 1280 px.
- [ ] **Saved-filter counts.** The "show a count" option is on the alert list only, since only its
  badges show counts.
- [ ] **The Observable Pattern filter's type** (PLAN.md decision 39) is the editor's free-text type field
  the exact Observable filter shares, where ace3's modal offers a menu of types, and its pattern has the
  editor's one value field with the filter's hint, where ace3's input has its own placeholder and
  tooltip. A refused quick filter's mark is a `!` in the danger colour with the reason as its tooltip.
  Check with analysts whether either needs more.

## Navigation and layout

- [ ] **The user menu doesn't close on a click outside it.** It's a `<details>`, and closing it that way
  needs a script.
- [ ] **At about 900 px the section links drop to a second row.** Nothing was designed for narrower
  screens.
- [ ] **Text size.** Body text is 14 px and table text 13 px. Check readability with analysts.

## Pages not looked at in a browser

The pass styled these through the shared foundation but nobody viewed them:

- [ ] Login and password change.
- [ ] The `jd` and `halloween` themes.
- [ ] Events list, search results, remediations and file collections with data in them. They were only
  seen empty, because the screenshot fixtures have none.
- [ ] Admin pages, monitoring, the CLI page, preferences and saved filters got no page-specific work.

## Screenshots and guides

- [ ] **No guide shows the email or hunt alert page.** `tools/help-screenshots/fixtures/4-alerts.sql`
  seeds one of each.
- [ ] **The regenerated screenshots were checked on contact sheets,** not each at full size.
- [ ] **A regeneration changes all 39 files,** because the pictures carry the date they were made.
- [ ] **Fixtures for the unseen pages.** `tools/help-screenshots/run` has no events, search results,
  remediations or file collections.

## Missing from ace3, by design or not yet built

- [ ] **Bulk actions over search results.** The search page is its own page, not a mode of the alert
  list.
- [ ] **A `scheduler.runs` page** beyond what `/admin/monitoring` shows.
- [ ] **Dialogs.** ace4 has none. A reason is a field beside the buttons, and a confirmation is a page.
  Check which of ace3's dialogs analysts miss.
- [ ] **A Sepia theme,** which ace3 gained in `e477e14f`. Not now, by the owner's decision of
  2026-11-16; not built.
- [x] **Selecting a range of alerts on the list,** by shift+click or by dragging over the checkboxes
  (ace3 `5fb36276`). Built on 2026-11-17 as `static/select.js`; `crates/ace-gui/src/list.rs`'s
  *Selection* says how it behaves and where it differs from ace3's. Seen working in the e2e's headless
  Chromium, not by a person with a mouse. Three things to check with analysts: the only hint that it
  exists is the tooltip on "Ticked alerts"; a drag doesn't scroll the page when it reaches the edge of
  the window, as in ace3; and it is mouse and keyboard only, so a touch screen ticks one box at a time.

## How to look at a change

`tools/help-screenshots/run` brings up the GUI on a throwaway database with made-up data and captures
pages with the e2e stack's browser container. Its docstring says how to run it. Look at each changed
page at 1280 px and about 900 px, in the light and dark themes.
