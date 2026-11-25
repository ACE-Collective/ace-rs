# The checks and tests, and the coverage report, all in the Compose stack's dev container with its
# Postgres, bucket and telemetry collector.
#
#   make build      compile every crate and its tests in the dev container
#   make images     build the stack's images (the dev container's, Postgres's and ace-rs's own)
#   make test       formatting, lints, the sqlx and layering checks, then every crate's tests:
#                   cargo nextest, which runs tests of different test programs at once, then
#                   cargo test --doc for the doctests, which nextest doesn't run
#   make test-all   make test, then the end-to-end test (tests/e2e/run), which compares the
#                   sample set with ace3's trees
#   make coverage   every crate's tests with coverage: an HTML report in coverage/html/index.html
#                   and a per-file summary in coverage/summary.txt (git-ignored)
#   make stack      build and start the whole stack, with the GUI at http://127.0.0.1:7443, and on a
#                   new database make a dev login, analyst / analystanalyst
#
# The others: make check (the checks without the tests), make e2e, make up, make down, and make
# hooks, which turns on the repository's git hooks for this clone.
#
# Cargo never deletes a build it no longer needs, and each change to a dependency or to a crate
# many depend on leaves a full set of test programs behind, about 15 GB a set. So build and check
# first empty target/debug when it holds more than TARGET_CAP_GB, and sccache makes the next build
# cheap (PLAN.md decision 68).

COMPOSE := docker compose
# Instrumented test binaries are large; more parallel builds than this fill the dev container's
# 12 GiB while they link.
COVERAGE_JOBS ?= 4
TARGET_CAP_GB ?= 20
DEV     := $(COMPOSE) exec -T dev
DEV_CI  := $(COMPOSE) exec -T -e CI=true dev

.PHONY: help build images up down stack check test e2e test-all coverage hooks target-cap

help:
	@sed -n '1,22p' Makefile | sed 's/^# \{0,1\}//'

target-cap: up
	@$(DEV) sh -c 'used=$$(du -sm target/debug 2>/dev/null | cut -f1); used=$${used:-0}; \
		if [ "$$used" -gt $$(( $(TARGET_CAP_GB) * 1024 )) ]; then \
			echo "target/debug holds $$(( used / 1024 )) GB, over TARGET_CAP_GB=$(TARGET_CAP_GB): emptying it"; \
			cargo clean --profile dev; fi'

build: target-cap
	$(DEV) cargo build --workspace --all-targets --locked

images:
	$(COMPOSE) build

up:
	$(COMPOSE) --profile telemetry up -d --wait dev postgres bucket collector

down:
	$(COMPOSE) --profile telemetry down

# ace-rs ships no default account (PLAN.md 5.4): ace3's seed makes analyst with a public password on
# every new database, production's included. This login is the Makefile's, which no deployment
# runs, and is made only while the database has no user; passwords are at least 12 characters.
STACK_USER     ?= analyst
STACK_PASSWORD ?= analystanalyst

stack:
	$(COMPOSE) up -d --build --wait
	@out=$$(printf '%s\n' '$(STACK_PASSWORD)' | $(COMPOSE) exec -T ace ace user create-first \
		$(STACK_USER) --password-stdin 2>&1); status=$$?; \
	if [ $$status -eq 0 ]; then echo "made the dev login $(STACK_USER) / $(STACK_PASSWORD)"; \
	elif printf '%s' "$$out" | grep -q 'a user exists already'; then \
		echo "the database has users already: log in as before"; \
	else printf '%s\n' "$$out" >&2; exit $$status; fi
	@echo "the GUI: http://127.0.0.1:$${ACE_RS_PORT_HTTPS:-7443}"

check: target-cap
	$(DEV) cargo fmt --all --check
	$(DEV) cargo clippy --workspace --all-targets --locked -- -D warnings
	$(DEV) tools/sqlx-check
	$(DEV) cargo run --locked --quiet -p ace-layering

test: check
	$(DEV_CI) cargo nextest run --workspace --locked --no-fail-fast
	$(DEV_CI) cargo test --doc --workspace --locked

e2e:
	tests/e2e/run

test-all: test e2e

# Built in target/llvm-cov-target, apart from the ordinary builds; the report goes to coverage/,
# since target/ is a volume of the dev container's that the host doesn't see. The build has no debug
# info: the report comes from the coverage mapping, and without it the build is about 6 GB smaller
# with the same report. It peaks at about 23 GB on Docker's disk, so the target refuses to start
# with less than COVERAGE_MIN_FREE_GB free there, and cleans the build away when the report is
# written (COVERAGE_KEEP=1 keeps it, for a faster next run). Most of the build is test programs,
# each linking every dependency, which is why a crate's tests/ files build as one program. sccache can't cache instrumented
# builds, so it is off for them. The comparison with ace3's trees (tests/e2e/run) runs the stack's
# release images, so it isn't in the report; the per-module comparisons with ace3's dumps are
# crates' tests and are.
#
# Skipped: three ace-pool containment tests that check what a contained helper leaves behind or
# prints. Under coverage the helper writes a .profraw file, or fails to inside the sandbox and says
# so on stderr, so they can't pass there; they run in make test.
COVERAGE_MIN_FREE_GB ?= 35
COVERAGE_SKIP := only_plain_files_are_kept a_run_keeps_at_most_max_kept_files \
	a_command_runs_contained_and_its_output_is_bounded

coverage: up
	$(COMPOSE) exec -T -e CI=true -e RUSTC_WRAPPER= -e CARGO_PROFILE_DEV_DEBUG=false dev sh -c '\
		free=$$(df -Pk target | awk "NR==2 {print int(\$$4 / 1048576)}"); \
		if [ "$$free" -lt $(COVERAGE_MIN_FREE_GB) ]; then \
			echo "Docker has $${free} GB free; coverage needs $(COVERAGE_MIN_FREE_GB) GB" >&2; exit 2; fi; \
		cargo llvm-cov clean --workspace \
		&& cargo llvm-cov --workspace --locked --no-fail-fast --no-report --jobs $(COVERAGE_JOBS) \
			-- $(foreach t,$(COVERAGE_SKIP),--skip $(t)); \
		status=$$?; \
		cargo llvm-cov report --html --output-dir coverage \
		&& cargo llvm-cov report --summary-only > coverage/summary.txt \
		&& tail -n 1 coverage/summary.txt \
		&& echo "report: coverage/html/index.html"; \
		[ -n "$(COVERAGE_KEEP)" ] || cargo llvm-cov clean; \
		exit $$status'

hooks:
	git config core.hooksPath tools/git-hooks
