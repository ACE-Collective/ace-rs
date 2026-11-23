# The checks and tests CI runs (.github/workflows/ci.yml), and the coverage report, all in the
# Compose stack's dev container with its Postgres, bucket and telemetry collector, as CI runs them.
#
#   make build      compile every crate and its tests in the dev container
#   make images     build the stack's images (the dev container's, Postgres's and ace4's own)
#   make test       formatting, lints, the sqlx and layering checks, then every crate's tests
#   make test-all   make test, then the end-to-end test (tests/e2e/run), which compares the
#                   sample set with ace3's trees
#   make coverage   every crate's tests with coverage: an HTML report in coverage/html/index.html
#                   and a per-file summary in coverage/summary.txt (git-ignored)
#
# The others: make check (the checks without the tests), make e2e, make up, make down, and make
# hooks, which turns on the repository's git hooks for this clone.

COMPOSE := docker compose
# Instrumented test binaries are large; more parallel builds than this fill the dev container's
# 12 GiB while they link.
COVERAGE_JOBS ?= 4
DEV     := $(COMPOSE) exec -T dev
DEV_CI  := $(COMPOSE) exec -T -e CI=true dev

.PHONY: help build images up down check test e2e test-all coverage hooks

help:
	@sed -n '1,14p' Makefile | sed 's/^# \{0,1\}//'

build: up
	$(DEV) cargo build --workspace --all-targets --locked

images:
	$(COMPOSE) build

up:
	$(COMPOSE) --profile telemetry up -d --wait dev postgres bucket collector

down:
	$(COMPOSE) --profile telemetry down

check: up
	$(DEV) cargo fmt --all --check
	$(DEV) cargo clippy --workspace --all-targets --locked -- -D warnings
	$(DEV) sh -c 'cargo sqlx migrate run && cargo sqlx prepare --workspace --check'
	$(DEV) cargo run --locked --quiet -p ace-layering

test: check
	$(DEV_CI) cargo test --workspace --locked --no-fail-fast

e2e:
	tests/e2e/run

test-all: test e2e

# Built in target/llvm-cov-target, apart from the ordinary builds; the report goes to coverage/,
# since target/ is a volume of the dev container's that the host doesn't see. That build is about
# 45 GB on Docker's disk, so the target refuses to start with less than COVERAGE_MIN_FREE_GB free
# there and cleans the build away when the report is written (COVERAGE_KEEP=1 keeps it, for a
# faster next run). sccache can't cache instrumented builds, so it is off for them. The comparison
# with ace3's trees (tests/e2e/run) runs the stack's release images, so it isn't in the report;
# the per-module comparisons with ace3's dumps are crates' tests and are.
#
# Skipped: three ace-pool containment tests that check what a contained helper leaves behind or
# prints. Under coverage the helper writes a .profraw file, or fails to inside the sandbox and says
# so on stderr, so they can't pass there; they run in make test.
COVERAGE_MIN_FREE_GB ?= 60
COVERAGE_SKIP := only_plain_files_are_kept a_run_keeps_at_most_max_kept_files \
	a_command_runs_contained_and_its_output_is_bounded

coverage: up
	$(COMPOSE) exec -T -e CI=true -e RUSTC_WRAPPER= dev sh -c '\
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
