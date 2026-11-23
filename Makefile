# Logbook build helper.
#
#   make            build every program (debug)
#   make test       run the test suite
#   make check      every local check, the same as CI: run before every push
#   make selftest   the checks' own tests: each rule broken on purpose must be caught
#   make claims     the map check: every due claim proven by a test that ran and passed
#   make summary    claims per milestone
#   make breaks     the break list: every deliberate mistake must be caught
#   make cheats     the cheat list: every known way to weaken the checks must be flagged
#   make gate BASE=main   does the change since BASE need the owner's approval?

CARGO ?= cargo

.PHONY: all test check selftest fmt clippy arch deny claims summary breaks cheats gate lost clean

all:
	$(CARGO) build --workspace --locked

test:
	$(CARGO) test --workspace --locked

fmt:
	$(CARGO) fmt --all --check

clippy:
	$(CARGO) clippy --workspace --all-targets --locked -- -D warnings

arch:
	python3 scripts/arch-check.py

# cargo-deny runs in CI; locally only when it is installed (it is said so).
deny:
	@if command -v cargo-deny >/dev/null 2>&1; then $(CARGO) deny check; \
	else echo "cargo-deny not installed: dependency check skipped here, it runs in CI"; fi

# claims runs the test suite itself and reads which tests ran and passed.
claims:
	python3 scripts/claims-check.py

summary:
	python3 scripts/claims-check.py --summary

breaks:
	python3 scripts/breaks-check.py

cheats:
	python3 scripts/cheats-check.py

BASE ?= main
gate:
	sh scripts/gate-run.sh $(BASE) HEAD

lost:
	sh scripts/tests-lost.sh $(BASE)

check: fmt clippy arch deny claims breaks selftest cheats

selftest:
	sh scripts/arch-check-selftest.sh
	sh scripts/claims-check-selftest.sh
	sh scripts/breaks-check-selftest.sh

clean:
	$(CARGO) clean
