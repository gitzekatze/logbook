# Logbook build helper.
#
#   make            build every program (debug)
#   make test       run the test suite
#   make check      every local check, the same as CI: run before every push
#   make selftest   the checks' own tests: each rule broken on purpose must be caught

CARGO ?= cargo

.PHONY: all test check selftest fmt clippy arch deny clean

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

check: fmt clippy arch deny test selftest

selftest:
	sh scripts/arch-check-selftest.sh

clean:
	$(CARGO) clean
