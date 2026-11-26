# Spec tests

Tests written before the code, one folder per step of a version
(build plan V15). The owner approves them in a spec pull request, and from then
on they are frozen: `verify/` is protected by the gate, so any change needs
the owner's approval again.

The code pull request includes the step's files unchanged, for example in
`crates/logbook-model/src/lib.rs`:

```rust
#[cfg(test)]
#[rustfmt::skip]
#[path = "../../../verify/spec/step1/model_spec.rs"]
mod spec_step1;
```

`#[rustfmt::skip]` keeps `cargo fmt` from rewriting the frozen file.

Test names start with the claim they prove (`c12_1_…`, `g7_…`). Once one claim
of a step has a test in the run, every claim of that step is due
(`scripts/claims-check.py`), so a code pull request can't bring in only the
easy tests of a step.

Each file's header says what the code must provide (types, functions,
dependencies). A test without a claim prefix checks the test itself, for
example that a generator covers every lane.

| Step | Folder | Claims |
|---|---|---|
| 0.1a, 1: event model and stable IDs | `step1/` | C01.2, C01.3, C12.4, G7 |
| 0.1a, 2: the store | `step2/` | D01.3, D01.4, D02.1, D03.1–D03.3, D04.1–D04.3, D05.1, D05.2, L10.1, L10.2 |
| 0.1a, 3: network block, file limits, starting programs | `step3/` | L02.1, L02.2, L03.1, L03.2 |
