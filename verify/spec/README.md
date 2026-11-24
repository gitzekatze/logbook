# Spec tests

Tests written before the code, one folder per step of a version
(build plan V15). The owner approves them in a spec pull request, and from then
on they are frozen: `verify/` is protected by the gate, so any change needs
the owner's approval again.

The code pull request includes the step's files unchanged, for example in
`crates/logbook-model/src/lib.rs`:

```rust
#[cfg(test)]
#[path = "../../../verify/spec/step1/model_spec.rs"]
mod spec_step1;
```

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
