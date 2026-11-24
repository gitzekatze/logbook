//! The frozen spec of the store's permissions (0.1a step 2, claims L10.1 and
//! L10.2), a test binary of its own because it sets the process's umask.

#[cfg(test)]
#[rustfmt::skip]
#[expect(
    clippy::type_complexity,
    reason = "the frozen spec lists its unsafe-store cases as an array of (name, fn) pairs"
)]
#[path = "../../../verify/spec/step2/permissions_spec.rs"]
mod spec_step2_permissions;
