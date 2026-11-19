//! Mechanical native ownership only. Combined task/source authority lives in
//! Services and requires an actual opaque Store-origin admission.

#[cfg(unix)]
pub use crate::execution_lease::NativeGrantLease;
