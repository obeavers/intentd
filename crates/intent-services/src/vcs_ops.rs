//! Shared error translation for the explicit recorded Git lane.
use intent_core::{vcs::VcsError, Error};
pub(crate) fn engine_error(error: VcsError) -> Error {
    match error {
        VcsError::Backend(error) => error,
        VcsError::InvalidInput { reason } => Error::InvalidParams(reason),
        error @ VcsError::Unsupported { .. } => Error::Unsupported(error.to_string()),
        error => Error::Internal(error.to_string()),
    }
}
