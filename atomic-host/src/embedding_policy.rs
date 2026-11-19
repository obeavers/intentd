//! The pinned public vault writers can invoke ambient external embeddings.
//! This guard supplements process isolation; it never proves OS containment.

use crate::{HostError, Result};

const EXTERNAL_KEYS: [&str; 3] = ["VOYAGE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"];

fn refuse_with_presence(mut configured: impl FnMut(&str) -> bool) -> Result<()> {
    if EXTERNAL_KEYS.into_iter().any(&mut configured) {
        return Err(HostError::Unsupported(
            "native public vault mutation refuses configured ambient external embedding providers",
        ));
    }
    Ok(())
}

/// Check only whether the pinned provider configuration is nonempty. Values
/// never leave this decision, and no environment variable is changed or logged.
pub(crate) fn refuse_ambient_embedding() -> Result<()> {
    refuse_with_presence(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::{refuse_with_presence, EXTERNAL_KEYS};
    #[test]
    fn every_pinned_external_provider_refuses_without_resolving_or_using_a_key() {
        assert!(refuse_with_presence(|_| false).is_ok());
        for configured in EXTERNAL_KEYS {
            assert!(refuse_with_presence(|name| name == configured).is_err());
        }
        let mut consulted = Vec::new();
        refuse_with_presence(|name| {
            consulted.push(name.to_owned());
            false
        })
        .unwrap();
        assert_eq!(consulted, EXTERNAL_KEYS);
    }
}
