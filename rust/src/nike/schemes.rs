//! The registry of named NIKE schemes.

use std::sync::{Arc, LazyLock};

use super::Scheme;
use super::x448::X448;
use super::x25519::X25519;

static SCHEMES: LazyLock<Vec<Arc<dyn Scheme>>> =
    LazyLock::new(|| vec![Arc::new(X25519), Arc::new(X448)]);

/// Looks up a scheme by name, ignoring ASCII case.
pub fn by_name(name: &str) -> Option<Arc<dyn Scheme>> {
    SCHEMES
        .iter()
        .find(|s| s.name().eq_ignore_ascii_case(name))
        .cloned()
}

pub fn all() -> &'static [Arc<dyn Scheme>] {
    &SCHEMES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_ignores_case() {
        assert_eq!(by_name("X25519").unwrap().name(), "x25519");
        assert_eq!(by_name("x448").unwrap().name(), "x448");
        assert!(by_name("x9").is_none());
    }

    #[test]
    fn all_schemes_work() {
        for scheme in all() {
            super::super::check_scheme(scheme.as_ref());
        }
    }
}
