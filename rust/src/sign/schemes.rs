//! The registry of named signature schemes.

use std::sync::{Arc, LazyLock};

use super::Scheme;
use super::ed25519::Ed25519;
use super::hybrid::Hybrid;
use super::mldsa::{MlDsa44, MlDsa65, MlDsa87};

static SCHEMES: LazyLock<Vec<Arc<dyn Scheme>>> = LazyLock::new(|| {
    let ed25519: Arc<dyn Scheme> = Arc::new(Ed25519);
    let mldsa: [Arc<dyn Scheme>; 3] = [
        Arc::new(MlDsa44::new()),
        Arc::new(MlDsa65::new()),
        Arc::new(MlDsa87::new()),
    ];
    let hybrids = mldsa.clone().map(|pq| -> Arc<dyn Scheme> {
        let name = format!("{}-Ed25519", pq.name());
        Arc::new(Hybrid::new(name, pq, ed25519.clone()))
    });
    [vec![ed25519.clone()], mldsa.to_vec(), hybrids.to_vec()].concat()
});

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
    fn names_match_go() {
        let names: Vec<_> = all().iter().map(|s| s.name()).collect();
        assert_eq!(
            names,
            [
                "Ed25519",
                "ML-DSA-44",
                "ML-DSA-65",
                "ML-DSA-87",
                "ML-DSA-44-Ed25519",
                "ML-DSA-65-Ed25519",
                "ML-DSA-87-Ed25519",
            ]
        );
        assert_eq!(by_name("ed25519").unwrap().name(), "Ed25519");
        assert!(by_name("rsa").is_none());
    }

    #[test]
    fn all_schemes_work() {
        for scheme in all() {
            super::super::check_scheme(scheme.as_ref());
        }
    }
}
