//! The registry of named KEM schemes.

use std::sync::{Arc, LazyLock};

use super::Scheme;
use super::adapter::NikeKem;
use super::combiner::Combiner;
use super::mlkem::{MlKem512, MlKem768, MlKem1024};
use crate::nike::{x448::X448, x25519::X25519};

static SCHEMES: LazyLock<Vec<Arc<dyn Scheme>>> = LazyLock::new(|| {
    let x25519: Arc<dyn Scheme> = Arc::new(NikeKem::new(Arc::new(X25519)));
    let x448: Arc<dyn Scheme> = Arc::new(NikeKem::new(Arc::new(X448)));
    let mlkem768: Arc<dyn Scheme> = Arc::new(MlKem768::new());
    let mlkem768_hedged: Arc<dyn Scheme> = Arc::new(MlKem768::hedged());
    vec![
        x25519.clone(),
        x448.clone(),
        Arc::new(MlKem512::new()),
        mlkem768.clone(),
        Arc::new(MlKem1024::new()),
        Arc::new(MlKem512::hedged()),
        mlkem768_hedged.clone(),
        Arc::new(MlKem1024::hedged()),
        combiner("MLKEM768-X25519", vec![x25519.clone(), mlkem768.clone()]),
        combiner("MLKEMHedged768-X25519", vec![x25519, mlkem768_hedged]),
        combiner("MLKEM768-X448", vec![x448, mlkem768]),
    ]
});

fn combiner(name: &str, schemes: Vec<Arc<dyn Scheme>>) -> Arc<dyn Scheme> {
    Arc::new(Combiner::new(name, schemes).expect("non-empty"))
}

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
        assert_eq!(
            by_name("mlkem768-x25519").unwrap().name(),
            "MLKEM768-X25519"
        );
        assert_eq!(by_name("X448").unwrap().name(), "x448");
        assert!(by_name("kyber").is_none());
    }

    #[test]
    fn all_schemes_work() {
        for scheme in all() {
            super::super::check_scheme(scheme.as_ref());
        }
    }
}
