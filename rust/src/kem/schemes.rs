//! The registry of named KEM schemes.

use std::sync::{Arc, LazyLock};

use super::Scheme;
use super::adapter::NikeKem;
use super::combiner::Combiner;
use super::mceliece::{Algorithm, McEliece};
use super::mlkem::{MlKem512, MlKem768, MlKem1024};
use crate::nike::{x448::X448, x25519::X25519};

static SCHEMES: LazyLock<Vec<Arc<dyn Scheme>>> = LazyLock::new(|| {
    let x25519: Arc<dyn Scheme> = Arc::new(NikeKem::new(Arc::new(X25519)));
    let x448: Arc<dyn Scheme> = Arc::new(NikeKem::new(Arc::new(X448)));
    let mlkem: [Arc<dyn Scheme>; 6] = [
        Arc::new(MlKem512::new()),
        Arc::new(MlKem768::new()),
        Arc::new(MlKem1024::new()),
        Arc::new(MlKem512::hedged()),
        Arc::new(MlKem768::hedged()),
        Arc::new(MlKem1024::hedged()),
    ];
    let mlkem_x25519 = mlkem.clone().map(|m| {
        let name = format!("{}-X25519", m.name());
        combiner(&name, vec![x25519.clone(), m])
    });
    let mlkem1024_x448 = combiner("MLKEM1024-X448", vec![x448.clone(), mlkem[2].clone()]);
    let mceliece = [
        Algorithm::McEliece348864,
        Algorithm::McEliece348864f,
        Algorithm::McEliece460896,
        Algorithm::McEliece460896f,
        Algorithm::McEliece6688128,
        Algorithm::McEliece6688128f,
        Algorithm::McEliece6960119,
        Algorithm::McEliece6960119f,
        Algorithm::McEliece8192128,
        Algorithm::McEliece8192128f,
    ]
    .map(|a| -> Arc<dyn Scheme> { Arc::new(McEliece::new(a)) });
    let mceliece_x25519 = mceliece.clone().map(|m| {
        let name = format!("{}-X25519", m.name());
        combiner(&name, vec![x25519.clone(), m])
    });
    let mut schemes = vec![x25519, x448];
    schemes.extend(mlkem);
    schemes.extend(mlkem_x25519);
    schemes.push(mlkem1024_x448);
    schemes.extend(mceliece);
    schemes.extend(mceliece_x25519);
    schemes
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
