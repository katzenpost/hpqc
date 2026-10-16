mod common;

use hpqc::rand_core::CryptoRng;
use hpqc::sign::{self, Scheme, ed25519::Ed25519, hybrid, mldsa, schemes};

fn rng() -> impl CryptoRng {
    hpqc::rand_core::UnwrapErr(getrandom::SysRng)
}

/// Signs with the deterministic variant of every component, as the
/// generator does.
fn sign_deterministic(key: &dyn sign::PrivateKey, msg: &[u8]) -> Vec<u8> {
    let key: &dyn std::any::Any = key;
    if let Some(k) = key.downcast_ref::<sign::ed25519::PrivateKey>() {
        return Ed25519.sign(k, msg, &mut rng()).unwrap();
    }
    if let Some(k) = key.downcast_ref::<mldsa::PrivateKey<ml_dsa::MlDsa44>>() {
        return k
            .0
            .expanded_key()
            .sign_deterministic(msg, &[])
            .unwrap()
            .encode()
            .to_vec();
    }
    if let Some(k) = key.downcast_ref::<mldsa::PrivateKey<ml_dsa::MlDsa65>>() {
        return k
            .0
            .expanded_key()
            .sign_deterministic(msg, &[])
            .unwrap()
            .encode()
            .to_vec();
    }
    if let Some(k) = key.downcast_ref::<mldsa::PrivateKey<ml_dsa::MlDsa87>>() {
        return k
            .0
            .expanded_key()
            .sign_deterministic(msg, &[])
            .unwrap()
            .encode()
            .to_vec();
    }
    let k = key.downcast_ref::<hybrid::PrivateKey>().unwrap();
    [
        sign_deterministic(&*k.first, msg),
        sign_deterministic(&*k.second, msg),
    ]
    .concat()
}

#[test]
fn sign_schemes_match_go() {
    let Some(v) = common::load("testvectors/sign/schemes.json") else {
        return;
    };
    for c in common::cases(&v) {
        let name = common::str(c, "name");
        let scheme = schemes::by_name(common::str(c, "scheme")).unwrap();
        let msg = common::hex(c, "message_hex");
        let sig = common::hex(c, "signature_hex");

        let sk = scheme.derive_key(&common::hex(c, "seed_hex")).unwrap();
        assert_eq!(*sk.to_bytes(), common::hex(c, "private_key_hex"), "{name}");
        assert_eq!(
            sk.public_key().to_bytes(),
            common::hex(c, "public_key_hex"),
            "{name}"
        );
        assert_eq!(sign_deterministic(&*sk, &msg), sig, "{name}");

        let pk = scheme
            .public_key_from_bytes(&common::hex(c, "public_key_hex"))
            .unwrap();
        scheme.verify(&*pk, &msg, &sig).unwrap();
        let sk = scheme
            .private_key_from_bytes(&common::hex(c, "private_key_hex"))
            .unwrap();
        scheme
            .verify(&*pk, &msg, &scheme.sign(&*sk, &msg, &mut rng()).unwrap())
            .unwrap();
    }
}

#[test]
fn ed25519_matches_go() {
    let Some(v) = common::load("testvectors/primitives/ed25519.json") else {
        return;
    };
    for c in common::cases(&v) {
        let pk = Ed25519
            .public_key_from_bytes(&common::hex(c, "public_key_hex"))
            .unwrap();
        let verified = Ed25519.verify(
            &*pk,
            &common::hex(c, "message_hex"),
            &common::hex(c, "signature_hex"),
        );
        assert!(verified.is_ok(), "{}", common::str(c, "name"));
    }
}
