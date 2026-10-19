mod common;

use hpqc::kem::schemes;
use sha2::{Digest, Sha256};

/// Key derivation, encodings and decapsulation against Go's circl.
#[test]
fn mceliece_matches_go() {
    let Some(v) = common::load("testvectors/kem/mceliece.json") else {
        return;
    };
    let cases = common::cases(&v);
    assert_eq!(cases.len(), 10);
    for c in cases {
        let name = common::str(c, "name");
        let scheme = schemes::by_name(common::str(c, "scheme")).unwrap();
        let sk = scheme.derive_key(&common::hex(c, "seed_hex")).unwrap();
        let pk = sk.public_key();
        assert_eq!(
            Sha256::digest(pk.to_bytes()).to_vec(),
            common::hex(c, "public_key_sha256_hex"),
            "{name}"
        );
        assert_eq!(
            Sha256::digest(&*sk.to_bytes()).to_vec(),
            common::hex(c, "private_key_sha256_hex"),
            "{name}"
        );
        let ss = scheme
            .decapsulate(&*sk, &common::hex(c, "ciphertext_hex"))
            .unwrap();
        assert_eq!(*ss, common::hex(c, "shared_secret_hex"), "{name}");

        let parsed = scheme.private_key_from_bytes(&sk.to_bytes()).unwrap();
        let pk2 = scheme.public_key_from_bytes(&pk.to_bytes()).unwrap();
        let (ct, ss) = scheme.encapsulate(&*pk2, &mut common::rng()).unwrap();
        assert_eq!(scheme.decapsulate(&*parsed, &ct).unwrap(), ss, "{name}");
    }
}
