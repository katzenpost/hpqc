mod common;

use std::sync::Arc;

use hpqc::kem::adapter::{NikeKem, Prf};
use hpqc::kem::combiner::{Combiner, split_prf};
use hpqc::kem::mlkem768::MlKem768;
use hpqc::kem::{self, Scheme};
use hpqc::nike::{self, Scheme as _};
use serde_json::Value;

fn prf(c: &Value) -> Prf {
    match common::str(c, "prf") {
        "blake2b-xof" => Prf::Blake2bXof,
        "sha256-v1" => Prf::Sha256V1,
        other => panic!("unknown prf {other}"),
    }
}

fn x25519_adapter(c: &Value) -> NikeKem {
    NikeKem::with_prf(Arc::new(nike::x25519::X25519), prf(c))
}

#[test]
fn adapter_matches_go() {
    let Some(v) = common::load("testvectors/kem/adapter_test_vectors.json") else {
        return;
    };
    for c in common::cases(&v) {
        let name = common::str(c, "name");
        let nike = nike::schemes::by_name(common::str(c, "nike_name")).unwrap();
        let kem = NikeKem::with_prf(nike.clone(), prf(c));

        let sk = kem
            .private_key_from_bytes(&common::hex(c, "static_private_key_hex"))
            .unwrap();
        assert_eq!(
            sk.public_key().to_bytes(),
            common::hex(c, "static_public_key_hex"),
            "{name}"
        );

        let eph = nike
            .private_key_from_bytes(&common::hex(c, "ephemeral_private_key_hex"))
            .unwrap();
        let (ct, ss) = kem
            .encapsulate_with_ephemeral(&*sk.public_key(), &*eph)
            .unwrap();
        assert_eq!(ct, common::hex(c, "ciphertext_hex"), "{name}");
        assert_eq!(*ss, common::hex(c, "shared_secret_hex"), "{name}");
        assert_eq!(*kem.decapsulate(&*sk, &ct).unwrap(), *ss, "{name}");
    }
}

fn check_combiner(c: &Value) {
    let name = common::str(c, "name");
    let x25519 = x25519_adapter(c);
    let x_sk = x25519
        .private_key_from_bytes(&common::hex(c, "x25519_static_private_key_hex"))
        .unwrap();
    assert_eq!(
        x_sk.public_key().to_bytes(),
        common::hex(c, "x25519_static_public_key_hex")
    );
    let eph = nike::x25519::X25519
        .private_key_from_bytes(&common::hex(c, "x25519_ephemeral_private_key_hex"))
        .unwrap();
    let (x_ct, x_ss) = x25519
        .encapsulate_with_ephemeral(&*x_sk.public_key(), &*eph)
        .unwrap();
    assert_eq!(x_ct, common::hex(c, "x25519_ciphertext_hex"), "{name}");
    assert_eq!(*x_ss, common::hex(c, "x25519_shared_secret_hex"), "{name}");

    let seed = [common::hex(c, "mlkem_d_hex"), common::hex(c, "mlkem_z_hex")].concat();
    let m_sk = MlKem768.derive_key(&seed).unwrap();
    let m_pk = m_sk.public_key();
    assert_eq!(
        m_pk.to_bytes(),
        common::hex(c, "mlkem_encapsulation_key_hex"),
        "{name}"
    );
    let m: [u8; 32] = common::hex(c, "mlkem_m_hex").try_into().unwrap();
    let (m_ct, m_ss) = MlKem768.encapsulate_deterministic(&*m_pk, &m).unwrap();
    assert_eq!(m_ct, common::hex(c, "mlkem_ciphertext_hex"), "{name}");
    assert_eq!(*m_ss, common::hex(c, "mlkem_shared_secret_hex"), "{name}");

    let combined_ct = [x_ct.as_slice(), &m_ct].concat();
    assert_eq!(
        combined_ct,
        common::hex(c, "combined_ciphertext_hex"),
        "{name}"
    );
    let combined_ss = split_prf(&[(&x_ss, &x_ct), (&m_ss, &m_ct)]).unwrap();
    assert_eq!(
        combined_ss.to_vec(),
        common::hex(c, "combined_shared_secret_hex"),
        "{name}"
    );

    let combiner = Combiner::new(
        "MLKEM768-X25519",
        vec![Arc::new(x25519), Arc::new(MlKem768)],
    )
    .unwrap();
    let sk_bytes = [x_sk.to_bytes().as_slice(), &m_sk.to_bytes()].concat();
    let sk = combiner.private_key_from_bytes(&sk_bytes).unwrap();
    assert_eq!(
        combiner.decapsulate(&*sk, &combined_ct).unwrap().to_vec(),
        combined_ss,
        "{name}"
    );
}

#[test]
fn mlkem768_x25519_combiner_matches_go() {
    let Some(v) = common::load("testvectors/kem/mlkem768_x25519_combiner.json") else {
        return;
    };
    common::cases(&v).iter().for_each(check_combiner);
}

#[test]
fn lean_combiner_vectors_match() {
    let Some(v) = common::load("kem/combiner/testdata/lean_mlkem768_x25519_combiner_vectors.json")
    else {
        return;
    };
    common::cases(&v).iter().for_each(check_combiner);
}

#[test]
fn registry_names_match_go() {
    for name in [
        "x25519",
        "x448",
        "MLKEM768",
        "MLKEM768-X25519",
        "MLKEM768-X448",
    ] {
        assert_eq!(kem::schemes::by_name(name).unwrap().name(), name);
    }
}
