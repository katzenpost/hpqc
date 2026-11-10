mod common;

use std::sync::Arc;

use hpqc::bacap::WriteCap;
use hpqc::nike::ctidh1024::Ctidh1024;
use hpqc::nike::schemes;
use hpqc::protocols::mkem::{Ciphertext, Mkem};
use hpqc::protocols::sealedbox::SealedBox;
use hpqc::voucher::{Form, ShakeRng, Vouchers};
use serde_json::Value;

fn hex(v: &Value, section: &str, field: &str) -> Vec<u8> {
    common::hex(&v[section], field)
}

/// Mints, inducts and opens from the recorded inputs and checks every
/// output byte for byte against what Go and Python produced. The voucher
/// takes highctidh-rs's CTIDH-1024 as a caller-supplied `nike::Scheme`, the
/// way firmware plugs in its own binding of highctidh's C library.
fn check_voucher_vectors(rel: &str, form: Form) {
    let vouchers = Vouchers::new(Arc::new(Ctidh1024));
    let Some(v) = common::load(rel) else {
        return;
    };
    let write_cap = WriteCap::from_bytes(&hex(&v, "inputs", "message_write_cap")).unwrap();
    let name = common::str(&v["inputs"], "display_name");
    let keypair_rng = &mut ShakeRng::new(&hex(&v, "inputs", "keypair_seed"));
    let minted = match form {
        Form::Compact => vouchers.mint(&write_cap, name, keypair_rng),
        Form::Long => vouchers.mint_long(&write_cap, name, keypair_rng),
    };
    assert_eq!(minted.form, form);
    assert_eq!(minted.voucher.to_vec(), hex(&v, "mint", "voucher"));
    assert_eq!(minted.payload, hex(&v, "mint", "voucher_payload"));
    assert_eq!(
        *minted.stream.write_cap.to_bytes(),
        hex(&v, "mint", "voucher_write_cap")
    );
    assert_eq!(
        *minted.stream.read_cap.to_bytes(),
        hex(&v, "mint", "voucher_read_cap")
    );
    assert_eq!(*minted.secret_key, hex(&v, "mint", "voucher_secret_key"));
    assert_eq!(minted.public_key, hex(&v, "mint", "voucher_public_key"));

    let salt: [u8; 32] = hex(&v, "inputs", "salt").try_into().unwrap();
    let inducted = vouchers
        .induct_with_salt(
            &minted.voucher,
            &minted.payload,
            &hex(&v, "inputs", "who_reply"),
            &salt,
            &mut ShakeRng::new(&hex(&v, "inputs", "seal_seed")),
        )
        .unwrap();
    assert_eq!(inducted.form, form);
    assert_eq!(
        inducted.display_name,
        common::str(&v["induct"], "display_name")
    );
    assert_eq!(
        *inducted.mutated_read_cap.to_bytes(),
        hex(&v, "induct", "mutated_message_read_cap")
    );
    assert_eq!(inducted.sealed_reply, hex(&v, "induct", "sealed_reply"));
    assert_eq!(
        *inducted.stream.write_cap.to_bytes(),
        hex(&v, "induct", "voucher_write_cap")
    );
    assert_eq!(inducted.salt.to_vec(), hex(&v, "induct", "salt"));

    let opened = vouchers
        .open_reply(
            &hex(&v, "mint", "voucher_secret_key"),
            &hex(&v, "induct", "sealed_reply"),
            &write_cap,
        )
        .unwrap();
    assert_eq!(opened.who_reply, hex(&v, "open", "who_reply"));
    assert_eq!(opened.salt.to_vec(), hex(&v, "open", "salt"));
    assert_eq!(
        *opened.mutated_write_cap.to_bytes(),
        hex(&v, "open", "mutated_message_write_cap")
    );
}

#[test]
fn compact_voucher_matches_go() {
    check_voucher_vectors("voucher/testdata/voucher_vectors_v2.json", Form::Compact);
}

#[test]
fn long_voucher_matches_go() {
    check_voucher_vectors("voucher/testdata/voucher_vectors.json", Form::Long);
}

#[test]
fn sealed_boxes_from_go_open() {
    let Some(v) = common::load("testvectors/protocols/sealedbox.json") else {
        return;
    };
    for c in common::cases(&v) {
        let nike = schemes::by_name(common::str(c, "nike_name")).unwrap();
        let sk = nike
            .private_key_from_bytes(&common::hex(c, "recipient_private_key_hex"))
            .unwrap();
        let pk = nike
            .public_key_from_bytes(&common::hex(c, "recipient_public_key_hex"))
            .unwrap();
        assert_eq!(sk.public_key().to_bytes(), pk.to_bytes());
        let plaintext = SealedBox::new(nike)
            .open(&*sk, &*pk, &common::hex(c, "ciphertext_hex"))
            .unwrap();
        assert_eq!(
            plaintext,
            common::hex(c, "plaintext_hex"),
            "{}",
            common::str(c, "name")
        );
    }
}

#[test]
fn mkem_ciphertexts_from_go_open() {
    let Some(v) = common::load("testvectors/kem/mkem.json") else {
        return;
    };
    for c in common::cases(&v) {
        let mkem = Mkem::new(schemes::by_name(common::str(c, "nike_name")).unwrap());
        let nike = schemes::by_name(common::str(c, "nike_name")).unwrap();
        let ct = Ciphertext::from_bytes(&mkem, &common::hex(c, "ciphertext_hex")).unwrap();
        assert_eq!(ct.to_bytes(), common::hex(c, "ciphertext_hex"));
        for key in c["recipient_private_keys_hex"].as_array().unwrap() {
            let sk = nike
                .private_key_from_bytes(&::hex::decode(key.as_str().unwrap()).unwrap())
                .unwrap();
            assert_eq!(
                mkem.decapsulate(&*sk, &ct).unwrap(),
                common::hex(c, "plaintext_hex"),
                "{}",
                common::str(c, "name")
            );
        }
    }
}
