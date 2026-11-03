mod common;

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use hpqc::Error;
use hpqc::bacap::{BoxId, MessageBoxIndex, ReadCap, WriteCap};
use hpqc::hash::hkdf_blake2b;
use hpqc::sign::blinded_ed25519::{BlindedSigningKey, blind_verifying_key};
use hpqc::sign::ed25519::ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha512, Sha512_256};

fn u64_of(c: &Value, field: &str) -> u64 {
    c[field]
        .as_u64()
        .unwrap_or_else(|| panic!("missing {field}"))
}

fn name(c: &Value) -> &str {
    common::str(c, "name")
}

fn box_id(c: &Value, field: &str) -> BoxId {
    common::hex(c, field).try_into().expect("32-byte box ID")
}

/// The vector list of `testvectors/<dir>/<file>.json`, after checking its
/// envelope.
fn load(rel: &str, primitive: &str) -> Option<Vec<Value>> {
    let v = common::load(rel)?;
    assert_eq!(v["format_version"], 1, "{rel}");
    assert_eq!(v["primitive"], primitive, "{rel}");
    Some(common::cases(&v).clone())
}

/// A WriteCap and its first index stepped `advance_by` forward.
fn cap_index(c: &Value) -> (WriteCap, MessageBoxIndex) {
    let wc = WriteCap::from_bytes(&common::hex(c, "writecap_hex")).unwrap();
    let idx = advanced(wc.index(), u64_of(c, "advance_by"));
    (wc, idx)
}

fn advanced(idx: &MessageBoxIndex, by: u64) -> MessageBoxIndex {
    idx.advance_to(idx.idx64() + by).unwrap()
}

fn check_digest(cases: &[Value], f: fn(&[u8]) -> Vec<u8>) {
    for c in cases {
        assert_eq!(
            f(&common::hex(c, "input_hex")),
            common::hex(c, "output_hex"),
            "{}",
            name(c)
        );
    }
}

fn check_sha512(cases: &[Value]) {
    check_digest(cases, |m| Sha512::digest(m).to_vec());
}

fn check_sha512_256(cases: &[Value]) {
    check_digest(cases, |m| Sha512_256::digest(m).to_vec());
}

fn check_blake2b_512(cases: &[Value]) {
    check_digest(cases, |m| blake2b_simd::blake2b(m).as_bytes().to_vec());
}

fn check_hkdf_blake2b(cases: &[Value]) {
    for c in cases {
        let mut okm = vec![0; u64_of(c, "length") as usize];
        hkdf_blake2b(
            &common::hex(c, "secret_hex"),
            &common::hex(c, "salt_hex"),
            &common::hex(c, "info_hex"),
            &mut okm,
        )
        .unwrap();
        assert_eq!(okm, common::hex(c, "okm_hex"), "{}", name(c));
    }
}

fn check_aes_gcm_siv(cases: &[Value]) {
    for c in cases {
        let cipher = Aes256GcmSiv::new_from_slice(&common::hex(c, "key_hex")).unwrap();
        let nonce = Nonce::try_from(&common::hex(c, "nonce_hex")[..]).unwrap();
        let (aad, pt, ct) = (
            common::hex(c, "aad_hex"),
            common::hex(c, "plaintext_hex"),
            common::hex(c, "ciphertext_hex"),
        );
        let sealed = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &pt,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(sealed, ct, "{}", name(c));
        let opened = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ct,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(opened, pt, "{}", name(c));
    }
}

fn vector_seed(label: &str, vname: &str, n: usize) -> Vec<u8> {
    let mut out = vec![0; n];
    let secret = format!("hpqc-vector-seed-{label}");
    hkdf_blake2b(secret.as_bytes(), &[], vname.as_bytes(), &mut out).unwrap();
    out
}

fn check_ed25519(cases: &[Value]) {
    for c in cases {
        let seed: [u8; 32] = vector_seed("ed25519_seed", name(c), 32).try_into().unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let (msg, sig) = (
            common::hex(c, "message_hex"),
            common::hex(c, "signature_hex"),
        );
        assert_eq!(
            sk.verifying_key().to_bytes().to_vec(),
            common::hex(c, "public_key_hex")
        );
        assert_eq!(sk.sign(&msg).to_bytes().to_vec(), sig, "{}", name(c));
        let pk = box_id(c, "public_key_hex");
        MessageBoxIndex::verify_box(&pk, &msg, &sig).unwrap();
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(MessageBoxIndex::verify_box(&pk, &msg, &bad).is_err());
    }
}

fn check_blinded_ed25519(cases: &[Value]) {
    for c in cases {
        let sk =
            SigningKey::from_keypair_bytes(&common::hex(c, "private_key_hex").try_into().unwrap())
                .unwrap();
        let factors: Vec<Vec<u8>> = c["blind_factors_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| hex::decode(f.as_str().unwrap()).unwrap())
            .collect();
        let mut key = BlindedSigningKey::new(&sk, &factors[0]).unwrap();
        let mut pk = blind_verifying_key(&sk.verifying_key(), &factors[0]).unwrap();
        for f in &factors[1..] {
            key = key.blind(f).unwrap();
            pk = blind_verifying_key(&pk, f).unwrap();
        }
        let expected_pk = common::hex(c, "blinded_pubkey_hex");
        assert_eq!(
            key.verifying_key().to_bytes().to_vec(),
            expected_pk,
            "{}",
            name(c)
        );
        assert_eq!(pk.to_bytes().to_vec(), expected_pk, "{}", name(c));
        let msg = common::hex(c, "message_hex");
        let sig = key.sign(&msg);
        assert_eq!(
            sig.to_bytes().to_vec(),
            common::hex(c, "blinded_signature_hex"),
            "{}",
            name(c)
        );
        pk.verify_strict(&msg, &sig).unwrap();
    }
}

fn check_message_box_index(cases: &[Value]) {
    for c in cases {
        let idx = MessageBoxIndex::from_bytes(&common::hex(c, "initial_index_hex")).unwrap();
        let got = idx.advance_to(u64_of(c, "advance_to")).unwrap();
        assert_eq!(
            *got.to_bytes(),
            common::hex(c, "expected_index_hex"),
            "{}",
            name(c)
        );
    }
}

fn check_box_id(cases: &[Value]) {
    for c in cases {
        let (wc, idx) = cap_index(c);
        let ctx = common::hex(c, "ctx_hex");
        let got = if c["use_context"].as_bool().unwrap() {
            idx.box_id(&wc.read_cap(), &ctx).unwrap()
        } else {
            let root = VerifyingKey::from_bytes(
                &common::hex(c, "writecap_hex")[32..64].try_into().unwrap(),
            )
            .unwrap();
            idx.derive_box_id(&root).unwrap()
        };
        assert_eq!(got, box_id(c, "expected_box_id_hex"), "{}", name(c));
    }
}

fn check_encrypt(cases: &[Value]) {
    for c in cases {
        let (wc, idx) = cap_index(c);
        let (ctx, pt) = (common::hex(c, "ctx_hex"), common::hex(c, "plaintext_hex"));
        let (bx, ct, sig) = idx.encrypt(&wc, &ctx, &pt).unwrap();
        assert_eq!(bx, box_id(c, "expected_box_id_hex"), "{}", name(c));
        assert_eq!(ct, common::hex(c, "expected_ciphertext_hex"), "{}", name(c));
        assert_eq!(
            sig.to_vec(),
            common::hex(c, "expected_signature_hex"),
            "{}",
            name(c)
        );
        assert_eq!(
            idx.decrypt(&bx, &ctx, &ct, &sig).unwrap(),
            pt,
            "{}",
            name(c)
        );
        assert_eq!(
            idx.open(&wc.read_cap(), &ctx, &bx, &ct, &sig).unwrap(),
            pt,
            "{}",
            name(c)
        );
    }
}

fn check_mutate_kdf_state(cases: &[Value]) {
    for c in cases {
        let (wc, idx) = cap_index(c);
        let mutated = idx.mutate_kdf_state(&common::hex(c, "salt_hex"));
        assert_eq!(
            *mutated.to_bytes(),
            common::hex(c, "expected_mutated_index_hex"),
            "{}",
            name(c)
        );
        let bx = mutated
            .box_id(&wc.read_cap(), &common::hex(c, "read_ctx_hex"))
            .unwrap();
        assert_eq!(bx, box_id(c, "expected_mutated_box_id_hex"), "{}", name(c));
    }
}

fn check_layout(cases: &[Value]) {
    for c in cases {
        let bytes = common::hex(c, "writecap_hex");
        let wc = WriteCap::from_bytes(&bytes).unwrap();
        assert_eq!(*wc.to_bytes(), bytes, "{}", name(c));
        let rc = wc.read_cap();
        assert_eq!(
            rc.root_public_key().to_bytes().to_vec(),
            common::hex(c, "expected_root_public_key_hex")
        );
        let rc_bytes = rc.to_bytes();
        assert_eq!(
            *rc_bytes,
            common::hex(c, "expected_readcap_hex"),
            "{}",
            name(c)
        );
        assert_eq!(
            *ReadCap::from_bytes(&rc_bytes).unwrap().to_bytes(),
            *rc_bytes
        );
        assert_eq!(*wc.index().to_bytes(), common::hex(c, "expected_index_hex"));
        assert_eq!(
            wc.index().idx64(),
            u64_of(c, "expected_idx64"),
            "{}",
            name(c)
        );
    }
}

fn check_tombstone(cases: &[Value]) {
    for c in cases {
        let (wc, idx) = cap_index(c);
        let ctx = common::hex(c, "ctx_hex");
        let (bx, sig) = idx.tombstone(&wc, &ctx).unwrap();
        assert_eq!(bx, box_id(c, "expected_box_id_hex"), "{}", name(c));
        assert_eq!(
            sig.to_vec(),
            common::hex(c, "expected_signature_hex"),
            "{}",
            name(c)
        );
        assert!(idx.decrypt(&bx, &ctx, &[], &sig).unwrap().is_empty());
        let rc = wc.read_cap();
        let pos = rc.position_at(&idx).unwrap();
        assert!(pos.open(&ctx, &bx, &[], &sig).unwrap().is_empty());
    }
}

fn check_position(cases: &[Value]) {
    for c in cases {
        let rc = ReadCap::from_bytes(&common::hex(c, "readcap_hex")).unwrap();
        let idx = MessageBoxIndex::from_bytes(&common::hex(c, "index_hex")).unwrap();
        if c["reachable"].as_bool().unwrap() {
            rc.contains(&idx).unwrap();
            assert_eq!(rc.position_at(&idx).unwrap().index(), &idx);
        } else {
            assert_eq!(
                rc.contains(&idx),
                Err(Error::IndexNotInStream),
                "{}",
                name(c)
            );
            assert!(rc.position_at(&idx).is_err(), "{}", name(c));
        }
    }
}

fn check_negative(cases: &[Value]) {
    for c in cases {
        let n = name(c);
        let hex_or_empty = |f: &str| c.get(f).map(|_| common::hex(c, f)).unwrap_or_default();
        let index = || MessageBoxIndex::from_bytes(&common::hex(c, "index_hex")).unwrap();
        let (ctx, ct, sig) = (
            hex_or_empty("ctx_hex"),
            hex_or_empty("ciphertext_hex"),
            hex_or_empty("signature_hex"),
        );
        let blob = hex_or_empty("blob_hex");
        match common::str(c, "operation") {
            "advance_index_to" => {
                assert!(index().advance_to(u64_of(c, "advance_to")).is_err(), "{n}")
            }
            "next_index" => assert!(index().next_index().is_err(), "{n}"),
            "decrypt" => {
                let (_, idx) = cap_index(c);
                let err = idx
                    .decrypt(&box_id(c, "box_id_hex"), &ctx, &ct, &sig)
                    .unwrap_err();
                let want = match common::str(c, "category") {
                    "signature_invalid" => Error::InvalidSignature,
                    "decrypt_failed" => Error::DecryptionFailed,
                    other => panic!("{n}: unknown category {other}"),
                };
                assert_eq!(err, want, "{n}");
            }
            "verify_box" => {
                assert!(
                    MessageBoxIndex::verify_box(&box_id(c, "box_id_hex"), &ct, &sig).is_err(),
                    "{n}"
                )
            }
            "open" => {
                let (wc, idx) = cap_index(c);
                let bx = box_id(c, "box_id_hex");
                assert_ne!(idx.box_id(&wc.read_cap(), &ctx).unwrap(), bx, "{n}");
                // A plain decrypt accepts the tombstone; open must not.
                assert!(idx.decrypt(&bx, &ctx, &ct, &sig).is_ok(), "{n}");
                assert_eq!(
                    idx.open(&wc.read_cap(), &ctx, &bx, &ct, &sig),
                    Err(Error::BoxMismatch),
                    "{n}"
                );
            }
            "parse_message_box_index" => {
                assert!(MessageBoxIndex::from_bytes(&blob).is_err(), "{n}")
            }
            "parse_read_cap" => assert!(ReadCap::from_bytes(&blob).is_err(), "{n}"),
            "parse_write_cap" => assert!(WriteCap::from_bytes(&blob).is_err(), "{n}"),
            other => panic!("{n}: unknown operation {other}"),
        }
    }
}

fn checker(primitive: &str) -> fn(&[Value]) {
    match primitive {
        "sha512" => check_sha512,
        "sha512_256" => check_sha512_256,
        "blake2b_512" => check_blake2b_512,
        "hkdf_blake2b" => check_hkdf_blake2b,
        "aes_gcm_siv" => check_aes_gcm_siv,
        "ed25519" => check_ed25519,
        "blinded_ed25519" => check_blinded_ed25519,
        "bacap_message_box_index" => check_message_box_index,
        "bacap_box_id" => check_box_id,
        "bacap_encrypt" => check_encrypt,
        "bacap_mutate_kdf_state" => check_mutate_kdf_state,
        "bacap_layout" => check_layout,
        "bacap_tombstone" => check_tombstone,
        "bacap_position" => check_position,
        "bacap_negative" => check_negative,
        other => panic!("no check for {other}"),
    }
}

macro_rules! vector_test {
    ($test:ident, $rel:literal, $primitive:literal) => {
        #[test]
        fn $test() {
            let Some(cases) = load($rel, $primitive) else {
                return;
            };
            assert!(!cases.is_empty());
            checker($primitive)(&cases);
        }
    };
}

vector_test!(
    aes_gcm_siv,
    "testvectors/primitives/aes_gcm_siv.json",
    "aes_gcm_siv"
);
vector_test!(
    blinded_ed25519,
    "testvectors/primitives/blinded_ed25519.json",
    "blinded_ed25519"
);
vector_test!(
    hkdf_blake2b_512,
    "testvectors/primitives/hkdf_blake2b.json",
    "hkdf_blake2b"
);
vector_test!(
    blake2b_512,
    "testvectors/primitives/blake2b_512.json",
    "blake2b_512"
);
vector_test!(ed25519, "testvectors/primitives/ed25519.json", "ed25519");
vector_test!(
    message_box_index,
    "testvectors/bacap/message_box_index.json",
    "bacap_message_box_index"
);
vector_test!(
    box_id_derivation,
    "testvectors/bacap/box_id.json",
    "bacap_box_id"
);
vector_test!(encrypt, "testvectors/bacap/encrypt.json", "bacap_encrypt");
vector_test!(
    mutate_kdf_state,
    "testvectors/bacap/mutate_kdf_state.json",
    "bacap_mutate_kdf_state"
);
vector_test!(layout, "testvectors/bacap/layout.json", "bacap_layout");
vector_test!(
    tombstone,
    "testvectors/bacap/tombstone.json",
    "bacap_tombstone"
);
vector_test!(
    position,
    "testvectors/bacap/position.json",
    "bacap_position"
);
vector_test!(
    negative,
    "testvectors/bacap/negative.json",
    "bacap_negative"
);

#[test]
fn bundle() {
    let Some(v) = common::load("testvectors/bacap/bundle.json") else {
        return;
    };
    assert_eq!(v["format_version"], 1);
    assert_eq!(v["bundle"], "bacap");
    let sections = v["sections"].as_array().unwrap();
    assert!(!sections.is_empty());
    for s in sections {
        let cases = common::cases(s);
        assert!(!cases.is_empty());
        checker(common::str(s, "primitive"))(cases);
    }
}

// The generator over inputs.json, as py/hpqc/bacap/gen_vectors.py: every
// committed BACAP file must be what the inputs generate.

fn spec_bytes(spec: &Value) -> Vec<u8> {
    if spec.is_null() {
        return Vec::new();
    }
    if let Some(h) = spec.get("hex") {
        return hex::decode(h.as_str().unwrap()).unwrap();
    }
    if let Some(s) = spec.get("utf8") {
        return s.as_str().unwrap().as_bytes().to_vec();
    }
    if let Some(r) = spec.get("repeat") {
        return vec![u64_of(r, "byte") as u8; u64_of(r, "count") as usize];
    }
    if let Some(d) = spec.get("derive") {
        return vector_seed(
            common::str(d, "label"),
            common::str(d, "name"),
            u64_of(d, "length") as usize,
        );
    }
    panic!("bad bytes spec {spec}");
}

fn build_cap(spec: &Value) -> WriteCap {
    let seed: [u8; 32] = spec_bytes(&spec["seed"]).try_into().unwrap();
    let mut bytes = SigningKey::from_bytes(&seed).to_keypair_bytes().to_vec();
    if !spec["index"].is_null() {
        bytes.extend(spec_bytes(&spec["index"]));
        return WriteCap::from_bytes(&bytes).unwrap();
    }
    let start = &spec["start_idx64"];
    let start = match start.get("irwin_hall") {
        None => start.as_u64().unwrap(),
        Some(h) => {
            let mut b = spec_bytes(h);
            b[7] &= 0x3f;
            b[15] &= 0x3f;
            let half = |r: &[u8]| u64::from_le_bytes(r.try_into().unwrap());
            half(&b[..8]).wrapping_add(half(&b[8..16]))
        }
    };
    let mut seed_index = start.to_le_bytes().to_vec();
    seed_index.extend([0; 64]);
    seed_index.extend(spec_bytes(&spec["hkdf_state"]));
    let first = MessageBoxIndex::from_bytes(&seed_index)
        .unwrap()
        .next_index()
        .unwrap();
    bytes.extend(first.to_bytes().iter());
    WriteCap::from_bytes(&bytes).unwrap()
}

fn h(b: &[u8]) -> Value {
    Value::String(hex::encode(b))
}

fn with_hkdf_state(idx: &MessageBoxIndex, f: impl FnOnce(&mut [u8])) -> MessageBoxIndex {
    let mut b = idx.to_bytes();
    f(&mut b[72..]);
    MessageBoxIndex::from_bytes(&b).unwrap()
}

fn with_idx64(idx: &MessageBoxIndex, idx64: u64) -> MessageBoxIndex {
    let mut b = idx.to_bytes();
    b[..8].copy_from_slice(&idx64.to_le_bytes());
    MessageBoxIndex::from_bytes(&b).unwrap()
}

fn generate_section(file: &str, inputs: &Value, cap: &dyn Fn(&Value) -> WriteCap) -> Vec<Value> {
    let entries = inputs[file].as_array().unwrap();
    entries
        .iter()
        .map(|v| {
            let by = v.get("advance_by").and_then(Value::as_u64).unwrap_or(0);
            match file {
                "message_box_index" => {
                    let idx = cap(v).index().clone();
                    json!({"name": v["name"], "initial_index_hex": h(&idx.to_bytes()),
                           "advance_to": idx.idx64() + by,
                           "expected_index_hex": h(&advanced(&idx, by).to_bytes())})
                }
                "box_id" => {
                    let wc = cap(v);
                    let idx = advanced(wc.index(), by);
                    let ctx = spec_bytes(&v["ctx"]);
                    let use_ctx = v["use_context"].as_bool().unwrap();
                    let bx = if use_ctx {
                        idx.box_id(&wc.read_cap(), &ctx).unwrap()
                    } else {
                        idx.derive_box_id(&wc.root_public_key()).unwrap()
                    };
                    json!({"name": v["name"], "writecap_hex": h(&wc.to_bytes()), "advance_by": by,
                           "ctx_hex": h(&ctx), "use_context": use_ctx, "expected_box_id_hex": h(&bx)})
                }
                "encrypt" => {
                    let wc = cap(v);
                    let idx = advanced(wc.index(), by);
                    let (ctx, pt) = (spec_bytes(&v["ctx"]), spec_bytes(&v["plaintext"]));
                    let (bx, ct, sig) = idx.encrypt(&wc, &ctx, &pt).unwrap();
                    json!({"name": v["name"], "writecap_hex": h(&wc.to_bytes()), "advance_by": by,
                           "ctx_hex": h(&ctx), "plaintext_hex": h(&pt), "expected_box_id_hex": h(&bx),
                           "expected_ciphertext_hex": h(&ct), "expected_signature_hex": h(&sig)})
                }
                "mutate_kdf_state" => {
                    let wc = cap(v);
                    let (salt, rctx) = (spec_bytes(&v["salt"]), spec_bytes(&v["read_ctx"]));
                    let m = advanced(wc.index(), by).mutate_kdf_state(&salt);
                    json!({"name": v["name"], "writecap_hex": h(&wc.to_bytes()), "advance_by": by,
                           "salt_hex": h(&salt), "read_ctx_hex": h(&rctx),
                           "expected_mutated_index_hex": h(&m.to_bytes()),
                           "expected_mutated_box_id_hex": h(&m.box_id(&wc.read_cap(), &rctx).unwrap())})
                }
                "layout" => {
                    let wc = cap(v);
                    let rc = wc.read_cap();
                    json!({"name": v["name"], "writecap_hex": h(&wc.to_bytes()),
                           "expected_root_public_key_hex": h(rc.root_public_key().as_bytes()),
                           "expected_readcap_hex": h(&rc.to_bytes()),
                           "expected_index_hex": h(&wc.index().to_bytes()), "expected_idx64": wc.index().idx64()})
                }
                "tombstone" => {
                    let wc = cap(v);
                    let ctx = spec_bytes(&v["ctx"]);
                    let (bx, sig) = advanced(wc.index(), by).tombstone(&wc, &ctx).unwrap();
                    json!({"name": v["name"], "writecap_hex": h(&wc.to_bytes()), "advance_by": by,
                           "ctx_hex": h(&ctx), "expected_box_id_hex": h(&bx), "expected_signature_hex": h(&sig)})
                }
                "position" => {
                    let wc = cap(v);
                    let mut rc = wc.read_cap();
                    let start = wc.index();
                    let idx = match common::str(v, "kind") {
                        "advance" => advanced(start, by),
                        "foreign" => {
                            let other = cap(&json!({"cap": v["other_cap"]}));
                            let offset = v["idx64_offset"].as_u64().unwrap();
                            with_idx64(other.index(), start.idx64() + offset)
                        }
                        "mutated" => advanced(&start.mutate_kdf_state(&spec_bytes(&v["salt"])), by),
                        "tampered" => {
                            assert_eq!(v["field"], "hkdf_state");
                            let (i, x) = (u64_of(v, "byte") as usize, u64_of(v, "xor") as u8);
                            with_hkdf_state(&advanced(start, by), |s| s[i] ^= x)
                        }
                        "behind" => {
                            rc = rc.with_index(&advanced(start, u64_of(v, "rebase_advance_by")));
                            start.clone()
                        }
                        other => panic!("unknown position kind {other}"),
                    };
                    json!({"name": v["name"], "readcap_hex": h(&rc.to_bytes()), "index_hex": h(&idx.to_bytes()),
                           "reachable": rc.contains(&idx).is_ok(), "description": v["description"]})
                }
                "negative" => generate_negative(v, cap),
                other => panic!("unknown file {other}"),
            }
        })
        .collect()
}

fn generate_negative(v: &Value, cap: &dyn Fn(&Value) -> WriteCap) -> Value {
    let mut n = Map::new();
    for k in ["name", "operation", "category", "description"] {
        n.insert(k.into(), v[k].clone());
    }
    n.insert("advance_by".into(), json!(0));
    let mut put = |k: &str, val: Value| {
        if val != json!("") {
            n.insert(k.into(), val);
        }
    };
    match common::str(v, "operation") {
        "advance_index_to" => {
            let idx = cap(v).index().clone();
            put("index_hex", h(&idx.to_bytes()));
            put("advance_to", json!(idx.idx64() - u64_of(v, "rewind_by")));
        }
        "next_index" => {
            let idx = advanced(cap(v).index(), u64_of(v, "index_advance_by"));
            put("index_hex", h(&idx.to_bytes()));
        }
        op @ ("decrypt" | "verify_box" | "open") => {
            let wc = cap(v);
            let src = &v["source"];
            let sidx = advanced(wc.index(), u64_of(src, "advance_by"));
            let (bx, mut ct, mut sig) = match common::str(src, "kind") {
                "encrypt" => {
                    let (bx, ct, sig) = sidx
                        .encrypt(
                            &wc,
                            &spec_bytes(&src["ctx"]),
                            &spec_bytes(&src["plaintext"]),
                        )
                        .unwrap();
                    (bx, ct, sig.to_vec())
                }
                "tombstone" => {
                    let (bx, sig) = sidx.tombstone(&wc, &spec_bytes(&src["ctx"])).unwrap();
                    (bx, Vec::new(), sig.to_vec())
                }
                other => panic!("unknown source kind {other}"),
            };
            if let Some(flip) = v.get("flip").filter(|f| !f.is_null()) {
                let i = u64_of(flip, "byte") as usize;
                match common::str(flip, "field") {
                    "ciphertext" => ct[i] ^= 1,
                    "signature" => sig[i] ^= 1,
                    other => panic!("unknown flip field {other}"),
                }
            }
            let by = u64_of(v, "advance_by");
            let ctx = spec_bytes(v.get("ctx").unwrap_or(&Value::Null));
            if op == "open" {
                let idx = advanced(wc.index(), by);
                assert!(idx.open(&wc.read_cap(), &ctx, &bx, &ct, &sig).is_err());
            }
            put("writecap_hex", h(&wc.to_bytes()));
            put("advance_by", json!(by));
            put("ctx_hex", h(&ctx));
            put("box_id_hex", h(&bx));
            put("ciphertext_hex", h(&ct));
            put("signature_hex", h(&sig));
        }
        _ => {
            let blob = &v["blob"];
            let wc = cap(blob);
            let mut b: Vec<u8> = match common::str(blob, "from") {
                "index" => wc.index().to_bytes().to_vec(),
                "readcap" => wc.read_cap().to_bytes().to_vec(),
                "writecap" => wc.to_bytes().to_vec(),
                other => panic!("unknown blob source {other}"),
            };
            let e = &blob["edit"];
            match common::str(e, "kind") {
                "empty" => b.clear(),
                "truncate" => b.truncate(b.len() - u64_of(e, "count") as usize),
                "append_zero" => b.extend(vec![0; u64_of(e, "count") as usize]),
                "replace" => {
                    let w = match e.get("public_key_of").and_then(Value::as_str) {
                        Some(other) => cap(&json!({"cap": other}))
                            .root_public_key()
                            .to_bytes()
                            .to_vec(),
                        None => spec_bytes(&e["bytes"]),
                    };
                    let off = u64_of(e, "offset") as usize;
                    b[off..off + w.len()].copy_from_slice(&w);
                }
                other => panic!("unknown blob edit {other}"),
            }
            put("blob_hex", h(&b));
        }
    }
    Value::Object(n)
}

#[test]
fn inputs_generate_committed_files() {
    let Some(inputs) = common::load("testvectors/bacap/inputs.json") else {
        return;
    };
    let caps: Vec<(String, WriteCap)> = inputs["caps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (name(c).to_string(), build_cap(c)))
        .collect();
    let cap = |v: &Value| -> WriteCap {
        let want = common::str(v, "cap");
        caps.iter().find(|(n, _)| n == want).unwrap().1.clone()
    };
    let files = inputs["files"].as_object().unwrap();
    assert_eq!(files.len(), 8);
    for (file, meta) in files {
        let generated = json!({
            "format_version": 1,
            "generator": "github.com/katzenpost/hpqc/testvectors/cmd/generate",
            "primitive": meta["primitive"],
            "description": meta["description"],
            "vectors": generate_section(file, &inputs, &cap),
        });
        let committed = common::load(&format!("testvectors/bacap/{file}.json")).unwrap();
        assert_eq!(
            generated, committed,
            "{file}.json differs from what inputs.json generates"
        );
    }
}
