mod common;

use hpqc::hash::{Blake2Xb, blake2b_256};

#[test]
fn blake2b_256_matches_go() {
    let Some(v) = common::load("testvectors/primitives/blake2b_256.json") else {
        return;
    };
    for c in common::cases(&v) {
        let digest = blake2b_256(&common::hex(c, "key_hex"), &common::hex(c, "msg_hex"));
        assert_eq!(
            digest.to_vec(),
            common::hex(c, "digest_hex"),
            "{}",
            common::str(c, "name")
        );
    }
}

#[test]
fn blake2xb_matches_go() {
    let Some(v) = common::load("testvectors/primitives/blake2b_xof.json") else {
        return;
    };
    for c in common::cases(&v) {
        let size = match c["xof_size"].as_u64().unwrap() {
            0 => None,
            n => Some(n as u32),
        };
        let mut xof = Blake2Xb::new(size, &common::hex(c, "key_hex")).unwrap();
        xof.update(&common::hex(c, "msg_hex"));
        let mut out = vec![0; c["length"].as_u64().unwrap() as usize];
        xof.finalize_xof().read(&mut out);
        assert_eq!(out, common::hex(c, "out_hex"), "{}", common::str(c, "name"));
    }
}
