mod common;

use hpqc::kem::Scheme;
use hpqc::kem::mlkem::{MlKem, MlKem512, MlKem768, MlKem1024, Params};

/// NIST ACVP vectors for each parameter set, by directory.
const ACVP: [(&str, &str); 3] = [
    ("512", "testvectors/kem"),
    ("768", "kem/mlkem768/testdata"),
    ("1024", "testvectors/kem"),
];

fn scheme(size: &str, hedged: bool) -> Box<dyn Scheme> {
    match (size, hedged) {
        ("512", false) => Box::new(MlKem512::new()),
        ("768", false) => Box::new(MlKem768::new()),
        ("1024", false) => Box::new(MlKem1024::new()),
        ("512", true) => Box::new(MlKem512::hedged()),
        ("768", true) => Box::new(MlKem768::hedged()),
        ("1024", true) => Box::new(MlKem1024::hedged()),
        _ => unreachable!(),
    }
}

fn encapsulate(size: &str, hedged: bool, pk: &[u8], m: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn run<P: Params>(hedged: bool, pk: &[u8], m: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let kem = if hedged {
            MlKem::<P>::hedged()
        } else {
            MlKem::new()
        };
        let pk = kem.public_key_from_bytes(pk).unwrap();
        let (ct, ss) = kem.encapsulate_deterministic(&*pk, m).unwrap();
        (ct, ss.to_vec())
    }
    let m: &[u8; 32] = m.try_into().unwrap();
    match size {
        "512" => run::<ml_kem::MlKem512>(hedged, pk, m),
        "768" => run::<ml_kem::MlKem768>(hedged, pk, m),
        "1024" => run::<ml_kem::MlKem1024>(hedged, pk, m),
        _ => unreachable!(),
    }
}

#[test]
fn acvp_keygen() {
    for (size, dir) in ACVP {
        let Some(v) = common::load(&format!("{dir}/mlkem{size}_keygen.json")) else {
            continue;
        };
        let kem = scheme(size, false);
        for c in common::cases(&v) {
            let seed = [common::hex(c, "d_hex"), common::hex(c, "z_hex")].concat();
            let sk = kem.derive_key(&seed).unwrap();
            assert_eq!(
                sk.public_key().to_bytes(),
                common::hex(c, "ek_hex"),
                "{size} {}",
                common::str(c, "name")
            );
        }
    }
}

#[test]
fn acvp_encapsulation() {
    for (size, dir) in ACVP {
        let Some(v) = common::load(&format!("{dir}/mlkem{size}_encapdecap.json")) else {
            continue;
        };
        for c in common::cases(&v) {
            if common::str(c, "mode") != "encap" {
                continue;
            }
            let (ct, ss) = encapsulate(
                size,
                false,
                &common::hex(c, "ek_hex"),
                &common::hex(c, "m_hex"),
            );
            let name = common::str(c, "name");
            assert_eq!(ct, common::hex(c, "c_hex"), "{size} {name}");
            assert_eq!(ss, common::hex(c, "k_hex"), "{size} {name}");
        }
    }
}

#[test]
fn acvp_encapsulation_key_check() {
    for (size, dir) in ACVP {
        let Some(v) = common::load(&format!("{dir}/mlkem{size}_keycheck.json")) else {
            continue;
        };
        let kem = scheme(size, false);
        for c in common::cases(&v) {
            if common::str(c, "mode") != "checkEK" {
                continue;
            }
            let ok = kem.public_key_from_bytes(&common::hex(c, "ek_hex")).is_ok();
            assert_eq!(
                ok,
                c["want_pass"].as_bool().unwrap(),
                "{size} {}",
                common::str(c, "name")
            );
        }
    }
}

/// Hedged vectors shared with the Go and Lean implementations.
#[test]
fn hedged() {
    let files = [
        ("768", "testvectors/kem/mlkem768_hedged.json"),
        (
            "768",
            "kem/mlkem768/testdata/lean_mlkem768_hedged_vectors.json",
        ),
        ("512", "testvectors/kem/lean_mlkem512_hedged_vectors.json"),
        ("1024", "testvectors/kem/lean_mlkem1024_hedged_vectors.json"),
    ];
    for (size, file) in files {
        let Some(v) = common::load(file) else {
            continue;
        };
        let kem = scheme(size, true);
        for c in common::cases(&v) {
            let name = common::str(c, "name");
            let seed = [common::hex(c, "d_hex"), common::hex(c, "z_hex")].concat();
            let sk = kem.derive_key(&seed).unwrap();
            let ek = sk.public_key().to_bytes();
            assert_eq!(ek, common::hex(c, "encapsulation_key_hex"), "{file} {name}");

            let m = common::hex(c, "m_hex");
            let (ct, ss) = encapsulate(size, true, &ek, &m);
            assert_eq!(ct, common::hex(c, "ciphertext_hex"), "{file} {name}");
            assert_eq!(ss, common::hex(c, "shared_secret_hex"), "{file} {name}");

            // The standard scheme agrees given the pre-hashed randomness.
            let (ct2, ss2) = encapsulate(size, false, &ek, &common::hex(c, "m_hash_hex"));
            assert_eq!((ct2, ss2), (ct.clone(), ss.clone()), "{file} {name}");

            assert_eq!(*kem.decapsulate(&*sk, &ct).unwrap(), ss, "{file} {name}");
        }
    }
}
