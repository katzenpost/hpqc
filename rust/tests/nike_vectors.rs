mod common;

use hpqc::nike::schemes;

#[test]
fn nike_schemes_match_go() {
    let Some(v) = common::load("testvectors/nike/schemes.json") else {
        return;
    };
    for c in common::cases(&v) {
        let name = common::str(c, "name");
        let scheme = schemes::by_name(common::str(c, "scheme")).unwrap();
        let alice = scheme
            .private_key_from_bytes(&common::hex(c, "alice_private_key_hex"))
            .unwrap();
        let bob = scheme
            .private_key_from_bytes(&common::hex(c, "bob_private_key_hex"))
            .unwrap();
        let factor = scheme
            .private_key_from_bytes(&common::hex(c, "blinding_factor_hex"))
            .unwrap();

        assert_eq!(
            *alice.to_bytes(),
            common::hex(c, "alice_private_key_hex"),
            "{name}"
        );
        assert_eq!(
            alice.public_key().to_bytes(),
            common::hex(c, "alice_public_key_hex"),
            "{name}"
        );
        assert_eq!(
            bob.public_key().to_bytes(),
            common::hex(c, "bob_public_key_hex"),
            "{name}"
        );

        let bob_pk = scheme
            .public_key_from_bytes(&common::hex(c, "bob_public_key_hex"))
            .unwrap();
        let ss = scheme.shared_secret(&*alice, &*bob_pk).unwrap();
        assert_eq!(*ss, common::hex(c, "shared_secret_hex"), "{name}");

        let blinded = scheme.blind(&*alice.public_key(), &*factor).unwrap();
        assert_eq!(
            blinded.to_bytes(),
            common::hex(c, "blinded_alice_public_key_hex"),
            "{name}"
        );
    }
}
