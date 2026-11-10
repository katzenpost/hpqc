# hpqc

Hybrid post-quantum cryptography for Rust: KEM, NIKE and signature schemes
behind object-safe traits, so they can be composed and selected at runtime.

- `nike`: X25519, X448, CTIDH-1024 (highctidh, through the
  [highctidh-rs](https://github.com/katzenpost/highctidh-rs) crate, so a C
  compiler is needed), and a hybrid of any two NIKEs.
- `kem`: ML-KEM-512/768/1024 and their hedged variants, Classic McEliece,
  any NIKE as a KEM (hashed ElGamal), and a combiner of any number of KEMs.
- `sign`: Ed25519, ML-DSA-44/65/87, a hybrid of any two signature schemes,
  and Ed25519 key blinding.
- `bacap`: BACAP, the blinded capability scheme of
  [Echomix](https://arxiv.org/abs/2501.02933) section 4.
- `protocols`: the sealed box and MKEM over any NIKE.
- `voucher`: the Contact Voucher, how a newcomer joins a Pigeonhole group.

## Features

The crate is `no_std` with `alloc`, and takes its randomness from the RNG the
caller passes. The default features build all of it. Without them, firmware
picks what it needs, e.g. `default-features = false, features = ["bacap",
"voucher"]`; `nike`, `sign`, `protocols` and `hash` are always built.

- `std`: the dependencies' std and default features.
- `bacap`, `voucher`: those modules. `voucher` needs `bacap`; without
  `ctidh`, the caller supplies CTIDH-1024 to `voucher::Vouchers::new`.
- `kem`: the `kem` module.
- `ctidh`: CTIDH-1024 and its hybrids, through highctidh-rs and
  highctidh's C library.
- `mceliece`: Classic McEliece, which needs `std`.

Each module has a registry that looks schemes up by name:

```rust
use hpqc::kem::schemes;
use hpqc::rand_core::UnwrapErr;

let kem = schemes::by_name("MLKEM768-X25519").unwrap();
let mut rng = UnwrapErr(getrandom::SysRng);

let private_key = kem.generate_key(&mut rng);
let (ciphertext, secret) = kem.encapsulate(&*private_key.public_key(), &mut rng)?;
assert_eq!(kem.decapsulate(&*private_key, &ciphertext)?, secret);
# Ok::<(), hpqc::Error>(())
```

Composition works the same way with schemes of your own:

```rust
use std::sync::Arc;

use hpqc::kem::{adapter::NikeKem, combiner::Combiner, mlkem::MlKem1024};
use hpqc::nike::x448::X448;

let kem = Combiner::new(
    "MLKEM1024-X448",
    vec![Arc::new(NikeKem::new(Arc::new(X448))), Arc::new(MlKem1024::new())],
)?;
# Ok::<(), hpqc::Error>(())
```

## BACAP

A `WriteCap` derives an endless stream of single-use boxes, each with its own
blinded Ed25519 key and AES-256-GCM-SIV key; its `ReadCap` derives the same
box IDs and decryption keys but cannot sign. Positions pair a cap with one box
on its own stream:

```rust
use hpqc::bacap::WriteCap;
use hpqc::rand_core::UnwrapErr;

let write_cap = WriteCap::generate(&mut UnwrapErr(getrandom::SysRng));
let read_cap = write_cap.read_cap();

let writer = write_cap.start();
let (box_id, ciphertext, signature) = writer.encrypt(b"ctx", b"hello")?;

let reader = read_cap.start();
assert_eq!(reader.box_id(b"ctx")?, box_id);
assert_eq!(reader.open(b"ctx", &box_id, &ciphertext, &signature)?, b"hello");

// An index from outside is checked against the cap's stream first.
let next = read_cap.position_at(writer.next()?.index())?;
# let _ = next;
# Ok::<(), hpqc::Error>(())
```

Encodings are byte compatible with the Go reference implementation,
[github.com/katzenpost/hpqc](https://github.com/katzenpost/hpqc), and are
checked against its shared test vectors.

## License

AGPL-3.0-only
