# hpqc

Hybrid post-quantum cryptography for Rust: KEM, NIKE and signature schemes
behind object-safe traits, so they can be composed and selected at runtime.

- `nike`: X25519, X448, and a hybrid of any two NIKEs.
- `kem`: ML-KEM-512/768/1024 and their hedged variants, Classic McEliece,
  any NIKE as a KEM (hashed ElGamal), and a combiner of any number of KEMs.
- `sign`: Ed25519, ML-DSA-44/65/87, and a hybrid of any two signature schemes.

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

Encodings are byte compatible with the Go reference implementation,
[github.com/katzenpost/hpqc](https://github.com/katzenpost/hpqc), and are
checked against its shared test vectors.

## License

AGPL-3.0-only
