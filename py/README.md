# hpqc (Python)

A Python port of selected primitives from
[katzenpost/hpqc](https://github.com/katzenpost/hpqc), the hybrid
post-quantum cryptography library used by the Katzenpost mix
network. The Go implementation is the reference; this Python
package mirrors the parts needed to build a Pigeonhole-compatible
thin client end-to-end.

For the broader project context, the full set of NIKE, KEM, and
signature schemes that hpqc implements, and the design rationale
behind BACAP, please see the
[main repository README](https://github.com/katzenpost/hpqc#readme).


## What is ported

* **BACAP** (`hpqc.bacap`): blinding-and-capability scheme. Stateless
  API (immutable `MessageBoxIndex`, `WriteCap`, `ReadCap`) plus
  stateful reader/writer wrappers. Encrypt, decrypt, sign, verify,
  and tombstones are all covered.
* **MKEM** (`hpqc.kem.mkem`): multi-recipient KEM construction over
  any NIKE.
* **NIKE abstractions** (`hpqc.nike.scheme`): `Scheme`, `PublicKey`,
  `PrivateKey` base classes mirroring the Go interfaces.
* **NIKE primitives**: X25519 (`hpqc.nike.x25519`), CTIDH at field
  sizes 511, 512, 1024, and 2048 (`hpqc.nike.ctidh{511,512,1024,2048}`,
  via the upstream `highctidh` package), and a generic `HybridNIKE`
  combiner (`hpqc.nike.hybrid`).
* **Ed25519 signing** (`hpqc.sign.ed25519`), including the blinded
  Ed25519 variant on which BACAP relies.

The Python and Go test suites read the same JSON vector files via
per-file symlinks under `tests/.../vectors/`, so any byte-level
divergence between the two ports trips a failing assertion on
whichever side runs first.


## Installation

The package is not yet published to PyPI. Until it is, install from
a checkout:

```bash
pip install -e /path/to/hpqc/py
```

Once published:

```bash
pip install hpqc
```

Runtime dependencies (`pynacl`, `cryptography`, `cbor2`,
`highctidh`) are pulled in automatically.


## Quick start

A BACAP round-trip:

```python
from hpqc.bacap import WriteCap

writer = WriteCap.generate()
reader = writer.read_cap()
ctx = b"my-application/v1"

mbi = writer.first_message_box_index
box_id, ciphertext, signature = mbi.encrypt_for_context(
    writer, ctx, b"hello, pigeonhole"
)

# Anyone holding the read cap can verify and decrypt:
plaintext = mbi.decrypt_for_context(box_id, ctx, ciphertext, signature)
assert plaintext == b"hello, pigeonhole"
```

Encapsulating a payload to multiple recipients with MKEM:

```python
from hpqc.kem.mkem import MKEMScheme
from hpqc.nike.x25519 import X25519

mkem = MKEMScheme(X25519())
alice_pk, alice_sk = mkem.generate_keypair()
bob_pk,   bob_sk   = mkem.generate_keypair()

eph_priv, ct = mkem.encapsulate([alice_pk, bob_pk], b"secret payload")
assert mkem.decapsulate(alice_sk, ct) == b"secret payload"
assert mkem.decapsulate(bob_sk,   ct) == b"secret payload"
```


## Running the tests

```bash
cd hpqc/py
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest
```

Cross-language vector tests live under `tests/bacap/`, `tests/kem/`,
and `tests/sign/`. They symlink into the canonical JSON vectors under
`../testvectors/`, which the Go test suite also consumes.


## License

AGPL-3.0-only. See [LICENSE](LICENSE).


## See also

* [Main repository README](https://github.com/katzenpost/hpqc#readme) — full Go reference, design notes, and tables of every NIKE, KEM, and signature scheme that hpqc implements.
* [Echomix paper](https://arxiv.org/abs/2501.02933) — the design of BACAP (§4) and Pigeonhole (§5).
* [Katzenpost mix network](https://katzenpost.network/) — the system this library serves.
