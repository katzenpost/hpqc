# Schemes

Every scheme registered in the Go, Python and Rust implementations, by the
name its registry accepts. Go and Rust look names up without regard to case.
Back to the [README](../README.md).

## Go

The Go registries are `nike/schemes`, `kem/schemes` and `sign/schemes`; each
has `ByName` and `All`.

### NIKE

| Primitive | Name | Security |
|---|---|---|
| X25519 | `x25519` | classic |
| X448 | `x448` | classic |
| CTIDH ([docs/ctidh.md](ctidh.md)) | `ctidh511`, `ctidh512`, `ctidh1024`, `ctidh2048` | post-quantum |
| CTIDH with X25519 | `CTIDH512-X25519`, `X25519-CTIDH1024` | hybrid |
| CTIDH with X448 | `CTIDH512-X448`, `CTIDH1024-X448`, `CTIDH2048-X448` | hybrid |

`CTIDH1024-X25519` is the legacy name of `X25519-CTIDH1024`. Both have the
same wire layout, X25519 first; new code should use `X25519-CTIDH1024`, whose
name matches it.

The classical Diffie-Hellman group in `nike/diffiehellman` (MODP4096 from
RFC 3526) implements the NIKE interface but is not registered.

### KEM

| Primitive | Name | Security |
|---|---|---|
| ML-KEM (FIPS 203) | `MLKEM512`, `MLKEM768`, `MLKEM1024` | post-quantum |
| Hedged ML-KEM: ML-KEM with round-3 Kyber's m ← H(m) pre-hash restored, as a hedge against a weak RNG. Not FIPS 203. `MLKEMHedged768` matches [Cryptlib](https://github.com/katzenpost/cryptlib)'s verified implementation. | `MLKEMHedged512`, `MLKEMHedged768`, `MLKEMHedged1024` | post-quantum |
| HQC, the three NIST parameter sets | `HQC-128`, `HQC-192`, `HQC-256` | post-quantum |
| FrodoKEM-640-SHAKE | `FrodoKEM-640-SHAKE` | post-quantum |
| Classic McEliece | `mceliece348864`, `mceliece348864f`, `mceliece460896`, `mceliece460896f`, `mceliece6688128`, `mceliece6688128f`, `mceliece6960119`, `mceliece6960119f`, `mceliece8192128`, `mceliece8192128f` | post-quantum |
| Streamlined NTRU Prime 4591^761 | `sntrup4591761` | post-quantum |
| X-Wing, which pre-combines ML-KEM-768 and X25519 | `XWING` | hybrid |
| ML-KEM with X25519, standard and hedged | `MLKEM512-X25519`, `MLKEMHedged512-X25519`, `MLKEM768-X25519`, `MLKEMHedged768-X25519`, `MLKEM1024-X25519`, `MLKEMHedged1024-X25519` | hybrid |
| ML-KEM-1024 with X448 | `MLKEM1024-X448` | hybrid |
| Kyber768 with X25519 | `Kyber768-X25519` | hybrid |
| HQC with X25519, and HQC-256 with X448 | `HQC-128-X25519`, `HQC-192-X25519`, `HQC-256-X25519`, `HQC-256-X448` | hybrid |
| FrodoKEM-640-SHAKE with X448 | `FrodoKEM-640-SHAKE-X448` | hybrid |
| NTRU Prime with X448 | `sntrup4591761-X448` | hybrid |
| Classic McEliece with X25519 | `mceliece348864-X25519`, `mceliece348864f-X25519`, `mceliece460896-X25519`, `mceliece460896f-X25519`, `mceliece6688128-X25519`, `mceliece6688128f-X25519`, `mceliece6960119-X25519`, `mceliece6960119f-X25519`, `mceliece8192128-X25519`, `mceliece8192128f-X25519` | hybrid |
| NIKEs through the KEM adapter | `x25519`, `x448`, `ctidh511`, `ctidh512`, `ctidh1024`, `ctidh2048`, `CTIDH512-X25519`, `CTIDH1024-X448` | as the NIKE |

Every hybrid except `XWING` is built with the KEM combiner. hpqc has its own
ML-KEM-768 and X25519 combination alongside X-Wing because of the combiner's
security property; see [docs/constructions.md](constructions.md). The
adapter and combiner also build schemes that are not registered, from any
NIKE and any set of KEMs.

### Signatures

| Primitive | Name | Security |
|---|---|---|
| Ed25519 | `Ed25519` | classic |
| Ed448 | `Ed448` | classic |
| ML-DSA (FIPS 204) | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` | post-quantum |
| SPHINCS+ SHAKE-256f | `Sphincs+` | post-quantum |
| Falcon, padded | `Falcon-padded-512`, `Falcon-padded-1024` | post-quantum |
| ML-DSA with Ed25519 | `ML-DSA-44-Ed25519`, `ML-DSA-65-Ed25519`, `ML-DSA-87-Ed25519` | hybrid |
| Dilithium2 with Ed25519, Dilithium3 with Ed448 | `Ed25519-Dilithium2`, `Ed448-Dilithium3` | hybrid |
| SPHINCS+ with Ed25519 and Ed448 | `Ed25519-Sphincs+`, `Ed448-Sphincs+` (legacy alias `Ed25519 Sphincs+`) | hybrid |
| Falcon, padded, with Ed25519 | `Falcon-padded-512-Ed25519`, `Falcon-padded-1024-Ed25519` | hybrid |

SPHINCS+ is not built on Windows, where `sphincsplus.Scheme()` returns nil.
`sign/sqisign` implements SQIsign level 1 (`SQIsign-lvl1`), and
`sign/hybrid` pairs it with Ed25519 as `SQIsign-lvl1-Ed25519`. Neither is
registered, and both build only on linux/amd64 with the `sqisign` build tag
(`go build -tags sqisign`), so nothing links the SQIsign static library unless
it asks for it.

## Python

The Python port covers a subset; anything missing here is Go only. Its
schemes are constructed directly rather than looked up by name.

| Kind | Primitive | Class | Security |
|---|---|---|---|
| NIKE | X25519 | `hpqc.nike.x25519.X25519` (`x25519`) | classic |
| NIKE | CTIDH | `hpqc.nike.ctidh511.CTIDH511`, and likewise for 512, 1024 and 2048 (`ctidh511`, ...) | post-quantum |
| NIKE | Any two NIKEs | `hpqc.nike.hybrid.HybridNIKE` | hybrid |
| Protocol | MKEM over any NIKE | `hpqc.protocols.mkem.MKEMScheme` | as the NIKE |
| Protocol | Sealed box over any NIKE | `hpqc.protocols.sealedbox.SealedBoxScheme` | as the NIKE |
| Signature | Ed25519, verify only | `hpqc.sign.ed25519.Ed25519Scheme` (`Ed25519`) | classic |
| Signature | Blinded Ed25519, sign and verify, for BACAP | `hpqc.sign.ed25519.SigningKey`, `BlindedSigningKey`, `VerifyKey` | classic |
| Signature | Falcon-padded-512, verify only | `hpqc.sign.falcon.FalconPadded512Scheme` (`Falcon-padded-512`) | post-quantum |
| Signature | Falcon-padded-512 with Ed25519, verify only | `hpqc.sign.hybrid.FalconPadded512Ed25519` (`Falcon-padded-512-Ed25519`) | hybrid |

The port also carries BACAP (`hpqc.bacap`) and the Contact Voucher
(`hpqc.voucher`). Ed25519 comes from `pynacl`. Falcon comes from `pqcrypto`,
which vendors the same PQClean C as the Go side and is an optional extra:
`pip install 'hpqc[falcon]'`. Signing and key generation for the
post-quantum schemes are Go only. See [py/README.md](../py/README.md).

## Rust

The Rust registries are `hpqc::nike::schemes`, `hpqc::kem::schemes` and
`hpqc::sign::schemes`; each has `by_name` and `all`. See
[rust/README.md](../rust/README.md).

| Kind | Names |
|---|---|
| NIKE | `x25519`, `x448` |
| KEM | `x25519`, `x448`, `MLKEM512`, `MLKEM768`, `MLKEM1024`, `MLKEMHedged512`, `MLKEMHedged768`, `MLKEMHedged1024`, each ML-KEM with `-X25519`, `MLKEM1024-X448`, the ten Classic McEliece parameter sets, each with `-X25519` |
| Signature | `Ed25519`, `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`, each ML-DSA with `-Ed25519` |

The Rust encodings are byte compatible with Go's.
