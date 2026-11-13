# Repository layout

The top-level packages are the Go reference implementation; `py/` and
`rust/` are the ports. All three read the shared vectors under
`testvectors/`. Back to the [README](../README.md).

```
hpqc/
├── nike/                    # Non-interactive key exchange
│   ├── nike.go              #   Scheme, PublicKey, PrivateKey interfaces
│   ├── x25519/, x448/
│   ├── ctidh/               #   CTIDH 511, 512, 1024, 2048 (cgo)
│   ├── hybrid/              #   two-NIKE hybrids: X25519-CTIDH1024, CTIDH1024-X448, ...
│   ├── diffiehellman/       #   classical MODP4096 DH, not registered
│   ├── pem/                 #   PEM encoding of NIKE keys
│   └── schemes/             #   ByName registry
├── kem/                     # Key encapsulation mechanisms
│   ├── interfaces.go        #   Scheme, PublicKey, PrivateKey interfaces
│   ├── mlkem768/            #   ML-KEM-768 and hedged ML-KEM-768
│   ├── mlkem/               #   ML-KEM-512 and -1024, standard and hedged
│   ├── hqc/                 #   HQC-128, -192, -256
│   ├── sntrup/              #   sntrup4591761 (NTRU Prime)
│   ├── xwing/               #   X-Wing (ML-KEM-768 with X25519)
│   ├── circlkem/            #   FrodoKEM, Classic McEliece, Kyber768 from circl
│   ├── adapter/             #   NIKE to KEM adapter (hashed ElGamal)
│   ├── combiner/            #   security-preserving KEM combiner
│   ├── pem/                 #   PEM encoding of KEM keys
│   └── schemes/             #   ByName registry
├── sign/                    # Signature schemes
│   ├── interfaces.go        #   Scheme, PublicKey, PrivateKey interfaces
│   ├── ed25519/             #   Ed25519 and blinded Ed25519
│   ├── circlsign/           #   Ed448, Ed25519-Dilithium2, Ed448-Dilithium3 from circl
│   ├── mldsa/               #   ML-DSA-44, -65, -87
│   ├── sphincsplus/         #   SPHINCS+ SHAKE-256f
│   ├── falcon/              #   Falcon-padded-512, -1024
│   ├── hybrid/              #   two-scheme hybrid signer
│   ├── pem/                 #   PEM encoding of signature keys
│   └── schemes/             #   ByName registry
├── protocols/               # Protocols over any NIKE
│   ├── mkem/                #   multi-recipient KEM
│   └── sealedbox/           #   anonymous public-key encryption to one recipient
├── bacap/                   # Blinding-and-capability scheme
├── voucher/                 # Contact Voucher cryptography, over BACAP
├── hash/                    # BLAKE2b-256 helpers
├── rand/                    # CSPRNG and deterministic test reader
├── util/                    # constant-time zero check, explicit bzero, PEM helpers
├── examples/                # nike_and_cipher, kem_and_cipher
├── py/                      # Python port ("hpqc" on PyPI)
│   ├── hpqc/                #   bacap, nike, protocols, sign, voucher, hash
│   └── tests/               #   pytest suites, with copies of the shared vectors
├── rust/                    # Rust port (crate "hpqc")
│   ├── src/                 #   hash, kem, nike, sign
│   └── tests/               #   tests against the shared vectors
├── testvectors/             # Cross-language test vectors and their generator
├── debian/, packaging/      # Debian packages and their build containers
├── misc/                    # Debian Go dependency installer for CI
├── BREAKING_CHANGES.md      # API-breaking changes and what replaces them
└── PLANNED_CHANGES.md       # changes planned for a later release
```
