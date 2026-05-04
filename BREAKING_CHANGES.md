# Breaking changes

1. **BACAP nonce 16 → 12 bytes.** `bacap.MessageBoxIndex.{Encrypt,Decrypt}ForContext` now feeds RFC 8452-compliant 12-byte nonces (`mICtx[:12]`) to AES-256-GCM-SIV. Old ciphertexts no longer decrypt. See [#96](https://github.com/katzenpost/hpqc/issues/96).

2. **`kem/combiner` SplitPRF input encoding.** The combiner now hashes a domain-separated, length-prefixed transcript:

	`BLAKE2b-256("splitprf-v1" || u32be(len(ss_i)) || ss_i || u32be(n) || u32be(len(cct_j)) || cct_j …)`

   Every hybrid KEM in `kem/schemes` (MLKEM768-X25519, MLKEM768-X448, Kyber768-X25519, the McEliece+X25519 family, Frodo640-SHAKE-X448, sntrup4591761-X448, CTIDH512-X25519, CTIDH1024-X448) produces a different shared secret for the same inputs. The legacy `kem/hybrid` package was removed; Kyber768-X25519 is now built via `kem/combiner` like the others.
