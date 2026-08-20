Test

# Breaking changes

1. **BACAP nonce 16 → 12 bytes.** `bacap.MessageBoxIndex.{Encrypt,Decrypt}ForContext` now feeds RFC 8452-compliant 12-byte nonces (`mICtx[:12]`) to AES-256-GCM-SIV. Old ciphertexts no longer decrypt. See [#96](https://github.com/katzenpost/hpqc/issues/96).

2. **`kem/combiner` SplitPRF construction.** The combiner now uses BLAKE2b-256 in keyed mode as the per-component PRF, with the key derived from the shared secret via an unkeyed BLAKE2b-256 hash:

	`key_i  := BLAKE2b-256(ss_i)`
	`hash_i := BLAKE2b-256(key=key_i, msg="splitprf-v1" || u32be(n) || u32be(len(cct_j)) || cct_j …)`
	`return hash_1 XOR … XOR hash_n`

   Every hybrid KEM in `kem/schemes` (MLKEM768-X25519, MLKEM768-X448, Kyber768-X25519, the McEliece+X25519 family, Frodo640-SHAKE-X448, sntrup4591761-X448, CTIDH512-X25519, CTIDH1024-X448) produces a different shared secret for the same inputs. The legacy `kem/hybrid` package was removed; Kyber768-X25519 is now built via `kem/combiner` like the others.
