# Breaking changes

1. **BACAP nonce 16 → 12 bytes.** `bacap.MessageBoxIndex.{Encrypt,Decrypt}ForContext` now feeds RFC 8452-compliant 12-byte nonces (`mICtx[:12]`) to AES-256-GCM-SIV. Old ciphertexts no longer decrypt. See [#96](https://github.com/katzenpost/hpqc/issues/96).

2. **`hybrid.CTIDH1024X25519` field order swap.** Wire layout is now `ctidh1024 || x25519`, matching the name. `CTIDH511X25519`, `CTIDH512X25519`, and `CTIDH512X448` retain their mislabelled order pending a future rename.

3. **`util.SplitPRF` input encoding.** Inputs are now domain-separated and length-prefixed:

	`BLAKE2b-256("splitprf-v1" || u32be(len(ss_i)) || ss_i || u32be(n) || u32be(len(cct_j)) || cct_j …)`

   Every shared key produced by `kem/combiner` and `kem/hybrid` changes.
