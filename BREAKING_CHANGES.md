# Breaking changes

1. **BACAP nonce 16 → 12 bytes.** `bacap.MessageBoxIndex.{Encrypt,Decrypt}ForContext` now feeds RFC 8452-compliant 12-byte nonces (`mICtx[:12]`) to AES-256-GCM-SIV. Old ciphertexts no longer decrypt. See [#96](https://github.com/katzenpost/hpqc/issues/96).

2. **`kem/combiner` SplitPRF construction.** The combiner now uses BLAKE2b-256 in keyed mode as the per-component PRF, with the key derived from the shared secret via an unkeyed BLAKE2b-256 hash:

	`key_i  := BLAKE2b-256(ss_i)`
	`hash_i := BLAKE2b-256(key=key_i, msg="splitprf-v1" || u32be(n) || u32be(len(cct_j)) || cct_j …)`
	`return hash_1 XOR … XOR hash_n`

   Every hybrid KEM in `kem/schemes` (MLKEM768-X25519, MLKEM768-X448, Kyber768-X25519, the McEliece+X25519 family, Frodo640-SHAKE-X448, sntrup4591761-X448, CTIDH512-X25519, CTIDH1024-X448) produces a different shared secret for the same inputs. The legacy `kem/hybrid` package was removed; Kyber768-X25519 is now built via `kem/combiner` like the others.

3. **BACAP `StatefulReader` and `StatefulWriter` removed.** Use positions (`ReadPosition`, `WritePosition`), which bind a capability to one box on its stream, so a capability can't be paired with another stream's index. The Python port's `hpqc.bacap.StatefulReader`/`StatefulWriter` are removed too.

   | Old | New |
   |---|---|
   | `NewStatefulReader(readCap, ctx)` | `readCap.Start()` |
   | `NewStatefulReaderWithIndex(readCap, ctx, idx)` | `readCap.PositionAt(idx)`, which also checks `idx` is on the cap's stream |
   | `StatefulReader.NextBoxID()` | `ReadPosition.BoxID(ctx)` |
   | `StatefulReader.DecryptNext(ctx, box, ct, sig)` | `ReadPosition.Open(ctx, box, ct, sig)`, then `Next()` |
   | `NewStatefulWriter(writeCap, ctx)` | `writeCap.Start()` |
   | `NewStatefulWriterWithIndex(writeCap, ctx, idx)` | `writeCap.PositionAt(idx)` |
   | `StatefulWriter.NextBoxID()` | `WritePosition.BoxID(ctx)` |
   | `StatefulWriter.PrepareNext(pt)` | `WritePosition.Encrypt(ctx, pt)` |
   | `StatefulWriter.AdvanceState()` | `WritePosition.Next()` |
   | `StatefulWriter.EncryptNext(pt)` | `WritePosition.Encrypt(ctx, pt)`, then `Next()` |
   | `GetCurrentMessageIndex()` / `GetNextMessageIndex()` | `Index()` on the position, or on its `Next()` |
   | `NewStatefulReaderFromBytes`, `NewStatefulWriterFromBytes` | `UnmarshalReadPosition`, `UnmarshalWritePosition` |

   A stateful type was stored as a CBOR blob; a position is stored as its capability's bytes followed by its index (`MarshalBinary`). To migrate stored state, decode each old blob with hpqc v0.0.90 (`NewStatefulReaderFromBytes`, `NewStatefulWriterFromBytes`) and keep its capability and next index; with this release, `PositionAt` turns those into a position. Code that keeps its own indexes can use the stateless methods on `MessageBoxIndex` (`EncryptForContext`, `OpenForContext`, `NextIndex`), checking an index from outside with `ReadCap.Contains` or `WriteCap.Contains`.
