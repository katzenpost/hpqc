# Planned changes

Changes we intend to make in a later release, so that applications can
prepare. Nothing here has happened yet; when a change lands, it moves to
[BREAKING_CHANGES.md](BREAKING_CHANGES.md).

## BACAP: remove `StatefulReader` and `StatefulWriter`

A position (`ReadPosition`, `WritePosition`) binds a capability to one box on
its stream, so a capability can no longer be paired with another stream's
index by mistake. The stateful types offer nothing positions do not, and
their constructors take a capability and an index side by side without
checking that they belong together. They are deprecated now and will be
removed once applications have moved to positions.

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

The serialized forms differ: a stateful type is a CBOR blob, a position is
its capability's bytes followed by its index. To migrate stored state, read
the old blob once with the deprecated constructor and call `PositionAt` with
its capability and next index.

Code that keeps its own indexes can use the stateless methods on
`MessageBoxIndex` instead (`EncryptForContext`, `OpenForContext`,
`NextIndex`), checking any index that arrives from outside with
`ReadCap.Contains` or `WriteCap.Contains`.

## BACAP: what stays

The capability types and the stateless methods on `MessageBoxIndex` stay as
the lower-level API. No removal is planned for them.

## BACAP: open question

`Contains` proves an index is on a capability's stream by stepping the
ratchet forward to it, a few microseconds per box. A stream re-seeded with
`MutateKDFState`, as the Contact Voucher does, cannot be reached that way at
all. A signature by the stream's owner over an index would be checked in
constant time and would cover re-seeded streams, but only the owner could
issue one, and it is a new use of the root key that needs its own security
argument. It is not planned; it is recorded here so the question is not lost.
