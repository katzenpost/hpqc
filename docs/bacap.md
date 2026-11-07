# BACAP

BACAP (blinding-and-capability) is described in section 4 of the
[Echomix paper](https://arxiv.org/abs/2501.02933); its main author is
@threebithacker. Back to the [README](../README.md). The Go API is documented
on [pkg.go.dev](https://pkg.go.dev/github.com/katzenpost/hpqc/bacap), and the
Python port (`hpqc.bacap`) has a quick start in
[py/README.md](../py/README.md).

## What it does

BACAP lets participants derive, from shared symmetric keys, a sequence of
public keys and matching encryption keys, each an independent single-use
capability. It is built on Ed25519 and relies on its blinding properties
throughout. It serves a range of capability-management applications;
Katzenpost's group chat uses it for multi-client messaging.

In a messaging system Alice uses one instance to send Bob an unbounded
sequence of messages, one per box (one public key in the sequence), and Bob
uses a second instance to send messages to Alice. Alice derives a root public
key for Bob from a root private key. The root key, and a CSPRNG built from
repeated KDF applications, yield a sequence of context-specific values for
exercising and verifying a capability. A context value `ctx`, the hash of a
universally public value, is mixed in. It can be the hash of the storage
network's name, or be bound to a period of time, such as the long-epoch SRV
the Katzenpost directory authorities publish, much as Tor uses its SRV in
onion services. The context lets messages be moved, unlinkably, to a
different network.

## Addressing boxes: positions

A box is named by a capability and a `MessageBoxIndex` together. The index
alone does not say which stream it belongs to: paired with the wrong
capability, it still derives a valid-looking box. A reader then waits
forever on a box nobody writes, a writer writes where nobody reads, and
neither sees an error.

A position is a capability bound to one box on its stream. Positions come
only from `Start`, `PositionAt` and `Next`, so a mismatched pair cannot be
built. Use them:

```go
w := writeCap.Start()                     // the first box the cap writes
box, ct, sig, err := w.Encrypt(ctx, msg)  // encrypt and sign for this box
w, err = w.Next()                         // the following box

r := readCap.Start()                      // the first box the cap reads
pt, err := r.Open(ctx, box, ct, sig)      // checks it is r's box, then decrypts
r, err = r.Next()
```

An index that arrives from outside, from storage or another process, is
checked once and then used as a position:

```go
r, err := readCap.PositionAt(idx) // ErrIndexNotInChannel unless idx is on the cap's stream
```

The capabilities and the stateless methods on `MessageBoxIndex`
(`EncryptForContext`, `OpenForContext`, `NextIndex`) remain the lower-level
API, for code that keeps its own indexes; `ReadCap.Contains` checks an index
there.

`StatefulReader` and `StatefulWriter` have been removed;
[BREAKING_CHANGES.md](../BREAKING_CHANGES.md) lists what replaces each of
their methods, and [PLANNED_CHANGES.md](../PLANNED_CHANGES.md) what may change
next.

## Contact Voucher

The `voucher` package, and `hpqc.voucher` in Python, implement the
cryptography of the Contact Voucher, which lets a newcomer and a group member
exchange BACAP read capabilities after handing over one small voucher out of
band. The two implementations agree byte for byte under shared test vectors.
