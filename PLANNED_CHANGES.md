# Planned changes

Changes we intend to make in a later release, so that applications can
prepare. Nothing here has happened yet; when a change lands, it moves to
[BREAKING_CHANGES.md](BREAKING_CHANGES.md).

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
