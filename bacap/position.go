// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !thinclient

package bacap

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/util"
)

// maxContainsWalk bounds how many ratchet steps Contains takes. A step
// costs a few microseconds, so this is about a second: far more boxes than
// a stream holds between rewrites, and a cap on what a hostile index can
// cost.
const maxContainsWalk = 1 << 18

var (
	// ErrIndexNotInChannel is returned when an index is not on a
	// capability's stream: stepping the capability's own index forward
	// never reaches it.
	ErrIndexNotInChannel = errors.New("bacap: index is not on this capability's stream")

	// ErrIndexTooFar is returned when an index lies further ahead of a
	// capability's own index than Contains will walk.
	ErrIndexTooFar = errors.New("bacap: index is too far ahead to check")

	// ErrEmptyBox is returned for an all-zero box ID.
	ErrEmptyBox = errors.New("bacap: empty box, no message received")

	// ErrBoxMismatch is returned when a box is not the one a capability
	// and index derive.
	ErrBoxMismatch = errors.New("bacap: box is not the one the capability and index derive")
)

// sameIndex compares every field in constant time: the fields are secret,
// so it must not stop at the first one that differs.
func sameIndex(a, b *MessageBoxIndex) bool {
	var ai, bi [8]byte
	binary.LittleEndian.PutUint64(ai[:], a.Idx64)
	binary.LittleEndian.PutUint64(bi[:], b.Idx64)
	eq := subtle.ConstantTimeCompare(ai[:], bi[:]) &
		subtle.ConstantTimeCompare(a.HKDFState[:], b.HKDFState[:]) &
		subtle.ConstantTimeCompare(a.CurBlindingFactor[:], b.CurBlindingFactor[:]) &
		subtle.ConstantTimeCompare(a.CurEncryptionKey[:], b.CurEncryptionKey[:])
	return eq == 1
}

// contains reports whether stepping start forward reaches idx.
func contains(start, idx *MessageBoxIndex) error {
	if idx == nil {
		return errors.New("bacap: nil index")
	}
	if idx.Idx64 < start.Idx64 {
		return ErrIndexNotInChannel
	}
	if idx.Idx64-start.Idx64 > maxContainsWalk {
		return ErrIndexTooFar
	}
	walked, err := start.AdvanceIndexTo(idx.Idx64)
	if err != nil {
		return err
	}
	if !sameIndex(walked, idx) {
		return ErrIndexNotInChannel
	}
	return nil
}

// Contains reports whether idx lies on this read cap's stream, by stepping
// the cap's own index forward to it. Use it on an index that comes from
// outside: one this process did not derive from the cap itself. It returns
// ErrIndexNotInChannel if idx is not on the stream (another stream's, one
// re-seeded by MutateKDFState, or one behind the cap's own index), and
// ErrIndexTooFar if it lies further ahead than Contains walks.
func (u *ReadCap) Contains(idx *MessageBoxIndex) error {
	return contains(u.messageBoxIndex, idx)
}

// Contains reports whether idx lies on this write cap's stream. See
// ReadCap.Contains.
func (o *WriteCap) Contains(idx *MessageBoxIndex) error {
	return contains(o.messageBoxIndex, idx)
}

// OpenForContext verifies and decrypts the box at this index on readCap's
// stream. Unlike DecryptForContext, it first checks that box is the one
// readCap and this index derive under ctx. That matters most for
// tombstones: a tombstone has no ciphertext to authenticate, so
// DecryptForContext alone accepts a tombstone signed for any box.
func (m *MessageBoxIndex) OpenForContext(readCap *ReadCap, ctx []byte, box [BoxIDSize]byte, ciphertext []byte, sig []byte) ([]byte, error) {
	if util.CtIsZero(box[:]) {
		return nil, ErrEmptyBox
	}
	expected, err := m.BoxIDForContext(readCap, ctx)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(box[:], expected.Bytes()) != 1 {
		return nil, ErrBoxMismatch
	}
	return m.DecryptForContext(box, ctx, ciphertext, sig)
}

// A ReadPosition is a read cap together with one box on its stream. The
// only ways to get one are ReadCap.Start, ReadCap.PositionAt, and moving an
// existing position forward, so a position never pairs a cap with an index
// from another stream.
type ReadPosition struct {
	cap   *ReadCap
	index *MessageBoxIndex
}

// A WritePosition is a write cap together with one box on its stream. See
// ReadPosition.
type WritePosition struct {
	cap   *WriteCap
	index *MessageBoxIndex
}

// Start returns the position of the cap's own index: the first box its
// holder can read.
func (u *ReadCap) Start() *ReadPosition {
	return &ReadPosition{cap: u, index: u.GetMessageBoxIndex()}
}

// Start returns the position of the cap's own index: the first box it writes.
func (o *WriteCap) Start() *WritePosition {
	return &WritePosition{cap: o, index: o.GetMessageBoxIndex()}
}

// PositionAt returns the position of idx on this cap's stream, after
// checking with Contains that idx is on it.
func (u *ReadCap) PositionAt(idx *MessageBoxIndex) (*ReadPosition, error) {
	if err := u.Contains(idx); err != nil {
		return nil, err
	}
	return &ReadPosition{cap: u, index: copyIndex(idx)}, nil
}

// PositionAt returns the position of idx on this cap's stream, after
// checking with Contains that idx is on it.
func (o *WriteCap) PositionAt(idx *MessageBoxIndex) (*WritePosition, error) {
	if err := o.Contains(idx); err != nil {
		return nil, err
	}
	return &WritePosition{cap: o, index: copyIndex(idx)}, nil
}

func copyIndex(idx *MessageBoxIndex) *MessageBoxIndex {
	c := *idx
	return &c
}

// Cap returns the position's read cap.
func (p *ReadPosition) Cap() *ReadCap { return p.cap }

// Index returns a copy of the position's index, for storing it.
func (p *ReadPosition) Index() *MessageBoxIndex { return copyIndex(p.index) }

// Next returns the position of the following box.
func (p *ReadPosition) Next() (*ReadPosition, error) {
	next, err := p.index.NextIndex()
	if err != nil {
		return nil, err
	}
	return &ReadPosition{cap: p.cap, index: next}, nil
}

// AdvanceTo returns the position of the box at Idx64 n, which must not be
// behind this one.
func (p *ReadPosition) AdvanceTo(n uint64) (*ReadPosition, error) {
	next, err := p.index.AdvanceIndexTo(n)
	if err != nil {
		return nil, err
	}
	return &ReadPosition{cap: p.cap, index: next}, nil
}

// BoxID returns the ID of the box at this position under ctx.
func (p *ReadPosition) BoxID(ctx []byte) (*ed25519.PublicKey, error) {
	return p.index.BoxIDForContext(p.cap, ctx)
}

// Open verifies and decrypts the box at this position. See
// MessageBoxIndex.OpenForContext.
func (p *ReadPosition) Open(ctx []byte, box [BoxIDSize]byte, ciphertext []byte, sig []byte) ([]byte, error) {
	return p.index.OpenForContext(p.cap, ctx, box, ciphertext, sig)
}

// Cap returns the position's write cap.
func (p *WritePosition) Cap() *WriteCap { return p.cap }

// Index returns a copy of the position's index, for storing it.
func (p *WritePosition) Index() *MessageBoxIndex { return copyIndex(p.index) }

// Next returns the position of the following box.
func (p *WritePosition) Next() (*WritePosition, error) {
	next, err := p.index.NextIndex()
	if err != nil {
		return nil, err
	}
	return &WritePosition{cap: p.cap, index: next}, nil
}

// AdvanceTo returns the position of the box at Idx64 n, which must not be
// behind this one.
func (p *WritePosition) AdvanceTo(n uint64) (*WritePosition, error) {
	next, err := p.index.AdvanceIndexTo(n)
	if err != nil {
		return nil, err
	}
	return &WritePosition{cap: p.cap, index: next}, nil
}

// BoxID returns the ID of the box at this position under ctx.
func (p *WritePosition) BoxID(ctx []byte) (*ed25519.PublicKey, error) {
	return p.index.BoxIDForContext(p.cap.ReadCap(), ctx)
}

// Encrypt encrypts and signs plaintext for the box at this position,
// returning the box ID, ciphertext and signature.
func (p *WritePosition) Encrypt(ctx []byte, plaintext []byte) ([BoxIDSize]byte, []byte, []byte, error) {
	return p.index.EncryptForContext(p.cap, ctx, plaintext)
}

// Tombstone signs the empty payload for the box at this position, returning
// the box ID and signature. Written with an empty payload, it deletes the box.
func (p *WritePosition) Tombstone(ctx []byte) ([BoxIDSize]byte, []byte, error) {
	return p.index.SignBox(p.cap, ctx, []byte{})
}

// ReadPosition returns the read position of the same box.
func (p *WritePosition) ReadPosition() *ReadPosition {
	return &ReadPosition{cap: p.cap.ReadCap(), index: copyIndex(p.index)}
}

// MarshalBinary encodes the position as its read cap followed by its index.
func (p *ReadPosition) MarshalBinary() ([]byte, error) {
	capBytes, err := p.cap.MarshalBinary()
	if err != nil {
		return nil, err
	}
	idxBytes, err := p.index.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(capBytes, idxBytes...), nil
}

// MarshalBinary encodes the position as its write cap followed by its index.
func (p *WritePosition) MarshalBinary() ([]byte, error) {
	capBytes, err := p.cap.MarshalBinary()
	if err != nil {
		return nil, err
	}
	idxBytes, err := p.index.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(capBytes, idxBytes...), nil
}

// UnmarshalReadPosition decodes a ReadPosition, checking with Contains that
// its index is on its cap's stream.
func UnmarshalReadPosition(b []byte) (*ReadPosition, error) {
	if len(b) != ReadCapSize+MessageBoxIndexSize {
		return nil, errors.New("bacap: invalid ReadPosition binary size")
	}
	cap, err := ReadCapFromBytes(b[:ReadCapSize])
	if err != nil {
		return nil, err
	}
	idx, err := NewEmptyMessageBoxIndexFromBytes(b[ReadCapSize:])
	if err != nil {
		return nil, err
	}
	return cap.PositionAt(idx)
}

// UnmarshalWritePosition decodes a WritePosition, checking with Contains that
// its index is on its cap's stream.
func UnmarshalWritePosition(b []byte) (*WritePosition, error) {
	if len(b) != WriteCapSize+MessageBoxIndexSize {
		return nil, errors.New("bacap: invalid WritePosition binary size")
	}
	cap, err := NewWriteCapFromBytes(b[:WriteCapSize])
	if err != nil {
		return nil, err
	}
	idx, err := NewEmptyMessageBoxIndexFromBytes(b[WriteCapSize:])
	if err != nil {
		return nil, err
	}
	return cap.PositionAt(idx)
}
