// SPDX-FileCopyrightText: © 2025 Katzenpost dev team
// SPDX-License-Identifier: AGPL-3.0-only

// bacap package provides the Blinded Cryptographic Capability system
package bacap

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"github.com/agl/gcmsiv"

	"github.com/katzenpost/hpqc/sign/ed25519"
)

/*
   BACAP
   =====

   BACAP is the Blinded Cryptographic Capability system with
   some resistance against quantum adversaries whose design
   is expounded upon in section 4 of our paper:

   "BACAP (Blinding-and-Capability scheme) allows us
   to deterministically derive a sequence of key pairs using
   blinding, built upon Ed25519, and suitable for un-
   linkable messaging. It enables participants to derive box
   IDs and corresponding encryption keys for independent,
   single-use boxes using shared symmetric keys.

   A box consists of an ID, a message payload, and a
   signature over the payload. There are two basic capabili-
   ties - one that lets a party derive the box IDs and decrypt
   the messages, and one that additionally lets the holder
   derive private keys to sign the messages. The signatures
   are universally veriﬁable, as the box ID for each box
   doubles as the public key for the signatures.

   In the context of a messaging system, the protocol is
   used by Alice to send an inﬁnite sequence of messages
   to Bob, one per box, with Bob using a separate, second
   instance of the protocol to send messages to Alice.
   "

   **our paper**

   Echomix: a Strong Anonymity System with Messaging

   https://arxiv.org/abs/2501.02933
   https://arxiv.org/pdf/2501.02933

   ** API design **

   Two Capability types:

   1. UniversalReadCap: The Universal Read Capability allows the bearer
   to generate an infinite sequence of verification and decryption keys
   for message boxes in a deterministic sequence.

   2. BoxOwnerCap: The Message Box Owner Capability allows the bearer to
   generate an infinite sequence of signing and encryption keys for
   messages boxes in a deterministic sequence.

   Each of the above two capabilities are used with the MessageBoxIndex
   to perform their respective encrypt and sign vs verify and decrypt operations.

   Beyond that we have two high level types: StatefulReader and StatefulWriter
   which encapsulate all the operational details of advancing state
   after message processing.


   **TODOs**

   This BACAP implementation could possibly be improved, here's a ticket for
   completing the TODO tasks written by it's original author:

   https://github.com/katzenpost/hpqc/issues/55
*/

// MessageBoxIndexSize is the size in bytes of one MessageBoxIndex struct.
const MessageBoxIndexSize = 8 + 32 + 32 + 32

// MessageBoxIndex type encapsulates all the various low level cryptographic operations
// such as progressing the HKDF hash object states, encryption/decryption
// of messages, signing and verifying messages.
type MessageBoxIndex struct {
	// i_{0..2^64}: the message counter / index
	Idx64 uint64

	// K_i: blinding value used to derive mailboxID by blinding ed25519 keys
	CurBlindingFactor [32]byte

	// E_i: for encryption message payloads
	CurEncryptionKey [32]byte

	// H_{i+1}, the HKDF key used to calculate MessageBoxIndex for Idx61 + 1
	HKDFState [32]byte // H_i, for computing the next mailbox
}

// ensure we implement encoding.BinaryMarshaler/BinaryUmarshaler
var _ encoding.BinaryMarshaler = (*MessageBoxIndex)(nil)
var _ encoding.BinaryUnmarshaler = (*MessageBoxIndex)(nil)

// MarshalBinary returns a binary blob of the given type.
func (m *MessageBoxIndex) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, m.Idx64)
	if err != nil {
		return nil, err
	}
	for _, field := range [][]byte{
		m.CurBlindingFactor[:],
		m.CurEncryptionKey[:],
		m.HKDFState[:],
	} {
		if _, err := buf.Write(field); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary populates the given MessageBoxIndex from the given serialized blob
// or it returns an error.
func (m *MessageBoxIndex) UnmarshalBinary(data []byte) error {
	if len(data) != MessageBoxIndexSize {
		return errors.New("invalid MessageBoxIndex binary size")
	}
	m.Idx64 = binary.LittleEndian.Uint64(data[:8])
	copy(m.CurBlindingFactor[:], data[8:40])
	copy(m.CurEncryptionKey[:], data[40:72])
	copy(m.HKDFState[:], data[72:104])
	return nil
}

func (mbox *MessageBoxIndex) deriveEForContext(ctx []byte) (eICtx [32]byte) {
	hash := func() hash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	}
	hkdfEncEI := hkdf.New(hash, mbox.CurEncryptionKey[:], ctx, []byte{})
	if n, err := hkdfEncEI.Read(eICtx[:]); err != nil || n != len(eICtx) {
		panic("hkdf error")
	}
	return
}

func (mbox *MessageBoxIndex) deriveKForContext(ctx []byte) (kICtx [32]byte) {
	hash := func() hash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	}
	hkdfBlindKI := hkdf.New(hash, mbox.CurBlindingFactor[:], ctx, []byte{})
	if n, err := hkdfBlindKI.Read(kICtx[:]); err != nil || n != len(kICtx) {
		panic("hkdf error")
	}
	return
}

// BoxIDForContext returns a new box ID given a universal read cap and a cryptographic context.
func (mbox *MessageBoxIndex) BoxIDForContext(cap *UniversalReadCap, ctx []byte) *ed25519.PublicKey {
	kICtx := mbox.deriveKForContext(ctx)
	return cap.rootPublicKey.Blind(kICtx[:]) // Produce M_i^ctx = P_R * K_i
}

// EncryptForContext encrypts the given plaintext. The given BoxOwnerCap type and context
// are used here in the encryption key derivation.
func (mbox *MessageBoxIndex) EncryptForContext(owner *BoxOwnerCap, ctx []byte, plaintext []byte) (mICtx [32]byte, cICtx []byte, sICtx []byte) {
	kICtx := mbox.deriveKForContext(ctx)
	mICtx = *(*[32]byte)(owner.rootPublicKey.Blind(kICtx[:]).Bytes())
	eICtx := mbox.deriveEForContext(ctx)
	sivenc, err := gcmsiv.NewGCMSIV(eICtx[:])
	if err != nil {
		panic(err) // Can't happen
	}

	// encrypt with AES-GCM-SIV:
	cICtx = sivenc.Seal([]byte{}, mICtx[:16], plaintext, mICtx[:32])

	// derive blinded private key specific to box index + context and sign the GCM-SIV ciphertext:
	SICtx := owner.rootPrivateKey.Blind(kICtx[:])
	sICtx = SICtx.Sign(cICtx)
	return // Produce M_i^ctx, c_i^ctx, s_i^ctx
}

// DecryptForContext decrypts the given ciphertext and verifies the given signature
// using a key derives from the context and other cryptographic materials.
func (mbox *MessageBoxIndex) DecryptForContext(box [32]byte, ctx []byte, ciphertext []byte, sig []byte) (plaintext []byte, err error) {
	var boxPk ed25519.PublicKey
	if err = boxPk.FromBytes(box[:]); err != nil {
		return
	}
	if false == boxPk.Verify(sig, ciphertext) {
		return nil, errors.New("signature verification failed")
	}
	eICtx := mbox.deriveEForContext(ctx)
	sivdec, err := gcmsiv.NewGCMSIV(eICtx[:])
	if err != nil {
		return nil, err
	}
	if plaintext, err = sivdec.Open([]byte{}, box[:16], ciphertext, box[:]); err != nil {
		return nil, err
	}
	return
}

// AdvanceIndexTo returns a MessageBoxIndex with it's state advanced to the specified index.
func (cur *MessageBoxIndex) AdvanceIndexTo(to uint64) (*MessageBoxIndex, error) {
	if to < cur.Idx64 {
		return nil, errors.New("cannot rewind index: target index is less than current index")
	}
	hash := func() hash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	}

	var next MessageBoxIndex
	next.Idx64 = cur.Idx64
	next.HKDFState = cur.HKDFState
	if to == next.Idx64 {
		return cur, nil
	}

	next.CurBlindingFactor = [32]byte{}
	next.CurEncryptionKey = [32]byte{}
	curIdxB := make([]byte, 8)

	for next.Idx64 < to {
		binary.LittleEndian.PutUint64(curIdxB, next.Idx64)
		hkdf := hkdf.New(hash, next.HKDFState[:], nil, curIdxB)
		// Read H_{i+1}, E_i, K_i from the KDF:
		if n, err := hkdf.Read(next.HKDFState[:]); err != nil || n != len(next.HKDFState) {
			panic("hkdf failed, not reachable")
		}
		if n, err := hkdf.Read(next.CurEncryptionKey[:]); err != nil || n != len(next.CurEncryptionKey) {
			panic("hkdf failed, not reachable")
		}
		if n, err := hkdf.Read(next.CurBlindingFactor[:]); err != nil || n != len(next.CurBlindingFactor) {
			panic("hkdf failed, not reachable")
		}
		next.Idx64 = next.Idx64 + 1
	}
	return &next, nil
}

// NextIndex returns a MessageBoxIndex type with it's state advanced to the next box.
func (cur *MessageBoxIndex) NextIndex() (*MessageBoxIndex, error) {
	return cur.AdvanceIndexTo(cur.Idx64 + 1)
}

// NewMessageBoxIndex returns a new MessageBoxIndex
func NewMessageBoxIndex(rng io.Reader) (*MessageBoxIndex, error) {
	m := MessageBoxIndex{}

	// Pick a random HKDF key for the conversation:
	if ilen, err := io.ReadFull(rng, m.HKDFState[:]); err != nil || ilen != 32 {
		panic(err)
	}

	// Pick a random start index for the conversation.
	// We could start at deterministic index 0, ie 0,
	// but then we would reveal to a later recipient of a capability
	// exactly how many messages preceeded it.
	idx64B := [16]byte{}
	if n, err := io.ReadFull(rng, idx64B[:]); err != nil || n != len(idx64B) {
		panic(err)
	}
	// Since these are not cyclic, overflow of the index denotes the
	// end of usable indices.
	// We pick two integers in 0..2^62-1 and add them together.
	// This ensures an exclusive upper bound of 2^63-2,
	// leaving at least 2^63 usable indices.
	// Sampling two 2^62 bit integers instead of one 2^63 bit biases
	// the distribution towards the middle, reducing the risk of
	// picking a number lower than R which otherwise would be R/2^63,
	// trading it for (R/2^(63-1))^2.
	// The reason is that when we introduce a new party to the conversation,
	// an index of N informs them that we have sent *at most* N messages
	// prior to introducing them, and we would like to minimize the
	// disclosure of such facts.
	idx64B[0] &= 0x2f // 0x2f leaves out the top two bits
	idx64B[8] &= 0x2f
	m.Idx64 = binary.LittleEndian.Uint64(idx64B[:8])
	m.Idx64 += binary.LittleEndian.Uint64(idx64B[8:])
	// believe this is called Irwin-Hall sum.
	// this might be better if normal distribution is what we want:
	// https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform

	nextIndex, err := m.NextIndex()
	if err != nil {
		return nil, err
	}
	return nextIndex, nil
}

// BoxOwnerCap is used by the creator of the message box. It encapsulates
// private key material.
type BoxOwnerCap struct {
	// on-disk:
	rootPrivateKey *ed25519.PrivateKey

	// in-memory only:
	rootPublicKey *ed25519.PublicKey

	firstMessageBoxIndex *MessageBoxIndex
}

// BoxOwnerCapSize is the size in bytes of a serialized BoxOwnerCap
// not counting it's rootPublicKey field.
const BoxOwnerCapSize = 64 + MessageBoxIndexSize

// ensure we implement encoding.BinaryMarshaler/BinaryUmarshaler
var _ encoding.BinaryMarshaler = (*BoxOwnerCap)(nil)
var _ encoding.BinaryUnmarshaler = (*BoxOwnerCap)(nil)

// MarshalBinary returns a binary blob of the BoxOwnerCap type.
// Only serialize the rootPrivateKey. We do not serialize the rootPublicKey
// because it can be derived from the private key.
func (o *BoxOwnerCap) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.Write(o.rootPrivateKey.Bytes()); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, o.firstMessageBoxIndex); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary deserializes a blob into the given type.
// Here we derive our public key from the given private key.
func (o *BoxOwnerCap) UnmarshalBinary(data []byte) error {
	if len(data) != BoxOwnerCapSize {
		return errors.New("invalid BoxOwnerCap binary size")
	}
	err := o.rootPrivateKey.FromBytes(data[:64])
	if err != nil {
		return err
	}
	o.rootPublicKey = o.rootPrivateKey.PublicKey()
	o.firstMessageBoxIndex = &MessageBoxIndex{}
	if err := o.firstMessageBoxIndex.UnmarshalBinary(data[64:]); err != nil {
		return err
	}
	return nil
}

// NewBoxOwnerCap creates a new BoxOwnerCap
func NewBoxOwnerCap(rng io.Reader) (*BoxOwnerCap, error) {
	o := BoxOwnerCap{}
	sk, pk, err := ed25519.NewKeypair(rng) // S_R, P_R
	if err != nil {
		panic(err)
	}
	o.rootPrivateKey = sk
	o.rootPublicKey = pk
	o.firstMessageBoxIndex, err = NewMessageBoxIndex(rng)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// UniversalReadCap is a universal read capability can be used to compute BACAP boxes
// and decrypt their message payloads for indices >= firstMessageBoxIndex
type UniversalReadCap struct {
	rootPublicKey *ed25519.PublicKey

	firstMessageBoxIndex *MessageBoxIndex
}

// UniversalReadCapSize is the size in bytes of the UniversalReadCap struct type.
const UniversalReadCapSize = 32 + MessageBoxIndexSize

// ensure we implement encoding.BinaryMarshaler/BinaryUmarshaler
var _ encoding.BinaryMarshaler = (*UniversalReadCap)(nil)
var _ encoding.BinaryUnmarshaler = (*UniversalReadCap)(nil)

// MarshalBinary returns a binary blob of the given type.
func (u *UniversalReadCap) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.Write(u.rootPublicKey.Bytes()); err != nil {
		return nil, err
	}
	mboxBytes, err := u.firstMessageBoxIndex.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err := buf.Write(mboxBytes); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary populates our types fields from the given binary blob.
func (u *UniversalReadCap) UnmarshalBinary(data []byte) error {
	if len(data) != UniversalReadCapSize {
		return errors.New("invalid UniversalReadCap binary size")
	}
	err := u.rootPublicKey.FromBytes(data[:32])
	if err != nil {
		return err
	}
	u.firstMessageBoxIndex = &MessageBoxIndex{}
	if err := u.firstMessageBoxIndex.UnmarshalBinary(data[32:]); err != nil {
		return err
	}
	return nil
}

// UniversalReadCap returns our UniversalReadCap
func (owner *BoxOwnerCap) UniversalReadCap() *UniversalReadCap {
	o := UniversalReadCap{}
	o.rootPublicKey = owner.rootPublicKey
	// NB: o is the firstIndex that we know about/can read,
	// not necessarily the first index in the conversation:
	o.firstMessageBoxIndex = owner.firstMessageBoxIndex
	//o.universalReadSecret = owner.UniversalCap(readCapString)
	return &o
}

// DeriveMessageBoxID derives the blinded public key, the mailbox ID, given the root public key.
func (mbIdx *MessageBoxIndex) DeriveMessageBoxID(rootPublicKey *ed25519.PublicKey) *ed25519.PublicKey {
	return rootPublicKey.Blind(mbIdx.CurBlindingFactor[:])
}

// warn about accidental copying of these as they have mutable state:
// https://stackoverflow.com/a/52495303
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// StatefulReader is a helper type with mutable state for sequential reading
type StatefulReader struct {
	noCopy        noCopy
	urcap         *UniversalReadCap
	lastInboxRead *MessageBoxIndex
	nextIndex     *MessageBoxIndex
	ctx           []byte
}

// NewStatefulReader initializes a StatefulReader for the given UniversalReadCap and context.
func NewStatefulReader(urcap *UniversalReadCap, ctx []byte) (*StatefulReader, error) {
	sr := &StatefulReader{
		urcap:         urcap,
		ctx:           ctx,
		lastInboxRead: urcap.firstMessageBoxIndex,
		nextIndex:     urcap.firstMessageBoxIndex,
	}
	return sr, nil
}

// ReadNext gets the next box ID to read.
func (sr *StatefulReader) NextBoxID() (*ed25519.PublicKey, error) {
	if sr.nextIndex == nil {
		tmp, err := sr.lastInboxRead.NextIndex()
		if err != nil {
			return nil, err
		}
		sr.nextIndex = tmp
	}
	if sr.ctx == nil {
		return nil, errors.New("next context is nil")
	}
	nextBox := sr.nextIndex.BoxIDForContext(sr.urcap, sr.ctx)
	return nextBox, nil
}

// ParseReply advances state if reading was successful.
func (sr *StatefulReader) DecryptNext(ctx []byte, box [32]byte, ciphertext []byte, sig [64]byte) ([]byte, error) {
	if box == [32]byte{} {
		return nil, errors.New("empty box, no message received")
	}
	if sr.nextIndex == nil {
		return nil, errors.New("next index is nil, cannot parse reply")
	}
	nextboxPubKey := sr.nextIndex.BoxIDForContext(sr.urcap, sr.ctx)
	if !bytes.Equal(box[:], nextboxPubKey.Bytes()) {
		return nil, errors.New("reply does not match expected box ID")
	}
	plaintext, err := sr.nextIndex.DecryptForContext(box, ctx, ciphertext, sig[:])
	if err != nil {
		return nil, err
	}
	sr.lastInboxRead = sr.nextIndex
	tmp, err := sr.nextIndex.NextIndex()
	if err != nil {
		return nil, err
	}
	sr.nextIndex = tmp
	return plaintext, nil
}

// StatefulWriter maintains sequential state for encrypting messages.
type StatefulWriter struct {
	noCopy        noCopy
	owner         *BoxOwnerCap
	lastOutboxIdx *MessageBoxIndex
	nextIndex     *MessageBoxIndex
	ctx           []byte
}

// NewStatefulWriter initializes a StatefulWriter for the given owner and context.
func NewStatefulWriter(owner *BoxOwnerCap, ctx []byte) (*StatefulWriter, error) {
	sw := &StatefulWriter{
		owner:         owner,
		ctx:           ctx,
		lastOutboxIdx: nil,                        // No messages written yet
		nextIndex:     owner.firstMessageBoxIndex, // Start at firstMessage boxIndex (not skipping)
	}
	return sw, nil
}

// NextBoxID returns the next mailbox ID for writing.
func (sw *StatefulWriter) NextBoxID() (*ed25519.PublicKey, error) {
	if sw.nextIndex == nil {
		return nil, errors.New("next index is nil")
	}
	if sw.ctx == nil {
		return nil, errors.New("ctx is nil")
	}
	return sw.nextIndex.BoxIDForContext(sw.owner.UniversalReadCap(), sw.ctx), nil
}

// EncryptNext encrypts a message, advancing state after success.
func (sw *StatefulWriter) EncryptNext(plaintext []byte) (boxID [32]byte, ciphertext []byte, sig []byte, err error) {
	if sw.nextIndex == nil {
		return [32]byte{}, nil, nil, errors.New("next index is nil")
	}

	// Encrypt the message
	boxID, ciphertext, sig = sw.nextIndex.EncryptForContext(sw.owner, sw.ctx, plaintext)

	// Advance the state
	sw.lastOutboxIdx = sw.nextIndex
	sw.nextIndex, err = sw.lastOutboxIdx.NextIndex()
	if err != nil {
		return [32]byte{}, nil, nil, err
	}
	return
}
