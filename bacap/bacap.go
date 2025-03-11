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
   BACAP is the Blinded Cryptographic Capability system whose
   design is expounded upon in section 4 of our paper:

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

   Echomix: a Strong Anonymity System with Messaging

   https://arxiv.org/abs/2501.02933
   https://arxiv.org/pdf/2501.02933


   This BACAP implementation could possibly be improved, here's a ticket for
   completing the TODO tasks written by it's original author:

   https://github.com/katzenpost/hpqc/issues/55
*/

const MailboxIndexSize = 8 + 32 + 32 + 32

type MailboxIndex struct {
	// i_{0..2^64}: the message counter / index
	Idx64 uint64

	// K_i: blinding value used to derive mailboxID by blinding ed25519 keys
	CurBlindingFactor [32]byte

	// E_i: for encryption message payloads
	CurEncryptionKey [32]byte

	// H_{i+1}, the HKDF key used to calculate MailboxIndex for Idx61 + 1
	HKDFState [32]byte // H_i, for computing the next mailbox
}

// ensure we implement encoding.BinaryMarshaler/BinaryUmarshaler
var _ encoding.BinaryMarshaler = (*MailboxIndex)(nil)
var _ encoding.BinaryUnmarshaler = (*MailboxIndex)(nil)

func (m *MailboxIndex) MarshalBinary() ([]byte, error) {
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

func (m *MailboxIndex) UnmarshalBinary(data []byte) error {
	if len(data) != MailboxIndexSize {
		return errors.New("invalid MailboxIndex binary size")
	}
	m.Idx64 = binary.LittleEndian.Uint64(data[:8])
	copy(m.CurBlindingFactor[:], data[8:40])
	copy(m.CurEncryptionKey[:], data[40:72])
	copy(m.HKDFState[:], data[72:104])
	return nil
}

func (mbox *MailboxIndex) deriveEForContext(ctx []byte) (eICtx [32]byte) {
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

func (mbox *MailboxIndex) deriveKForContext(ctx []byte) (kICtx [32]byte) {
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

// Produce M_i^ctx = P_R * K_i
func (mbox *MailboxIndex) BoxIDForContext(cap *UniversalReadCap, ctx []byte) *ed25519.PublicKey {
	kICtx := mbox.deriveKForContext(ctx)
	return cap.rootPublicKey.Blind(kICtx[:])
}

// Produce M_i^ctx, c_i^ctx, s_i^ctx
func (mbox *MailboxIndex) EncryptForContext(owner *Owner, ctx []byte, plaintext []byte) (mICtx [32]byte, cICtx []byte, sICtx []byte) {
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
	return
}

func (mbox *MailboxIndex) DecryptForContext(box [32]byte, ctx []byte, ciphertext []byte, sig []byte) (plaintext []byte, err error) {
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

func (cur *MailboxIndex) AdvanceIndexTo(to uint64) (*MailboxIndex, error) {
	if to < cur.Idx64 {
		return nil, errors.New("cannot rewind index: target index is less than current index")
	}
	hash := func() hash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	}

	curIdxB := make([]byte, 8)

	var next MailboxIndex
	next.Idx64 = cur.Idx64
	next.HKDFState = cur.HKDFState
	if to == next.Idx64 {
		next.CurBlindingFactor = cur.CurBlindingFactor
		next.CurEncryptionKey = cur.CurEncryptionKey
		return &next, nil
	}

	next.CurBlindingFactor = [32]byte{}
	next.CurEncryptionKey = [32]byte{}

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

func (cur *MailboxIndex) NextIndex() (*MailboxIndex, error) {
	return cur.AdvanceIndexTo(cur.Idx64 + 1)
}

func NewMailboxIndex(rng io.Reader) (*MailboxIndex, error) {
	m := MailboxIndex{}

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

type Owner struct {
	// on-disk:
	rootPrivateKey *ed25519.PrivateKey

	// in-memory only:
	rootPublicKey *ed25519.PublicKey

	firstMailboxIndex *MailboxIndex
}

const OwnerSize = 64 + 32 + MailboxIndexSize

// ensure we implement encoding.BinaryMarshaler/BinaryUmarshaler
var _ encoding.BinaryMarshaler = (*Owner)(nil)
var _ encoding.BinaryUnmarshaler = (*Owner)(nil)

func (o *Owner) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.Write(o.rootPrivateKey.Bytes()); err != nil {
		return nil, err
	}
	if _, err := buf.Write(o.rootPublicKey.Bytes()); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, o.firstMailboxIndex); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (o *Owner) UnmarshalBinary(data []byte) error {
	if len(data) != OwnerSize {
		return errors.New("invalid Owner binary size")
	}
	err := o.rootPrivateKey.FromBytes(data[:64])
	if err != nil {
		return err
	}
	err = o.rootPublicKey.FromBytes(data[64:96])
	if err != nil {
		return err
	}
	o.firstMailboxIndex = &MailboxIndex{}
	if err := o.firstMailboxIndex.UnmarshalBinary(data[96:]); err != nil {
		return err
	}
	return nil
}

func NewOwner(rng io.Reader) (*Owner, error) {
	o := Owner{}
	sk, pk, err := ed25519.NewKeypair(rng) // S_R, P_R
	if err != nil {
		panic(err)
	}
	o.rootPrivateKey = sk
	o.rootPublicKey = pk
	o.firstMailboxIndex, err = NewMailboxIndex(rng)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

// A universal read capability can be used to compute BACAP boxes and decrypt their message payloads
// for indices >= firstMailboxIndex
type UniversalReadCap struct {
	rootPublicKey *ed25519.PublicKey

	firstMailboxIndex *MailboxIndex
}

const UniversalReadCapSize = 32 + MailboxIndexSize

// ensure we implement encoding.BinaryMarshaler/BinaryUmarshaler
var _ encoding.BinaryMarshaler = (*UniversalReadCap)(nil)
var _ encoding.BinaryUnmarshaler = (*UniversalReadCap)(nil)

func (u *UniversalReadCap) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.Write(u.rootPublicKey.Bytes()); err != nil {
		return nil, err
	}
	mboxBytes, err := u.firstMailboxIndex.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err := buf.Write(mboxBytes); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (u *UniversalReadCap) UnmarshalBinary(data []byte) error {
	if len(data) != UniversalReadCapSize {
		return errors.New("invalid UniversalReadCap binary size")
	}
	err := u.rootPublicKey.FromBytes(data[:32])
	if err != nil {
		return err
	}
	u.firstMailboxIndex = &MailboxIndex{}
	if err := u.firstMailboxIndex.UnmarshalBinary(data[32:]); err != nil {
		return err
	}
	return nil
}

func (owner *Owner) NewUniversalReadCap() *UniversalReadCap {
	o := UniversalReadCap{}
	o.rootPublicKey = owner.rootPublicKey
	// NB: o is the firstIndex that we know about/can read,
	// not necessarily the first index in the conversation:
	o.firstMailboxIndex = owner.firstMailboxIndex
	//o.universalReadSecret = owner.UniversalCap(readCapString)
	return &o
}

// DeriveMailboxID derives the blinded public key, the mailbox ID, given the root public key.
func (mbIdx *MailboxIndex) DeriveMailboxID(rootPublicKey *ed25519.PublicKey) *ed25519.PublicKey {
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
	lastInboxRead *MailboxIndex
	nextIndex     *MailboxIndex
	ctx           []byte
}

// ReadNext gets the next box ID to read. Not thread-safe.
func (sr *StatefulReader) ReadNext() (*ed25519.PublicKey, error) {
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

// ParseReplyParse repl  advances state if reading was successful. Not thread safe.
func (sr *StatefulReader) ParseReply(box [32]byte, ciphertext []byte, sig [64]byte) (plaintext []byte, err error) {
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

	mailboxKey := sr.nextIndex.DeriveMailboxID(sr.urcap.rootPublicKey)
	scheme := mailboxKey.Scheme()
	if !scheme.Verify(mailboxKey, ciphertext, sig[:], nil) {
		return nil, errors.New("signature verification failed")
	}

	// we got a valid reply (deleted msg or msg with payload)
	sr.lastInboxRead = sr.nextIndex
	tmp, err := sr.nextIndex.NextIndex()
	if err != nil {
		return nil, err
	}
	sr.nextIndex = tmp
	return plaintext, nil
}
