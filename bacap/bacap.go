// SPDX-FileCopyrightText: © 2025 Katzenpost dev team
// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"bytes"
	"crypto/sha512"
	"encoding"
	"encoding/binary"
	"errors"
	"io"

	"github.com/agl/gcmsiv"
	"golang.org/x/crypto/hkdf"

	"github.com/katzenpost/hpqc/sign/ed25519"
)

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
	ret := new(bytes.Buffer)
	err := binary.Write(ret, binary.LittleEndian, m.Idx64)
	if err != nil {
		return nil, err
	}
	for _, field := range [][]byte{
		m.CurBlindingFactor[:],
		m.CurEncryptionKey[:],
		m.HKDFState[:],
	} {
		if _, err := ret.Write(field); err != nil {
			return nil, err
		}
	}
	return ret.Bytes(), nil
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
	hash := sha512.New
	hkdfEncryptionEI := hkdf.New(hash, mbox.CurEncryptionKey[:], ctx, []byte{})
	if n, err := hkdfEncryptionEI.Read(eICtx[:]); err != nil || n != len(eICtx) {
		panic("hkdf error")
	}
	return
}

func (mbox *MailboxIndex) deriveKForContext(ctx []byte) (kICtx [32]byte) {
	hash := sha512.New
	hkdfBlindingKI := hkdf.New(hash, mbox.CurBlindingFactor[:], ctx, []byte{})
	if n, err := hkdfBlindingKI.Read(kICtx[:]); err != nil || n != len(kICtx) {
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
	boxPk := new(ed25519.PublicKey)
	if err = boxPk.FromBytes(box[:]); err != nil {
		return
	}
	if false == boxPk.Verify(sig, ciphertext) {
		panic("verification failed TODO should be an error")
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

// a MailboxIndex specialized for a given "context" (Ctx)
type BACAPBox struct {
	Ctx   [32]byte
	EICtx [32]byte
	KICtx [32]byte
	mICtx [32]byte
}

// Verify the integrity of a received payload
func (box *BACAPBox) Verify() error {
	// - check that mICtx was the public key used to produce valid ed25519 signature
	//   sICtx over cICtx
	return nil
}

// Decrypt a message, after checking the signature
func (box *BACAPBox) Unseal() error {
	return nil
}

// Encrypt a message, signing it
func (box *BACAPBox) Seal() []byte {
	return []byte{}
}

func (cur *MailboxIndex) AdvanceIndexTo(to uint64) (next MailboxIndex) {
	if to < cur.Idx64 {
		panic("TODO that is an error")
	}
	hash := sha512.New // TODO blake

	curIdxB := make([]byte, 8)

	next.Idx64 = cur.Idx64
	next.HKDFState = cur.HKDFState
	if to == next.Idx64 {
		next.CurBlindingFactor = cur.CurBlindingFactor
		next.CurEncryptionKey = cur.CurEncryptionKey
		return
	} else {
		next.CurBlindingFactor = [32]byte{}
		next.CurEncryptionKey = [32]byte{}
	}
	for idx := next.Idx64; next.Idx64 < to; idx += 1 {
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
	return
}
func (cur *MailboxIndex) NextIndex() MailboxIndex {
	ne := cur.AdvanceIndexTo(cur.Idx64 + 1)
	return ne
}

func NewMailboxIndex(rng io.Reader) *MailboxIndex {
	this := MailboxIndex{}

	// Pick a random HKDF key for the conversation:
	if ilen, err := io.ReadFull(rng, this.HKDFState[:]); err != nil || ilen != 32 {
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
	this.Idx64 = binary.LittleEndian.Uint64(idx64B[:8])
	this.Idx64 += binary.LittleEndian.Uint64(idx64B[8:])
	// believe this is called Irwin-Hall sum.
	// this might be better if normal distribution is what we want:
	// https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform

	this = this.NextIndex()
	return &this
}

type Owner struct {
	// on-disk:
	rootPrivateKey ed25519.PrivateKey

	// in-memory only:
	rootPublicKey ed25519.PublicKey

	firstMailboxIndex *MailboxIndex
}

const OwnerSize = 64 + 32 + MailboxIndexSize

// ensure we implement encoding.BinaryMarshaler/BinaryUmarshaler
var _ encoding.BinaryMarshaler = (*Owner)(nil)
var _ encoding.BinaryUnmarshaler = (*Owner)(nil)

func (o *Owner) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// Write rootPrivateKey (64 bytes for ed25519.PrivateKey)
	if _, err := buf.Write(o.rootPrivateKey.Bytes()); err != nil {
		return nil, err
	}

	// Write rootPublicKey (32 bytes for ed25519.PublicKey)
	if _, err := buf.Write(o.rootPublicKey.Bytes()); err != nil {
		return nil, err
	}

	// Marshal and write firstMailboxIndex
	mboxBytes, err := o.firstMailboxIndex.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err := buf.Write(mboxBytes); err != nil {
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

func NewOwner(rng io.Reader) *Owner {
	this := Owner{}
	//this.rootPrivateKey, this.rootPublicKey, err
	sk, pk, err := ed25519.NewKeypair(rng) // S_R, P_R
	if err != nil {
		panic("rng is broken")
	}
	this.rootPrivateKey = *sk
	this.rootPublicKey = *pk
	this.firstMailboxIndex = NewMailboxIndex(rng)
	return &this
}

// A universal read capability can be used to compute BACAP boxes and decrypt their message payloads
// for indices >= firstMailboxIndex
type UniversalReadCap struct {
	rootPublicKey ed25519.PublicKey

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
	this := UniversalReadCap{}
	this.rootPublicKey = owner.rootPublicKey
	// NB: this is the firstIndex that we know about/can read,
	// not necessarily the first index in the conversation:
	this.firstMailboxIndex = owner.firstMailboxIndex
	//this.universalReadSecret = owner.UniversalCap(readCapString)
	return &this
}

func (mbIdx *MailboxIndex) DeriveMailboxID(rootPublicKey *ed25519.PublicKey) *ed25519.PublicKey {
	//fmt.Println("DeriveMailboxID: blinding rootPublicKey",rootPublicKey)
	//fmt.Println("DeriveMailboxID: curblind:", mbIdx.CurBlindingFactor)
	pk := rootPublicKey.Blind(mbIdx.CurBlindingFactor[:])
	//fmt.Println("DeriveMailboxID => pk:", pk)
	return pk
}

// TODO:
// - need to excercise the caps with signature
// - need iterated "advance by x / advance to x" helpers
// - some kind of data structure to support skip indexes ?
// - figure out if there's a practical reason to have a fixed KDF key instead of just plain iteration.
//   - maybe put the rootPublicKey in blind derivation?

// warn about accidental copying of these as they have mutable state:
// https://stackoverflow.com/a/52495303
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

type StatefulWriter struct {
	noCopy noCopy
}

// Helper type with mutable state for sequential reading
type StatefulReader struct {
	noCopy        noCopy
	urcap         UniversalReadCap
	lastInboxRead MailboxIndex
	nextIndex     *MailboxIndex
	ctx           []byte
}

// Get the next box ID to read. Not thread-safe.
func (sr *StatefulReader) ReadNext() *ed25519.PublicKey {
	// TODO specialize it for sr.ctx
	if sr.nextIndex == nil {
		tmp := sr.lastInboxRead.NextIndex()
		sr.nextIndex = &tmp
	}
	nextBox := sr.nextIndex.BoxIDForContext(&sr.urcap, sr.ctx)
	return nextBox
}

// Not thread-safe. Parse reply, advance state if reading was successful.
func (sr *StatefulReader) ParseReply(box [32]byte, ciphertext []byte, sig [64]byte) (plaintext []byte, err error) {
	// if box == [32]byte{0} {
	//   there was no reply, either the message hasn't been sent or it has been deleted.
	// }
	// if box != sr.nextIndex.BoxIDForContext(&sr.urcap, sr.ctx) {
	//   then we have a problem, where the reply is for a different box than we asked for.
	// }
	// sr.nextIndex.deriveEForContext(sr.ctx)
	if true {
		// we got a valid reply (deleted msg or msg with payload)
		sr.lastInboxRead = *sr.nextIndex
		tmp := sr.nextIndex.NextIndex()
		sr.nextIndex = &tmp
	} else {
		plaintext = nil
	}
	return
}
