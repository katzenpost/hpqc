package bacap

import (
	//	"crypto"
	"crypto/sha512"
	"encoding"
	"encoding/binary"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"golang.org/x/crypto/hkdf"
	"io"
	//"fmt"
	"github.com/agl/gcmsiv"
)

type MailboxIndex struct {
	encoding.BinaryMarshaler

	// i_{0..2^64}: the message counter / index
	Idx64 uint64

	// K_i: blinding value used to derive mailboxID by blinding ed25519 keys
	CurBlindingFactor [32]byte

	// E_i: for encryption message payloads
	CurEncryptionKey [32]byte

	// H_{i+1}, the HKDF key used to calculate MailboxIndex for Idx61 + 1
	HKDFState [32]byte // H_i, for computing the next mailbox
}

func (mbox *MailboxIndex) compute_E_ForContext(ctx []byte) (e_i_ctx [32]byte) {
	hash := sha512.New
	hkdf_encryption_E_i := hkdf.New(hash, mbox.CurEncryptionKey[:], ctx, []byte{})
	if n, err := hkdf_encryption_E_i.Read(e_i_ctx[:]); err != nil || n != len(e_i_ctx) {
		panic("hkdf error")
	}
	return
}

func (mbox *MailboxIndex) compute_K_ForContext(ctx []byte) (k_i_ctx [32]byte) {
	hash := sha512.New
	hkdf_blinding_K_i := hkdf.New(hash, mbox.CurBlindingFactor[:], ctx, []byte{})
	if n, err := hkdf_blinding_K_i.Read(k_i_ctx[:]); err != nil || n != len(k_i_ctx) {
		panic("hkdf error")
	}
	return
}

// Produce M_i^ctx = P_R * K_i
func (mbox *MailboxIndex) BoxIDForContext(cap *UniversalReadCap, ctx []byte) *ed25519.PublicKey {
	k_i_ctx := mbox.compute_K_ForContext(ctx)
	return cap.rootPublicKey.Blind(k_i_ctx[:])
}

// Produce M_i^ctx, c_i^ctx, s_i^ctx
func (mbox *MailboxIndex) EncryptForContext(owner *Owner, ctx []byte, plaintext []byte) (m_i_ctx [32]byte, c_i_ctx []byte, s_i_ctx []byte) {
	k_i_ctx := mbox.compute_K_ForContext(ctx)
	m_i_ctx = *(*[32]byte)(owner.rootPublicKey.Blind(k_i_ctx[:]).Bytes())
	e_i_ctx := mbox.compute_E_ForContext(ctx)
	sivenc, err := gcmsiv.NewGCMSIV(e_i_ctx[:])
	if err != nil {
		panic(err) // Can't happen
	}

	// encrypt with AES-GCM-SIV:
	c_i_ctx = sivenc.Seal([]byte{}, m_i_ctx[:16], plaintext, m_i_ctx[:32])

	// derive blinded private key specific to box index + context and sign the GCM-SIV ciphertext:
	S_i_ctx := owner.rootPrivateKey.Blind(k_i_ctx[:])
	s_i_ctx = S_i_ctx.Sign(c_i_ctx)
	return
}

func (mbox *MailboxIndex) DecryptForContext(box [32]byte, ctx []byte, ciphertext []byte) (plaintext []byte, err error) {
	e_i_ctx := mbox.compute_E_ForContext(ctx)
	sivdec, err := gcmsiv.NewGCMSIV(e_i_ctx[:])
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
	Ctx     [32]byte
	E_i_ctx [32]byte
	K_i_ctx [32]byte
	M_i_ctx [32]byte
}

// Verify the integrity of a received payload
func (box *BACAPBox) Verify() error {
	// - check that M_i_ctx was the public key used to produce valid ed25519 signature
	//   s_i_ctx over c_i_ctx
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
	binary.LittleEndian.PutUint64(curIdxB, cur.Idx64)

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
	//fmt.Println("AdvanceIndexTo", to)
	for idx := next.Idx64; next.Idx64 < to; idx += 1 {
		binary.LittleEndian.PutUint64(curIdxB, next.Idx64)
		next.Idx64 = next.Idx64 + 1
		//fmt.Println("AdvanceIndexTo: idx => ", next.Idx64)
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
		binary.LittleEndian.PutUint64(curIdxB, cur.Idx64)
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
	idx64_b := [16]byte{}
	if n, err := io.ReadFull(rng, idx64_b[:]); err != nil || n != len(idx64_b) {
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
	idx64_b[0] &= 0x2f // 0x2f leaves out the top two bits
	idx64_b[8] &= 0x2f
	this.Idx64 = binary.LittleEndian.Uint64(idx64_b[:8])
	this.Idx64 += binary.LittleEndian.Uint64(idx64_b[8:])
	// believe this is called Irwin-Hall sum.
	// this might be better if normal distribution is what we want:
	// https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform

	this = this.NextIndex()
	return &this
}

type Owner struct {
	encoding.BinaryMarshaler

	// on-disk:
	rootPrivateKey    ed25519.PrivateKey
	firstMailboxIndex *MailboxIndex

	// in-memory only:
	rootPublicKey ed25519.PublicKey
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
	//cb := sk.Bytes()
	//fmt.Println("NewOwner rootPrivateKey", cb)
	//fmt.Println("NewOwner rootPublicKey", *pk)
	this.firstMailboxIndex = NewMailboxIndex(rng)
	//fmt.Println("NewOwner first index", this.firstMailboxIndex.Idx64)
	//fmt.Println("NewOwner first blind", this.firstMailboxIndex.CurBlindingFactor)
	return &this
}

// A universal read capability can be used to compute BACAP boxes and decrypt their message payloads
// for indices >= firstMailboxIndex
type UniversalReadCap struct {
	encoding.BinaryMarshaler
	rootPublicKey ed25519.PublicKey
	//universalReadSecret *ed25519.BlindedPrivateKey
	firstMailboxIndex *MailboxIndex
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
	// sr.nextIndex.compute_E_ForContext(sr.ctx)
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
