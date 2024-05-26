package bacap

import (
  "encoding"
  "encoding/binary"
"io"
  "github.com/katzenpost/hpqc/sign/ed25519"
  "crypto/sha512"
  "golang.org/x/crypto/hkdf"
)

const readCapString = "READ"

type MailboxIndex struct {
  encoding.BinaryMarshaler

  // the integer corresponding to CurBlind
  Idx64 uint64
  // the blinding value used to derive mailboxID
  CurBlind [32]byte 
  // the HKDF key used to calculate MailboxIndex for Idx61 + 1
  StateBlind [32]byte
}

func AdvanceIndex(cur *MailboxIndex) MailboxIndex {
hash := sha512.New

  curIdxB := make([]byte, 8)
  binary.LittleEndian.PutUint64(curIdxB, cur.Idx64)

  next := MailboxIndex{}
  next.Idx64 = cur.Idx64 + 1
  hkdf := hkdf.New(hash, cur.StateBlind[:], cur.CurBlind[:], curIdxB)
  if n, err := hkdf.Read(next.CurBlind[:]); err != nil || n!=len(next.CurBlind) { panic("hkdf failed") }
  if n, err := hkdf.Read(next.StateBlind[:]); err != nil || n!=len(next.StateBlind) {
   panic("hkdf failed")
  }
  return next
}

func NewMailboxIndex(rng io.Reader) (*MailboxIndex) {
  this := MailboxIndex{}
  if ilen, err := io.ReadFull(rng, this.StateBlind[:]); err!=nil || ilen != 32 {
  panic("rng is broken") }

  idx64_b := [8]byte{}
  if n, err := io.ReadFull(rng, idx64_b[:]); err != nil || n!=len(idx64_b) {
    panic(err)
  }
  // The division by 2 is not necessary but it helps to not have
  // to think about overflow for now:
  this.Idx64 = binary.LittleEndian.Uint64(idx64_b[:]) / 2

  this = AdvanceIndex(&this)
  return &this
}


type Owner struct {
  encoding.BinaryMarshaler

  // on-disk:
  conversationBlind	ed25519.PrivateKey
  firstMailboxIndex     *MailboxIndex

  // in-memory only:
  conversationPK        ed25519.PublicKey
}

func NewOwner(rng io.Reader) *Owner {
  this := Owner {}
  //this.conversationBlind, this.conversationPK, err
  sk, pk, err := ed25519.NewKeypair(rng)
  if err != nil { panic("rng is broken") }
  this.conversationBlind = *sk
  this.conversationPK = *pk
  this.firstMailboxIndex = NewMailboxIndex(rng)
  return &this
}

type UniversalReadCap struct {
  encoding.BinaryMarshaler
  conversationPK ed25519.PublicKey
  universalReadSecret [32]byte
  indexBlind   [32]byte
  blindedIndex [32]byte
  firstIndex  uint64
}

func NewUniversalCap(owner *Owner, capName string) (capSK *ed25519.BlindedPrivateKey) {

     // this is a public value, there's no secret key in the hash:
     hash := sha512.New
     hkdf := hkdf.New(hash, []byte{}, []byte(capName), []byte{})
     capHash := [32]byte{}
     n, err := io.ReadFull(hkdf, capHash[:])
     if n != 32 || err != nil { panic("bad rng") }

     capSK = owner.conversationBlind.Blind(capHash[:])
     return
}

func NewUniversalReadCap(owner *Owner) *UniversalReadCap {
     this := UniversalReadCap{}
     this.conversationPK = owner.conversationPK
     // NB: this is the firstIndex that we know about/can read,
     // not necessarily the first index in the conversation:
     this.firstIndex = owner.firstMailboxIndex.Idx64
     NewUniversalCap(owner, readCapString)
     return &this
}


func DeriveMailboxID(mbIdx *MailboxIndex, conversationPK *ed25519.PublicKey) *ed25519.PublicKey {
  return conversationPK.Blind(mbIdx.CurBlind[:])
}