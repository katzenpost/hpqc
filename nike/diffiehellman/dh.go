// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package diffiehellman

import (
	"encoding/base64"
	"errors"
	"io"

	"gitlab.com/elixxir/crypto/cyclic"
	dh "gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/xx_network/crypto/large"

	"github.com/katzenpost/hpqc/nike"
)

const (
	// GroupElementLength is the length of a ECDH group element in bytes.
	// XXX wrong size FIXME: fix the serialization so that key blobs are
	// the same size as group element size. i think gob encoding adds extra bytes.
	GroupElementLength = 56

	// PublicKeySize is the size of a serialized PublicKey in bytes.
	PublicKeySize = GroupElementLength

	// PrivateKeySize is the size of a serialized PrivateKey in bytes.
	PrivateKeySize = GroupElementLength
)

var (
	// ErrBlindDataSizeInvalid indicates that the blinding data size was invalid.
	ErrBlindDataSizeInvalid error = errors.New("x448: blinding data size invalid")

	errInvalidKey = errors.New("x448: invalid key")

	group = cyclic.NewGroup(
		large.NewIntFromString("E2EE983D031DC1DB6F1A7A67DF0E9A8E5561DB8E8D49413394C049B"+
			"7A8ACCEDC298708F121951D9CF920EC5D146727AA4AE535B0922C688B55B3DD2AE"+
			"DF6C01C94764DAB937935AA83BE36E67760713AB44A6337C20E7861575E745D31F"+
			"8B9E9AD8412118C62A3E2E29DF46B0864D0C951C394A5CBBDC6ADC718DD2A3E041"+
			"023DBB5AB23EBB4742DE9C1687B5B34FA48C3521632C4A530E8FFB1BC51DADDF45"+
			"3B0B2717C2BC6669ED76B4BDD5C9FF558E88F26E5785302BEDBCA23EAC5ACE9209"+
			"6EE8A60642FB61E8F3D24990B8CB12EE448EEF78E184C7242DD161C7738F32BF29"+
			"A841698978825B4111B4BC3E1E198455095958333D776D8B2BEEED3A1A1A221A6E"+
			"37E664A64B83981C46FFDDC1A45E3D5211AAF8BFBC072768C4F50D7D7803D2D4F2"+
			"78DE8014A47323631D7E064DE81C0C6BFA43EF0E6998860F1390B5D3FEACAF1696"+
			"015CB79C3F9C2D93D961120CD0E5F12CBB687EAB045241F96789C38E89D796138E"+
			"6319BE62E35D87B1048CA28BE389B575E994DCA755471584A09EC723742DC35873"+
			"847AEF49F66E43873", 16),
		large.NewIntFromString("2", 16))
)

var _ nike.PrivateKey = (*PrivateKey)(nil)
var _ nike.PublicKey = (*PublicKey)(nil)
var _ nike.Scheme = (*scheme)(nil)

// EcdhNike implements the Nike interface using our ecdh module.
type scheme struct {
	rng io.Reader
}

// Scheme instantiates a new X448 scheme given a CSPRNG.
func Scheme(rng io.Reader) *scheme {
	return &scheme{
		rng: rng,
	}

}

func (e *scheme) GeneratePrivateKey(rng io.Reader) nike.PrivateKey {
	privKey, err := NewKeypair(rng)
	if err != nil {
		panic(err)
	}
	return privKey
}

func (e *scheme) GenerateKeyPairFromEntropy(rng io.Reader) (nike.PublicKey, nike.PrivateKey, error) {
	privKey, err := NewKeypair(rng)
	if err != nil {
		return nil, nil, err
	}
	return privKey.Public(), privKey, nil
}

func (e *scheme) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	return e.GenerateKeyPairFromEntropy(e.rng)
}

func (e *scheme) Name() string {
	return "mod_p_DH"
}

// PublicKeySize returns the size in bytes of the public key.
func (e *scheme) PublicKeySize() int {
	return PublicKeySize
}

// PrivateKeySize returns the size in bytes of the private key.
func (e *scheme) PrivateKeySize() int {
	return PublicKeySize
}

// NewEmptyPublicKey returns an uninitialized
// PublicKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *scheme) NewEmptyPublicKey() nike.PublicKey {
	return new(PublicKey)
}

// NewEmptyPrivateKey returns an uninitialized
// PrivateKey which is suitable to be loaded
// via some serialization format via FromBytes
// or FromPEMFile methods.
func (e *scheme) NewEmptyPrivateKey() nike.PrivateKey {
	return new(PrivateKey)
}

// DeriveSecret derives a shared secret given a private key
// from one party and a public key from another.
func (e *scheme) DeriveSecret(privKey nike.PrivateKey, pubKey nike.PublicKey) []byte {
	sharedSecret := Exp(privKey.(*PrivateKey).privKey, (pubKey.(*PublicKey)).pubKey)
	return sharedSecret[:]
}

// DerivePublicKey derives a public key given a private key.
func (e *scheme) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	return privKey.(*PrivateKey).Public()
}

func (e *scheme) Blind(groupMember nike.PublicKey, blindingFactor nike.PrivateKey) nike.PublicKey {
	sharedSecret := Exp(groupMember.(*PublicKey).pubKey, blindingFactor.(*PrivateKey).privKey)
	pubKey := new(PublicKey)
	err := pubKey.FromBytes(sharedSecret)
	if err != nil {
		panic(err)
	}

	return pubKey
}

// UnmarshalBinaryPublicKey loads a public key from byte slice.
func (e *scheme) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	pubKey := new(PublicKey)
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// UnmarshalBinaryPrivateKey loads a private key from byte slice.
func (e *scheme) UnmarshalBinaryPrivateKey(b []byte) (nike.PrivateKey, error) {
	privKey := new(PrivateKey)
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, err
}

type PrivateKey struct {
	pubKey  *PublicKey
	privKey *cyclic.Int
}

func NewKeypair(rng io.Reader) (nike.PrivateKey, error) {
	privKey := dh.GeneratePrivateKey(dh.DefaultPrivateKeyLength, group, rng)
	pubkey := dh.GeneratePublicKey(privKey, group)
	mypubkey := &PublicKey{
		pubKey: pubkey,
	}
	mypubkey.rebuildB64String()
	return &PrivateKey{
		pubKey:  mypubkey,
		privKey: privKey,
	}, nil
}

func (p *PrivateKey) Public() nike.PublicKey {
	return p.pubKey
}

func (p *PrivateKey) Reset() {
	// no op
}

func (p *PrivateKey) Bytes() []byte {
	blob, err := p.privKey.GobEncode()
	if err != nil {
		panic(err)
	}
	return blob
}

func (p *PrivateKey) FromBytes(data []byte) error {
	return p.privKey.GobDecode(data)
}

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *PrivateKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(p.Bytes())), nil
}

func (p *PrivateKey) UnmarshalBinary(data []byte) error {
	return p.FromBytes(data)
}

func (p *PrivateKey) UnmarshalText(data []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	return p.FromBytes(raw)
}

type PublicKey struct {
	pubKey    *cyclic.Int
	b64String string
}

func (p *PublicKey) Blind(blindingFactor nike.PrivateKey) error {
	// FIX ME
	return nil
}

func (p *PublicKey) Reset() {
	// no op
}

func (p *PublicKey) Bytes() []byte {
	blob, err := p.pubKey.GobEncode()
	if err != nil {
		panic(err)
	}
	return blob
}

func (p *PublicKey) rebuildB64String() {
	p.b64String = base64.StdEncoding.EncodeToString(p.Bytes())
}

func (p *PublicKey) FromBytes(data []byte) error {
	err := p.pubKey.GobDecode(data)
	if err != nil {
		return err
	}
	p.rebuildB64String()
	return nil
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *PublicKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(p.Bytes())), nil
}

func (p *PublicKey) UnmarshalBinary(data []byte) error {
	return p.FromBytes(data)
}

func (p *PublicKey) UnmarshalText(data []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	return p.FromBytes(raw)
}

// Exp returns the group element, the result of x^y, over the ECDH group.
func Exp(x, y *cyclic.Int) []byte {
	ss := dh.GenerateSessionKey(x, y, group)
	blob, err := ss.GobEncode()
	if err != nil {
		panic(err)
	}
	return blob
}
