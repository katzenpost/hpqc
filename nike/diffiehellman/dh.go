// SPDX-FileCopyrightText: Copyright © 2024 xx foundation
// SPDX-License-Identifier: BSD 2-clause

package diffiehellman

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/xx_network/crypto/large"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"
)

const (
	bitSize        = 4096
	groupSize      = bitSize / 8
	privateKeySize = groupSize + 8
	publicKeySize  = groupSize + 8
)

// MODP4096 is taken from RFC 3526
// This prime is: 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 }
const MODP4096 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" +
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" +
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" +
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
	"FFFFFFFFFFFFFFFF"

type dhNIKE struct{}

// Scheme instantiates a new mod p DH scheme.
func Scheme() *dhNIKE {
	return &dhNIKE{}
}

var _ nike.PrivateKey = (*PrivateKey)(nil)
var _ nike.PublicKey = (*PublicKey)(nil)
var _ nike.Scheme = (*dhNIKE)(nil)

func (d *dhNIKE) Name() string {
	return "DH4096_RFC3526"
}

func (d *dhNIKE) PublicKeySize() int {
	return publicKeySize
}

func (d *dhNIKE) PrivateKeySize() int {
	return privateKeySize
}

func (d *dhNIKE) GeneratePrivateKey(rng io.Reader) nike.PrivateKey {
	group := d.group()
	privKey := diffieHellman.GeneratePrivateKey(privateKeySize, group, rng)
	return &PrivateKey{
		privateKey: privKey,
	}
}

func (d *dhNIKE) GenerateKeyPairFromEntropy(rng io.Reader) (nike.PublicKey, nike.PrivateKey, error) {
	privkey, pubkey := d.NewKeypair(rng)
	return pubkey, privkey, nil
}

func (d *dhNIKE) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	privkey, pubkey := d.NewKeypair(rand.Reader)
	return pubkey, privkey, nil
}

func (d *dhNIKE) NewEmptyPrivateKey() nike.PrivateKey {
	return &PrivateKey{
		privateKey: new(cyclic.Int),
	}
}

func (d *dhNIKE) NewEmptyPublicKey() nike.PublicKey {
	return &PublicKey{
		publicKey: new(cyclic.Int),
	}
}

// UnmarshalBinaryPublicKey unmarshals the public key bytes.
func (d *dhNIKE) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	pubKey := d.NewEmptyPublicKey()
	err := pubKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// UnmarshalBinaryPrivateKey unmarshals the public key bytes.
func (d *dhNIKE) UnmarshalBinaryPrivateKey(b []byte) (nike.PrivateKey, error) {
	privKey := d.NewEmptyPrivateKey()
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func (d *dhNIKE) group() *cyclic.Group {
	p := large.NewInt(1)
	p.SetString(MODP4096, 16)
	g := large.NewInt(2)
	return cyclic.NewGroup(p, g)
}

func (d *dhNIKE) NewKeypair(rng io.Reader) (nike.PrivateKey, nike.PublicKey) {
	group := d.group()
	privKey := diffieHellman.GeneratePrivateKey(privateKeySize, group, rng)
	pubKey := diffieHellman.GeneratePublicKey(privKey, group)
	return &PrivateKey{
			privateKey: privKey,
		}, &PublicKey{
			publicKey: pubKey,
		}
}

func (d *dhNIKE) DeriveSecret(privateKey nike.PrivateKey, publicKey nike.PublicKey) []byte {
	c := diffieHellman.GenerateSessionKey(privateKey.(*PrivateKey).privateKey, publicKey.(*PublicKey).publicKey, Scheme().group())
	return c.BinaryEncode()
}

func (d *dhNIKE) Blind(groupMember nike.PublicKey, blindingFactor nike.PrivateKey) nike.PublicKey {
	return &PublicKey{
		publicKey: diffieHellman.GenerateSessionKey(blindingFactor.(*PrivateKey).privateKey, groupMember.(*PublicKey).publicKey, Scheme().group()),
	}
}

func (d *dhNIKE) DerivePublicKey(privKey nike.PrivateKey) nike.PublicKey {
	return &PublicKey{
		publicKey: diffieHellman.GeneratePublicKey(privKey.(*PrivateKey).privateKey, d.group()),
	}
}

type PrivateKey struct {
	privateKey *cyclic.Int
}

func (p *PrivateKey) CyclicInt() *cyclic.Int {
	return p.privateKey
}

func (p *PrivateKey) DeriveSecret(pubKey nike.PublicKey) []byte {
	c := diffieHellman.GenerateSessionKey(p.privateKey,
		(pubKey.(*PublicKey)).publicKey,
		Scheme().group())
	return c.Bytes()
}

func (p *PrivateKey) Reset() {
	b := make([]byte, privateKeySize)
	err := p.FromBytes(b)
	if err != nil {
		panic(err)
	}
}

func (p *PrivateKey) Bytes() []byte {
	if p.privateKey == nil {
		return nil
	}
	return p.privateKey.BinaryEncode()
}

func (p *PrivateKey) FromBytes(data []byte) error {
	if len(data) != Scheme().PrivateKeySize() {
		return fmt.Errorf("invalid key size, expected %d but got %d", Scheme().PrivateKeySize(), len(data))
	}
	return p.privateKey.BinaryDecode(data)
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

func (p *PrivateKey) Public() nike.PublicKey {
	return p.Scheme().DerivePublicKey(p)
}

func (p *PrivateKey) Scheme() nike.Scheme {
	return Scheme()
}

type PublicKey struct {
	publicKey *cyclic.Int
}

func (p *PublicKey) Blind(blindingFactor nike.PrivateKey) error {
	p.publicKey = diffieHellman.GenerateSessionKey(blindingFactor.(*PrivateKey).privateKey, p.publicKey, Scheme().group())
	return nil
}

func (p *PublicKey) CyclicInt() *cyclic.Int {
	return p.publicKey
}

func (p *PublicKey) Reset() {
	b := make([]byte, publicKeySize)
	p.FromBytes(b)
}

func (p *PublicKey) Bytes() []byte {
	if p.publicKey == nil {
		return nil
	}
	return p.publicKey.BinaryEncode()
}

func (p *PublicKey) FromBytes(data []byte) error {
	if len(data) != Scheme().PublicKeySize() {
		return fmt.Errorf("invalid key size, expected %d but got %d", Scheme().PublicKeySize(), len(data))
	}
	err := p.publicKey.BinaryDecode(data)
	if err != nil {
		return nil
	}
	if !diffieHellman.CheckPublicKey(Scheme().group(), p.publicKey) {
		return errors.New("not a valid public key")
	}
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

func (p *PublicKey) Scheme() nike.Scheme {
	return Scheme()
}
