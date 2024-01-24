// pem.go - PEM file write barrier.
//
// Copyright (C) 2022  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package pem

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/util"
)

func ToPublicPEMString(key kem.PublicKey) string {
	return string(ToPublicPEMBytes(key))
}

func ToPublicPEMBytes(key kem.PublicKey) []byte {
	keyType := fmt.Sprintf("%s PUBLIC KEY", strings.ToUpper(key.Scheme().Name()))
	blob, err := key.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if util.CtIsZero(blob) {
		panic(fmt.Sprintf("ToPEMString/%s: attempted to serialize scrubbed key", keyType))
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: blob,
	}
	return pem.EncodeToMemory(blk)
}

func PublicKeyToFile(f string, key kem.PublicKey) error {
	out, err := os.OpenFile(f, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	outBuf := ToPublicPEMBytes(key)
	writeCount, err := out.Write(outBuf)
	if err != nil {
		return err
	}
	if writeCount != len(outBuf) {
		return errors.New("partial write failure")
	}
	err = out.Sync()
	if err != nil {
		return err
	}
	return out.Close()
}

func FromPublicPEMString(s string, scheme kem.Scheme) (kem.PublicKey, error) {
	return FromPublicPEMPubBytes([]byte(s), scheme)
}

func FromPublicPEMPubBytes(b []byte, scheme kem.Scheme) (kem.PublicKey, error) {
	keyType := fmt.Sprintf("%s PUBLIC KEY", strings.ToUpper(scheme.Name()))
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("failed to decode PEM data from %s PEM", keyType)
	}
	if strings.ToUpper(blk.Type) != keyType {
		return nil, fmt.Errorf("attempted to decode PEM file with wrong key type %v != %v", blk.Type, keyType)
	}
	return scheme.UnmarshalBinaryPublicKey(blk.Bytes)
}

func FromPublicPEMFile(f string, scheme kem.Scheme) (kem.PublicKey, error) {
	buf, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("pem.FromFile error: %s", err)
	}
	return FromPublicPEMPubBytes(buf, scheme)
}

// private key

func ToPrivatePEMString(key kem.PrivateKey) string {
	return string(ToPrivatePEMBytes(key))
}

func ToPrivatePEMBytes(key kem.PrivateKey) []byte {
	keyType := fmt.Sprintf("%s PRIVATE KEY", strings.ToUpper(key.Scheme().Name()))
	blob, err := key.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if util.CtIsZero(blob) {
		panic(fmt.Sprintf("ToPEMString/%s: attempted to serialize scrubbed key", keyType))
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: blob,
	}
	return pem.EncodeToMemory(blk)
}

func PrivateKeyToFile(f string, key kem.PrivateKey) error {
	out, err := os.OpenFile(f, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	outBuf := ToPrivatePEMBytes(key)
	writeCount, err := out.Write(outBuf)
	if err != nil {
		return err
	}
	if writeCount != len(outBuf) {
		return errors.New("partial write failure")
	}
	err = out.Sync()
	if err != nil {
		return err
	}
	return out.Close()
}

func FromPrivatePEMString(s string, scheme kem.Scheme) (kem.PrivateKey, error) {
	return FromPrivatePEMPubBytes([]byte(s), scheme)
}

func FromPrivatePEMPubBytes(b []byte, scheme kem.Scheme) (kem.PrivateKey, error) {
	keyType := fmt.Sprintf("%s PRIVATE KEY", strings.ToUpper(scheme.Name()))
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("failed to decode PEM data from %s PEM", keyType)
	}
	if strings.ToUpper(blk.Type) != keyType {
		return nil, fmt.Errorf("attempted to decode PEM file with wrong key type %v != %v", blk.Type, keyType)
	}
	return scheme.UnmarshalBinaryPrivateKey(blk.Bytes)
}

func FromPrivatePEMFile(f string, scheme kem.Scheme) (kem.PrivateKey, error) {
	buf, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("pem.FromFile error: %s", err)
	}
	return FromPrivatePEMPubBytes(buf, scheme)
}
