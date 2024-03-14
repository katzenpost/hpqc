/*
Copyright (c) 2019 Cloudflare. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Cloudflare nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

========================================================================

Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

package schemes_test

import (
	"fmt"
	"testing"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/schemes"
)

func TestCaseSensitivity(t *testing.T) {
	if schemes.ByName("ed25519") != schemes.ByName("Ed25519") {
		t.Fatal()
	}
}

func TestApi(t *testing.T) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		scheme := scheme
		t.Run(scheme.Name(), func(t *testing.T) {
			if scheme == nil {
				t.Fatal()
			}

			t.Logf("%s Signature size is %d\n", scheme.Name(), scheme.SignatureSize())

			pk, sk, err := scheme.GenerateKey()
			if err != nil {
				t.Fatal()
			}

			packedPk, err := pk.MarshalBinary()
			if err != nil {
				t.Fatal()
			}

			if len(packedPk) != scheme.PublicKeySize() {
				t.Fatal()
			}

			packedSk, err := sk.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			if len(packedSk) != scheme.PrivateKeySize() {
				t.Fatal()
			}

			pk2, err := scheme.UnmarshalBinaryPublicKey(packedPk)
			if err != nil {
				t.Fatal(err)
			}

			sk2, err := scheme.UnmarshalBinaryPrivateKey(packedSk)
			if err != nil {
				t.Fatal(err)
			}

			if !sk.Equal(sk2) {
				t.Fatal()
			}

			if !pk.Equal(pk2) {
				t.Fatal()
			}

			msg := []byte(fmt.Sprintf("Signing with %s", scheme.Name()))
			opts := &sign.SignatureOpts{}
			if scheme.SupportsContext() {
				opts.Context = "A context"
			}
			sig := scheme.Sign(sk, msg, opts)

			if scheme.SignatureSize() != len(sig) {
				t.Fatal()
			}

			if !scheme.Verify(pk2, msg, sig, opts) {
				t.Fatal()
			}

			if scheme.SupportsContext() {
				opts2 := opts
				opts2.Context = "Wrong context"
				if scheme.Verify(pk2, msg, sig, opts2) {
					t.Fatal()
				}
			}

			sig[0]++
			if scheme.Verify(pk2, msg, sig, opts) {
				t.Fatal()
			}

			scheme2 := schemes.ByName(scheme.Name())
			if scheme2 == nil || scheme2 != scheme {
				t.Fatal()
			}

			if pk.Scheme() != scheme {
				t.Fatal()
			}

			if sk.Scheme() != scheme {
				t.Fatal()
			}
		})
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		scheme := scheme
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _ = scheme.GenerateKey()
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	allSchemes := schemes.All()
	opts := &sign.SignatureOpts{}
	for _, scheme := range allSchemes {
		msg := []byte(fmt.Sprintf("Signing with %s", scheme.Name()))
		scheme := scheme
		_, sk, _ := scheme.GenerateKey()
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = scheme.Sign(sk, msg, opts)
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	allSchemes := schemes.All()
	opts := &sign.SignatureOpts{}
	for _, scheme := range allSchemes {
		msg := []byte(fmt.Sprintf("Signing with %s", scheme.Name()))
		scheme := scheme
		pk, sk, _ := scheme.GenerateKey()
		sig := scheme.Sign(sk, msg, opts)
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = scheme.Verify(pk, msg, sig, opts)
			}
		})
	}
}
