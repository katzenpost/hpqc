package wire

import (
	"bytes"
	"testing"

	"github.com/katzenpost/nyquist"
	"github.com/katzenpost/nyquist/cipher"
	"github.com/katzenpost/nyquist/hash"
	"github.com/katzenpost/nyquist/kem"
	"github.com/katzenpost/nyquist/pattern"
	"github.com/katzenpost/nyquist/seec"

	"github.com/katzenpost/hpqc/primitive/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
)

func BenchmarkPQNoise(b *testing.B) {
	seecGenRand, err := seec.GenKeyPRPAES(rand.Reader, 256)
	if err != nil {
		panic(err)
	}

	protocol := &nyquist.Protocol{
		Pattern: pattern.PqXX,
		KEM: kem.FromHpqcKEM(
			schemes.ByName("sntrup4591761_X25519"),
		),
		Cipher: cipher.ChaChaPoly,
		Hash:   hash.BLAKE2s,
	}

	clientStatic, err := protocol.KEM.GenerateKeypair(seecGenRand)
	if err != nil {
		panic(err)
	}

	wireVersion := []byte{0x03} // Prologue indicates version 3.
	maxMsgLen := 1048576

	clientCfg := &nyquist.HandshakeConfig{
		Protocol:       protocol,
		Rng:            rand.Reader,
		Prologue:       wireVersion,
		MaxMessageSize: maxMsgLen,
		KEM: &nyquist.KEMConfig{
			LocalStatic: clientStatic,
			GenKey:      seec.GenKeyPRPAES,
		},
		IsInitiator: true,
	}

	serverStatic, err := protocol.KEM.GenerateKeypair(seecGenRand)
	if err != nil {
		panic(err)
	}

	serverCfg := &nyquist.HandshakeConfig{
		Protocol:       protocol,
		Rng:            rand.Reader,
		Prologue:       wireVersion,
		MaxMessageSize: maxMsgLen,
		KEM: &nyquist.KEMConfig{
			LocalStatic: serverStatic,
			GenKey:      seec.GenKeyPRPAES,
		},
		IsInitiator: false,
	}

	var serverMsg3 []byte
	var serverMsg3Plaintext []byte
	const plaintext = "I tell you: one must still have chaos in oneself in order to be able to give birth to a dancing star. I tell you: you still have chaos within you."

	for n := 0; n < b.N; n++ {

		clientHs, err := nyquist.NewHandshake(clientCfg)
		if err != nil {
			panic(err)
		}
		defer clientHs.Reset()

		serverHs, err := nyquist.NewHandshake(serverCfg)
		if err != nil {
			panic(err)
		}
		defer serverHs.Reset()

		clientSs := clientHs.SymmetricState()
		if clientSs == nil {
			panic("found nil")
		}
		clientCs := clientSs.CipherState()
		if clientCs == nil {
			panic("found nil")
		}

		var (
			authLen = 1 + MaxAdditionalDataLength + 4
		)

		// (client) -> (prologue), e
		clientMsg1, err := clientHs.WriteMessage(nil, nil)
		if err != nil {
			panic(err)
		}

		_, err = serverHs.ReadMessage(nil, clientMsg1)
		if err != nil {
			panic(err)
		}

		// -> ekem, s, (auth)
		rawAuth := make([]byte, authLen)
		serverMsg1, err := serverHs.WriteMessage(nil, rawAuth)
		if err != nil {
			panic(err)
		}

		_, err = clientHs.ReadMessage(nil, serverMsg1)
		if err != nil {
			panic(err)
		}

		// -> skem, s, (auth)
		clientMsg2, err := clientHs.WriteMessage(nil, rawAuth)
		if err != nil {
			panic(err)
		}

		_, err = serverHs.ReadMessage(nil, clientMsg2)
		if err != nil {
			panic(err)
		}

		// (server) -> skem
		serverMsg2, err := serverHs.WriteMessage(nil, nil)
		if err != nyquist.ErrDone {
			panic(err)
		}

		_, err = clientHs.ReadMessage(nil, serverMsg2)
		if err != nyquist.ErrDone {
			panic(err)
		}

		clientStatus := clientHs.GetStatus()
		serverStatus := serverHs.GetStatus()

		// send messages

		_, clientrx := clientStatus.CipherStates[0], clientStatus.CipherStates[1]
		_, servertx := serverStatus.CipherStates[0], serverStatus.CipherStates[1]

		serverMsg3, err = servertx.EncryptWithAd(nil, nil, []byte(plaintext))
		if err != nil {
			b.Fatal(err)
		}

		serverMsg3Plaintext, err = clientrx.DecryptWithAd(nil, nil, serverMsg3)
		if err != nil {
			b.Fatal(err)
		}
	}

	if !bytes.Equal(serverMsg3Plaintext[:], []byte(plaintext)) {
		b.Fatal("decrypted plaintext does not match")
	}
}

func BenchmarkClassicalNoise(b *testing.B) {
	protocol, err := nyquist.NewProtocol("Noise_XX_25519_ChaChaPoly_BLAKE2s")
	if err != nil {
		panic(err)
	}

	clientStatic, err := protocol.DH.GenerateKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}

	clientCfg := &nyquist.HandshakeConfig{
		Protocol: protocol,
		DH: &nyquist.DHConfig{
			LocalStatic: clientStatic,
		},
		IsInitiator: true,
	}

	serverStatic, err := protocol.DH.GenerateKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}

	serverCfg := &nyquist.HandshakeConfig{
		Protocol: protocol,
		DH: &nyquist.DHConfig{
			LocalStatic: serverStatic,
		},
		IsInitiator: false,
	}

	var serverMsg3 []byte
	var serverMsg3Plaintext []byte
	const plaintext = "I tell you: one must still have chaos in oneself in order to be able to give birth to a dancing star. I tell you: you still have chaos within you."

	for n := 0; n < b.N; n++ {

		clientHs, err := nyquist.NewHandshake(clientCfg)
		if err != nil {
			panic(err)
		}
		defer clientHs.Reset()

		serverHs, err := nyquist.NewHandshake(serverCfg)
		if err != nil {
			panic(err)
		}
		defer serverHs.Reset()

		clientSs := clientHs.SymmetricState()
		if clientSs == nil {
			panic("found nil")
		}
		clientCs := clientSs.CipherState()
		if clientCs == nil {
			panic("found nil")
		}

		var (
			authLen = 1 + MaxAdditionalDataLength + 4
		)

		// (client) -> (prologue), e
		clientMsg1, err := clientHs.WriteMessage(nil, nil)
		if err != nil {
			panic(err)
		}

		_, err = serverHs.ReadMessage(nil, clientMsg1)
		if err != nil {
			panic(err)
		}

		// -> ekem, s, (auth)
		rawAuth := make([]byte, authLen)
		serverMsg1, err := serverHs.WriteMessage(nil, rawAuth)
		if err != nil {
			panic(err)
		}

		_, err = clientHs.ReadMessage(nil, serverMsg1)
		if err != nil {
			panic(err)
		}

		// -> skem, s, (auth)
		clientMsg2, err := clientHs.WriteMessage(nil, rawAuth)
		if err != nyquist.ErrDone {
			panic(err)
		}

		_, err = serverHs.ReadMessage(nil, clientMsg2)
		if err != nyquist.ErrDone {
			panic(err)
		}

		// (server) -> skem
		serverMsg2, err := serverHs.WriteMessage(nil, nil)
		if err != nyquist.ErrDone {
			panic(err)
		}

		_, err = clientHs.ReadMessage(nil, serverMsg2)
		if err != nyquist.ErrDone {
			panic(err)
		}

		clientStatus := clientHs.GetStatus()
		serverStatus := serverHs.GetStatus()

		// send messages

		_, clientrx := clientStatus.CipherStates[0], clientStatus.CipherStates[1]
		_, servertx := serverStatus.CipherStates[0], serverStatus.CipherStates[1]

		serverMsg3, err = servertx.EncryptWithAd(nil, nil, []byte(plaintext))
		if err != nil {
			b.Fatal(err)
		}

		serverMsg3Plaintext, err = clientrx.DecryptWithAd(nil, nil, serverMsg3)
		if err != nil {
			b.Fatal(err)
		}
	}

	if !bytes.Equal(serverMsg3Plaintext[:], []byte(plaintext)) {
		b.Fatal("decrypted plaintext does not match")
	}
}
