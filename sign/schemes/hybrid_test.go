package schemes

import (
	"testing"
)

// TestHybridSchemeInitialization tests the initialization and basic operations of the hybrid scheme.
func TestHybridSchemeInitialization(t *testing.T) {
	hybridScheme := ByName("Ed25519 Sphincs+")
	if hybridScheme == nil {
		t.Fatal("Hybrid scheme 'Ed25519 Sphincs+' not available")
	}

	pub, priv, err := hybridScheme.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	message := []byte("test message")
	signature := hybridScheme.Sign(priv, message, nil)
	if !hybridScheme.Verify(pub, message, signature, nil) {
		t.Error("Verification failed, signature should be valid")
	}

	// Negative test: verify with altered message
	alteredMessage := []byte("altered test message")
	if hybridScheme.Verify(pub, alteredMessage, signature, nil) {
		t.Error("Verification succeeded, should fail with altered message")
	}
}
