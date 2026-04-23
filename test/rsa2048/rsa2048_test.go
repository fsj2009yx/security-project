package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	crypto2 "security-project/common/crypto"
	"security-project/common/krb"
)

func TestRSA2048Interop(t *testing.T) {
	t.Run("stage1_verify_stdlib_signature", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		message := []byte("RSA_Raw_Interoperability_Test_2026")
		hashed := sha256.Sum256(message)
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15: %v", err)
		}
		pub := &crypto2.RSAKey{N: new(big.Int).Set(priv.N), E: big.NewInt(int64(priv.E))}
		if err := krb.VerifySHA256(message, toSig256(sig), pub); err != nil {
			t.Fatalf("our verifier rejected stdlib signature: %v", err)
		}
	})

	t.Run("stage2_sign_our_signature", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		message := []byte("Verify_Target_Signature_Logic")
		pub := &crypto2.RSAKey{N: new(big.Int).Set(priv.N), E: big.NewInt(int64(priv.E))}
		privK := &crypto2.RSAKey{N: new(big.Int).Set(priv.N), E: big.NewInt(int64(priv.E)), D: new(big.Int).Set(priv.D)}
		sig, err := krb.SignSHA256(message, privK)
		if err != nil {
			t.Fatalf("our signer failed: %v", err)
		}
		hashed := sha256.Sum256(message)
		if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hashed[:], sig[:]); err != nil {
			t.Fatalf("stdlib verifier rejected our signature: %v", err)
		}
		if err := krb.VerifySHA256(message, sig, pub); err != nil {
			t.Fatalf("our verifier rejected our signature: %v", err)
		}
	})
}

func toSig256(sig []byte) [256]byte {
	var out [256]byte
	copy(out[:], sig)
	return out
}
