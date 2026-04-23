package main

import (
	"crypto/rand"
	"crypto/sha256"
	"security-project/common/crypto"
	"testing"
)

func TestSHA256Interop(t *testing.T) {
	t.Run("stage1_ascii", func(t *testing.T) {
		plainStr := "Kerberos_Auth_SHA256_Test_2026"
		expectedHash1 := sha256.Sum256([]byte(plainStr))
		actualHash1 := crypto.Sum256([]byte(plainStr))
		if actualHash1 != expectedHash1 {
			t.Fatalf("stage1 hash mismatch: expected %x got %x", expectedHash1, actualHash1)
		}
	})

	t.Run("stage2_binary", func(t *testing.T) {
		binaryData := make([]byte, 45)
		if _, err := rand.Read(binaryData); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		binaryData[10] = 0x00
		binaryData[25] = 0x00

		expectedHash2 := sha256.Sum256(binaryData)
		actualHash2 := crypto.Sum256(binaryData)
		if actualHash2 != expectedHash2 {
			t.Fatalf("stage2 hash mismatch: expected %x got %x", expectedHash2, actualHash2)
		}
	})
}
