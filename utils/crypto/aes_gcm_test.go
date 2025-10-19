// Copyright 2024 The NewBee Authors. All Rights Reserved.

package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"AES-128", 16, false},
		{"AES-192", 24, false},
		{"AES-256", 32, false},
		{"Invalid size", 20, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey(tt.size)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.size, len(key))
		})
	}
}

func TestGenerateKeyBase64(t *testing.T) {
	keyBase64, err := GenerateKeyBase64(AES256KeySize)
	require.NoError(t, err)
	
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	require.NoError(t, err)
	assert.Equal(t, AES256KeySize, len(key))
}

func TestNewAESGCMCipher(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantErr bool
	}{
		{"Valid AES-128", 16, false},
		{"Valid AES-192", 24, false},
		{"Valid AES-256", 32, false},
		{"Invalid size", 20, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := GenerateKey(tt.keySize)
			cipher, err := NewAESGCMCipher(key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cipher)
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey(AES256KeySize)
	require.NoError(t, err)

	cipher, err := NewAESGCMCipher(key)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		plaintext string
	}{
		{"Simple text", "Hello, World!"},
		{"Empty string", ""},
		{"JSON data", `{"user":"test","password":"secret"}`},
		{"Unicode", "你好世界🌍"},
		{"Long text", string(make([]byte, 10000))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, nonce, err := cipher.Encrypt([]byte(tc.plaintext))
			require.NoError(t, err)
			assert.Equal(t, GCMNonceSize, len(nonce))

			decrypted, err := cipher.Decrypt(ciphertext, nonce)
			require.NoError(t, err)
			assert.Equal(t, tc.plaintext, string(decrypted))
		})
	}
}

func TestEncryptDecryptBase64(t *testing.T) {
	key, err := GenerateKey(AES256KeySize)
	require.NoError(t, err)

	cipher, err := NewAESGCMCipher(key)
	require.NoError(t, err)

	plaintext := `{"username":"admin","data":{"items":[1,2,3]}}`

	ciphertextB64, nonceB64, err := cipher.EncryptToBase64([]byte(plaintext))
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertextB64)
	assert.NotEmpty(t, nonceB64)

	decrypted, err := cipher.DecryptFromBase64(ciphertextB64, nonceB64)
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(decrypted))
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1, _ := GenerateKey(AES256KeySize)
	key2, _ := GenerateKey(AES256KeySize)

	cipher1, _ := NewAESGCMCipher(key1)
	cipher2, _ := NewAESGCMCipher(key2)

	plaintext := []byte("secret message")
	ciphertext, nonce, err := cipher1.Encrypt(plaintext)
	require.NoError(t, err)

	_, err = cipher2.Decrypt(ciphertext, nonce)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestDecryptWithTamperedData(t *testing.T) {
	key, _ := GenerateKey(AES256KeySize)
	cipher, _ := NewAESGCMCipher(key)

	plaintext := []byte("important data")
	ciphertext, nonce, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)

	ciphertext[5] ^= 0xFF

	_, err = cipher.Decrypt(ciphertext, nonce)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}

func TestDecryptWithInvalidNonceSize(t *testing.T) {
	key, _ := GenerateKey(AES256KeySize)
	cipher, _ := NewAESGCMCipher(key)

	plaintext := []byte("test")
	ciphertext, _, err := cipher.Encrypt(plaintext)
	require.NoError(t, err)

	invalidNonce := make([]byte, 8)
	_, err = cipher.Decrypt(ciphertext, invalidNonce)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nonce size")
}

func TestNewAESGCMCipherFromBase64(t *testing.T) {
	keyB64 := "ZLc5cHF1ZjJzMTZ3OXh5emFiY2RlZmdoaWprbG1ub3A="
	
	cipher, err := NewAESGCMCipherFromBase64(keyB64)
	require.NoError(t, err)

	plaintext := "test encryption"
	ciphertext, nonce, err := cipher.Encrypt([]byte(plaintext))
	require.NoError(t, err)

	decrypted, err := cipher.Decrypt(ciphertext, nonce)
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(decrypted))
}

func TestNewAESGCMCipherFromBase64_InvalidBase64(t *testing.T) {
	_, err := NewAESGCMCipherFromBase64("invalid-base64!!!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode")
}

func BenchmarkEncrypt(b *testing.B) {
	key, _ := GenerateKey(AES256KeySize)
	cipher, _ := NewAESGCMCipher(key)
	plaintext := []byte("benchmark data for encryption performance testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = cipher.Encrypt(plaintext)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key, _ := GenerateKey(AES256KeySize)
	cipher, _ := NewAESGCMCipher(key)
	plaintext := []byte("benchmark data for decryption performance testing")
	ciphertext, nonce, _ := cipher.Encrypt(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cipher.Decrypt(ciphertext, nonce)
	}
}

func BenchmarkEncryptToBase64(b *testing.B) {
	key, _ := GenerateKey(AES256KeySize)
	cipher, _ := NewAESGCMCipher(key)
	plaintext := []byte(`{"user":"test","data":{"items":[1,2,3,4,5]}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = cipher.EncryptToBase64(plaintext)
	}
}
