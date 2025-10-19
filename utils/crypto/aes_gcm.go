// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	// AES-256需要32字节密钥
	AES256KeySize = 32
	// GCM标准IV大小为12字节
	GCMNonceSize = 12
)

// AESGCMCipher AES-GCM加密器
type AESGCMCipher struct {
	key []byte
}

// NewAESGCMCipher 创建AES-GCM加密器
// key: AES密钥（16/24/32字节，对应AES-128/192/256）
func NewAESGCMCipher(key []byte) (*AESGCMCipher, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: %d, must be 16, 24, or 32 bytes", len(key))
	}
	return &AESGCMCipher{key: key}, nil
}

// NewAESGCMCipherFromBase64 从Base64编码的密钥创建加密器
func NewAESGCMCipherFromBase64(keyBase64 string) (*AESGCMCipher, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key: %w", err)
	}
	return NewAESGCMCipher(key)
}

// Encrypt 加密数据
// 返回: (密文, IV, error)
func (c *AESGCMCipher) Encrypt(plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// 生成随机IV
	nonce := make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// 加密（GCM会自动添加认证标签）
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

// EncryptToBase64 加密并返回Base64编码
// 返回: (密文Base64, IV Base64, error)
func (c *AESGCMCipher) EncryptToBase64(plaintext []byte) (string, string, error) {
	ciphertext, nonce, err := c.Encrypt(plaintext)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext),
		base64.StdEncoding.EncodeToString(nonce),
		nil
}

// Decrypt 解密数据
func (c *AESGCMCipher) Decrypt(ciphertext []byte, nonce []byte) ([]byte, error) {
	if len(nonce) != GCMNonceSize {
		return nil, fmt.Errorf("invalid nonce size: %d, expected %d", len(nonce), GCMNonceSize)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// 解密并验证认证标签
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (data may be tampered): %w", err)
	}

	return plaintext, nil
}

// DecryptFromBase64 从Base64解密
func (c *AESGCMCipher) DecryptFromBase64(ciphertextBase64 string, nonceBase64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	return c.Decrypt(ciphertext, nonce)
}

// GenerateKey 生成指定大小的随机密钥
// size: 16 (AES-128), 24 (AES-192), 32 (AES-256)
func GenerateKey(size int) ([]byte, error) {
	if size != 16 && size != 24 && size != 32 {
		return nil, fmt.Errorf("invalid key size: %d, must be 16, 24, or 32", size)
	}

	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return key, nil
}

// GenerateKeyBase64 生成Base64编码的随机密钥
func GenerateKeyBase64(size int) (string, error) {
	key, err := GenerateKey(size)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
