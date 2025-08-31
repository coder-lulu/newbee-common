// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");

package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/auth/core"
)

// KeyManager handles secure key management with dynamic loading and rotation
type KeyManager struct {
	mu           sync.RWMutex
	keys         map[string]*SecureKey
	defaultKeyID string
	rotationInterval time.Duration
	maxKeyAge    time.Duration
	autoRotate   bool
}

// SecureKey represents a cryptographic key with metadata
type SecureKey struct {
	ID        string    `json:"id"`
	KeyData   []byte    `json:"-"` // Never serialize the actual key
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Usage     KeyUsage  `json:"usage"`
	TenantID  string    `json:"tenant_id,omitempty"` // For multi-tenant key isolation
}

// KeyUsage defines how a key can be used
type KeyUsage string

const (
	KeyUsageSign      KeyUsage = "sign"
	KeyUsageVerify    KeyUsage = "verify"
	KeyUsageSignVerify KeyUsage = "sign-verify"
	KeyUsageEncrypt   KeyUsage = "encrypt"
	KeyUsageDecrypt   KeyUsage = "decrypt"
)

// NewKeyManager creates a new key manager with secure defaults
func NewKeyManager(rotationInterval, maxKeyAge time.Duration) *KeyManager {
	return &KeyManager{
		keys:             make(map[string]*SecureKey),
		rotationInterval: rotationInterval,
		maxKeyAge:        maxKeyAge,
		autoRotate:       true,
	}
}

// LoadKey loads a key from various sources (Fix #1: No hardcoded secrets)
func (km *KeyManager) LoadKey(keyID, source, algorithm string, usage KeyUsage, tenantID string) error {
	keyData, err := km.loadKeyFromSource(source)
	if err != nil {
		return fmt.Errorf("failed to load key %s: %w", keyID, err)
	}

	// Validate key strength
	if err := km.validateKeyStrength(keyData, algorithm); err != nil {
		return fmt.Errorf("key validation failed for %s: %w", keyID, err)
	}

	key := &SecureKey{
		ID:        keyID,
		KeyData:   keyData,
		Algorithm: algorithm,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(km.maxKeyAge),
		Usage:     usage,
		TenantID:  tenantID,
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	km.keys[keyID] = key
	if km.defaultKeyID == "" {
		km.defaultKeyID = keyID
	}

	return nil
}

// GetKey retrieves a key by ID with security validation
func (km *KeyManager) GetKey(keyID string) (*SecureKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	key, exists := km.keys[keyID]
	if !exists {
		return nil, &core.AuthError{
			Code:    "KEY_NOT_FOUND",
			Message: fmt.Sprintf("Key %s not found", keyID),
		}
	}

	// Check if key is expired
	if time.Now().After(key.ExpiresAt) {
		return nil, &core.AuthError{
			Code:    "KEY_EXPIRED",
			Message: fmt.Sprintf("Key %s has expired", keyID),
		}
	}

	return key, nil
}

// GetKeyForTenant retrieves a tenant-specific key (Fix #5: Tenant isolation)
func (km *KeyManager) GetKeyForTenant(tenantID string) (*SecureKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	// Look for tenant-specific key first
	for _, key := range km.keys {
		if key.TenantID == tenantID && time.Now().Before(key.ExpiresAt) {
			return key, nil
		}
	}

	// NO FALLBACK TO MASTER KEY - strict tenant isolation
	return nil, &core.AuthError{
		Code:    core.ErrCodeTenantViolation,
		Message: fmt.Sprintf("No valid key found for tenant %s", tenantID),
	}
}

// GenerateKey generates a new cryptographic key
func (km *KeyManager) GenerateKey(keyID, algorithm string, usage KeyUsage, tenantID string) error {
	var keyLength int
	switch algorithm {
	case "HS256":
		keyLength = 32 // 256 bits
	case "HS384":
		keyLength = 48 // 384 bits
	case "HS512":
		keyLength = 64 // 512 bits
	default:
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	// Generate cryptographically secure random key
	keyData := make([]byte, keyLength)
	if _, err := rand.Read(keyData); err != nil {
		return fmt.Errorf("failed to generate random key: %w", err)
	}

	key := &SecureKey{
		ID:        keyID,
		KeyData:   keyData,
		Algorithm: algorithm,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(km.maxKeyAge),
		Usage:     usage,
		TenantID:  tenantID,
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	km.keys[keyID] = key
	if km.defaultKeyID == "" {
		km.defaultKeyID = keyID
	}

	return nil
}

// RotateKey creates a new version of an existing key
func (km *KeyManager) RotateKey(keyID string) error {
	km.mu.RLock()
	oldKey, exists := km.keys[keyID]
	km.mu.RUnlock()

	if !exists {
		return fmt.Errorf("key %s not found for rotation", keyID)
	}

	// Generate new key with same parameters
	newKeyID := fmt.Sprintf("%s_v%d", keyID, time.Now().Unix())
	if err := km.GenerateKey(newKeyID, oldKey.Algorithm, oldKey.Usage, oldKey.TenantID); err != nil {
		return fmt.Errorf("failed to rotate key %s: %w", keyID, err)
	}

	// Keep old key for grace period (allows tokens signed with old key to still validate)
	km.mu.Lock()
	oldKey.ExpiresAt = time.Now().Add(time.Hour) // 1-hour grace period
	km.defaultKeyID = newKeyID // Switch to new key for new tokens
	km.mu.Unlock()

	return nil
}

// StartAutoRotation starts automatic key rotation
func (km *KeyManager) StartAutoRotation() {
	if !km.autoRotate {
		return
	}

	go func() {
		ticker := time.NewTicker(km.rotationInterval)
		defer ticker.Stop()

		for range ticker.C {
			km.mu.RLock()
			keysToRotate := make([]string, 0)
			for keyID, key := range km.keys {
				if time.Until(key.ExpiresAt) < km.rotationInterval {
					keysToRotate = append(keysToRotate, keyID)
				}
			}
			km.mu.RUnlock()

			for _, keyID := range keysToRotate {
				if err := km.RotateKey(keyID); err != nil {
					// Log error but don't stop rotation
					fmt.Printf("Failed to rotate key %s: %v\n", keyID, err)
				}
			}
		}
	}()
}

// CleanupExpiredKeys removes expired keys from memory
func (km *KeyManager) CleanupExpiredKeys() {
	km.mu.Lock()
	defer km.mu.Unlock()

	for keyID, key := range km.keys {
		if time.Now().After(key.ExpiresAt.Add(time.Hour)) { // Extra hour buffer
			delete(km.keys, keyID)
		}
	}
}

// GetDefaultKey returns the current default key for signing
func (km *KeyManager) GetDefaultKey() (*SecureKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.defaultKeyID == "" {
		return nil, errors.New("no default key configured")
	}

	return km.GetKey(km.defaultKeyID)
}

// ListKeys returns metadata about all keys (without sensitive data)
func (km *KeyManager) ListKeys() []map[string]interface{} {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keys := make([]map[string]interface{}, 0, len(km.keys))
	for _, key := range km.keys {
		keys = append(keys, map[string]interface{}{
			"id":         key.ID,
			"algorithm":  key.Algorithm,
			"created_at": key.CreatedAt,
			"expires_at": key.ExpiresAt,
			"usage":      key.Usage,
			"tenant_id":  key.TenantID,
			"is_expired": time.Now().After(key.ExpiresAt),
		})
	}

	return keys
}

// loadKeyFromSource loads key material from various sources (Fix #1)
func (km *KeyManager) loadKeyFromSource(source string) ([]byte, error) {
	if source == "" {
		return nil, errors.New("key source cannot be empty")
	}

	// Environment variable source
	if strings.HasPrefix(source, "env:") {
		envVar := strings.TrimPrefix(source, "env:")
		keyData := os.Getenv(envVar)
		if keyData == "" {
			return nil, fmt.Errorf("environment variable %s is empty or not set", envVar)
		}
		return []byte(keyData), nil
	}

	// File source
	if strings.HasPrefix(source, "file:") {
		filePath := strings.TrimPrefix(source, "file:")
		keyData, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", filePath, err)
		}
		return keyData, nil
	}

	// Hex-encoded source
	if strings.HasPrefix(source, "hex:") {
		hexData := strings.TrimPrefix(source, "hex:")
		keyData, err := hex.DecodeString(hexData)
		if err != nil {
			return nil, fmt.Errorf("invalid hex-encoded key: %w", err)
		}
		return keyData, nil
	}

	// Direct source (for testing only - not recommended for production)
	if strings.HasPrefix(source, "direct:") {
		return []byte(strings.TrimPrefix(source, "direct:")), nil
	}

	return nil, fmt.Errorf("unsupported key source format: %s", source)
}

// validateKeyStrength validates that the key meets security requirements
func (km *KeyManager) validateKeyStrength(keyData []byte, algorithm string) error {
	if len(keyData) == 0 {
		return errors.New("key data cannot be empty")
	}

	var minLength int
	switch algorithm {
	case "HS256":
		minLength = 32 // 256 bits minimum
	case "HS384":
		minLength = 48 // 384 bits minimum
	case "HS512":
		minLength = 64 // 512 bits minimum
	default:
		return fmt.Errorf("unsupported algorithm for validation: %s", algorithm)
	}

	if len(keyData) < minLength {
		return fmt.Errorf("key length %d is below minimum %d bytes for %s", len(keyData), minLength, algorithm)
	}

	// Check for weak keys (all same character, common patterns)
	if km.isWeakKey(keyData) {
		return errors.New("key appears to be weak or predictable")
	}

	return nil
}

// isWeakKey performs basic checks for weak key patterns
func (km *KeyManager) isWeakKey(keyData []byte) bool {
	if len(keyData) == 0 {
		return true
	}

	// Check if all bytes are the same
	firstByte := keyData[0]
	allSame := true
	for _, b := range keyData[1:] {
		if b != firstByte {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	// Check for common weak patterns
	keyStr := string(keyData)
	weakPatterns := []string{"password", "secret", "key", "admin", "test", "123456"}
	for _, pattern := range weakPatterns {
		if strings.Contains(strings.ToLower(keyStr), pattern) {
			return true
		}
	}

	return false
}

// GetKeyHash returns a hash of the key for identification (not the key itself)
func (km *KeyManager) GetKeyHash(keyID string) (string, error) {
	key, err := km.GetKey(keyID)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(key.KeyData)
	return hex.EncodeToString(hash[:])[:16], nil // Return first 16 chars of hash
}