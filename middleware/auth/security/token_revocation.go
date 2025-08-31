// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");

package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/auth/core"
)

// TokenRevocation handles token blacklisting and revocation
type TokenRevocation struct {
	mu             sync.RWMutex
	blacklistedTokens map[string]*RevokedToken
	cleanupInterval   time.Duration
	maxStoredTokens   int
	// Optional Redis client for distributed revocation
	redisClient interface{} // Placeholder for Redis client interface
}

// RevokedToken represents a revoked token with metadata
type RevokedToken struct {
	TokenID    string    `json:"token_id"`
	TokenHash  string    `json:"token_hash"` // Store hash, not actual token
	RevokedAt  time.Time `json:"revoked_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Reason     string    `json:"reason"`
	UserID     string    `json:"user_id,omitempty"`
	TenantID   string    `json:"tenant_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
}

// RevocationReason defines common revocation reasons
type RevocationReason string

const (
	ReasonUserLogout        RevocationReason = "user_logout"
	ReasonPasswordChanged   RevocationReason = "password_changed"
	ReasonSecurityBreach    RevocationReason = "security_breach"
	ReasonAdminRevocation   RevocationReason = "admin_revocation"
	ReasonSessionExpired    RevocationReason = "session_expired"
	ReasonSuspiciousActivity RevocationReason = "suspicious_activity"
)

// NewTokenRevocation creates a new token revocation manager
func NewTokenRevocation(cleanupInterval time.Duration, maxStoredTokens int) *TokenRevocation {
	tr := &TokenRevocation{
		blacklistedTokens: make(map[string]*RevokedToken),
		cleanupInterval:   cleanupInterval,
		maxStoredTokens:   maxStoredTokens,
	}

	// Start background cleanup
	go tr.startCleanupRoutine()

	return tr
}

// RevokeToken revokes a specific token by its content
func (tr *TokenRevocation) RevokeToken(tokenString, reason, userID, tenantID, sessionID string, expiry time.Time) error {
	if tokenString == "" {
		return fmt.Errorf("token string cannot be empty")
	}

	tokenHash := tr.hashToken(tokenString)
	tokenID := tr.generateTokenID(tokenString)

	revokedToken := &RevokedToken{
		TokenID:   tokenID,
		TokenHash: tokenHash,
		RevokedAt: time.Now(),
		ExpiresAt: expiry,
		Reason:    reason,
		UserID:    userID,
		TenantID:  tenantID,
		SessionID: sessionID,
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()

	// Check storage limits
	if len(tr.blacklistedTokens) >= tr.maxStoredTokens {
		tr.cleanupExpiredNoLock()
	}

	tr.blacklistedTokens[tokenHash] = revokedToken

	return nil
}

// IsTokenRevoked checks if a token is revoked
func (tr *TokenRevocation) IsTokenRevoked(tokenString string) bool {
	if tokenString == "" {
		return false
	}

	tokenHash := tr.hashToken(tokenString)

	tr.mu.RLock()
	defer tr.mu.RUnlock()

	revokedToken, exists := tr.blacklistedTokens[tokenHash]
	if !exists {
		return false
	}

	// Check if the revocation has expired
	if time.Now().After(revokedToken.ExpiresAt) {
		// Token revocation has expired, remove it
		go func() {
			tr.mu.Lock()
			delete(tr.blacklistedTokens, tokenHash)
			tr.mu.Unlock()
		}()
		return false
	}

	return true
}

// RevokeAllUserTokens revokes all tokens for a specific user
func (tr *TokenRevocation) RevokeAllUserTokens(userID, reason string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()

	count := 0
	for _, revokedToken := range tr.blacklistedTokens {
		if revokedToken.UserID == userID {
			// Extend expiration to ensure tokens remain revoked
			revokedToken.ExpiresAt = time.Now().Add(24 * time.Hour)
			revokedToken.Reason = reason
			count++
		}
	}

	return nil
}

// RevokeAllTenantTokens revokes all tokens for a specific tenant
func (tr *TokenRevocation) RevokeAllTenantTokens(tenantID, reason string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()

	count := 0
	for _, revokedToken := range tr.blacklistedTokens {
		if revokedToken.TenantID == tenantID {
			// Extend expiration to ensure tokens remain revoked
			revokedToken.ExpiresAt = time.Now().Add(24 * time.Hour)
			revokedToken.Reason = reason
			count++
		}
	}

	return nil
}

// RevokeAllSessionTokens revokes all tokens for a specific session
func (tr *TokenRevocation) RevokeAllSessionTokens(sessionID, reason string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	tr.mu.Lock()
	defer tr.mu.Unlock()

	for _, revokedToken := range tr.blacklistedTokens {
		if revokedToken.SessionID == sessionID {
			// Extend expiration to ensure tokens remain revoked
			revokedToken.ExpiresAt = time.Now().Add(24 * time.Hour)
			revokedToken.Reason = reason
		}
	}

	return nil
}

// GetRevocationInfo returns information about a revoked token
func (tr *TokenRevocation) GetRevocationInfo(tokenString string) (*RevokedToken, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("token string cannot be empty")
	}

	tokenHash := tr.hashToken(tokenString)

	tr.mu.RLock()
	defer tr.mu.RUnlock()

	revokedToken, exists := tr.blacklistedTokens[tokenHash]
	if !exists {
		return nil, fmt.Errorf("token is not revoked")
	}

	// Return a copy to prevent external modification
	return &RevokedToken{
		TokenID:   revokedToken.TokenID,
		TokenHash: revokedToken.TokenHash,
		RevokedAt: revokedToken.RevokedAt,
		ExpiresAt: revokedToken.ExpiresAt,
		Reason:    revokedToken.Reason,
		UserID:    revokedToken.UserID,
		TenantID:  revokedToken.TenantID,
		SessionID: revokedToken.SessionID,
	}, nil
}

// ListRevokedTokens returns a list of currently revoked tokens (for admin purposes)
func (tr *TokenRevocation) ListRevokedTokens(limit int) []*RevokedToken {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	tokens := make([]*RevokedToken, 0, limit)
	count := 0

	for _, revokedToken := range tr.blacklistedTokens {
		if count >= limit {
			break
		}
		// Don't include the actual hash in the response
		tokens = append(tokens, &RevokedToken{
			TokenID:   revokedToken.TokenID,
			RevokedAt: revokedToken.RevokedAt,
			ExpiresAt: revokedToken.ExpiresAt,
			Reason:    revokedToken.Reason,
			UserID:    revokedToken.UserID,
			TenantID:  revokedToken.TenantID,
			SessionID: revokedToken.SessionID,
		})
		count++
	}

	return tokens
}

// GetStats returns statistics about token revocation
func (tr *TokenRevocation) GetStats() map[string]interface{} {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	now := time.Now()
	active := 0
	expired := 0

	reasonCounts := make(map[string]int)

	for _, revokedToken := range tr.blacklistedTokens {
		if now.After(revokedToken.ExpiresAt) {
			expired++
		} else {
			active++
		}
		reasonCounts[revokedToken.Reason]++
	}

	return map[string]interface{}{
		"total_revoked":    len(tr.blacklistedTokens),
		"active_revoked":   active,
		"expired_revoked":  expired,
		"reason_breakdown": reasonCounts,
	}
}

// CleanupExpiredTokens manually triggers cleanup of expired token revocations
func (tr *TokenRevocation) CleanupExpiredTokens() int {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	return tr.cleanupExpiredNoLock()
}

// ValidateTokenWithRevocationCheck combines token validation with revocation check
func (tr *TokenRevocation) ValidateTokenWithRevocationCheck(ctx context.Context, tokenString string, validator core.TokenValidator) (*core.Claims, error) {
	// First check if token is revoked
	if tr.IsTokenRevoked(tokenString) {
		revInfo, _ := tr.GetRevocationInfo(tokenString)
		reason := "unknown"
		if revInfo != nil {
			reason = revInfo.Reason
		}
		return nil, &core.AuthError{
			Code:    core.ErrCodeTokenRevoked,
			Message: fmt.Sprintf("Token has been revoked: %s", reason),
		}
	}

	// If not revoked, proceed with normal validation
	return validator.ValidateToken(tokenString)
}

// hashToken creates a SHA-256 hash of the token for storage (security best practice)
func (tr *TokenRevocation) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// generateTokenID creates a shorter token ID from the hash
func (tr *TokenRevocation) generateTokenID(token string) string {
	hash := tr.hashToken(token)
	return hash[:16] // Use first 16 characters as ID
}

// startCleanupRoutine starts the background cleanup routine
func (tr *TokenRevocation) startCleanupRoutine() {
	ticker := time.NewTicker(tr.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cleaned := tr.CleanupExpiredTokens()
		if cleaned > 0 {
			// Optional: Log cleanup activity
			fmt.Printf("Cleaned up %d expired token revocations\n", cleaned)
		}
	}
}

// cleanupExpiredNoLock removes expired token revocations (must be called with lock held)
func (tr *TokenRevocation) cleanupExpiredNoLock() int {
	now := time.Now()
	count := 0

	for hash, revokedToken := range tr.blacklistedTokens {
		if now.After(revokedToken.ExpiresAt) {
			delete(tr.blacklistedTokens, hash)
			count++
		}
	}

	return count
}

// Plugin interface implementation for integration with auth middleware
type RevocationPlugin struct {
	revocation *TokenRevocation
}

// NewRevocationPlugin creates a new revocation plugin
func NewRevocationPlugin(revocation *TokenRevocation) *RevocationPlugin {
	return &RevocationPlugin{
		revocation: revocation,
	}
}

// Name returns the plugin name
func (rp *RevocationPlugin) Name() string {
	return "token_revocation"
}

// Priority returns the plugin priority (high priority for security)
func (rp *RevocationPlugin) Priority() int {
	return 100 // High priority - check revocation before other validations
}

// PreProcess checks if token is revoked before processing
func (rp *RevocationPlugin) PreProcess(ctx context.Context, token string, req interface{}) error {
	if rp.revocation.IsTokenRevoked(token) {
		return &core.AuthError{
			Code:    core.ErrCodeTokenRevoked,
			Message: "Token has been revoked",
		}
	}
	return nil
}

// PostProcess does nothing for revocation plugin
func (rp *RevocationPlugin) PostProcess(ctx context.Context, claims *core.Claims, req interface{}) (context.Context, error) {
	return ctx, nil
}

// OnError handles errors (could log revocation attempts)
func (rp *RevocationPlugin) OnError(ctx context.Context, err error, req interface{}) {
	// Optional: Log suspicious activities that might warrant token revocation
}