// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");

package core

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTValidator implements the TokenValidator interface with security fixes
type JWTValidator struct {
	mu              sync.RWMutex
	secretKey       []byte
	algorithm       string
	allowedAlgorithms map[string]bool
	clockSkew       time.Duration
}

// NewJWTValidator creates a new JWT validator with secure defaults
func NewJWTValidator(algorithm, secretSource string, clockSkew time.Duration) (*JWTValidator, error) {
	// Fix #1: Remove hardcoded secrets, load from environment
	secretKey, err := loadSecretFromSource(secretSource)
	if err != nil {
		return nil, &AuthError{
			Code:    "INVALID_CONFIG",
			Message: "Failed to load JWT secret",
			Cause:   err,
		}
	}

	// Fix #3: Algorithm confusion prevention - explicit whitelist
	allowedAlgos := make(map[string]bool)
	if err := validateAndSetAlgorithm(algorithm, allowedAlgos); err != nil {
		return nil, err
	}

	return &JWTValidator{
		secretKey:         secretKey,
		algorithm:         algorithm,
		allowedAlgorithms: allowedAlgos,
		clockSkew:         clockSkew,
	}, nil
}

// ValidateToken validates a JWT token with comprehensive security checks
func (jv *JWTValidator) ValidateToken(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, &AuthError{
			Code:    ErrCodeMissingToken,
			Message: "Token is empty or missing",
		}
	}

	// Parse token with custom key function for algorithm validation
	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, jv.keyFunc)
	if err != nil {
		return nil, &AuthError{
			Code:    ErrCodeInvalidToken,
			Message: "Token parsing failed",
			Cause:   err,
		}
	}

	if !token.Valid {
		return nil, &AuthError{
			Code:    ErrCodeInvalidToken,
			Message: "Token is invalid",
		}
	}

	// Extract and validate claims
	mapClaims, ok := token.Claims.(*jwt.MapClaims)
	if !ok {
		return nil, &AuthError{
			Code:    ErrCodeInvalidClaims,
			Message: "Invalid claims structure",
		}
	}

	claims, err := jv.convertMapClaimsToStandardClaims(*mapClaims)
	if err != nil {
		return nil, err
	}

	// Additional security validations
	if err := jv.validateTimeClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// ValidateAlgorithm validates the JWT algorithm against allowed list
func (jv *JWTValidator) ValidateAlgorithm(algorithm string) error {
	jv.mu.RLock()
	defer jv.mu.RUnlock()

	if !jv.allowedAlgorithms[algorithm] {
		return &AuthError{
			Code:    ErrCodeInvalidAlgorithm,
			Message: fmt.Sprintf("Algorithm %s is not allowed", algorithm),
		}
	}
	return nil
}

// UpdateSecret safely updates the secret key (Fix #2: Race condition protection)
func (jv *JWTValidator) UpdateSecret(secretSource string) error {
	newSecret, err := loadSecretFromSource(secretSource)
	if err != nil {
		return err
	}

	jv.mu.Lock()
	defer jv.mu.Unlock()
	jv.secretKey = newSecret
	return nil
}

// keyFunc is the key function for JWT parsing with algorithm validation
func (jv *JWTValidator) keyFunc(token *jwt.Token) (interface{}, error) {
	// Fix #3: Strict algorithm validation
	alg, ok := token.Header["alg"].(string)
	if !ok {
		return nil, errors.New("missing algorithm in token header")
	}

	if err := jv.ValidateAlgorithm(alg); err != nil {
		return nil, err
	}

	jv.mu.RLock()
	defer jv.mu.RUnlock()
	
	// Return the appropriate key based on algorithm type
	if strings.HasPrefix(alg, "HS") {
		return jv.secretKey, nil
	}

	// For asymmetric algorithms (RS*, ES*, PS*), would need public key
	// This is a placeholder for future RSA/ECDSA support
	return nil, errors.New("asymmetric algorithms not yet supported")
}

// convertMapClaimsToStandardClaims converts JWT MapClaims to our standard Claims
func (jv *JWTValidator) convertMapClaimsToStandardClaims(mapClaims jwt.MapClaims) (*Claims, error) {
	claims := &Claims{
		Extra: make(map[string]interface{}),
	}

	// Extract standard claims with type safety
	if userID, ok := mapClaims["user_id"].(string); ok {
		claims.UserID = userID
	}
	if tenantID, ok := mapClaims["tenant_id"].(string); ok {
		claims.TenantID = tenantID
	}
	if role, ok := mapClaims["role"].(string); ok {
		claims.Role = role
	}
	if sessionID, ok := mapClaims["session_id"].(string); ok {
		claims.SessionID = sessionID
	}

	// Handle roles array
	if rolesInterface, ok := mapClaims["roles"]; ok {
		if roles, err := interfaceSliceToStringSlice(rolesInterface); err == nil {
			claims.Roles = roles
		}
	}

	// Handle permissions array
	if permsInterface, ok := mapClaims["permissions"]; ok {
		if permissions, err := interfaceSliceToStringSlice(permsInterface); err == nil {
			claims.Permissions = permissions
		}
	}

	// Handle time claims
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = time.Unix(int64(iat), 0)
	}
	if exp, ok := mapClaims["exp"].(float64); ok {
		claims.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if nbf, ok := mapClaims["nbf"].(float64); ok {
		claims.NotBefore = time.Unix(int64(nbf), 0)
	}

	// Store remaining claims in Extra
	for key, value := range mapClaims {
		switch key {
		case "user_id", "tenant_id", "role", "roles", "permissions", "session_id", "iat", "exp", "nbf":
			// Skip already processed claims
		default:
			claims.Extra[key] = value
		}
	}

	return claims, nil
}

// validateTimeClaims validates time-based claims with clock skew tolerance
func (jv *JWTValidator) validateTimeClaims(claims *Claims) error {
	now := time.Now()

	// Check if token is expired (with clock skew tolerance)
	if !claims.ExpiresAt.IsZero() && now.After(claims.ExpiresAt.Add(jv.clockSkew)) {
		return &AuthError{
			Code:    ErrCodeExpiredToken,
			Message: "Token has expired",
		}
	}

	// Check if token is not yet valid
	if !claims.NotBefore.IsZero() && now.Before(claims.NotBefore.Add(-jv.clockSkew)) {
		return &AuthError{
			Code:    ErrCodeInvalidToken,
			Message: "Token is not yet valid",
		}
	}

	return nil
}

// loadSecretFromSource loads the secret key from various sources (Fix #1)
func loadSecretFromSource(source string) ([]byte, error) {
	if source == "" {
		return nil, errors.New("secret source cannot be empty")
	}

	// Environment variable source
	if strings.HasPrefix(source, "env:") {
		envVar := strings.TrimPrefix(source, "env:")
		secret := os.Getenv(envVar)
		if secret == "" {
			return nil, fmt.Errorf("environment variable %s is empty or not set", envVar)
		}
		return []byte(secret), nil
	}

	// File source
	if strings.HasPrefix(source, "file:") {
		// Implementation would read from file
		return nil, errors.New("file source not yet implemented")
	}

	// Direct secret (for testing only)
	if strings.HasPrefix(source, "direct:") {
		return []byte(strings.TrimPrefix(source, "direct:")), nil
	}

	return nil, fmt.Errorf("unsupported secret source format: %s", source)
}

// validateAndSetAlgorithm validates and sets the allowed algorithm (Fix #3)
func validateAndSetAlgorithm(algorithm string, allowedAlgos map[string]bool) error {
	// Clear any existing algorithms
	for k := range allowedAlgos {
		delete(allowedAlgos, k)
	}

	// Validate and set the single allowed algorithm
	switch algorithm {
	case "HS256", "HS384", "HS512":
		allowedAlgos[algorithm] = true
	case "RS256", "RS384", "RS512":
		// Future support for RSA
		return errors.New("RSA algorithms not yet supported")
	case "ES256", "ES384", "ES512":
		// Future support for ECDSA
		return errors.New("ECDSA algorithms not yet supported")
	case "none":
		return errors.New("'none' algorithm is forbidden for security reasons")
	default:
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return nil
}

// interfaceSliceToStringSlice converts interface{} slice to string slice
func interfaceSliceToStringSlice(input interface{}) ([]string, error) {
	switch v := input.(type) {
	case []interface{}:
		result := make([]string, len(v))
		for i, item := range v {
			if str, ok := item.(string); ok {
				result[i] = str
			} else {
				return nil, fmt.Errorf("non-string item at index %d", i)
			}
		}
		return result, nil
	case []string:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported slice type: %T", input)
	}
}

// SecureCompare performs constant-time string comparison (Fix #2)
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}