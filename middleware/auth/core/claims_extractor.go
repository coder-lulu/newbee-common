// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");

package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ClaimsExtractor handles extraction and validation of JWT claims
type ClaimsExtractor struct {
	validator    TokenValidator
	contextMgr   ContextManager
	clockSkew    time.Duration
	requiredClaims []string
}

// NewClaimsExtractor creates a new claims extractor
func NewClaimsExtractor(validator TokenValidator, contextMgr ContextManager, clockSkew time.Duration) *ClaimsExtractor {
	return &ClaimsExtractor{
		validator:    validator,
		contextMgr:   contextMgr,
		clockSkew:    clockSkew,
		requiredClaims: []string{"user_id"}, // Default required claims
	}
}

// ExtractClaims extracts and validates claims from a JWT token string
func (ce *ClaimsExtractor) ExtractClaims(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, &AuthError{
			Code:    ErrCodeMissingToken,
			Message: "Token string is empty",
		}
	}

	// Validate token and extract claims using the validator
	claims, err := ce.validator.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Additional claims validation
	if err := ce.ValidateClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// ValidateClaims performs comprehensive validation of extracted claims
func (ce *ClaimsExtractor) ValidateClaims(claims *Claims) error {
	if claims == nil {
		return &AuthError{
			Code:    ErrCodeInvalidClaims,
			Message: "Claims cannot be nil",
		}
	}

	// Validate required claims
	if err := ce.validateRequiredClaims(claims); err != nil {
		return err
	}

	// Validate claim formats and content
	if err := ce.validateClaimFormats(claims); err != nil {
		return err
	}

	// Additional business logic validation
	if err := ce.validateBusinessRules(claims); err != nil {
		return err
	}

	return nil
}

// ExtractTokenFromRequest extracts JWT token from HTTP request
func (ce *ClaimsExtractor) ExtractTokenFromRequest(req *http.Request) (string, error) {
	// Try Authorization header first (preferred method)
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		return ce.extractFromAuthorizationHeader(authHeader)
	}

	// Try query parameter as fallback (less secure, use with caution)
	token := req.URL.Query().Get("token")
	if token != "" {
		return token, nil
	}

	// Try cookie as another fallback
	if cookie, err := req.Cookie("auth_token"); err == nil {
		return cookie.Value, nil
	}

	return "", &AuthError{
		Code:    ErrCodeMissingToken,
		Message: "No authentication token found in request",
	}
}

// ExtractAndValidateFromRequest combines token extraction and claims validation
func (ce *ClaimsExtractor) ExtractAndValidateFromRequest(req *http.Request) (*Claims, error) {
	token, err := ce.ExtractTokenFromRequest(req)
	if err != nil {
		return nil, err
	}

	return ce.ExtractClaims(token)
}

// SetRequiredClaims sets the list of claims that must be present
func (ce *ClaimsExtractor) SetRequiredClaims(claims []string) {
	ce.requiredClaims = claims
}

// AddRequiredClaim adds a claim to the required claims list
func (ce *ClaimsExtractor) AddRequiredClaim(claim string) {
	for _, existing := range ce.requiredClaims {
		if existing == claim {
			return // Already exists
		}
	}
	ce.requiredClaims = append(ce.requiredClaims, claim)
}

// GenerateTokenID generates a unique token ID from the token content (for caching/revocation)
func (ce *ClaimsExtractor) GenerateTokenID(tokenString string) string {
	hash := sha256.Sum256([]byte(tokenString))
	return hex.EncodeToString(hash[:])[:16] // Use first 16 chars for compact ID
}

// validateRequiredClaims checks if all required claims are present and non-empty
func (ce *ClaimsExtractor) validateRequiredClaims(claims *Claims) error {
	for _, requiredClaim := range ce.requiredClaims {
		switch requiredClaim {
		case "user_id":
			if claims.UserID == "" {
				return &AuthError{
					Code:    ErrCodeInvalidClaims,
					Message: "Required claim 'user_id' is missing or empty",
				}
			}
		case "tenant_id":
			if claims.TenantID == "" {
				return &AuthError{
					Code:    ErrCodeInvalidClaims,
					Message: "Required claim 'tenant_id' is missing or empty",
				}
			}
		case "role":
			if claims.Role == "" && len(claims.Roles) == 0 {
				return &AuthError{
					Code:    ErrCodeInvalidClaims,
					Message: "Required claim 'role' or 'roles' is missing or empty",
				}
			}
		case "session_id":
			if claims.SessionID == "" {
				return &AuthError{
					Code:    ErrCodeInvalidClaims,
					Message: "Required claim 'session_id' is missing or empty",
				}
			}
		}
	}
	return nil
}

// validateClaimFormats validates the format and content of claims
func (ce *ClaimsExtractor) validateClaimFormats(claims *Claims) error {
	// Validate user_id format (should not contain special characters for security)
	if claims.UserID != "" {
		if err := ce.validateIdentifier(claims.UserID, "user_id"); err != nil {
			return err
		}
	}

	// Validate tenant_id format
	if claims.TenantID != "" {
		if err := ce.validateIdentifier(claims.TenantID, "tenant_id"); err != nil {
			return err
		}
	}

	// Validate session_id format
	if claims.SessionID != "" {
		if err := ce.validateIdentifier(claims.SessionID, "session_id"); err != nil {
			return err
		}
	}

	// Validate roles array
	if err := ce.validateRolesArray(claims.Roles); err != nil {
		return err
	}

	// Validate permissions array
	if err := ce.validatePermissionsArray(claims.Permissions); err != nil {
		return err
	}

	return nil
}

// validateBusinessRules validates business-specific rules
func (ce *ClaimsExtractor) validateBusinessRules(claims *Claims) error {
	// Example: Validate that user_id follows expected format (customize as needed)
	if claims.UserID != "" {
		if len(claims.UserID) > 100 {
			return &AuthError{
				Code:    ErrCodeInvalidClaims,
				Message: "user_id exceeds maximum length of 100 characters",
			}
		}
	}

	// Example: Validate tenant_id format
	if claims.TenantID != "" {
		if len(claims.TenantID) > 50 {
			return &AuthError{
				Code:    ErrCodeInvalidClaims,
				Message: "tenant_id exceeds maximum length of 50 characters",
			}
		}
	}

	// Validate that token is not too old (additional security check)
	if !claims.IssuedAt.IsZero() {
		maxAge := 24 * time.Hour // Max token age
		if time.Since(claims.IssuedAt) > maxAge {
			return &AuthError{
				Code:    ErrCodeExpiredToken,
				Message: "Token is too old, please re-authenticate",
			}
		}
	}

	return nil
}

// validateIdentifier validates ID format for security
func (ce *ClaimsExtractor) validateIdentifier(id, fieldName string) error {
	if id == "" {
		return nil // Empty is handled by required claims check
	}

	// Check for potentially dangerous characters
	if strings.ContainsAny(id, "<>\"'&;") {
		return &AuthError{
			Code:    ErrCodeInvalidClaims,
			Message: fmt.Sprintf("%s contains invalid characters", fieldName),
		}
	}

	// Check length limits
	if len(id) < 1 || len(id) > 255 {
		return &AuthError{
			Code:    ErrCodeInvalidClaims,
			Message: fmt.Sprintf("%s length must be between 1 and 255 characters", fieldName),
		}
	}

	return nil
}

// validateRolesArray validates the roles array content
func (ce *ClaimsExtractor) validateRolesArray(roles []string) error {
	if len(roles) > 50 {
		return &AuthError{
			Code:    ErrCodeInvalidClaims,
			Message: "Too many roles specified (maximum 50)",
		}
	}

	for i, role := range roles {
		if role == "" {
			return &AuthError{
				Code:    ErrCodeInvalidClaims,
				Message: fmt.Sprintf("Empty role at index %d", i),
			}
		}
		if len(role) > 100 {
			return &AuthError{
				Code:    ErrCodeInvalidClaims,
				Message: fmt.Sprintf("Role at index %d exceeds 100 characters", i),
			}
		}
		// Validate role format
		if err := ce.validateIdentifier(role, "role"); err != nil {
			return fmt.Errorf("invalid role at index %d: %w", i, err)
		}
	}

	return nil
}

// validatePermissionsArray validates the permissions array content
func (ce *ClaimsExtractor) validatePermissionsArray(permissions []string) error {
	if len(permissions) > 200 {
		return &AuthError{
			Code:    ErrCodeInvalidClaims,
			Message: "Too many permissions specified (maximum 200)",
		}
	}

	for i, permission := range permissions {
		if permission == "" {
			return &AuthError{
				Code:    ErrCodeInvalidClaims,
				Message: fmt.Sprintf("Empty permission at index %d", i),
			}
		}
		if len(permission) > 200 {
			return &AuthError{
				Code:    ErrCodeInvalidClaims,
				Message: fmt.Sprintf("Permission at index %d exceeds 200 characters", i),
			}
		}
	}

	return nil
}

// extractFromAuthorizationHeader extracts token from Authorization header
func (ce *ClaimsExtractor) extractFromAuthorizationHeader(authHeader string) (string, error) {
	const bearerPrefix = "Bearer "
	
	if len(authHeader) <= len(bearerPrefix) {
		return "", &AuthError{
			Code:    ErrCodeInvalidToken,
			Message: "Invalid Authorization header format",
		}
	}

	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", &AuthError{
			Code:    ErrCodeInvalidToken,
			Message: "Authorization header must start with 'Bearer '",
		}
	}

	token := strings.TrimSpace(authHeader[len(bearerPrefix):])
	if token == "" {
		return "", &AuthError{
			Code:    ErrCodeMissingToken,
			Message: "Token is empty in Authorization header",
		}
	}

	return token, nil
}