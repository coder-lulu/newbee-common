// Copyright 2024 The NewBee Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package core

import (
	"context"
	"net/http"
	"time"
)

// AuthPlugin defines the interface for authentication plugins
type AuthPlugin interface {
	Name() string
	Priority() int
	PreProcess(ctx context.Context, token string, req *http.Request) error
	PostProcess(ctx context.Context, claims *Claims, req *http.Request) (context.Context, error)
	OnError(ctx context.Context, err error, req *http.Request)
}

// TokenValidator interface for JWT validation
type TokenValidator interface {
	ValidateToken(tokenString string) (*Claims, error)
	ValidateAlgorithm(algorithm string) error
}

// ClaimsExtractor interface for extracting and validating claims
type ClaimsExtractor interface {
	ExtractClaims(tokenString string) (*Claims, error)
	ValidateClaims(claims *Claims) error
}

// ContextManager interface for managing authentication context
type ContextManager interface {
	InjectContext(ctx context.Context, claims *Claims) context.Context
	ExtractUserID(ctx context.Context) (string, bool)
	ExtractTenantID(ctx context.Context) (string, bool)
}

// Claims represents the standardized JWT claims
type Claims struct {
	UserID     string            `json:"user_id"`
	TenantID   string            `json:"tenant_id"`
	Role       string            `json:"role"`
	Roles      []string          `json:"roles,omitempty"`
	Permissions []string         `json:"permissions,omitempty"`
	SessionID  string            `json:"session_id,omitempty"`
	IssuedAt   time.Time         `json:"iat"`
	ExpiresAt  time.Time         `json:"exp"`
	NotBefore  time.Time         `json:"nbf,omitempty"`
	Extra      map[string]interface{} `json:"extra,omitempty"`
}

// AuthMiddleware represents the main authentication middleware
type AuthMiddleware struct {
	validator TokenValidator
	extractor ClaimsExtractor
	context   ContextManager
	plugins   []AuthPlugin
}

// MiddlewareBuilder interface for building middleware with plugins
type MiddlewareBuilder interface {
	WithCore(validator TokenValidator, extractor ClaimsExtractor, contextMgr ContextManager) MiddlewareBuilder
	WithPlugin(plugin AuthPlugin) MiddlewareBuilder
	Build() *AuthMiddleware
}

// Config represents the base configuration for authentication
type Config struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	Algorithm     string        `yaml:"algorithm" json:"algorithm"`
	SecretSource  string        `yaml:"secret_source" json:"secret_source"`
	TokenExpiry   time.Duration `yaml:"token_expiry" json:"token_expiry"`
	RefreshExpiry time.Duration `yaml:"refresh_expiry" json:"refresh_expiry"`
	SkipPaths     []string      `yaml:"skip_paths" json:"skip_paths"`
}

// AuthError represents authentication errors with context
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Cause   error  `json:"cause,omitempty"`
}

func (e *AuthError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Common error codes
const (
	ErrCodeInvalidToken      = "INVALID_TOKEN"
	ErrCodeExpiredToken      = "EXPIRED_TOKEN"
	ErrCodeInvalidAlgorithm  = "INVALID_ALGORITHM"
	ErrCodeMissingToken      = "MISSING_TOKEN"
	ErrCodeInvalidClaims     = "INVALID_CLAIMS"
	ErrCodeTenantViolation   = "TENANT_VIOLATION"
	ErrCodeInsufficientPerms = "INSUFFICIENT_PERMISSIONS"
	ErrCodeRateLimited       = "RATE_LIMITED"
	ErrCodeTokenRevoked      = "TOKEN_REVOKED"
)