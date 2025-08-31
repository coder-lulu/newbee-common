// Copyright 2023 The Ryan SU Authors (https://github.com/suyuan32). All Rights Reserved.
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

package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Option describes the jwt extra data
type Option struct {
	Key string
	Val any
}

// WithOption returns the option from k/v
func WithOption(key string, val any) Option {
	return Option{
		Key: key,
		Val: val,
	}
}

// NewJwtToken returns the jwt token from the given data.
func NewJwtToken(secretKey string, iat, seconds int64, opt ...Option) (string, error) {
	claims := make(jwt.MapClaims)
	claims["exp"] = iat + seconds
	claims["iat"] = iat

	for _, v := range opt {
		claims[v.Key] = v.Val
	}

	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = claims
	return token.SignedString([]byte(secretKey))
}

// TokenInfo contains validated JWT token information
type TokenInfo struct {
	UserID    string        `json:"userId"`
	TenantID  string        `json:"tenantId"`
	Claims    jwt.MapClaims `json:"claims"`
	IssuedAt  time.Time     `json:"issuedAt"`
	ExpiresAt time.Time     `json:"expiresAt"`
	Valid     bool          `json:"valid"`
}

// ParseJwtToken parses and validates JWT token with signature verification
func ParseJwtToken(tokenString, secretKey string) (jwt.MapClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token string")
	}

	if secretKey == "" {
		return nil, fmt.Errorf("empty secret key")
	}

	// Remove Bearer prefix if present
	tokenString = StripBearerPrefixFromToken(tokenString)

	// Parse the token with signature verification
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 🔒 强化算法验证 - 防止none算法攻击
		if token.Header["alg"] == "none" {
			return nil, fmt.Errorf("none algorithm not allowed")
		}

		// 验证算法是否在白名单中
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// 只允许特定的安全算法
		allowedAlgorithms := []string{"HS256", "HS384", "HS512"}
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("missing algorithm in token header")
		}

		allowed := false
		for _, allowedAlg := range allowedAlgorithms {
			if alg == allowedAlg {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("algorithm %s not allowed", alg)
		}

		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Verify token is valid
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract and validate claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// 🔒 额外的安全验证
	if err := validateTokenClaims(claims); err != nil {
		return nil, fmt.Errorf("token claims validation failed: %w", err)
	}

	return claims, nil
}

// validateTokenClaims 验证token声明的安全性
func validateTokenClaims(claims jwt.MapClaims) error {
	// 验证必需的声明字段
	if _, ok := claims["exp"]; !ok {
		return fmt.Errorf("missing exp claim")
	}

	if _, ok := claims["iat"]; !ok {
		return fmt.Errorf("missing iat claim")
	}

	// 验证exp和iat的类型
	if exp, ok := claims["exp"].(float64); ok {
		if exp <= 0 {
			return fmt.Errorf("invalid exp claim")
		}
	} else {
		return fmt.Errorf("exp claim must be a number")
	}

	if iat, ok := claims["iat"].(float64); ok {
		if iat <= 0 {
			return fmt.Errorf("invalid iat claim")
		}
	} else {
		return fmt.Errorf("iat claim must be a number")
	}

	return nil
}

// ValidateJwtToken validates JWT token and returns structured user information
func ValidateJwtToken(tokenString, secretKey string) (*TokenInfo, error) {
	claims, err := ParseJwtToken(tokenString, secretKey)
	if err != nil {
		return nil, err
	}

	// Extract and validate required fields
	userID, ok := claims["userId"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid userId in token")
	}

	// Handle tenantId - can be either string or numeric
	var tenantID string
	if tenantStr, ok := claims["tenantId"].(string); ok {
		tenantID = tenantStr
	} else if tenantFloat, ok := claims["tenantId"].(float64); ok {
		// JWT numeric values are stored as float64
		tenantID = fmt.Sprintf("%.0f", tenantFloat)
	} else if tenantInt, ok := claims["tenantId"].(int64); ok {
		// Handle int64 case
		tenantID = fmt.Sprintf("%d", tenantInt)
	} else {
		return nil, fmt.Errorf("missing or invalid tenantId in token")
	}

	// Validate expiration time
	if exp, ok := claims["exp"].(float64); ok {
		expirationTime := time.Unix(int64(exp), 0)
		if time.Now().After(expirationTime) {
			return nil, fmt.Errorf("token has expired")
		}
	} else {
		return nil, fmt.Errorf("missing or invalid expiration time")
	}

	// Validate issued at time
	var issuedAt time.Time
	if iat, ok := claims["iat"].(float64); ok {
		issuedAt = time.Unix(int64(iat), 0)
		// Check if token is used before it was issued (clock skew tolerance: 5 minutes)
		if time.Now().Before(issuedAt.Add(-5 * time.Minute)) {
			return nil, fmt.Errorf("token used before valid")
		}
	} else {
		return nil, fmt.Errorf("missing or invalid issued at time")
	}

	// Extract expiration time
	var expiresAt time.Time
	if exp, ok := claims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0)
	}

	return &TokenInfo{
		UserID:    userID,
		TenantID:  tenantID,
		Claims:    claims,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		Valid:     true,
	}, nil
}
