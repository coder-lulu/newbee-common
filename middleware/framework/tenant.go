package framework

import (
	"context"
	"time"
)

// TenantStatus represents the status of a tenant.
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
)

// TenantInfo contains normalized tenant metadata used by middleware plugins.
type TenantInfo struct {
	ID        string       `json:"id"`
	Status    TenantStatus `json:"status"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// TenantInfoProvider supplies tenant metadata for middleware validation.
type TenantInfoProvider interface {
	GetTenantInfo(ctx context.Context, tenantID string) (*TenantInfo, error)
}
