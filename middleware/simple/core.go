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

package simple

import (
	"net/http"
	"time"
)

// HealthStatus represents middleware health state
type HealthStatus int

const (
	HealthUnknown HealthStatus = iota
	HealthHealthy
	HealthUnhealthy
)

func (hs HealthStatus) String() string {
	switch hs {
	case HealthHealthy:
		return "healthy"
	case HealthUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// Middleware defines the core middleware interface
// Simplified from 25+ interfaces to single essential interface
type Middleware interface {
	// Handle processes the HTTP request with middleware logic
	Handle(next http.HandlerFunc) http.HandlerFunc

	// Name returns the middleware name
	Name() string

	// Health returns current health status
	Health() HealthStatus

	// Close gracefully shuts down and releases resources
	Close() error
}

// ConfigurableMiddleware extends core middleware with configuration updates
// Only when configuration changes are actually needed
type ConfigurableMiddleware interface {
	Middleware
	UpdateConfig(config interface{}) error
}

// BasicMetrics provides essential metrics only
type BasicMetrics struct {
	RequestCount uint64        `json:"request_count"`
	ErrorCount   uint64        `json:"error_count"`
	AvgLatency   time.Duration `json:"avg_latency"`
	LastUpdated  time.Time     `json:"last_updated"`
}

// MonitorableMiddleware provides metrics when monitoring is essential
type MonitorableMiddleware interface {
	Middleware
	GetMetrics() BasicMetrics
}

// BaseMiddleware provides common functionality for all middleware
type BaseMiddleware struct {
	name   string
	health HealthStatus
}

func NewBaseMiddleware(name string) *BaseMiddleware {
	return &BaseMiddleware{
		name:   name,
		health: HealthHealthy,
	}
}

func (bm *BaseMiddleware) Name() string {
	return bm.name
}

func (bm *BaseMiddleware) Health() HealthStatus {
	return bm.health
}

func (bm *BaseMiddleware) SetHealth(status HealthStatus) {
	bm.health = status
}

func (bm *BaseMiddleware) Close() error {
	bm.health = HealthUnknown
	return nil
}

// MiddlewareRegistry simplified registry without complex factory patterns
type MiddlewareRegistry struct {
	middlewares map[string]Middleware
}

func NewRegistry() *MiddlewareRegistry {
	return &MiddlewareRegistry{
		middlewares: make(map[string]Middleware),
	}
}

func (r *MiddlewareRegistry) Register(name string, middleware Middleware) {
	r.middlewares[name] = middleware
}

func (r *MiddlewareRegistry) Get(name string) (Middleware, bool) {
	middleware, exists := r.middlewares[name]
	return middleware, exists
}

func (r *MiddlewareRegistry) List() []string {
	names := make([]string, 0, len(r.middlewares))
	for name := range r.middlewares {
		names = append(names, name)
	}
	return names
}

func (r *MiddlewareRegistry) Close() error {
	for _, middleware := range r.middlewares {
		middleware.Close()
	}
	r.middlewares = make(map[string]Middleware)
	return nil
}

// Global registry instance
var GlobalRegistry = NewRegistry()

// Convenience functions for global registry
func Register(name string, middleware Middleware) {
	GlobalRegistry.Register(name, middleware)
}

func Get(name string) (Middleware, bool) {
	return GlobalRegistry.Get(name)
}

func List() []string {
	return GlobalRegistry.List()
}
