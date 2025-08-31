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

package middleware

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/zeromicro/go-zero/core/logx"
)

// CircuitBreakerState represents the state of the circuit breaker
type CircuitBreakerState int32

const (
	StateClosed   CircuitBreakerState = iota // 关闭状态：正常通过请求
	StateOpen                                // 开启状态：拒绝所有请求
	StateHalfOpen                            // 半开状态：试探性允许部分请求
)

func (s CircuitBreakerState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// CircuitBreakerConfig defines configuration for circuit breaker
type CircuitBreakerConfig struct {
	// 基础配置
	Name        string        `json:"name"`         // 熔断器名称
	MaxRequests uint32        `json:"max_requests"` // 半开状态最大请求数
	Interval    time.Duration `json:"interval"`     // 统计时间窗口
	Timeout     time.Duration `json:"timeout"`      // 开启状态持续时间

	// 失败阈值配置
	ReadyToTrip             func(counts Counts) bool `json:"-"`                         // 自定义触发条件
	FailureThreshold        uint32                   `json:"failure_threshold"`         // 失败次数阈值
	FailureRate             float64                  `json:"failure_rate"`              // 失败率阈值 (0.0-1.0)
	MinimumRequestThreshold uint32                   `json:"minimum_request_threshold"` // 最小请求数阈值

	// 回调函数
	OnStateChange func(name string, from CircuitBreakerState, to CircuitBreakerState) `json:"-"`
}

// DefaultCircuitBreakerConfig returns default circuit breaker configuration
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		Name:                    "default",
		MaxRequests:             10,
		Interval:                60 * time.Second,
		Timeout:                 30 * time.Second,
		FailureThreshold:        5,
		FailureRate:             0.5, // 50% 失败率
		MinimumRequestThreshold: 10,
		ReadyToTrip: func(counts Counts) bool {
			return counts.Requests >= 10 && counts.Failures >= 5
		},
	}
}

// Counts holds statistics for circuit breaker
type Counts struct {
	Requests       uint32
	TotalSuccesses uint32
	TotalFailures  uint32
	Failures       uint32
	Successes      uint32
}

// Reset resets all counts
func (c *Counts) Reset() {
	c.Requests = 0
	c.TotalSuccesses = 0
	c.TotalFailures = 0
	c.Failures = 0
	c.Successes = 0
}

// FailureRate calculates the current failure rate
func (c *Counts) FailureRate() float64 {
	if c.Requests == 0 {
		return 0.0
	}
	return float64(c.Failures) / float64(c.Requests)
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config     *CircuitBreakerConfig
	mutex      sync.RWMutex
	state      CircuitBreakerState
	generation uint64
	counts     Counts
	expiry     time.Time
}

// NewCircuitBreaker creates a new circuit breaker instance
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}

	if config.ReadyToTrip == nil {
		config.ReadyToTrip = func(counts Counts) bool {
			return counts.Requests >= config.MinimumRequestThreshold &&
				(counts.Failures >= config.FailureThreshold ||
					counts.FailureRate() >= config.FailureRate)
		}
	}

	cb := &CircuitBreaker{
		config: config,
		state:  StateClosed,
		expiry: time.Now().Add(config.Interval),
	}

	logx.Infow("Circuit breaker initialized",
		logx.Field("name", config.Name),
		logx.Field("failureThreshold", config.FailureThreshold),
		logx.Field("failureRate", config.FailureRate),
		logx.Field("interval", config.Interval))

	return cb
}

// Execute executes the given function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(ctx context.Context) error) error {
	generation, err := cb.beforeRequest()
	if err != nil {
		return err
	}

	defer func() {
		if r := recover(); r != nil {
			cb.afterRequest(generation, false)
			panic(r)
		}
	}()

	err = fn(ctx)
	cb.afterRequest(generation, err == nil)
	return err
}

// Call is an alias for Execute for backward compatibility
func (cb *CircuitBreaker) Call(ctx context.Context, fn func(ctx context.Context) error) error {
	return cb.Execute(ctx, fn)
}

// beforeRequest checks if the request can proceed
func (cb *CircuitBreaker) beforeRequest() (uint64, error) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	now := time.Now()
	state, generation := cb.currentState(now)

	if state == StateOpen {
		logx.Debugw("Circuit breaker is open, rejecting request",
			logx.Field("name", cb.config.Name),
			logx.Field("failures", cb.counts.Failures),
			logx.Field("requests", cb.counts.Requests))
		return generation, ErrCircuitBreakerOpen
	}

	if state == StateHalfOpen && cb.counts.Requests >= cb.config.MaxRequests {
		logx.Debugw("Circuit breaker half-open request limit exceeded",
			logx.Field("name", cb.config.Name),
			logx.Field("requests", cb.counts.Requests),
			logx.Field("maxRequests", cb.config.MaxRequests))
		return generation, ErrCircuitBreakerOpen
	}

	cb.counts.Requests++
	return generation, nil
}

// afterRequest processes the request result
func (cb *CircuitBreaker) afterRequest(before uint64, success bool) {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	now := time.Now()
	state, generation := cb.currentState(now)
	if generation != before {
		return // 忽略过期的结果
	}

	if success {
		cb.onSuccess(state, now)
	} else {
		cb.onFailure(state, now)
	}
}

// onSuccess handles successful request
func (cb *CircuitBreaker) onSuccess(state CircuitBreakerState, now time.Time) {
	cb.counts.Successes++
	cb.counts.TotalSuccesses++

	if state == StateHalfOpen {
		// 半开状态成功，考虑关闭熔断器
		if cb.counts.Successes >= cb.config.MaxRequests {
			cb.setState(StateClosed, now)
		}
	}
}

// onFailure handles failed request
func (cb *CircuitBreaker) onFailure(state CircuitBreakerState, now time.Time) {
	cb.counts.Failures++
	cb.counts.TotalFailures++

	if state == StateClosed {
		// 关闭状态检查是否需要打开
		if cb.config.ReadyToTrip(cb.counts) {
			cb.setState(StateOpen, now)
		}
	} else if state == StateHalfOpen {
		// 半开状态失败，立即打开
		cb.setState(StateOpen, now)
	}
}

// currentState returns the current state and generation
func (cb *CircuitBreaker) currentState(now time.Time) (CircuitBreakerState, uint64) {
	switch cb.state {
	case StateClosed:
		if !cb.expiry.IsZero() && cb.expiry.Before(now) {
			cb.toNewGeneration(now)
		}
	case StateOpen:
		if cb.expiry.Before(now) {
			cb.setState(StateHalfOpen, now)
		}
	}
	return cb.state, cb.generation
}

// setState changes the circuit breaker state
func (cb *CircuitBreaker) setState(state CircuitBreakerState, now time.Time) {
	if cb.state == state {
		return
	}

	prev := cb.state
	cb.state = state
	cb.toNewGeneration(now)

	logx.Infow("Circuit breaker state changed",
		logx.Field("name", cb.config.Name),
		logx.Field("from", prev.String()),
		logx.Field("to", state.String()),
		logx.Field("failures", cb.counts.Failures),
		logx.Field("requests", cb.counts.Requests),
		logx.Field("failureRate", cb.counts.FailureRate()))

	if cb.config.OnStateChange != nil {
		go cb.config.OnStateChange(cb.config.Name, prev, state)
	}
}

// toNewGeneration creates a new generation
func (cb *CircuitBreaker) toNewGeneration(now time.Time) {
	cb.generation++
	cb.counts.Reset()

	switch cb.state {
	case StateClosed:
		if cb.config.Interval > 0 {
			cb.expiry = now.Add(cb.config.Interval)
		} else {
			cb.expiry = time.Time{}
		}
	case StateOpen:
		cb.expiry = now.Add(cb.config.Timeout)
	case StateHalfOpen:
		cb.expiry = time.Time{}
	}
}

// State returns the current state of the circuit breaker
func (cb *CircuitBreaker) State() CircuitBreakerState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()

	state, _ := cb.currentState(time.Now())
	return state
}

// Counts returns a copy of the current counts
func (cb *CircuitBreaker) Counts() Counts {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.counts
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	cb.toNewGeneration(time.Now())
	cb.state = StateClosed

	logx.Infow("Circuit breaker reset",
		logx.Field("name", cb.config.Name))
}

// Common circuit breaker errors
var (
	ErrCircuitBreakerOpen    = errors.New("circuit breaker is open")
	ErrCircuitBreakerTimeout = errors.New("circuit breaker execution timeout")
)

// TimeoutConfig defines timeout configuration
type TimeoutConfig struct {
	RequestTimeout  time.Duration `json:"request_timeout"`  // 单个请求超时
	HandlerTimeout  time.Duration `json:"handler_timeout"`  // 处理器超时
	ShutdownTimeout time.Duration `json:"shutdown_timeout"` // 关闭超时
}

// DefaultTimeoutConfig returns default timeout configuration
func DefaultTimeoutConfig() *TimeoutConfig {
	return &TimeoutConfig{
		RequestTimeout:  5 * time.Second,
		HandlerTimeout:  30 * time.Second,
		ShutdownTimeout: 10 * time.Second,
	}
}

// WithTimeout executes a function with timeout control
func WithTimeout(ctx context.Context, timeout time.Duration, fn func(ctx context.Context) error) error {
	if timeout <= 0 {
		return fn(ctx)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				select {
				case done <- errors.New("panic in timeout function"):
				default:
				}
			}
		}()
		done <- fn(timeoutCtx)
	}()

	select {
	case err := <-done:
		return err
	case <-timeoutCtx.Done():
		return ErrCircuitBreakerTimeout
	}
}
