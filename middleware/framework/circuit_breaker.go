// Copyright 2024 The NewBee Authors. All Rights Reserved.

package framework

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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
	name         string
	config       *CircuitBreakerConfig
	state        CircuitBreakerState
	generation   uint64
	counts       Counts
	expiry       time.Time
	mu           sync.RWMutex
	
	// 原子计数器用于高性能统计
	totalRequests int64
	totalFailures int64
	totalTimeouts int64
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}

	cb := &CircuitBreaker{
		name:   config.Name,
		config: config,
		state:  StateClosed,
		expiry: time.Now().Add(config.Interval),
	}

	// 如果没有自定义触发条件，使用默认条件
	if config.ReadyToTrip == nil {
		config.ReadyToTrip = func(counts Counts) bool {
			// 达到最小请求数阈值，并且失败率超过配置的阈值
			return counts.Requests >= config.MinimumRequestThreshold &&
				(counts.Failures >= config.FailureThreshold || counts.FailureRate() >= config.FailureRate)
		}
	}

	logx.Infow("Circuit breaker created",
		logx.Field("name", config.Name),
		logx.Field("maxRequests", config.MaxRequests),
		logx.Field("interval", config.Interval),
		logx.Field("timeout", config.Timeout))

	return cb
}

// Execute executes the given function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
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

	// 执行函数
	err = fn()
	cb.afterRequest(generation, err == nil)
	return err
}

// Call is an alias for Execute for backward compatibility
func (cb *CircuitBreaker) Call(fn func() error) error {
	return cb.Execute(context.Background(), fn)
}

// beforeRequest checks if request should be allowed
func (cb *CircuitBreaker) beforeRequest() (uint64, error) {
	atomic.AddInt64(&cb.totalRequests, 1)

	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	state, generation := cb.currentState(now)

	if state == StateOpen {
		return generation, errors.New("circuit breaker is open")
	}

	if state == StateHalfOpen && cb.counts.Requests >= cb.config.MaxRequests {
		return generation, errors.New("circuit breaker is half-open and max requests exceeded")
	}

	cb.counts.Requests++
	return generation, nil
}

// afterRequest updates circuit breaker state after request completion
func (cb *CircuitBreaker) afterRequest(before uint64, success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()
	state, generation := cb.currentState(now)

	if generation != before {
		// 代数已经改变，说明状态已经重置，忽略这次结果
		return
	}

	if success {
		cb.onSuccess(state, now)
	} else {
		atomic.AddInt64(&cb.totalFailures, 1)
		cb.onFailure(state, now)
	}
}

// currentState returns current state and generation
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

// onSuccess handles successful request
func (cb *CircuitBreaker) onSuccess(state CircuitBreakerState, now time.Time) {
	cb.counts.Successes++
	cb.counts.TotalSuccesses++

	if state == StateHalfOpen {
		// 半开状态下的成功请求，检查是否可以关闭熔断器
		if cb.counts.Successes >= cb.config.MaxRequests {
			cb.setState(StateClosed, now)
		}
	}
}

// onFailure handles failed request
func (cb *CircuitBreaker) onFailure(state CircuitBreakerState, now time.Time) {
	cb.counts.Failures++
	cb.counts.TotalFailures++

	switch state {
	case StateClosed:
		if cb.config.ReadyToTrip(cb.counts) {
			cb.setState(StateOpen, now)
		}
	case StateHalfOpen:
		// 半开状态下的失败立即转为开启状态
		cb.setState(StateOpen, now)
	}
}

// setState changes the state of the circuit breaker
func (cb *CircuitBreaker) setState(state CircuitBreakerState, now time.Time) {
	prev := cb.state

	if cb.state != state {
		cb.state = state

		switch state {
		case StateClosed:
			cb.toNewGeneration(now)
		case StateOpen:
			cb.generation++
			cb.counts.Reset()
			cb.expiry = now.Add(cb.config.Timeout)
		case StateHalfOpen:
			cb.generation++
			cb.counts.Reset()
		}

		logx.Infow("Circuit breaker state changed",
			logx.Field("name", cb.name),
			logx.Field("from", prev.String()),
			logx.Field("to", state.String()))

		// 调用回调函数
		if cb.config.OnStateChange != nil {
			go cb.config.OnStateChange(cb.name, prev, state)
		}
	}
}

// toNewGeneration resets to a new generation
func (cb *CircuitBreaker) toNewGeneration(now time.Time) {
	cb.generation++
	cb.counts.Reset()
	cb.expiry = now.Add(cb.config.Interval)
}

// State returns current state
func (cb *CircuitBreaker) State() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	state, _ := cb.currentState(time.Now())
	return state
}

// Counts returns current counts
func (cb *CircuitBreaker) Counts() Counts {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	return cb.counts
}

// Stats returns circuit breaker statistics
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.RLock()
	counts := cb.counts
	state := cb.state
	cb.mu.RUnlock()

	return CircuitBreakerStats{
		Name:           cb.name,
		State:          state.String(),
		TotalRequests:  atomic.LoadInt64(&cb.totalRequests),
		TotalFailures:  atomic.LoadInt64(&cb.totalFailures),
		TotalTimeouts:  atomic.LoadInt64(&cb.totalTimeouts),
		Requests:       counts.Requests,
		Successes:      counts.Successes,
		Failures:       counts.Failures,
		FailureRate:    counts.FailureRate(),
		Generation:     cb.generation,
	}
}

// CircuitBreakerStats holds circuit breaker statistics
type CircuitBreakerStats struct {
	Name           string  `json:"name"`
	State          string  `json:"state"`
	TotalRequests  int64   `json:"total_requests"`
	TotalFailures  int64   `json:"total_failures"`
	TotalTimeouts  int64   `json:"total_timeouts"`
	Requests       uint32  `json:"requests"`
	Successes      uint32  `json:"successes"`
	Failures       uint32  `json:"failures"`
	FailureRate    float64 `json:"failure_rate"`
	Generation     uint64  `json:"generation"`
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.setState(StateClosed, time.Now())
	logx.Infow("Circuit breaker manually reset", logx.Field("name", cb.name))
}

// Trip manually trips the circuit breaker to open state
func (cb *CircuitBreaker) Trip() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.setState(StateOpen, time.Now())
	logx.Infow("Circuit breaker manually tripped", logx.Field("name", cb.name))
}