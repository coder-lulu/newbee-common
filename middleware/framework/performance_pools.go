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

package framework

import (
	"bytes"
	"sync"
	"time"
)

// RequestPool manages Request object pooling for memory efficiency
type RequestPool struct {
	pool    sync.Pool
	metrics RequestPoolMetrics
}

// ResponsePool manages Response object pooling for memory efficiency
type ResponsePool struct {
	pool    sync.Pool
	metrics ResponsePoolMetrics
}

// BufferPool manages byte buffer pooling for body data
type BufferPool struct {
	pool    sync.Pool
	maxSize int
	metrics BufferPoolMetrics
}

// StringPool manages string pooling for headers and paths
type StringPool struct {
	internMap sync.Map
	metrics   StringPoolMetrics
}

// RequestPoolMetrics tracks object pool performance
type RequestPoolMetrics struct {
	Gets     int64     `json:"gets"`
	Puts     int64     `json:"puts"`
	Hits     int64     `json:"hits"`
	Misses   int64     `json:"misses"`
	Creates  int64     `json:"creates"`
	Resets   int64     `json:"resets"`
	LastUsed time.Time `json:"last_used"`
}

// ResponsePoolMetrics tracks response pool performance
type ResponsePoolMetrics struct {
	Gets     int64     `json:"gets"`
	Puts     int64     `json:"puts"`
	Hits     int64     `json:"hits"`
	Misses   int64     `json:"misses"`
	Creates  int64     `json:"creates"`
	Resets   int64     `json:"resets"`
	LastUsed time.Time `json:"last_used"`
}

// BufferPoolMetrics tracks buffer pool performance
type BufferPoolMetrics struct {
	Gets      int64     `json:"gets"`
	Puts      int64     `json:"puts"`
	Hits      int64     `json:"hits"`
	Misses    int64     `json:"misses"`
	Creates   int64     `json:"creates"`
	Discards  int64     `json:"discards"`
	TotalSize int64     `json:"total_size"`
	MaxSize   int       `json:"max_size"`
	LastUsed  time.Time `json:"last_used"`
}

// StringPoolMetrics tracks string interning performance
type StringPoolMetrics struct {
	Lookups  int64     `json:"lookups"`
	Hits     int64     `json:"hits"`
	Misses   int64     `json:"misses"`
	Interns  int64     `json:"interns"`
	MapSize  int64     `json:"map_size"`
	LastUsed time.Time `json:"last_used"`
}

// Global pool instances
var (
	DefaultRequestPool  *RequestPool
	DefaultResponsePool *ResponsePool
	DefaultBufferPool   *BufferPool
	DefaultStringPool   *StringPool
)

func init() {
	DefaultRequestPool = NewRequestPool()
	DefaultResponsePool = NewResponsePool()
	DefaultBufferPool = NewBufferPool(64 * 1024) // 64KB max buffer size
	DefaultStringPool = NewStringPool()
}

// NewRequestPool creates a new request object pool
func NewRequestPool() *RequestPool {
	rp := &RequestPool{}
	rp.pool.New = func() interface{} {
		rp.metrics.Creates++
		return &Request{
			Headers: make(map[string][]string),
			Context: make(map[string]interface{}),
		}
	}
	return rp
}

// Get retrieves a Request from the pool
func (rp *RequestPool) Get() *Request {
	rp.metrics.Gets++
	rp.metrics.LastUsed = time.Now()

	if req, ok := rp.pool.Get().(*Request); ok {
		rp.metrics.Hits++
		return req
	}

	rp.metrics.Misses++
	rp.metrics.Creates++
	return &Request{
		Headers: make(map[string][]string),
		Context: make(map[string]interface{}),
	}
}

// Put returns a Request to the pool after resetting it
func (rp *RequestPool) Put(req *Request) {
	if req == nil {
		return
	}

	rp.metrics.Puts++
	rp.metrics.Resets++

	// Reset request fields to avoid memory leaks
	req.ID = ""
	req.Method = ""
	req.Path = ""
	req.Body = req.Body[:0] // Keep capacity, reset length
	req.RemoteAddr = ""
	req.UserAgent = ""
	req.ContentType = ""
	req.Timestamp = time.Time{}

	// Clear maps but keep capacity
	for k := range req.Headers {
		delete(req.Headers, k)
	}
	for k := range req.Context {
		delete(req.Context, k)
	}

	rp.pool.Put(req)
}

// GetMetrics returns current pool metrics
func (rp *RequestPool) GetMetrics() RequestPoolMetrics {
	return rp.metrics
}

// ResetMetrics resets pool metrics
func (rp *RequestPool) ResetMetrics() {
	rp.metrics = RequestPoolMetrics{}
}

// NewResponsePool creates a new response object pool
func NewResponsePool() *ResponsePool {
	resp := &ResponsePool{}
	resp.pool.New = func() interface{} {
		resp.metrics.Creates++
		return &Response{
			Headers:  make(map[string][]string),
			Metadata: make(map[string]interface{}),
		}
	}
	return resp
}

// Get retrieves a Response from the pool
func (resp *ResponsePool) Get() *Response {
	resp.metrics.Gets++
	resp.metrics.LastUsed = time.Now()

	if r, ok := resp.pool.Get().(*Response); ok {
		resp.metrics.Hits++
		return r
	}

	resp.metrics.Misses++
	resp.metrics.Creates++
	return &Response{
		Headers:  make(map[string][]string),
		Metadata: make(map[string]interface{}),
	}
}

// Put returns a Response to the pool after resetting it
func (resp *ResponsePool) Put(r *Response) {
	if r == nil {
		return
	}

	resp.metrics.Puts++
	resp.metrics.Resets++

	// Reset response fields
	r.StatusCode = 0
	r.Body = r.Body[:0] // Keep capacity, reset length
	r.Error = nil

	// Clear maps but keep capacity
	for k := range r.Headers {
		delete(r.Headers, k)
	}
	for k := range r.Metadata {
		delete(r.Metadata, k)
	}

	resp.pool.Put(r)
}

// GetMetrics returns current pool metrics
func (resp *ResponsePool) GetMetrics() ResponsePoolMetrics {
	return resp.metrics
}

// ResetMetrics resets pool metrics
func (resp *ResponsePool) ResetMetrics() {
	resp.metrics = ResponsePoolMetrics{}
}

// NewBufferPool creates a new buffer pool with specified max size
func NewBufferPool(maxSize int) *BufferPool {
	bp := &BufferPool{
		maxSize: maxSize,
	}
	bp.pool.New = func() interface{} {
		bp.metrics.Creates++
		return bytes.NewBuffer(make([]byte, 0, 1024)) // Start with 1KB capacity
	}
	return bp
}

// Get retrieves a buffer from the pool
func (bp *BufferPool) Get() *bytes.Buffer {
	bp.metrics.Gets++
	bp.metrics.LastUsed = time.Now()

	if buf, ok := bp.pool.Get().(*bytes.Buffer); ok {
		bp.metrics.Hits++
		buf.Reset() // Clear content but keep capacity
		return buf
	}

	bp.metrics.Misses++
	bp.metrics.Creates++
	return bytes.NewBuffer(make([]byte, 0, 1024))
}

// Put returns a buffer to the pool if it's not too large
func (bp *BufferPool) Put(buf *bytes.Buffer) {
	if buf == nil {
		return
	}

	bp.metrics.Puts++

	// Discard oversized buffers to prevent memory hoarding
	if buf.Cap() > bp.maxSize {
		bp.metrics.Discards++
		return
	}

	bp.metrics.TotalSize += int64(buf.Cap())
	buf.Reset()
	bp.pool.Put(buf)
}

// GetMetrics returns current buffer pool metrics
func (bp *BufferPool) GetMetrics() BufferPoolMetrics {
	bp.metrics.MaxSize = bp.maxSize
	return bp.metrics
}

// ResetMetrics resets buffer pool metrics
func (bp *BufferPool) ResetMetrics() {
	maxSize := bp.metrics.MaxSize
	bp.metrics = BufferPoolMetrics{MaxSize: maxSize}
}

// NewStringPool creates a new string interning pool
func NewStringPool() *StringPool {
	return &StringPool{}
}

// Intern returns the canonical representation of the string
func (sp *StringPool) Intern(s string) string {
	if s == "" {
		return s
	}

	sp.metrics.Lookups++
	sp.metrics.LastUsed = time.Now()

	// Try to load existing string
	if existing, loaded := sp.internMap.LoadOrStore(s, s); loaded {
		sp.metrics.Hits++
		return existing.(string)
	}

	// New string was stored
	sp.metrics.Misses++
	sp.metrics.Interns++
	return s
}

// GetMetrics returns current string pool metrics
func (sp *StringPool) GetMetrics() StringPoolMetrics {
	// Count map size (approximate)
	var size int64
	sp.internMap.Range(func(_, _ interface{}) bool {
		size++
		return true
	})
	sp.metrics.MapSize = size

	return sp.metrics
}

// ResetMetrics resets string pool metrics
func (sp *StringPool) ResetMetrics() {
	mapSize := sp.metrics.MapSize
	sp.metrics = StringPoolMetrics{MapSize: mapSize}
}

// Clear removes all interned strings (use with caution)
func (sp *StringPool) Clear() {
	sp.internMap = sync.Map{}
	sp.metrics.MapSize = 0
}

// PerformancePoolManager coordinates all object pools
type PerformancePoolManager struct {
	requestPool  *RequestPool
	responsePool *ResponsePool
	bufferPool   *BufferPool
	stringPool   *StringPool
	enabled      bool
}

// NewPerformancePoolManager creates a new pool manager
func NewPerformancePoolManager() *PerformancePoolManager {
	return &PerformancePoolManager{
		requestPool:  DefaultRequestPool,
		responsePool: DefaultResponsePool,
		bufferPool:   DefaultBufferPool,
		stringPool:   DefaultStringPool,
		enabled:      true,
	}
}

// Enable/Disable pool usage
func (ppm *PerformancePoolManager) SetEnabled(enabled bool) {
	ppm.enabled = enabled
}

// IsEnabled returns whether pools are enabled
func (ppm *PerformancePoolManager) IsEnabled() bool {
	return ppm.enabled
}

// GetRequest gets a request from pool (if enabled) or creates new one
func (ppm *PerformancePoolManager) GetRequest() *Request {
	if ppm.enabled {
		return ppm.requestPool.Get()
	}
	return &Request{
		Headers: make(map[string][]string),
		Context: make(map[string]interface{}),
	}
}

// PutRequest returns request to pool (if enabled)
func (ppm *PerformancePoolManager) PutRequest(req *Request) {
	if ppm.enabled && req != nil {
		ppm.requestPool.Put(req)
	}
}

// GetResponse gets a response from pool (if enabled) or creates new one
func (ppm *PerformancePoolManager) GetResponse() *Response {
	if ppm.enabled {
		return ppm.responsePool.Get()
	}
	return &Response{
		Headers:  make(map[string][]string),
		Metadata: make(map[string]interface{}),
	}
}

// PutResponse returns response to pool (if enabled)
func (ppm *PerformancePoolManager) PutResponse(resp *Response) {
	if ppm.enabled && resp != nil {
		ppm.responsePool.Put(resp)
	}
}

// GetBuffer gets a buffer from pool (if enabled) or creates new one
func (ppm *PerformancePoolManager) GetBuffer() *bytes.Buffer {
	if ppm.enabled {
		return ppm.bufferPool.Get()
	}
	return bytes.NewBuffer(make([]byte, 0, 1024))
}

// PutBuffer returns buffer to pool (if enabled)
func (ppm *PerformancePoolManager) PutBuffer(buf *bytes.Buffer) {
	if ppm.enabled && buf != nil {
		ppm.bufferPool.Put(buf)
	}
}

// InternString interns a string (if enabled) or returns as-is
func (ppm *PerformancePoolManager) InternString(s string) string {
	if ppm.enabled {
		return ppm.stringPool.Intern(s)
	}
	return s
}

// GetAllMetrics returns metrics from all pools
func (ppm *PerformancePoolManager) GetAllMetrics() map[string]interface{} {
	return map[string]interface{}{
		"enabled":       ppm.enabled,
		"request_pool":  ppm.requestPool.GetMetrics(),
		"response_pool": ppm.responsePool.GetMetrics(),
		"buffer_pool":   ppm.bufferPool.GetMetrics(),
		"string_pool":   ppm.stringPool.GetMetrics(),
	}
}

// ResetAllMetrics resets metrics for all pools
func (ppm *PerformancePoolManager) ResetAllMetrics() {
	ppm.requestPool.ResetMetrics()
	ppm.responsePool.ResetMetrics()
	ppm.bufferPool.ResetMetrics()
	ppm.stringPool.ResetMetrics()
}

// Global performance pool manager instance
var GlobalPoolManager = NewPerformancePoolManager()
