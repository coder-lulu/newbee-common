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
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// TraceManager handles distributed tracing for the framework
type TraceManager struct {
	serviceName string
	spans       map[string]*Span
	spansMutex  sync.RWMutex
	enabled     bool
	config      *TracingConfig
	exporter    TraceExporter
	sampler     TraceSampler
	processor   SpanProcessor
}

// TracingConfig defines tracing configuration
type TracingConfig struct {
	Enabled          bool              `json:"enabled" yaml:"enabled"`
	ServiceName      string            `json:"service_name" yaml:"service_name"`
	ServiceVersion   string            `json:"service_version" yaml:"service_version"`
	Environment      string            `json:"environment" yaml:"environment"`
	SamplingRate     float64           `json:"sampling_rate" yaml:"sampling_rate"`
	ExportEndpoint   string            `json:"export_endpoint" yaml:"export_endpoint"`
	ExportTimeout    time.Duration     `json:"export_timeout" yaml:"export_timeout"`
	BatchSize        int               `json:"batch_size" yaml:"batch_size"`
	FlushInterval    time.Duration     `json:"flush_interval" yaml:"flush_interval"`
	MaxSpansPerBatch int               `json:"max_spans_per_batch" yaml:"max_spans_per_batch"`
	Attributes       map[string]string `json:"attributes" yaml:"attributes"`
}

// Span represents a single trace span
type Span struct {
	TraceID       string                 `json:"trace_id"`
	SpanID        string                 `json:"span_id"`
	ParentSpanID  string                 `json:"parent_span_id,omitempty"`
	OperationName string                 `json:"operation_name"`
	ServiceName   string                 `json:"service_name"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
	Duration      time.Duration          `json:"duration"`
	Status        SpanStatus             `json:"status"`
	Tags          map[string]interface{} `json:"tags"`
	Logs          []SpanLog              `json:"logs"`
	Events        []SpanEvent            `json:"events"`
	Links         []SpanLink             `json:"links"`
	Resource      map[string]string      `json:"resource"`
	finished      bool
	mutex         sync.RWMutex
}

// SpanStatus represents the status of a span
type SpanStatus struct {
	Code    SpanStatusCode `json:"code"`
	Message string         `json:"message"`
}

// SpanStatusCode represents status codes
type SpanStatusCode int

const (
	SpanStatusUnset SpanStatusCode = iota
	SpanStatusOK
	SpanStatusError
)

// SpanLog represents a log entry within a span
type SpanLog struct {
	Timestamp time.Time              `json:"timestamp"`
	Fields    map[string]interface{} `json:"fields"`
}

// SpanEvent represents an event within a span
type SpanEvent struct {
	Name       string                 `json:"name"`
	Timestamp  time.Time              `json:"timestamp"`
	Attributes map[string]interface{} `json:"attributes"`
}

// SpanLink represents a link to another span
type SpanLink struct {
	TraceID    string                 `json:"trace_id"`
	SpanID     string                 `json:"span_id"`
	Attributes map[string]interface{} `json:"attributes"`
}

// TraceExporter exports trace data
type TraceExporter interface {
	ExportSpans(ctx context.Context, spans []*Span) error
	Shutdown(ctx context.Context) error
}

// TraceSampler determines if a trace should be sampled
type TraceSampler interface {
	ShouldSample(ctx context.Context, traceID string, spanName string) bool
}

// SpanProcessor processes spans before export
type SpanProcessor interface {
	OnStart(ctx context.Context, span *Span)
	OnEnd(ctx context.Context, span *Span)
	ForceFlush(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// NewTraceManager creates a new trace manager
func NewTraceManager(config *TracingConfig) *TraceManager {
	if config == nil {
		config = DefaultTracingConfig()
	}

	tm := &TraceManager{
		serviceName: config.ServiceName,
		spans:       make(map[string]*Span),
		enabled:     config.Enabled,
		config:      config,
		sampler:     NewProbabilitySampler(config.SamplingRate),
		processor:   NewBatchSpanProcessor(config),
	}

	// Set default exporter if none provided
	if tm.exporter == nil {
		tm.exporter = NewConsoleExporter()
	}

	return tm
}

// DefaultTracingConfig returns default tracing configuration
func DefaultTracingConfig() *TracingConfig {
	return &TracingConfig{
		Enabled:          true,
		ServiceName:      "middleware-framework",
		ServiceVersion:   "1.0.0",
		Environment:      "production",
		SamplingRate:     1.0,
		ExportTimeout:    30 * time.Second,
		BatchSize:        512,
		FlushInterval:    5 * time.Second,
		MaxSpansPerBatch: 512,
		Attributes: map[string]string{
			"framework.name":    "newbee-middleware",
			"framework.version": "1.0.0",
		},
	}
}

// StartSpan creates and starts a new span
func (tm *TraceManager) StartSpan(ctx context.Context, operationName string, opts ...SpanOption) (*Span, context.Context) {
	if !tm.enabled {
		return nil, ctx
	}

	// Extract parent span from context
	parentSpan := SpanFromContext(ctx)

	// Generate trace ID and span ID
	var traceID string
	if parentSpan != nil {
		traceID = parentSpan.TraceID
	} else {
		traceID = generateTraceID()
	}

	// Check sampling decision
	if !tm.sampler.ShouldSample(ctx, traceID, operationName) {
		return nil, ctx
	}

	span := &Span{
		TraceID:       traceID,
		SpanID:        generateSpanID(),
		OperationName: operationName,
		ServiceName:   tm.serviceName,
		StartTime:     time.Now(),
		Status:        SpanStatus{Code: SpanStatusUnset},
		Tags:          make(map[string]interface{}),
		Logs:          make([]SpanLog, 0),
		Events:        make([]SpanEvent, 0),
		Links:         make([]SpanLink, 0),
		Resource:      make(map[string]string),
	}

	if parentSpan != nil {
		span.ParentSpanID = parentSpan.SpanID
	}

	// Apply options
	for _, opt := range opts {
		opt(span)
	}

	// Add service attributes
	for key, value := range tm.config.Attributes {
		span.Resource[key] = value
	}

	// Store span
	tm.spansMutex.Lock()
	tm.spans[span.SpanID] = span
	tm.spansMutex.Unlock()

	// Notify processor
	if tm.processor != nil {
		tm.processor.OnStart(ctx, span)
	}

	// Add span to context
	newCtx := ContextWithSpan(ctx, span)

	return span, newCtx
}

// FinishSpan completes a span
func (tm *TraceManager) FinishSpan(span *Span) {
	if span == nil || span.finished {
		return
	}

	span.mutex.Lock()
	span.EndTime = time.Now()
	span.Duration = span.EndTime.Sub(span.StartTime)
	span.finished = true
	span.mutex.Unlock()

	// Notify processor
	if tm.processor != nil {
		tm.processor.OnEnd(context.Background(), span)
	}

	// Remove from active spans
	tm.spansMutex.Lock()
	delete(tm.spans, span.SpanID)
	tm.spansMutex.Unlock()
}

// SpanOption configures a span
type SpanOption func(*Span)

// WithSpanTag adds a tag to the span
func WithSpanTag(key string, value interface{}) SpanOption {
	return func(span *Span) {
		span.Tags[key] = value
	}
}

// WithSpanLink adds a link to another span
func WithSpanLink(traceID, spanID string, attributes map[string]interface{}) SpanOption {
	return func(span *Span) {
		span.Links = append(span.Links, SpanLink{
			TraceID:    traceID,
			SpanID:     spanID,
			Attributes: attributes,
		})
	}
}

// WithSpanResource adds resource attributes
func WithSpanResource(key, value string) SpanOption {
	return func(span *Span) {
		span.Resource[key] = value
	}
}

// Span methods

// SetTag sets a tag on the span
func (s *Span) SetTag(key string, value interface{}) {
	if s == nil {
		return
	}
	s.mutex.Lock()
	s.Tags[key] = value
	s.mutex.Unlock()
}

// SetStatus sets the span status
func (s *Span) SetStatus(code SpanStatusCode, message string) {
	if s == nil {
		return
	}
	s.mutex.Lock()
	s.Status = SpanStatus{Code: code, Message: message}
	s.mutex.Unlock()
}

// AddEvent adds an event to the span
func (s *Span) AddEvent(name string, attributes map[string]interface{}) {
	if s == nil {
		return
	}
	s.mutex.Lock()
	s.Events = append(s.Events, SpanEvent{
		Name:       name,
		Timestamp:  time.Now(),
		Attributes: attributes,
	})
	s.mutex.Unlock()
}

// LogFields adds a log entry to the span
func (s *Span) LogFields(fields map[string]interface{}) {
	if s == nil {
		return
	}
	s.mutex.Lock()
	s.Logs = append(s.Logs, SpanLog{
		Timestamp: time.Now(),
		Fields:    fields,
	})
	s.mutex.Unlock()
}

// RecordError records an error in the span
func (s *Span) RecordError(err error) {
	if s == nil || err == nil {
		return
	}
	s.SetStatus(SpanStatusError, err.Error())
	s.AddEvent("error", map[string]interface{}{
		"error.message": err.Error(),
		"error.type":    fmt.Sprintf("%T", err),
	})
}

// Context utilities

type spanContextKey struct{}

// ContextWithSpan adds a span to context
func ContextWithSpan(ctx context.Context, span *Span) context.Context {
	return context.WithValue(ctx, spanContextKey{}, span)
}

// SpanFromContext extracts a span from context
func SpanFromContext(ctx context.Context) *Span {
	if span, ok := ctx.Value(spanContextKey{}).(*Span); ok {
		return span
	}
	return nil
}

// Sampling implementations

// ProbabilitySampler samples based on probability
type ProbabilitySampler struct {
	rate float64
}

// NewProbabilitySampler creates a probability-based sampler
func NewProbabilitySampler(rate float64) *ProbabilitySampler {
	if rate < 0 {
		rate = 0
	}
	if rate > 1 {
		rate = 1
	}
	return &ProbabilitySampler{rate: rate}
}

// ShouldSample determines if a trace should be sampled
func (ps *ProbabilitySampler) ShouldSample(ctx context.Context, traceID string, spanName string) bool {
	if ps.rate >= 1.0 {
		return true
	}
	if ps.rate <= 0.0 {
		return false
	}

	// Use trace ID for consistent sampling decision across the trace
	hash := simpleHash(traceID)
	return (hash % 100) < int(ps.rate*100)
}

// Span processor implementations

// BatchSpanProcessor batches spans for export
type BatchSpanProcessor struct {
	config     *TracingConfig
	exporter   TraceExporter
	spans      []*Span
	spansMutex sync.Mutex
	ticker     *time.Ticker
	done       chan struct{}
}

// NewBatchSpanProcessor creates a new batch span processor
func NewBatchSpanProcessor(config *TracingConfig) *BatchSpanProcessor {
	bsp := &BatchSpanProcessor{
		config:   config,
		exporter: NewConsoleExporter(),
		spans:    make([]*Span, 0, config.BatchSize),
		done:     make(chan struct{}),
	}

	// Start background flush routine
	bsp.ticker = time.NewTicker(config.FlushInterval)
	go bsp.flushRoutine()

	return bsp
}

// OnStart is called when a span starts
func (bsp *BatchSpanProcessor) OnStart(ctx context.Context, span *Span) {
	// No action needed on start
}

// OnEnd is called when a span ends
func (bsp *BatchSpanProcessor) OnEnd(ctx context.Context, span *Span) {
	bsp.spansMutex.Lock()
	bsp.spans = append(bsp.spans, span)
	shouldFlush := len(bsp.spans) >= bsp.config.BatchSize
	bsp.spansMutex.Unlock()

	if shouldFlush {
		bsp.flush(ctx)
	}
}

// ForceFlush forces immediate export of all spans
func (bsp *BatchSpanProcessor) ForceFlush(ctx context.Context) error {
	return bsp.flush(ctx)
}

// Shutdown stops the processor
func (bsp *BatchSpanProcessor) Shutdown(ctx context.Context) error {
	close(bsp.done)
	bsp.ticker.Stop()
	return bsp.flush(ctx)
}

// flush exports accumulated spans
func (bsp *BatchSpanProcessor) flush(ctx context.Context) error {
	bsp.spansMutex.Lock()
	if len(bsp.spans) == 0 {
		bsp.spansMutex.Unlock()
		return nil
	}

	spansToExport := make([]*Span, len(bsp.spans))
	copy(spansToExport, bsp.spans)
	bsp.spans = bsp.spans[:0]
	bsp.spansMutex.Unlock()

	return bsp.exporter.ExportSpans(ctx, spansToExport)
}

// flushRoutine periodically flushes spans
func (bsp *BatchSpanProcessor) flushRoutine() {
	for {
		select {
		case <-bsp.ticker.C:
			bsp.flush(context.Background())
		case <-bsp.done:
			return
		}
	}
}

// Console exporter for development
type ConsoleExporter struct{}

// NewConsoleExporter creates a console exporter
func NewConsoleExporter() *ConsoleExporter {
	return &ConsoleExporter{}
}

// ExportSpans exports spans to console
func (ce *ConsoleExporter) ExportSpans(ctx context.Context, spans []*Span) error {
	for _, span := range spans {
		fmt.Printf("TRACE: %s [%s] %s %v %s\n",
			span.TraceID,
			span.SpanID,
			span.OperationName,
			span.Duration,
			span.Status.Message,
		)
	}
	return nil
}

// Shutdown stops the exporter
func (ce *ConsoleExporter) Shutdown(ctx context.Context) error {
	return nil
}

// Utility functions

// generateTraceID generates a unique trace ID
func generateTraceID() string {
	return fmt.Sprintf("%016x%016x",
		rand.Uint64(),
		rand.Uint64())
}

// generateSpanID generates a unique span ID
func generateSpanID() string {
	return fmt.Sprintf("%016x", rand.Uint64())
}

// simpleHash creates a simple hash of a string
func simpleHash(s string) int {
	hash := 0
	for _, c := range s {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	return hash
}

// Framework integration

// TracingMiddleware creates a tracing middleware for the framework
func TracingMiddleware(traceManager *TraceManager) MiddlewareHandler {
	return &tracingMiddleware{
		traceManager: traceManager,
	}
}

type tracingMiddleware struct {
	traceManager *TraceManager
}

// Handle implements MiddlewareHandler
func (tm *tracingMiddleware) Handle(ctx context.Context, req *Request, next HandlerFunc) (*Response, error) {
	// Extract trace context from request headers
	traceID := extractTraceID(req)
	spanID := extractSpanID(req)

	// Create span context if trace information exists
	if traceID != "" && spanID != "" {
		parentSpan := &Span{
			TraceID: traceID,
			SpanID:  spanID,
		}
		ctx = ContextWithSpan(ctx, parentSpan)
	}

	// Start span for this request
	span, newCtx := tm.traceManager.StartSpan(ctx, fmt.Sprintf("%s %s", req.Method, req.Path),
		WithSpanTag("http.method", req.Method),
		WithSpanTag("http.path", req.Path),
		WithSpanTag("http.user_agent", req.UserAgent),
		WithSpanTag("http.remote_addr", req.RemoteAddr),
		WithSpanResource("service.name", tm.traceManager.serviceName),
	)

	if span != nil {
		defer tm.traceManager.FinishSpan(span)

		// Add request ID if available
		if req.ID != "" {
			span.SetTag("request.id", req.ID)
		}

		// Add user context if available
		if userID, exists := req.Context["user_id"]; exists {
			span.SetTag("user.id", userID)
		}
		if tenantID, exists := req.Context["tenant_id"]; exists {
			span.SetTag("tenant.id", tenantID)
		}
	}

	// Process request
	resp, err := next(newCtx, req)

	// Record span information
	if span != nil {
		if resp != nil {
			span.SetTag("http.status_code", resp.StatusCode)
			if resp.StatusCode >= 400 {
				span.SetStatus(SpanStatusError, fmt.Sprintf("HTTP %d", resp.StatusCode))
			} else {
				span.SetStatus(SpanStatusOK, "")
			}
		}

		if err != nil {
			span.RecordError(err)
		}
	}

	return resp, err
}

// extractTraceID extracts trace ID from request headers
func extractTraceID(req *Request) string {
	// Try common trace headers
	headers := []string{"X-Trace-Id", "X-B3-TraceId", "Traceparent"}
	for _, header := range headers {
		if values, exists := req.Headers[header]; exists && len(values) > 0 {
			// For traceparent, extract trace ID portion
			if header == "Traceparent" && len(values[0]) >= 35 {
				return values[0][3:35] // Extract 32-char trace ID
			}
			return values[0]
		}
	}
	return ""
}

// extractSpanID extracts span ID from request headers
func extractSpanID(req *Request) string {
	// Try common span headers
	headers := []string{"X-Span-Id", "X-B3-SpanId", "Traceparent"}
	for _, header := range headers {
		if values, exists := req.Headers[header]; exists && len(values) > 0 {
			// For traceparent, extract span ID portion
			if header == "Traceparent" && len(values[0]) >= 51 {
				return values[0][36:51] // Extract 16-char span ID
			}
			return values[0]
		}
	}
	return ""
}
