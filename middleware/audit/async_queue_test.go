package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/coder-lulu/newbee-common/middleware/framework"
)

type stubAuditWriter struct {
	done  chan struct{}
	calls []framework.AuditLogData
	mu    sync.Mutex
}

func (s *stubAuditWriter) WriteAuditLog(ctx context.Context, data framework.AuditLogData) error {
	s.mu.Lock()
	s.calls = append(s.calls, data)
	s.mu.Unlock()
	if s.done != nil {
		select {
		case s.done <- struct{}{}:
		default:
		}
	}
	return nil
}

func TestAsyncAuditQueue_Shutdown(t *testing.T) {
	done := make(chan struct{}, 1)
	writer := &stubAuditWriter{done: done}
	queue := NewAsyncAuditQueue(writer, 1, 1)

	auditData := framework.AuditLogData{TenantID: "tenant-1", UserID: "user-1"}
	if err := queue.Enqueue(auditData); err != nil {
		t.Fatalf("enqueue returned error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("write did not complete in time")
	}

	queue.Shutdown()

	if err := queue.Enqueue(auditData); err == nil {
		t.Fatalf("expected error when enqueueing after shutdown")
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()
	if len(writer.calls) != 1 {
		t.Fatalf("expected exactly one write, got %d", len(writer.calls))
	}
}
