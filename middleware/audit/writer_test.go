package audit

import "testing"

func TestMapMethodToOperationType(t *testing.T) {
	w := &BuiltinAuditWriter{}
	tests := map[string]string{
		"GET":     "READ",
		"HEAD":    "READ",
		"OPTIONS": "READ",
		"POST":    "CREATE",
		"PUT":     "UPDATE",
		"PATCH":   "UPDATE",
		"DELETE":  "DELETE",
		"TRACE":   "READ",
	}

	for method, want := range tests {
		if got := w.mapMethodToOperationType(method); got != want {
			t.Fatalf("mapMethodToOperationType(%q) = %q, want %q", method, got, want)
		}
	}
}

func TestMapHTTPMethodToOperation(t *testing.T) {
	tests := map[string]string{
		"GET":     "READ",
		"HEAD":    "READ",
		"OPTIONS": "READ",
		"POST":    "CREATE",
		"PUT":     "UPDATE",
		"PATCH":   "UPDATE",
		"DELETE":  "DELETE",
		"TRACE":   "READ",
	}

	for method, want := range tests {
		if got := mapHTTPMethodToOperation(method); got != want {
			t.Fatalf("mapHTTPMethodToOperation(%q) = %q, want %q", method, got, want)
		}
	}
}
