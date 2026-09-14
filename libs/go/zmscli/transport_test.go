// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type deleteRequestTransport struct {
	t             *testing.T
	path          string
	paths         []string
	auditRef      string
	resourceOwner string
	calls         int
}

func (tr *deleteRequestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.t.Helper()
	expectedPath := tr.path
	if len(tr.paths) > 0 {
		if tr.calls >= len(tr.paths) {
			tr.t.Fatalf("unexpected request path: %s", req.URL.Path)
		}
		expectedPath = tr.paths[tr.calls]
	}
	tr.calls++
	if req.Method != http.MethodDelete {
		tr.t.Errorf("unexpected method: %s", req.Method)
	}
	if req.URL.Path != expectedPath {
		tr.t.Errorf("unexpected path: %s", req.URL.Path)
	}
	if req.URL.RawQuery != "" {
		tr.t.Errorf("unexpected query: %s", req.URL.RawQuery)
	}
	if req.Header.Get("Y-Audit-Ref") != tr.auditRef {
		tr.t.Errorf("unexpected audit ref: %s", req.Header.Get("Y-Audit-Ref"))
	}
	if req.Header.Get("Athenz-Resource-Owner") != tr.resourceOwner {
		tr.t.Errorf("unexpected resource owner: %s", req.Header.Get("Athenz-Resource-Owner"))
	}
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func (tr *deleteRequestTransport) assertCalled() {
	tr.t.Helper()
	if tr.calls == 0 {
		tr.t.Fatal("expected delete request")
	}
	if len(tr.paths) > 0 && tr.calls != len(tr.paths) {
		tr.t.Fatalf("expected %d delete requests, got %d", len(tr.paths), tr.calls)
	}
}

func TestBulkDeleteNameChunksMaxPathParamLength(t *testing.T) {
	names := []string{
		strings.Repeat("a", 3000),
		strings.Repeat("b", 3000),
		"c",
	}

	chunks := bulkDeleteNameChunks(names)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	if len(chunks[0]) != 1 {
		t.Errorf("expected first chunk with 1 name, got %d", len(chunks[0]))
	}
	if len(chunks[1]) != 2 {
		t.Errorf("expected second chunk with 2 names, got %d", len(chunks[1]))
	}
}
