// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zms

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type bulkDeleteRequestTransport struct {
	t             *testing.T
	paths         []string
	auditRef      string
	resourceOwner string
	calls         int
}

func (tr *bulkDeleteRequestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.t.Helper()
	if tr.calls >= len(tr.paths) {
		tr.t.Fatalf("unexpected request path: %s", req.URL.Path)
	}
	expectedPath := tr.paths[tr.calls]
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

func (tr *bulkDeleteRequestTransport) assertCalled() {
	tr.t.Helper()
	if tr.calls != len(tr.paths) {
		tr.t.Fatalf("expected %d delete requests, got %d", len(tr.paths), tr.calls)
	}
}

func TestDeleteRoleListChunks(t *testing.T) {
	roleNames := make([]EntityName, BulkDeleteChunkSize+1)
	roleNameStrings := make([]string, BulkDeleteChunkSize+1)
	for idx := range roleNames {
		roleName := fmt.Sprintf("role%d", idx)
		roleNames[idx] = EntityName(roleName)
		roleNameStrings[idx] = roleName
	}

	transport := &bulkDeleteRequestTransport{
		t: t,
		paths: []string{
			"/domain/domain1/roles/" + strings.Join(roleNameStrings[:BulkDeleteChunkSize], ","),
			"/domain/domain1/roles/" + roleNameStrings[BulkDeleteChunkSize],
		},
		auditRef:      "audit",
		resourceOwner: "owner",
	}
	client := NewClient("http://zms", transport)

	if err := client.DeleteRoleList("domain1", roleNames, "audit", "owner"); err != nil {
		t.Fatal(err)
	}
	transport.assertCalled()
}

func TestDeleteRoleListDeduplicatesNames(t *testing.T) {
	roleNames := make([]EntityName, BulkDeleteChunkSize+1)
	roleNameStrings := make([]string, BulkDeleteChunkSize)
	for idx := 0; idx < BulkDeleteChunkSize; idx++ {
		roleName := fmt.Sprintf("role%d", idx)
		roleNames[idx] = EntityName(roleName)
		roleNameStrings[idx] = roleName
	}
	roleNames[BulkDeleteChunkSize] = "Role0"

	transport := &bulkDeleteRequestTransport{
		t: t,
		paths: []string{
			"/domain/domain1/roles/" + strings.Join(roleNameStrings, ","),
		},
		auditRef:      "audit",
		resourceOwner: "owner",
	}
	client := NewClient("http://zms", transport)

	if err := client.DeleteRoleList("domain1", roleNames, "audit", "owner"); err != nil {
		t.Fatal(err)
	}
	transport.assertCalled()
}

func TestDeletePolicyListChunksMaxPathParamLength(t *testing.T) {
	policyNames := []EntityName{
		EntityName(strings.Repeat("a", 3000)),
		EntityName(strings.Repeat("b", 3000)),
		"c",
	}

	transport := &bulkDeleteRequestTransport{
		t: t,
		paths: []string{
			"/domain/domain1/policies/" + string(policyNames[0]),
			"/domain/domain1/policies/" + string(policyNames[1]) + ",c",
		},
		auditRef:      "audit",
		resourceOwner: "owner",
	}
	client := NewClient("http://zms", transport)

	if err := client.DeletePolicyList("domain1", policyNames, "audit", "owner"); err != nil {
		t.Fatal(err)
	}
	transport.assertCalled()
}

func TestDeletePolicyListDeduplicatesNames(t *testing.T) {
	policyNames := make([]EntityName, BulkDeleteChunkSize+1)
	policyNameStrings := make([]string, BulkDeleteChunkSize)
	for idx := 0; idx < BulkDeleteChunkSize; idx++ {
		policyName := fmt.Sprintf("policy%d", idx)
		policyNames[idx] = EntityName(policyName)
		policyNameStrings[idx] = policyName
	}
	policyNames[BulkDeleteChunkSize] = "Policy0"

	transport := &bulkDeleteRequestTransport{
		t: t,
		paths: []string{
			"/domain/domain1/policies/" + strings.Join(policyNameStrings, ","),
		},
		auditRef:      "audit",
		resourceOwner: "owner",
	}
	client := NewClient("http://zms", transport)

	if err := client.DeletePolicyList("domain1", policyNames, "audit", "owner"); err != nil {
		t.Fatal(err)
	}
	transport.assertCalled()
}

func TestDeleteRoleListOversizedName(t *testing.T) {
	client := NewClient("http://zms", &bulkDeleteRequestTransport{t: t})

	err := client.DeleteRoleList("domain1",
		[]EntityName{EntityName(strings.Repeat("a", BulkDeleteMaxPathParamLength+1))}, "audit", "owner")
	if err == nil {
		t.Fatal("expected oversized role name error")
	}
	if err.Error() != "role name exceeds maximum path parameter length" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDeletePolicyListEmptyList(t *testing.T) {
	client := NewClient("http://zms", &bulkDeleteRequestTransport{t: t})

	err := client.DeletePolicyList("domain1", nil, "audit", "owner")
	if err == nil {
		t.Fatal("expected empty policy names error")
	}
	if err.Error() != "no policy names specified" {
		t.Errorf("unexpected error: %v", err)
	}
}
