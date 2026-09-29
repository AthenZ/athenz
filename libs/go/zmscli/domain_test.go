// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/AthenZ/athenz/clients/go/zms"
)

type getAuditLogTransport struct {
	t          *testing.T
	path       string
	query      map[string]string
	statusCode int
	body       string
	calls      int
}

func (tr *getAuditLogTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.t.Helper()
	tr.calls++
	if req.Method != http.MethodGet {
		tr.t.Errorf("unexpected method: %s", req.Method)
	}
	if req.URL.Path != tr.path {
		tr.t.Errorf("unexpected path: %s", req.URL.Path)
	}
	values := req.URL.Query()
	if len(values) != len(tr.query) {
		tr.t.Errorf("unexpected query: %s", req.URL.RawQuery)
	}
	for key, value := range tr.query {
		if values.Get(key) != value {
			tr.t.Errorf("unexpected query value for %s: %s", key, values.Get(key))
		}
	}
	return &http.Response{
		StatusCode: tr.statusCode,
		Body:       io.NopCloser(strings.NewReader(tr.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

const auditLogResponse = `{"entries":[{"api":"putRole","entity":"readers","principal":"user.jane","clientIp":"10.1.1.1",` +
	`"timestamp":"2026-09-01T10:00:00.000Z","justification":"ticket-1234","details":"{\"member\": \"user.joe\"}"}]}`

func TestGetDomainAuditLog(t *testing.T) {
	transport := &getAuditLogTransport{
		t:          t,
		path:       "/domain/domain1/history/audit",
		query:      map[string]string{},
		statusCode: http.StatusOK,
		body:       auditLogResponse,
	}

	cli := Zms{
		OutputFormat: DefaultOutputFormat,
		Zms:          zms.NewClient("http://zms", transport),
	}

	output, err := cli.GetDomainAuditLog("domain1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if transport.calls != 1 {
		t.Fatalf("expected 1 request, got %d", transport.calls)
	}
	for _, expected := range []string{"api: putRole", "entity: readers", "principal: user.jane",
		"clientip: 10.1.1.1", "justification: ticket-1234", `"member": "user.joe"`} {
		if !strings.Contains(*output, expected) {
			t.Errorf("output does not contain %q: %s", expected, *output)
		}
	}
}

func TestGetDomainAuditLogWithFilters(t *testing.T) {
	transport := &getAuditLogTransport{
		t:    t,
		path: "/domain/domain1/history/audit",
		query: map[string]string{
			"api":       "putRole",
			"entity":    "readers",
			"principal": "user.jane",
			"start":     "2026-09-01T00:00:00Z",
			"end":       "2026-09-02T00:00:00Z",
			"limit":     "10",
		},
		statusCode: http.StatusOK,
		body:       auditLogResponse,
	}

	cli := Zms{
		OutputFormat: JSONOutputFormat,
		Zms:          zms.NewClient("http://zms", transport),
	}

	output, err := cli.GetDomainAuditLog("domain1", []string{"api=putRole", "entity=readers",
		"principal=user.jane", "start=2026-09-01T00:00:00Z", "end=2026-09-02T00:00:00Z", "limit=10"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(*output, `"justification": "ticket-1234"`) {
		t.Errorf("unexpected output: %s", *output)
	}
}

func TestGetDomainAuditLogPartial(t *testing.T) {
	transport := &getAuditLogTransport{
		t:          t,
		path:       "/domain/domain1/history/audit",
		query:      map[string]string{"limit": "1"},
		statusCode: http.StatusOK,
		body:       strings.TrimSuffix(auditLogResponse, "}") + `,"partial":true}`,
	}
	cli := Zms{
		OutputFormat: DefaultOutputFormat,
		Zms:          zms.NewClient("http://zms", transport),
	}

	output, err := cli.GetDomainAuditLog("domain1", []string{"limit=1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(*output, "partial: true") {
		t.Errorf("output does not contain partial flag: %s", *output)
	}
}

func TestGetDomainAuditLogInvalidArgs(t *testing.T) {
	transport := &getAuditLogTransport{t: t}
	cli := Zms{
		OutputFormat: DefaultOutputFormat,
		Zms:          zms.NewClient("http://zms", transport),
	}

	tests := []struct {
		args     []string
		errorMsg string
	}{
		{[]string{"putRole"}, "expected key=value format"},
		{[]string{"api="}, "expected key=value format"},
		{[]string{"limit=abc"}, "invalid limit value"},
		{[]string{"unknown=value"}, "unknown argument"},
	}
	for _, tt := range tests {
		_, err := cli.GetDomainAuditLog("domain1", tt.args)
		if err == nil || !strings.Contains(err.Error(), tt.errorMsg) {
			t.Errorf("args %v: expected error containing %q, got %v", tt.args, tt.errorMsg, err)
		}
	}
	if transport.calls != 0 {
		t.Errorf("expected no requests, got %d", transport.calls)
	}
}

func TestGetDomainAuditLogServerError(t *testing.T) {
	transport := &getAuditLogTransport{
		t:          t,
		path:       "/domain/domain1/history/audit",
		query:      map[string]string{},
		statusCode: http.StatusForbidden,
		body:       `{"code":403,"message":"access denied"}`,
	}
	cli := Zms{
		OutputFormat: DefaultOutputFormat,
		Zms:          zms.NewClient("http://zms", transport),
	}

	_, err := cli.GetDomainAuditLog("domain1", nil)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected access denied error, got %v", err)
	}
}
