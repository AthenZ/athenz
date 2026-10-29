// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/AthenZ/athenz/clients/go/zms"
)

type putDomainTemplateTransport struct {
	t          *testing.T
	path       string
	auditRef   string
	statusCode int
	respBody   string
	calls      int
	got        zms.DomainTemplate
}

func (tr *putDomainTemplateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.t.Helper()
	tr.calls++
	if req.Method != http.MethodPut {
		tr.t.Errorf("unexpected method: %s", req.Method)
	}
	if req.URL.Path != tr.path {
		tr.t.Errorf("unexpected path: %s", req.URL.Path)
	}
	if req.Header.Get("Y-Audit-Ref") != tr.auditRef {
		tr.t.Errorf("unexpected audit ref: %s", req.Header.Get("Y-Audit-Ref"))
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		tr.t.Fatalf("unable to read request body: %v", err)
	}
	if err := json.Unmarshal(body, &tr.got); err != nil {
		tr.t.Fatalf("unable to decode request body %q: %v", body, err)
	}
	return &http.Response{
		StatusCode: tr.statusCode,
		Body:       io.NopCloser(strings.NewReader(tr.respBody)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestSetDomainTemplateExt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		template   string
		paramArgs  []string
		wantParams []*zms.TemplateParam
	}{
		{
			name:     "no params",
			template: "vipng",
		},
		{
			name:      "with params",
			template:  "vipng",
			paramArgs: []string{"service=api", "region=us-east-1"},
			wantParams: []*zms.TemplateParam{
				{Name: "service", Value: "api"},
				{Name: "region", Value: "us-east-1"},
			},
		},
		{
			name:       "param value containing equals",
			template:   "vipng",
			paramArgs:  []string{"service=a=b"},
			wantParams: []*zms.TemplateParam{{Name: "service", Value: "a=b"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			transport := &putDomainTemplateTransport{
				t:          t,
				path:       "/domain/domain1/template/" + tt.template,
				auditRef:   "audit",
				statusCode: http.StatusNoContent,
			}
			cli := Zms{
				AuditRef:     "audit",
				OutputFormat: DefaultOutputFormat,
				Zms:          zms.NewClient("http://zms", transport),
			}

			output, err := cli.SetDomainTemplateExt("domain1", tt.template, tt.paramArgs)
			if err != nil {
				t.Fatalf("SetDomainTemplateExt() error = %v", err)
			}

			if transport.calls != 1 {
				t.Errorf("got %d requests, want 1", transport.calls)
			}
			if len(transport.got.TemplateNames) != 1 || string(transport.got.TemplateNames[0]) != tt.template {
				t.Errorf("got template names %v, want [%s]", transport.got.TemplateNames, tt.template)
			}
			if len(transport.got.Params) != len(tt.wantParams) {
				t.Fatalf("got %d params, want %d", len(transport.got.Params), len(tt.wantParams))
			}
			for i, want := range tt.wantParams {
				got := transport.got.Params[i]
				if got.Name != want.Name || got.Value != want.Value {
					t.Errorf("param[%d]: got %s=%s, want %s=%s", i, got.Name, got.Value, want.Name, want.Value)
				}
			}
			if want := "[Template successfully applied to domain]"; *output != want {
				t.Errorf("got output %q, want %q", *output, want)
			}
		})
	}
}

func TestSetDomainTemplateExtInvalidParam(t *testing.T) {
	t.Parallel()
	transport := &putDomainTemplateTransport{t: t}
	cli := Zms{
		AuditRef:     "audit",
		OutputFormat: DefaultOutputFormat,
		Zms:          zms.NewClient("http://zms", transport),
	}

	output, err := cli.SetDomainTemplateExt("domain1", "vipng", []string{"service=api", "cm3"})
	if err == nil {
		t.Fatal("SetDomainTemplateExt() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "cm3") {
		t.Errorf("error %q does not mention the invalid argument", err)
	}
	if output != nil {
		t.Errorf("got output %q, want nil", *output)
	}
	if transport.calls != 0 {
		t.Errorf("got %d requests, want 0", transport.calls)
	}
}

func TestSetDomainTemplateExtServerError(t *testing.T) {
	t.Parallel()
	transport := &putDomainTemplateTransport{
		t:          t,
		path:       "/domain/domain1/template/vipng",
		auditRef:   "audit",
		statusCode: http.StatusBadRequest,
		respBody:   `{"code":400,"message":"putDomainTemplateExt: template name mismatch"}`,
	}
	cli := Zms{
		AuditRef:     "audit",
		OutputFormat: DefaultOutputFormat,
		Zms:          zms.NewClient("http://zms", transport),
	}

	output, err := cli.SetDomainTemplateExt("domain1", "vipng", nil)
	if err == nil {
		t.Fatal("SetDomainTemplateExt() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "template name mismatch") {
		t.Errorf("error %q does not contain server message", err)
	}
	if output != nil {
		t.Errorf("got output %q, want nil", *output)
	}
	if transport.calls != 1 {
		t.Errorf("got %d requests, want 1", transport.calls)
	}
}
