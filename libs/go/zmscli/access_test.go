// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AthenZ/athenz/clients/go/zms"
)

func TestShowAccessExtCaseSensitive(t *testing.T) {

	var caseSensitiveParam string
	var actionPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caseSensitiveParam = r.URL.Query().Get("caseSensitive")
		actionPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"granted":true}`))
	}))
	defer server.Close()

	cli := Zms{
		Zms:          zms.NewClient(server.URL, nil),
		UserDomain:   "user",
		OutputFormat: DefaultOutputFormat,
	}

	// without the flag we must not send the caseSensitive parameter

	output, err := cli.ShowAccessExt("coretech", "ReaD", "Node.Host1", nil, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(*output, "access: granted") {
		t.Errorf("unexpected output: %s", *output)
	}
	if caseSensitiveParam != "" {
		t.Errorf("caseSensitive parameter must not be set: %s", caseSensitiveParam)
	}

	// with case-sensitive check, the parameter must be passed along
	// with the action in its original case

	_, err = cli.ShowAccessExt("coretech", "ReaD", "Node.Host1", nil, nil, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if caseSensitiveParam != "true" {
		t.Errorf("caseSensitive parameter must be true: %s", caseSensitiveParam)
	}
	if actionPath != "/access/ReaD" {
		t.Errorf("unexpected request path: %s", actionPath)
	}
}

func TestEvalCommandShowAccessExtCaseSensitive(t *testing.T) {

	var rawQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"granted":false}`))
	}))
	defer server.Close()

	cli := Zms{
		Zms:          zms.NewClient(server.URL, nil),
		Domain:       "coretech",
		UserDomain:   "user",
		OutputFormat: DefaultOutputFormat,
	}

	output, err := cli.EvalCommand([]string{"show-access-ext-case-sensitive", "ReaD", "Node.Host1", "user.john"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(*output, "access: denied") {
		t.Errorf("unexpected output: %s", *output)
	}
	if !strings.Contains(rawQuery, "caseSensitive=true") || !strings.Contains(rawQuery, "principal=user.john") {
		t.Errorf("unexpected query: %s", rawQuery)
	}

	_, err = cli.EvalCommand([]string{"show-access-ext", "ReaD", "Node.Host1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(rawQuery, "caseSensitive") {
		t.Errorf("caseSensitive parameter must not be set: %s", rawQuery)
	}
}
