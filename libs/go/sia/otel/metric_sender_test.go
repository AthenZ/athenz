//
// Copyright The AthenZ Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package otel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/config"
	"go.opentelemetry.io/otel"
	metricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func testExportOneCounter(ctx context.Context) error {
	m := otel.Meter("test-meter")
	c, err := m.Int64Counter("test_counter")
	if err != nil {
		return fmt.Errorf("new counter: %w", err)
	}
	c.Add(ctx, 1)
	if prov := otel.GetMeterProvider(); prov != nil {
		type flusher interface{ ForceFlush(context.Context) error }
		if f, ok := prov.(flusher); ok {
			flushCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			return f.ForceFlush(flushCtx)
		}
	}
	return nil
}

func caTempFile(t *testing.T, cert *x509.Certificate) (string, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if len(pemBytes) == 0 {
		return "", os.ErrInvalid
	}

	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, "test-cert.pem")

	err := os.WriteFile(tmpPath, pemBytes, 0600)
	if err != nil {
		return "", err
	}

	return tmpPath, nil
}

func Test_initializeOTelSDK_HTTP(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/metrics" && r.Method == "POST" {
			atomic.AddInt32(&hits, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	caPath, err := caTempFile(t, httptest.NewTLSServer(nil).Certificate())
	if err != nil {
		t.Fatalf("failed to create caTempFile: %v", err)
	}

	cfg := config.OTel{
		CollectorEndpoint: srv.URL,
		CACertPath:        caPath,
	}

	shutdown, err := initializeOTelSDK(ctx, cfg)
	if err != nil {
		t.Fatalf("initializeOTelSDK http: %v", err)
	}
	defer func() { _ = shutdown(ctx) }()

	if err := testExportOneCounter(ctx); err != nil {
		t.Fatalf("export http: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	if atomic.LoadInt32(&hits) == 0 {
		t.Fatalf("server didn't receive any /v1/metrics POST")
	}
}

func Test_initializeOTelSDK_HTTPS(t *testing.T) {
	var hits int32

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/metrics" && r.Method == "POST" {
			atomic.AddInt32(&hits, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
			return
		}
		http.NotFound(w, r)
	}))
	defer tlsSrv.Close()

	caPath, err := caTempFile(t, tlsSrv.Certificate())
	if err != nil {
		t.Fatalf("failed to create caTempFile: %v", err)
	}

	cfg := config.OTel{
		CollectorEndpoint: tlsSrv.URL,
		CACertPath:        caPath,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	shutdown, err := initializeOTelSDK(ctx, cfg)
	if err != nil {
		t.Fatalf("initializeOTelSDK https: %v", err)
	}
	defer func() { _ = shutdown(ctx) }()

	if err := testExportOneCounter(ctx); err != nil {
		t.Fatalf("export https: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	if atomic.LoadInt32(&hits) == 0 {
		t.Fatalf("server didn't receive any /v1/metrics POST (HTTPS)")
	}
}

type metricsService struct {
	metricspb.UnimplementedMetricsServiceServer
	hits *int32
}

func (m *metricsService) Export(ctx context.Context, req *metricspb.ExportMetricsServiceRequest) (*metricspb.ExportMetricsServiceResponse, error) {
	atomic.AddInt32(m.hits, 1)
	return &metricspb.ExportMetricsServiceResponse{}, nil
}

func startGRPCOTLPMetricsTLSServer(t *testing.T) (addr string, closeFn func(), caCertPath string, hits *int32) {
	t.Helper()

	h := httptest.NewTLSServer(http.NewServeMux())
	defer h.Close()

	serverTLS := &tls.Config{
		Certificates: h.TLS.Certificates,
		MinVersion:   tls.VersionTLS12,
	}
	caCertPath, err := caTempFile(t, h.Certificate())
	if err != nil {
		t.Fatalf("failed to create caTempFile: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var hitCount int32
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	metricspb.RegisterMetricsServiceServer(s, &metricsService{hits: &hitCount})

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Printf("grpc serve stopped: %v", err)
		}
	}()

	return lis.Addr().String(), func() { s.GracefulStop() }, caCertPath, &hitCount
}

func Test_initializeOTelSDK_GRPC(t *testing.T) {
	addr, stop, caCertPath, hits := startGRPCOTLPMetricsTLSServer(t)
	defer stop()

	cfg := config.OTel{
		CollectorEndpoint: "grpc://" + addr,
		CACertPath:        caCertPath,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	shutdown, err := initializeOTelSDK(ctx, cfg)
	if err != nil {
		t.Fatalf("initializeOTelSDK grpc: %v", err)
	}
	defer func() { _ = shutdown(ctx) }()

	if err := testExportOneCounter(ctx); err != nil {
		t.Fatalf("export grpc: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if atomic.LoadInt32(hits) == 0 {
		t.Fatalf("gRPC MetricsService didn't receive any Export calls")
	}
}
