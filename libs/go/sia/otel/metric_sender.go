//
// Copyright The Athenz Authors
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
	"fmt"
	"log"
	"os"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"google.golang.org/grpc/credentials"
)

// ShutdownFn is a function type that defines oTel provider shutting down.
type ShutdownFn func(context.Context) error

var (
	// oTelEnabled indicates whether OpenTelemetry is enabled. (false by default)
	// It is guarantee that go.opentelemetry.io package is imported into application only when oTelEnabled is true.
	oTelEnabled = false

	// NilShutdown is a no-op shutdown function that does nothing.
	NilShutdown = func(ctx context.Context) error { return nil }
)

// StartOTelProvider starts the OpenTelemetry provider, and returns a shutdown function.
// It first checks if the collector endpoint is configured and if the TLS file is ready.
// If not ready, it will start a goroutine waiting for the TLS files to be ready before initializing the OTel SDK.
func StartOTelProvider(oTelCfg config.OTel) ShutdownFn {
	// If CollectorEndpoint is not configured, no-op.
	if oTelCfg.CollectorEndpoint == "" {
		log.Println("oTel: collector endpoint is not configured, oTel is disabled")
		oTelEnabled = false
		return NilShutdown
	}

	oTelEnabled = true

	// For single TLS: directly init if the CA file is ready.
	if !oTelCfg.MTLS {
		if _, err := os.Stat(oTelCfg.CACertPath); err == nil {
			log.Println("oTel: TLS CA cert is ready, initializing OTel SDK")
			shutdownFn, err := initializeOTelSDK(context.Background(), oTelCfg)
			if err != nil {
				log.Printf("oTel: SDK init failed: %v", err)
				oTelEnabled = false
				return NilShutdown
			}
			return shutdownFn
		}
	}

	// If mTLS is enabled or if the CA file is unready, we need to wait for the TLS files to be ready.
	shutdownCh := make(chan ShutdownFn, 1)
	// Always return a shutdown function that waits for initialization result.
	providerShutdown := func(ctx context.Context) error {
		select {
		case shutdownFn := <-shutdownCh:
			return shutdownFn(ctx)
		case <-time.After(time.Second):
			log.Println("oTel: no oTel shutdown function received, continuing without shutdown")
		}
		return nil
	}

	log.Println("oTel: waiting for TLS files to be ready before starting OTel provider")
	go func() {
		if err := waitForTLSFileReady(oTelCfg); err != nil {
			log.Printf("oTel: failed to wait for TLS files ready, err: %v\n", err)
			oTelEnabled = false
			shutdownCh <- NilShutdown
			return
		}
		shutdownFn, err := initializeOTelSDK(context.Background(), oTelCfg)
		if err != nil {
			log.Printf("oTel: SDK init failed: %v", err)
			oTelEnabled = false
			shutdownCh <- NilShutdown
			return
		}
		shutdownCh <- shutdownFn
	}()

	return providerShutdown
}

// initializeOTelSDK initializes the OTel SDK.
func initializeOTelSDK(ctx context.Context, oTelCfg config.OTel) (ShutdownFn, error) {
	log.Println("oTel: initializing OTel SDK")

	oTelResource, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceNameKey.String("sia")),
	)

	if oTelCfg.ServiceInstanceID != "" {
		oTelResource, _ = resource.Merge(
			oTelResource,
			resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceInstanceIDKey.String(oTelCfg.ServiceInstanceID)),
		)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create oTel resource, %v", err)
	}
	oTelTLSConf, err := getOTelClientTLSConfig(oTelCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get oTel TLS config: %v", err)
	}

	// Set up an OTel exporter for metrics.
	var metricExporter sdkmetric.Exporter
	if isGRPCProtocol(oTelCfg.CollectorEndpoint) {
		// gRPC protocol.
		var opts []otlpmetricgrpc.Option
		opts = append(opts, otlpmetricgrpc.WithEndpoint(trimScheme(oTelCfg.CollectorEndpoint)))
		opts = append(opts, otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(oTelTLSConf)))
		metricExporter, err = otlpmetricgrpc.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create oTel metric gRPC exporter for endpoint %s: %v", oTelCfg.CollectorEndpoint, err)
		}
	} else {
		// HTTP/HTTPS protocol.
		var opts []otlpmetrichttp.Option
		if hasProtocolScheme(oTelCfg.CollectorEndpoint) {
			opts = append(opts, otlpmetrichttp.WithEndpointURL(oTelCfg.CollectorEndpoint))
		} else {
			opts = append(opts, otlpmetrichttp.WithEndpoint(oTelCfg.CollectorEndpoint))
		}

		opts = append(opts, otlpmetrichttp.WithTLSClientConfig(oTelTLSConf))
		metricExporter, err = otlpmetrichttp.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create oTel metric http exporter for endpoint %s: %v", oTelCfg.CollectorEndpoint, err)
		}
	}

	// Set up a metric provider.
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(metricExporter),
		),
		sdkmetric.WithResource(oTelResource),
	)

	otel.SetMeterProvider(meterProvider)

	return meterProvider.Shutdown, nil
}

func waitForTLSFileReady(oTelCfg config.OTel) error {
	if _, err := os.Stat(oTelCfg.CACertPath); err != nil {
		log.Printf("oTel: wait for the TLS CA cert ready before starting oTel instrumentation")
		if err := waitForFileReady(oTelCfg.CACertPath, 300*time.Second); err != nil {
			return err
		}
	}

	if !oTelCfg.MTLS {
		return nil
	}

	if _, err := os.Stat(oTelCfg.ClientCertPath); err != nil {
		log.Printf("oTel: wait for the TLS client cert ready before starting oTel instrumentation")
		if err := waitForFileReady(oTelCfg.ClientCertPath, 300*time.Second); err != nil {
			return err
		}
	}
	return nil
}

func waitForFileReady(path string, timeout time.Duration) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := os.Stat(path); err == nil {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("file %s not found within timeout", path)
		}
	}
}
