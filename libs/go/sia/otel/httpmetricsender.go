package otel

import (
	"context"
	"crypto/tls"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

// SetupOTelSDK initializes the OTel SDK.
func SetupOTelSDK(ctx context.Context, collectorEndpoint string, tlsConfig *tls.Config, res *resource.Resource) (shutdown func(context.Context) error) {
	// Set up an OTel exporter for metrics.
	var opts []otlpmetrichttp.Option
	opts = append(opts, otlpmetrichttp.WithEndpoint(collectorEndpoint))
	opts = append(opts, otlpmetrichttp.WithTLSClientConfig(tlsConfig))

	metricExporter, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		log.Fatalf("failed to create metric exporter: %v", err)
	}

	// Set up a metric provider.
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(metricExporter),
		),
		sdkmetric.WithResource(res),
	)

	otel.SetMeterProvider(meterProvider)

	return meterProvider.Shutdown
}
