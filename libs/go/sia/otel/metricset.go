package otel

import (
	"context"
	"crypto/x509"
	"log"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	scopeName                  = "github.com/AthenZ/athenz/libs/go"
	defaultMetricExportTimeout = 3 * time.Second

	serviceCertValidityRemainingDays = "sia.service_cert.validity.remaining_days"
	roleCertValidityRemainingDays    = "sia.role_cert.validity.remaining_days"
)

var metricSet siaMetricSet

type siaMetricSet struct {
	serviceCertExpiryRemainingDaysGauge metric.Int64Gauge
	roleCertExpiryRemainingDaysGauge    metric.Int64Gauge
}

func init() {
	meter := otel.GetMeterProvider().Meter(scopeName)

	var err error
	metricSet.serviceCertExpiryRemainingDaysGauge, err = meter.Int64Gauge(
		serviceCertValidityRemainingDays,
		metric.WithUnit("1"),
		metric.WithDescription("number of days remaining before the current service TLS certificate expires"),
	)
	if err != nil {
		log.Printf("Error creating metric for %s: %v\n", serviceCertValidityRemainingDays, err)
	}

	metricSet.roleCertExpiryRemainingDaysGauge, err = meter.Int64Gauge(
		roleCertValidityRemainingDays,
		metric.WithUnit("1"),
		metric.WithDescription("number of days remaining before the current service role certificate expires"),
	)
	if err != nil {
		log.Printf("Error creating metric for %s: %v\n", roleCertValidityRemainingDays, err)
	}
}

func metricContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultMetricExportTimeout)
}

// ExportServiceCertMetric exports the service certificate expiry metric.
func ExportServiceCertMetric(cert *x509.Certificate) {
	if cert == nil {
		log.Println("ExportServiceCertMetric: metrics exported with nil cert")
		return
	}

	daysUntilExpiry := int64(cert.NotAfter.Sub(time.Now()).Hours() / 24)

	cname := cert.Subject.CommonName

	metricCtx, cancel := metricContext()
	defer cancel()
	metricSet.serviceCertExpiryRemainingDaysGauge.Record(metricCtx, daysUntilExpiry,
		metric.WithAttributes(
			attribute.String("cname", cname)),
	)
}

// ExportRoleCertMetric exports the role certificate expiry metric.
func ExportRoleCertMetric(cert *x509.Certificate) {
	if cert == nil {
		log.Println("ExportRoleCertMetric: metrics exported with nil cert")
		return
	}
	daysUntilExpiry := int64(cert.NotAfter.Sub(time.Now()).Hours() / 24)

	cname := cert.Subject.CommonName

	metricCtx, cancel := metricContext()
	defer cancel()
	metricSet.roleCertExpiryRemainingDaysGauge.Record(metricCtx, daysUntilExpiry,
		metric.WithAttributes(
			attribute.String("cname", cname)),
	)
}
