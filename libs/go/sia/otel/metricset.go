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

	metricNameServiceCertValidityRemainingSecs = "sia.service_cert.validity.remaining_secs"
	metricNameRoleCertValidityRemainingSecs    = "sia.role_cert.validity.remaining_secs"
	metricAgentCommandResult                   = "sia.agent_command.result_total"
)

var metricSet siaMetricSet

type siaMetricSet struct {
	serviceCertExpiryRemainingSecsGauge metric.Int64Gauge
	roleCertExpiryRemainingSecsGauge    metric.Int64Gauge
	agentCmdResultCounter               metric.Int64Counter
}

func init() {
	meter := otel.GetMeterProvider().Meter(scopeName)

	var err error
	metricSet.serviceCertExpiryRemainingSecsGauge, err = meter.Int64Gauge(
		metricNameServiceCertValidityRemainingSecs,
		metric.WithUnit("1"),
		metric.WithDescription("number of seconds remaining before the current service TLS certificate expires"),
	)
	if err != nil {
		log.Printf("Error creating metric for %s: %v\n", metricNameServiceCertValidityRemainingSecs, err)
	}

	metricSet.roleCertExpiryRemainingSecsGauge, err = meter.Int64Gauge(
		metricNameRoleCertValidityRemainingSecs,
		metric.WithUnit("1"),
		metric.WithDescription("number of seconds remaining before the current service role certificate expires"),
	)
	if err != nil {
		log.Printf("Error creating metric for %s: %v\n", metricNameRoleCertValidityRemainingSecs, err)
	}

	metricSet.agentCmdResultCounter, err = meter.Int64Counter(
		metricAgentCommandResult,
		metric.WithDescription("Counts the total number of agent command executions by type and result"),
	)
	if err != nil {
		log.Printf("Error creating metric for %s: %v\n", metricAgentCommandResult, err)
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

	secsUntilExpiry := int64(cert.NotAfter.Sub(time.Now()).Seconds())

	cname := cert.Subject.CommonName

	metricCtx, cancel := metricContext()
	defer cancel()
	metricSet.serviceCertExpiryRemainingSecsGauge.Record(metricCtx, secsUntilExpiry,
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
	secsUntilExpiry := int64(cert.NotAfter.Sub(time.Now()).Seconds())

	cname := cert.Subject.CommonName

	metricCtx, cancel := metricContext()
	defer cancel()
	metricSet.roleCertExpiryRemainingSecsGauge.Record(metricCtx, secsUntilExpiry,
		metric.WithAttributes(
			attribute.String("cname", cname)),
	)
}

// RecordAgentCommandResult records the result of an agent command execution.
func RecordAgentCommandResult(function string, success bool) {
	status := "failure"
	if success {
		status = "success"
	}

	metricCtx, cancel := metricContext()
	defer cancel()

	metricSet.agentCmdResultCounter.Add(metricCtx, 1,
		metric.WithAttributes(
			attribute.String("function", function),
			attribute.String("result", status),
		),
	)
}
