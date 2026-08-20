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
	"net/url"
	"strings"
)

// defaultMetricsPath is the default OTLP/HTTP URL path for metrics.
// Ref: https://opentelemetry.io/docs/specs/otel/protocol/exporter/
const defaultMetricsPath = "/v1/metrics"

// isGRPCProtocol checks if the endpoint is using gRPC protocol
// Port 4317 is the default gRPC port for OpenTelemetry.
// Ref: https://opentelemetry.io/docs/specs/otel/protocol/exporter/
func isGRPCProtocol(endpoint string) bool {
	if strings.HasPrefix(endpoint, "grpc://") {
		return true
	}
	if strings.Contains(endpoint, "://") {
		// It has a scheme, but not grpc://, so it's not gRPC.
		return false
	}
	// Schemaless, check for port 4317
	return strings.HasSuffix(endpoint, ":4317")
}

// trimScheme removes the scheme from a URL string.
func trimScheme(s string) string {
	separatorIndex := strings.Index(s, "://")
	if separatorIndex != -1 {
		return s[separatorIndex+3:]
	}
	return s
}

// hasProtocolScheme checks if the string contains a protocol scheme.
func hasProtocolScheme(s string) bool {
	return strings.Index(s, "://") != -1
}

// metricsEndpointURL returns the URL to be used for the OTLP/HTTP metric exporter.
// The exporter uses the path of the given URL as-is, and an endpoint without a path
// targets the root path, so the default metrics path is appended when the configured
// endpoint does not carry one.
func metricsEndpointURL(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = defaultMetricsPath
	}
	return u.String()
}
