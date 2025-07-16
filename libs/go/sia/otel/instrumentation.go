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
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// HttpTransport returns a http.RoundTripper that is instrumented with OpenTelemetry if oTelEnabled is true.
func HttpTransport(base http.RoundTripper, opts ...otelhttp.Option) http.RoundTripper {
	if oTelEnabled {
		return otelhttp.NewTransport(base, opts...)
	}
	return base
}
