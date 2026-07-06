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

package spiffe

import (
	"testing"
)

func TestDefaultFormatterFormatServiceURI(t *testing.T) {
	formatter := &DefaultFormatter{}

	tests := []struct {
		name      string
		trustDom  string
		namespace string
		domain    string
		service   string
		expected  string
	}{
		{
			name:      "with trust domain and namespace",
			trustDom:  "athenz.io",
			namespace: "production",
			domain:    "mycompany",
			service:   "api",
			expected:  "spiffe://athenz.io/ns/production/sa/mycompany.api",
		},
		{
			name:      "with trust domain but no namespace",
			trustDom:  "athenz.io",
			namespace: "",
			domain:    "mycompany",
			service:   "api",
			expected:  "spiffe://mycompany/sa/api",
		},
		{
			name:      "no trust domain",
			trustDom:  "",
			namespace: "production",
			domain:    "mycompany",
			service:   "api",
			expected:  "spiffe://mycompany/sa/api",
		},
		{
			name:      "no trust domain or namespace",
			trustDom:  "",
			namespace: "",
			domain:    "mycompany",
			service:   "api",
			expected:  "spiffe://mycompany/sa/api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatter.FormatServiceURI(tt.trustDom, tt.namespace, tt.domain, tt.service, "")
			if result != tt.expected {
				t.Errorf("FormatServiceURI() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestDefaultFormatterFormatRoleURI(t *testing.T) {
	formatter := &DefaultFormatter{}

	tests := []struct {
		name     string
		trustDom string
		domain   string
		role     string
		expected string
	}{
		{
			name:     "with trust domain",
			trustDom: "athenz.io",
			domain:   "mycompany",
			role:     "admin",
			expected: "spiffe://athenz.io/ns/mycompany/ra/admin",
		},
		{
			name:     "without trust domain",
			trustDom: "",
			domain:   "mycompany",
			role:     "admin",
			expected: "spiffe://mycompany/ra/admin",
		},
		{
			name:     "with dots in domain",
			trustDom: "athenz.io",
			domain:   "my.company.com",
			role:     "viewer",
			expected: "spiffe://athenz.io/ns/my.company.com/ra/viewer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatter.FormatRoleURI(tt.trustDom, tt.domain, tt.role)
			if result != tt.expected {
				t.Errorf("FormatRoleURI() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestDefaultFormatterFormatUserURI(t *testing.T) {
	formatter := &DefaultFormatter{}

	tests := []struct {
		name          string
		trustDom      string
		namespace     string
		principalName string
		expected      string
	}{
		{
			name:          "with namespace",
			trustDom:      "athenz.io",
			namespace:     "engineering",
			principalName: "user@example.com",
			expected:      "spiffe://athenz.io/ns/engineering/sa/user@example.com",
		},
		{
			name:          "without namespace",
			trustDom:      "athenz.io",
			namespace:     "",
			principalName: "user@example.com",
			expected:      "spiffe://athenz.io/ns/default/sa/user@example.com",
		},
		{
			name:          "with empty string namespace",
			trustDom:      "athenz.io",
			namespace:     "",
			principalName: "john.doe",
			expected:      "spiffe://athenz.io/ns/default/sa/john.doe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatter.FormatUserURI(tt.trustDom, tt.namespace, tt.principalName, "")
			if result != tt.expected {
				t.Errorf("FormatUserURI() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestDefaultParserParseServiceURI(t *testing.T) {
	parser := &DefaultParser{}

	tests := []struct {
		name              string
		uri               string
		expectedTrustDom  string
		expectedNamespace string
		expectedDomain    string
		expectedService   string
	}{
		{
			name:              "full SPIFFE URI with namespace",
			uri:               "spiffe://athenz.io/ns/production/sa/mycompany.api",
			expectedTrustDom:  "athenz.io",
			expectedNamespace: "production",
			expectedDomain:    "mycompany",
			expectedService:   "api",
		},
		{
			name:              "basic SPIFFE URI without namespace",
			uri:               "spiffe://mycompany/sa/api",
			expectedTrustDom:  "",
			expectedNamespace: "",
			expectedDomain:    "mycompany",
			expectedService:   "api",
		},
		{
			name:              "URI with complex domain",
			uri:               "spiffe://athenz.io/ns/ns1/sa/my.company.com.service",
			expectedTrustDom:  "athenz.io",
			expectedNamespace: "ns1",
			expectedDomain:    "my.company.com",
			expectedService:   "service",
		},
		{
			name:              "invalid URI format",
			uri:               "https://example.com/invalid",
			expectedTrustDom:  "",
			expectedNamespace: "",
			expectedDomain:    "",
			expectedService:   "",
		},
		{
			name:              "URI without service part",
			uri:               "spiffe://athenz.io/ns/production/sa/",
			expectedTrustDom:  "",
			expectedNamespace: "",
			expectedDomain:    "",
			expectedService:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trustDom, namespace, domain, service, _ := parser.ParseServiceURI(tt.uri)
			if trustDom != tt.expectedTrustDom || namespace != tt.expectedNamespace ||
				domain != tt.expectedDomain || service != tt.expectedService {
				t.Errorf("ParseServiceURI(%s) = (%s, %s, %s, %s), want (%s, %s, %s, %s)",
					tt.uri, trustDom, namespace, domain, service,
					tt.expectedTrustDom, tt.expectedNamespace, tt.expectedDomain, tt.expectedService)
			}
		})
	}
}

func TestDefaultParserParseRoleURI(t *testing.T) {
	parser := &DefaultParser{}

	tests := []struct {
		name           string
		uri            string
		expectedDomain string
		expectedRole   string
	}{
		{
			name:           "basic role URI",
			uri:            "spiffe://mycompany/ra/admin",
			expectedDomain: "mycompany",
			expectedRole:   "admin",
		},
		{
			name:           "role URI with complex domain",
			uri:            "spiffe://my.company.com/ra/viewer",
			expectedDomain: "my.company.com",
			expectedRole:   "viewer",
		},
		{
			name:           "invalid URI format",
			uri:            "https://example.com/role",
			expectedDomain: "",
			expectedRole:   "",
		},
		{
			name:           "URI without role part",
			uri:            "spiffe://mycompany/ra/",
			expectedDomain: "",
			expectedRole:   "",
		},
		{
			name:           "URI with namespace (returns full domain component)",
			uri:            "spiffe://athenz.io/ns/production/ra/admin",
			expectedDomain: "athenz.io/ns/production",
			expectedRole:   "admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, role := parser.ParseRoleURI(tt.uri)
			if domain != tt.expectedDomain || role != tt.expectedRole {
				t.Errorf("ParseRoleURI(%s) = (%s, %s), want (%s, %s)",
					tt.uri, domain, role, tt.expectedDomain, tt.expectedRole)
			}
		})
	}
}

func TestDefaultParserParseCAURI(t *testing.T) {
	parser := &DefaultParser{}

	tests := []struct {
		name              string
		uri               string
		expectedTrustDom  string
		expectedNamespace string
		expectedCAName    string
	}{
		{
			name:              "valid CA URI",
			uri:               "spiffe://athenz.io/ns/production/ca/root",
			expectedTrustDom:  "athenz.io",
			expectedNamespace: "production",
			expectedCAName:    "root",
		},
		{
			name:              "CA URI with complex namespace",
			uri:               "spiffe://athenz.io/ns/my.namespace/ca/intermediate",
			expectedTrustDom:  "athenz.io",
			expectedNamespace: "my.namespace",
			expectedCAName:    "intermediate",
		},
		{
			name:              "URI without namespace",
			uri:               "spiffe://athenz.io/ca/root",
			expectedTrustDom:  "",
			expectedNamespace: "",
			expectedCAName:    "",
		},
		{
			name:              "invalid URI format",
			uri:               "https://example.com/ca",
			expectedTrustDom:  "",
			expectedNamespace: "",
			expectedCAName:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trustDom, namespace, caName := parser.ParseCAURI(tt.uri)
			if trustDom != tt.expectedTrustDom || namespace != tt.expectedNamespace || caName != tt.expectedCAName {
				t.Errorf("ParseCAURI(%s) = (%s, %s, %s), want (%s, %s, %s)",
					tt.uri, trustDom, namespace, caName, tt.expectedTrustDom, tt.expectedNamespace, tt.expectedCAName)
			}
		})
	}
}

// customTestFormatter is a test implementation of URIFormatter
type customTestFormatter struct{}

func (f *customTestFormatter) FormatServiceURI(trustDomain, namespace, domain, service, workloadId string) string {
	return "custom:service:" + domain + ":" + service
}

func (f *customTestFormatter) FormatRoleURI(trustDomain, domain, role string) string {
	return "custom:role:" + domain + ":" + role
}

func (f *customTestFormatter) FormatUserURI(trustDomain, namespace, principalName, deviceId string) string {
	return "custom:user:" + principalName
}

// customTestParser is a test implementation of URIParser
type customTestParser struct{}

func (p *customTestParser) ParseServiceURI(uri string) (string, string, string, string, string) {
	return "custom-trust", "custom-ns", "custom-domain", "custom-service", ""
}

func (p *customTestParser) ParseRoleURI(uri string) (string, string) {
	return "custom-domain", "custom-role"
}

func (p *customTestParser) ParseCAURI(uri string) (string, string, string) {
	return "custom-trust", "custom-ns", "custom-ca"
}

func TestCustomFormatterIntegration(t *testing.T) {
	// Test that custom formatter can be injected and used directly
	customFormatter := &customTestFormatter{}
	serviceURI := customFormatter.FormatServiceURI("td", "ns", "domain", "svc", "")
	if serviceURI != "custom:service:domain:svc" {
		t.Errorf("Custom formatter not working correctly: got %s", serviceURI)
	}
}

func TestCustomParserIntegration(t *testing.T) {
	// Test that custom parser can be injected and used directly
	customParser := &customTestParser{}
	td, ns, domain, service, _ := customParser.ParseServiceURI("some-uri")
	if td != "custom-trust" || ns != "custom-ns" || domain != "custom-domain" || service != "custom-service" {
		t.Errorf("Custom parser not working correctly: got (%s, %s, %s, %s)", td, ns, domain, service)
	}
}

func TestParseURIEdgeCases(t *testing.T) {
	parser := &DefaultParser{}

	tests := []struct {
		name              string
		uri               string
		expectedTrustDom  string
		expectedNamespace string
		expectedDomain    string
		expectedService   string
	}{
		{
			name:              "empty URI",
			uri:               "",
			expectedTrustDom:  "",
			expectedNamespace: "",
			expectedDomain:    "",
			expectedService:   "",
		},
		{
			name:              "URI with no sa component",
			uri:               "spiffe://athenz.io/ns/production",
			expectedTrustDom:  "",
			expectedNamespace: "",
			expectedDomain:    "",
			expectedService:   "",
		},
		{
			name:              "multiple service names",
			uri:               "spiffe://athenz.io/ns/ns1/sa/domain.service1.service2",
			expectedTrustDom:  "athenz.io",
			expectedNamespace: "ns1",
			expectedDomain:    "domain.service1",
			expectedService:   "service2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trustDom, namespace, domain, service, _ := parser.ParseServiceURI(tt.uri)
			if trustDom != tt.expectedTrustDom || namespace != tt.expectedNamespace ||
				domain != tt.expectedDomain || service != tt.expectedService {
				t.Errorf("ParseServiceURI(%s) = (%s, %s, %s, %s), want (%s, %s, %s, %s)",
					tt.uri, trustDom, namespace, domain, service,
					tt.expectedTrustDom, tt.expectedNamespace, tt.expectedDomain, tt.expectedService)
			}
		})
	}
}

func TestRoundTripFormatParse(t *testing.T) {
	formatter := &DefaultFormatter{}
	parser := &DefaultParser{}

	testCases := []struct {
		name      string
		trustDom  string
		namespace string
		domain    string
		service   string
	}{
		{
			name:      "basic service",
			trustDom:  "athenz.io",
			namespace: "production",
			domain:    "company",
			service:   "api",
		},
		{
			name:      "service without namespace",
			trustDom:  "",
			namespace: "",
			domain:    "company",
			service:   "api",
		},
		{
			name:      "complex domain name",
			trustDom:  "example.io",
			namespace: "staging",
			domain:    "my.company.net",
			service:   "web-api",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Format the URI
			uri := formatter.FormatServiceURI(tc.trustDom, tc.namespace, tc.domain, tc.service, "")

			// Parse it back
			parsedTD, parsedNS, parsedDomain, parsedService, _ := parser.ParseServiceURI(uri)

			// Verify round-trip
			if parsedTD != tc.trustDom || parsedNS != tc.namespace ||
				parsedDomain != tc.domain || parsedService != tc.service {
				t.Errorf("Round-trip failed: formatted %s, parsed (%s, %s, %s, %s), want (%s, %s, %s, %s)",
					uri, parsedTD, parsedNS, parsedDomain, parsedService,
					tc.trustDom, tc.namespace, tc.domain, tc.service)
			}
		})
	}
}
