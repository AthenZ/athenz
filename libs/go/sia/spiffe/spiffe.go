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

// Package spiffe provides interfaces and utilities for SPIFFE URI handling.
package spiffe

import (
	"fmt"
	"strings"
)

// URIFormatter defines custom SPIFFE URI formatting behavior for CSR generation.
// Implementations can override the default SPIFFE URI format (e.g., for custom trust domains or namespaces).
// Implementations of this interface can be provided via options or set as the default formatter.
type URIFormatter interface {
	// FormatServiceURI returns a SPIFFE service URI given trust domain, namespace, domain, service name, and optional workload ID.
	// The workloadId parameter is provided for custom implementations that need it; the default formatter ignores it.
	FormatServiceURI(trustDomain, namespace, domain, service, workloadId string) string
	// FormatRoleURI returns a SPIFFE role URI given trust domain, domain, and role name.
	FormatRoleURI(trustDomain, domain, role string) string
	// FormatUserURI returns a SPIFFE user URI given trust domain, namespace, principal name, and optional device ID.
	// The deviceId parameter is provided for custom implementations that need it; the default formatter ignores it.
	FormatUserURI(trustDomain, namespace, principalName, deviceId string) string
}

// DefaultFormatter provides standard SPIFFE URI formatting.
// It generates SPIFFE URIs with optional namespace support based on trust domain configuration.
type DefaultFormatter struct{}

// FormatServiceURI returns a SPIFFE service URI in the format:
// - With trust domain and namespace: spiffe://{trustDomain}/ns/{namespace}/sa/{domain}.{service}
// - Without trust domain/namespace: spiffe://{domain}/sa/{service}
// The workloadId parameter is accepted but ignored by the default formatter.
func (f *DefaultFormatter) FormatServiceURI(trustDomain, namespace, domain, service, workloadId string) string {
	if trustDomain != "" && namespace != "" {
		return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s.%s", trustDomain, namespace, domain, service)
	}
	return fmt.Sprintf("spiffe://%s/sa/%s", domain, service)
}

// FormatRoleURI returns a SPIFFE role URI in the format:
// - With trust domain: spiffe://{trustDomain}/ns/{domain}/ra/{role}
// - Without trust domain: spiffe://{domain}/ra/{role}
func (f *DefaultFormatter) FormatRoleURI(trustDomain, domain, role string) string {
	if trustDomain != "" {
		return fmt.Sprintf("spiffe://%s/ns/%s/ra/%s", trustDomain, domain, role)
	}
	return fmt.Sprintf("spiffe://%s/ra/%s", domain, role)
}

// FormatUserURI returns a SPIFFE user URI in the format:
// spiffe://{trustDomain}/ns/{namespace}/sa/{principalName}
// The namespace defaults to "default" if not specified.
// The deviceId parameter is accepted but ignored by the default formatter.
func (f *DefaultFormatter) FormatUserURI(trustDomain, namespace, principalName, deviceId string) string {
	if namespace == "" {
		namespace = "default"
	}
	return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, namespace, principalName)
}

// URIParser defines SPIFFE URI parsing behavior.
type URIParser interface {
	// ParseServiceURI parses a SPIFFE service URI and returns its components including an optional workload ID.
	// The workloadId will always be empty string for the default parser.
	ParseServiceURI(uri string) (trustDomain, namespace, domain, service, workloadId string)
	ParseRoleURI(uri string) (domain, role string)
	ParseCAURI(uri string) (trustDomain, namespace, caName string)
}

// DefaultParser provides standard SPIFFE URI parsing.
// It parses both standard and namespaced SPIFFE URIs.
type DefaultParser struct{}

// ParseServiceURI parses a SPIFFE service URI and returns its components.
// Returns (trustDomain, namespace, domain, service, workloadId) for full URIs, or ("", "", domain, service, "") for basic URIs.
// The default parser always returns an empty string for workloadId.
func (p *DefaultParser) ParseServiceURI(uri string) (string, string, string, string, string) {
	idx := strings.Index(uri, "/ns/")
	if idx == -1 {
		domain, service := parseURIWithoutNamespace(uri, "/sa/")
		return "", "", domain, service, ""
	}
	trustDomain, namespace, athenzService := parseURIWithNamespace(uri, "/sa/")
	idx = strings.LastIndex(athenzService, ".")
	if idx < 0 {
		return "", "", "", "", ""
	}
	return trustDomain, namespace, athenzService[0:idx], athenzService[idx+1:], ""
}

// ParseRoleURI parses a SPIFFE role URI and returns domain and role.
func (p *DefaultParser) ParseRoleURI(uri string) (string, string) {
	return parseURIWithoutNamespace(uri, "/ra/")
}

// ParseCAURI parses a SPIFFE CA URI and returns its components.
// Returns (trustDomain, namespace, caName) or ("", "", "") if not a valid CA URI.
func (p *DefaultParser) ParseCAURI(uri string) (string, string, string) {
	idx := strings.Index(uri, "/ns/")
	if idx == -1 {
		return "", "", ""
	}
	return parseURIWithNamespace(uri, "/ca/")
}

// parseURIWithoutNamespace is a helper that parses SPIFFE URIs without namespace.
// It extracts the two components separated by objType (e.g., "/sa/", "/ra/").
func parseURIWithoutNamespace(uri, objType string) (string, string) {
	if !strings.HasPrefix(uri, "spiffe://") {
		return "", ""
	}
	comp := uri[9:]
	idx := strings.Index(comp, objType)
	if idx == -1 {
		return "", ""
	}
	comp1 := comp[0:idx]
	comp2 := comp[idx+len(objType):]
	if comp1 == "" || comp2 == "" {
		return "", ""
	}
	return comp1, comp2
}

// parseURIWithNamespace is a helper that parses SPIFFE URIs with namespace.
// It extracts trustDomain, namespace, and remaining component separated by objType.
func parseURIWithNamespace(uri, objType string) (string, string, string) {
	if !strings.HasPrefix(uri, "spiffe://") {
		return "", "", ""
	}
	comp := uri[9:]
	idx := strings.Index(comp, "/ns/")
	if idx == -1 {
		return "", "", ""
	}
	trustDomain := comp[0:idx]
	nsComp := comp[idx+4:]
	idx = strings.Index(nsComp, objType)
	if idx == -1 {
		return "", "", ""
	}
	return trustDomain, nsComp[0:idx], nsComp[idx+len(objType):]
}

var (
	defaultFormatter URIFormatter = &DefaultFormatter{}
	defaultParser    URIParser    = &DefaultParser{}
)

// GetDefaultFormatter returns the current default SPIFFE URI formatter.
// Returns a DefaultFormatter instance.
func GetDefaultFormatter() URIFormatter {
	return defaultFormatter
}

// GetDefaultParser returns the current default SPIFFE URI parser.
// Returns a DefaultParser instance.
func GetDefaultParser() URIParser {
	return defaultParser
}
