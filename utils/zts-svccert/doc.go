// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

// Zts-svccert is a program to generate service token, generate a CSR
// and request a X509 Certificate for that service token from ZTS Server.
//
// The -spiffe flag includes a SPIFFE URI but also permits Athenz URI SANs.
// Use -spiffe-svid to keep exactly one SPIFFE URI SAN, including when -instance
// or -hostname is specified. Existing DNS and IP SANs and Subject fields are
// preserved. When -instance is set, its ID is included in the supported
// <instance-id>.instanceid.athenz.<dns-domain> DNS SAN so ZTS can read it from
// both the issued certificate and a newly generated provider refresh CSR.
// The DNS suffix must be authorized for instance IDs by the provider.
// With -spiffe-svid, a supplied -request-csr must already contain exactly one
// SPIFFE URI SAN; its signed contents are never rewritten.
// The -spiffe-svid flag follows the opt-in convention of zts-svctoken.
//
// Provider registration with -spiffe-svid or -request-csr sends -instance as
// x509CertInstanceId, matching the existing athenz-issuer registration flow.
// ZTS must support x509CertInstanceId when the CSR contains no instance ID.
// The -hostname value is still sent as the registration request's hostname.
// A pre-generated CSR must already carry a matching instance-ID DNS SAN to
// support provider refresh; x509CertInstanceId alone only supports registration.
package main
