// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

// Zts-svccert is a program to generate service token, generate a CSR
// and request a X509 Certificate for that service token from ZTS Server.
//
// The -spiffe flag includes a SPIFFE URI but also permits Athenz URI SANs.
// Use -spiffe-svid to keep exactly one SPIFFE URI SAN, including when -instance
// or -hostname is specified. DNS and IP SANs and Subject fields are preserved.
// With -spiffe-svid, a supplied -request-csr must already contain exactly one
// SPIFFE URI SAN; its signed contents are never rewritten.
// The -spiffe-svid flag follows the opt-in convention of zts-svctoken.
//
// Provider registration with -spiffe-svid or -request-csr sends -instance as
// x509CertInstanceId, matching the existing athenz-issuer registration flow.
// ZTS must support x509CertInstanceId when the CSR contains no instance ID.
// The -hostname value is still sent as the registration request's hostname.
// The resulting certificate does not contain the Athenz instance-ID URI used
// by the traditional instance refresh API. Renew it by registering again
// with fresh attestation rather than using that refresh API.
package main
