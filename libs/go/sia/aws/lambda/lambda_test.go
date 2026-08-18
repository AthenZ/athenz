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

package lambda

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/aws/attestation"
	"github.com/AthenZ/athenz/libs/go/sia/aws/stssession"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockACMClient is a mock implementation of ACM client methods used by getCertificateArnByTag
type mockACMClient struct {
	listCertificatesPages     []*acm.ListCertificatesOutput
	listCertificatesError     error
	listTagsForCertificateMap map[string]*acm.ListTagsForCertificateOutput
	listTagsErrorMap          map[string]error
	addTagsToCertificateError error
	currentPageIndex          int
}

func newMockACMClient() *mockACMClient {
	return &mockACMClient{
		listTagsForCertificateMap: make(map[string]*acm.ListTagsForCertificateOutput),
		listTagsErrorMap:          make(map[string]error),
		currentPageIndex:          0,
	}
}

func (m *mockACMClient) ListCertificates(_ context.Context, _ *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	if m.listCertificatesError != nil {
		return nil, m.listCertificatesError
	}
	if m.currentPageIndex < len(m.listCertificatesPages) {
		result := m.listCertificatesPages[m.currentPageIndex]
		// Set NextToken to indicate there are more pages (except for the last page)
		if m.currentPageIndex < len(m.listCertificatesPages)-1 {
			result.NextToken = aws.String("next-page-token")
		}
		m.currentPageIndex++
		return result, nil
	}
	return &acm.ListCertificatesOutput{
		CertificateSummaryList: []acmtypes.CertificateSummary{},
	}, nil
}

func (m *mockACMClient) ListTagsForCertificate(_ context.Context, params *acm.ListTagsForCertificateInput, _ ...func(*acm.Options)) (*acm.ListTagsForCertificateOutput, error) {
	// Check for per-certificate error first
	if err, ok := m.listTagsErrorMap[*params.CertificateArn]; ok {
		return nil, err
	}
	if output, ok := m.listTagsForCertificateMap[*params.CertificateArn]; ok {
		return output, nil
	}
	return &acm.ListTagsForCertificateOutput{
		Tags: []acmtypes.Tag{},
	}, nil
}

func (m *mockACMClient) AddTagsToCertificate(_ context.Context, _ *acm.AddTagsToCertificateInput, _ ...func(*acm.Options)) (*acm.AddTagsToCertificateOutput, error) {
	if m.addTagsToCertificateError != nil {
		return nil, m.addTagsToCertificateError
	}
	return &acm.AddTagsToCertificateOutput{}, nil
}

// TestGetCertificateArnByTag tests getCertificateArnByTag using the testable version with mock client
func TestGetCertificateArnByTag(t *testing.T) {
	tests := []struct {
		name           string
		certTagIdKey   string
		certTagIdValue string
		setupMock      func() *mockACMClient
		expectedARN    string
		expectedError  string
	}{
		{
			name:           "successful match found",
			certTagIdKey:   "athenz:service",
			certTagIdValue: "test-service",
			setupMock: func() *mockACMClient {
				certArn1 := aws.String("arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012")
				certArn2 := aws.String("arn:aws:acm:us-east-1:123456789012:certificate/87654321-4321-4321-4321-210987654321")
				client := newMockACMClient()
				client.listCertificatesPages = []*acm.ListCertificatesOutput{
					{
						CertificateSummaryList: []acmtypes.CertificateSummary{
							{CertificateArn: certArn1},
							{CertificateArn: certArn2},
						},
					},
				}
				client.listTagsForCertificateMap = map[string]*acm.ListTagsForCertificateOutput{
					*certArn1: {
						Tags: []acmtypes.Tag{
							{Key: aws.String("athenz:service"), Value: aws.String("other-service")},
							{Key: aws.String("athenz:domain"), Value: aws.String("test-domain")},
						},
					},
					*certArn2: {
						Tags: []acmtypes.Tag{
							{Key: aws.String("athenz:service"), Value: aws.String("test-service")},
							{Key: aws.String("athenz:domain"), Value: aws.String("test-domain")},
						},
					},
				}
				return client
			},
			expectedARN:   "arn:aws:acm:us-east-1:123456789012:certificate/87654321-4321-4321-4321-210987654321",
			expectedError: "",
		},
		{
			name:           "no matching certificate found",
			certTagIdKey:   "athenz:service",
			certTagIdValue: "non-existent-service",
			setupMock: func() *mockACMClient {
				certArn := aws.String("arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012")
				client := newMockACMClient()
				client.listCertificatesPages = []*acm.ListCertificatesOutput{
					{
						CertificateSummaryList: []acmtypes.CertificateSummary{
							{CertificateArn: certArn},
						},
					},
				}
				client.listTagsForCertificateMap = map[string]*acm.ListTagsForCertificateOutput{
					*certArn: {
						Tags: []acmtypes.Tag{
							{Key: aws.String("athenz:service"), Value: aws.String("other-service")},
						},
					},
				}
				return client
			},
			expectedARN:   "",
			expectedError: "no certificate found with the specified tag key/value pair",
		},
		{
			name:           "empty certificate list",
			certTagIdKey:   "athenz:service",
			certTagIdValue: "test-service",
			setupMock: func() *mockACMClient {
				client := newMockACMClient()
				client.listCertificatesPages = []*acm.ListCertificatesOutput{
					{
						CertificateSummaryList: []acmtypes.CertificateSummary{},
					},
				}
				return client
			},
			expectedARN:   "",
			expectedError: "no certificate found with the specified tag key/value pair",
		},
		{
			name:           "list certificates error",
			certTagIdKey:   "athenz:service",
			certTagIdValue: "test-service",
			setupMock: func() *mockACMClient {
				client := newMockACMClient()
				client.listCertificatesError = errors.New("failed to list certificates")
				return client
			},
			expectedARN:   "",
			expectedError: "failed to list certificates",
		},
		{
			name:           "list tags error continues search",
			certTagIdKey:   "athenz:service",
			certTagIdValue: "test-service",
			setupMock: func() *mockACMClient {
				certArn1 := aws.String("arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012")
				certArn2 := aws.String("arn:aws:acm:us-east-1:123456789012:certificate/87654321-4321-4321-4321-210987654321")
				client := newMockACMClient()
				client.listCertificatesPages = []*acm.ListCertificatesOutput{
					{
						CertificateSummaryList: []acmtypes.CertificateSummary{
							{CertificateArn: certArn1},
							{CertificateArn: certArn2},
						},
					},
				}
				client.listTagsErrorMap = map[string]error{
					*certArn1: errors.New("failed to list tags"),
				}
				client.listTagsForCertificateMap = map[string]*acm.ListTagsForCertificateOutput{
					*certArn2: {
						Tags: []acmtypes.Tag{
							{Key: aws.String("athenz:service"), Value: aws.String("test-service")},
						},
					},
				}
				return client
			},
			expectedARN:   "arn:aws:acm:us-east-1:123456789012:certificate/87654321-4321-4321-4321-210987654321",
			expectedError: "",
		},
		{
			name:           "pagination across multiple pages",
			certTagIdKey:   "athenz:service",
			certTagIdValue: "test-service",
			setupMock: func() *mockACMClient {
				certArn1 := aws.String("arn:aws:acm:us-east-1:123456789012:certificate/11111111-1111-1111-1111-111111111111")
				certArn2 := aws.String("arn:aws:acm:us-east-1:123456789012:certificate/22222222-2222-2222-2222-222222222222")
				certArn3 := aws.String("arn:aws:acm:us-east-1:123456789012:certificate/33333333-3333-3333-3333-333333333333")
				client := newMockACMClient()
				client.listCertificatesPages = []*acm.ListCertificatesOutput{
					{
						CertificateSummaryList: []acmtypes.CertificateSummary{
							{CertificateArn: certArn1},
							{CertificateArn: certArn2},
						},
					},
					{
						CertificateSummaryList: []acmtypes.CertificateSummary{
							{CertificateArn: certArn3},
						},
					},
				}
				client.listTagsForCertificateMap = map[string]*acm.ListTagsForCertificateOutput{
					*certArn1: {
						Tags: []acmtypes.Tag{
							{Key: aws.String("athenz:service"), Value: aws.String("other-service")},
						},
					},
					*certArn2: {
						Tags: []acmtypes.Tag{
							{Key: aws.String("athenz:service"), Value: aws.String("other-service2")},
						},
					},
					*certArn3: {
						Tags: []acmtypes.Tag{
							{Key: aws.String("athenz:service"), Value: aws.String("test-service")},
						},
					},
				}
				return client
			},
			expectedARN:   "arn:aws:acm:us-east-1:123456789012:certificate/33333333-3333-3333-3333-333333333333",
			expectedError: "",
		},
		{
			name:           "tag with nil key or value skipped",
			certTagIdKey:   "athenz:service",
			certTagIdValue: "test-service",
			setupMock: func() *mockACMClient {
				certArn := aws.String("arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012")
				client := newMockACMClient()
				client.listCertificatesPages = []*acm.ListCertificatesOutput{
					{
						CertificateSummaryList: []acmtypes.CertificateSummary{
							{CertificateArn: certArn},
						},
					},
				}
				client.listTagsForCertificateMap = map[string]*acm.ListTagsForCertificateOutput{
					*certArn: {
						Tags: []acmtypes.Tag{
							{Key: nil, Value: aws.String("test-service")},
							{Key: aws.String("athenz:service"), Value: nil},
							{Key: aws.String("athenz:service"), Value: aws.String("test-service")},
						},
					},
				}
				return client
			},
			expectedARN:   "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := tt.setupMock()

			// Use the testable version that accepts the interface
			arn, err := getCertificateArnByTag(context.Background(), mockClient, tt.certTagIdKey, tt.certTagIdValue)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Empty(t, arn)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedARN, arn)
			}
		})
	}
}

func TestStoreAthenzIdentityInACM(t *testing.T) {
	tests := []struct {
		name           string
		certArn        string
		certTagIdKey   string
		certTagIdValue string
		siaCertData    *util.SiaCertData
		expectedError  string
	}{
		{
			name:           "empty certificate PEM",
			certArn:        "",
			certTagIdKey:   "athenz:service",
			certTagIdValue: "test-service",
			siaCertData: &util.SiaCertData{
				X509CertificatePem: "",
				PrivateKeyPem:      "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----",
			},
			expectedError: "certificate PEM is empty",
		},
		{
			name:           "empty private key PEM",
			certArn:        "",
			certTagIdKey:   "athenz:service",
			certTagIdValue: "test-service",
			siaCertData: &util.SiaCertData{
				X509CertificatePem: "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----",
				PrivateKeyPem:      "",
			},
			expectedError: "private key PEM is empty",
		},
		{
			name:           "missing certArn and tag",
			certArn:        "",
			certTagIdKey:   "",
			certTagIdValue: "",
			siaCertData: &util.SiaCertData{
				X509CertificatePem: "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----",
				PrivateKeyPem:      "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----",
			},
			expectedError: "either certificate ARN or Tag ID Name/Value must be specified",
		},
		{
			name:           "missing certArn and tag key",
			certArn:        "",
			certTagIdKey:   "",
			certTagIdValue: "test-value",
			siaCertData: &util.SiaCertData{
				X509CertificatePem: "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----",
				PrivateKeyPem:      "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----",
			},
			expectedError: "either certificate ARN or Tag ID Name/Value must be specified",
		},
		{
			name:           "missing certArn and tag value",
			certArn:        "",
			certTagIdKey:   "athenz:service",
			certTagIdValue: "",
			siaCertData: &util.SiaCertData{
				X509CertificatePem: "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----",
				PrivateKeyPem:      "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----",
			},
			expectedError: "either certificate ARN or Tag ID Name/Value must be specified",
		},
		{
			name:           "valid data with certArn",
			certArn:        "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
			certTagIdKey:   "",
			certTagIdValue: "",
			siaCertData: &util.SiaCertData{
				X509CertificatePem: "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----",
				PrivateKeyPem:      "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----",
			},
			expectedError: "", // Validation passes, but will fail on actual ACM operation without AWS credentials
		},
		{
			name:           "valid data with tags",
			certArn:        "",
			certTagIdKey:   "athenz:service",
			certTagIdValue: "test-service",
			siaCertData: &util.SiaCertData{
				X509CertificatePem: "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----",
				PrivateKeyPem:      "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----",
			},
			expectedError: "", // Validation passes, but will fail on actual ACM operation without AWS credentials
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arn, err := StoreAthenzIdentityInACM(tt.certArn, tt.certTagIdKey, tt.certTagIdValue, tt.siaCertData, nil)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Empty(t, arn)
			} else {
				// Note: Without AWS credentials, actual ACM operations will fail
				// These tests focus on validation logic - if validation passes but AWS operations fail,
				// that's expected and acceptable for unit tests
				if err != nil {
					// Expected for tests without AWS setup - validation passed, but AWS operation failed
					// Check that it's an AWS-related error (not a validation error)
					assert.NotContains(t, err.Error(), "certificate PEM is empty")
					assert.NotContains(t, err.Error(), "private key PEM is empty")
					assert.NotContains(t, err.Error(), "either certificate ARN or Tag ID Name/Value must be specified")
					assert.NotContains(t, err.Error(), "unable to load AWS config")
				} else {
					assert.NotEmpty(t, arn)
				}
			}
		})
	}
}

func TestSetCertificateTags(t *testing.T) {
	tests := []struct {
		name           string
		certificateArn string
		acmTags        []acmtypes.Tag
		setupMock      func() *mockACMClient
		expectedError  string
	}{
		{
			name:           "successful tag setting with single tag",
			certificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
			acmTags: []acmtypes.Tag{
				{Key: aws.String("athenz:service"), Value: aws.String("test-service")},
			},
			setupMock: func() *mockACMClient {
				return newMockACMClient()
			},
			expectedError: "",
		},
		{
			name:           "successful tag setting with multiple tags",
			certificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
			acmTags: []acmtypes.Tag{
				{Key: aws.String("athenz:service"), Value: aws.String("test-service")},
				{Key: aws.String("athenz:domain"), Value: aws.String("test-domain")},
				{Key: aws.String("Environment"), Value: aws.String("production")},
			},
			setupMock: func() *mockACMClient {
				return newMockACMClient()
			},
			expectedError: "",
		},
		{
			name:           "successful tag setting with empty tags",
			certificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
			acmTags:        []acmtypes.Tag{},
			setupMock: func() *mockACMClient {
				return newMockACMClient()
			},
			expectedError: "",
		},
		{
			name:           "error when AddTagsToCertificate fails",
			certificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
			acmTags: []acmtypes.Tag{
				{Key: aws.String("athenz:service"), Value: aws.String("test-service")},
			},
			setupMock: func() *mockACMClient {
				client := newMockACMClient()
				client.addTagsToCertificateError = errors.New("failed to add tags: resource not found")
				return client
			},
			expectedError: "failed to add tags: resource not found",
		},
		{
			name:           "error when AddTagsToCertificate fails with permission error",
			certificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
			acmTags: []acmtypes.Tag{
				{Key: aws.String("athenz:service"), Value: aws.String("test-service")},
			},
			setupMock: func() *mockACMClient {
				client := newMockACMClient()
				client.addTagsToCertificateError = errors.New("AccessDeniedException: User is not authorized to perform: acm:AddTagsToCertificate")
				return client
			},
			expectedError: "AccessDeniedException: User is not authorized to perform: acm:AddTagsToCertificate",
		},
		{
			name:           "tags with nil key or value",
			certificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
			acmTags: []acmtypes.Tag{
				{Key: nil, Value: aws.String("test-value")},
				{Key: aws.String("athenz:service"), Value: nil},
				{Key: aws.String("athenz:domain"), Value: aws.String("test-domain")},
			},
			setupMock: func() *mockACMClient {
				return newMockACMClient()
			},
			expectedError: "",
		},
		{
			name:           "empty certificate ARN",
			certificateArn: "",
			acmTags: []acmtypes.Tag{
				{Key: aws.String("athenz:service"), Value: aws.String("test-service")},
			},
			setupMock: func() *mockACMClient {
				return newMockACMClient()
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := tt.setupMock()
			ctx := context.Background()

			err := setCertificateTags(ctx, mockClient, tt.certificateArn, tt.acmTags)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ztsTestServer is a mock ZTS instance register endpoint. It signs the submitted CSR
// with a test CA so that the caller receives a certificate matching the private key
// that was generated during the identity registration.
type ztsTestServer struct {
	*httptest.Server
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	caCertPem  string
	statusCode int                               // response status code; 201 when not set
	requests   []zts.InstanceRegisterInformation // captured register requests
}

func newZtsTestServer(t *testing.T) *ztsTestServer {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Athenz Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDer)
	require.NoError(t, err)

	server := &ztsTestServer{
		caCert:    caCert,
		caKey:     caKey,
		caCertPem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDer})),
	}
	router := http.NewServeMux()
	router.HandleFunc("POST /instance", server.registerInstance(t))
	server.Server = httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server
}

func (s *ztsTestServer) registerInstance(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		contents, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("unable to read register request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var info zts.InstanceRegisterInformation
		if err := json.Unmarshal(contents, &info); err != nil {
			t.Errorf("unable to parse register request: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.requests = append(s.requests, info)

		if s.statusCode != 0 && s.statusCode != http.StatusCreated {
			w.WriteHeader(s.statusCode)
			_, _ = w.Write([]byte(`{"code":403,"message":"unable to verify attestation data"}`))
			return
		}

		certPem, err := s.signCsr(info.Csr)
		if err != nil {
			t.Errorf("unable to sign csr: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		identity := &zts.InstanceIdentity{
			Provider:              zts.ServiceName(info.Provider),
			Name:                  zts.ServiceName(string(info.Domain) + "." + string(info.Service)),
			InstanceId:            "id-001",
			X509Certificate:       certPem,
			X509CertificateSigner: s.caCertPem,
		}
		data, _ := json.Marshal(identity)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(data)
	}
}

func (s *ztsTestServer) signCsr(csrPem string) (string, error) {
	block, _ := pem.Decode([]byte(csrPem))
	if block == nil {
		return "", errors.New("unable to decode csr pem block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		URIs:         csr.URIs,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	certDer, err := x509.CreateCertificate(rand.Reader, template, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})), nil
}

// lastRequest returns the register request received by the server along with its
// parsed attestation data and CSR.
func (s *ztsTestServer) lastRequest(t *testing.T) (zts.InstanceRegisterInformation, attestation.AttestationData, *x509.CertificateRequest) {
	t.Helper()
	require.NotEmpty(t, s.requests, "no register request received by the zts server")
	info := s.requests[len(s.requests)-1]

	var data attestation.AttestationData
	require.NoError(t, json.Unmarshal([]byte(info.AttestationData), &data))

	block, _ := pem.Decode([]byte(info.Csr))
	require.NotNil(t, block)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)

	return info, data, csr
}

// stsAttestationCall captures the arguments passed to the stubbed temporary
// credentials attestation data generator
type stsAttestationCall struct {
	domain         string
	service        string
	region         string
	account        string
	ec2Document    string
	ec2Signature   string
	useRegionalSTS bool
	omitDomain     bool
	rolePath       string
	called         bool
}

// stubStsAttestationData replaces the temporary credentials attestation generator with
// one that records its arguments and returns the given attestation data/error
func stubStsAttestationData(t *testing.T, attestationData string, err error) *stsAttestationCall {
	t.Helper()
	orig := stsAttestationData
	t.Cleanup(func() { stsAttestationData = orig })

	call := &stsAttestationCall{}
	stsAttestationData = func(domain, service, region, account, ec2Document, ec2Signature string, useRegionalSTS, omitDomain bool, rolePath string) (string, error) {
		call.domain = domain
		call.service = service
		call.region = region
		call.account = account
		call.ec2Document = ec2Document
		call.ec2Signature = ec2Signature
		call.useRegionalSTS = useRegionalSTS
		call.omitDomain = omitDomain
		call.rolePath = rolePath
		call.called = true
		return attestationData, err
	}
	return call
}

// webIdentityCall captures the arguments passed to the stubbed web identity token fetcher
type webIdentityCall struct {
	useRegionalSTS   bool
	region           string
	audience         string
	signingAlgorithm string
	durationSeconds  int32
	tags             []ststypes.Tag
	called           bool
}

// stubWebIdentityTokenFetcher replaces the sts web identity token fetcher with one
// that records its arguments and returns the given token/error
func stubWebIdentityTokenFetcher(t *testing.T, token string, err error) *webIdentityCall {
	t.Helper()
	orig := stssession.WebIdentityTokenFetcher
	t.Cleanup(func() { stssession.WebIdentityTokenFetcher = orig })

	call := &webIdentityCall{}
	stssession.WebIdentityTokenFetcher = func(useRegionalSTS bool, region, audience, signingAlgorithm string, durationSeconds int32, tags []ststypes.Tag) (string, error) {
		call.useRegionalSTS = useRegionalSTS
		call.region = region
		call.audience = audience
		call.signingAlgorithm = signingAlgorithm
		call.durationSeconds = durationSeconds
		call.tags = tags
		call.called = true
		return token, err
	}
	return call
}

// stubAwsAccountIdFetcher replaces the aws account id lookup with one returning the given value
func stubAwsAccountIdFetcher(t *testing.T, account string) {
	t.Helper()
	orig := awsAccountIdFetcher
	t.Cleanup(func() { awsAccountIdFetcher = orig })
	awsAccountIdFetcher = func() string {
		return account
	}
}

func TestGetAthenzServiceIdentityInvalidRequest(t *testing.T) {
	tests := []struct {
		name          string
		request       *AthenzIdentityRequest
		expectedError string
	}{
		{
			name:          "nil request",
			request:       nil,
			expectedError: "no athenz identity request specified",
		},
		{
			name: "empty domain",
			request: &AthenzIdentityRequest{
				AthenzService:  "api",
				AthenzProvider: "athenz.aws.us-west-2",
				ZTSUrl:         "http://localhost:4443",
			},
			expectedError: "athenz domain, service, provider and zts url must be specified",
		},
		{
			name: "empty service",
			request: &AthenzIdentityRequest{
				AthenzDomain:   "sports",
				AthenzProvider: "athenz.aws.us-west-2",
				ZTSUrl:         "http://localhost:4443",
			},
			expectedError: "athenz domain, service, provider and zts url must be specified",
		},
		{
			name: "empty provider",
			request: &AthenzIdentityRequest{
				AthenzDomain:  "sports",
				AthenzService: "api",
				ZTSUrl:        "http://localhost:4443",
			},
			expectedError: "athenz domain, service, provider and zts url must be specified",
		},
		{
			name: "empty zts url",
			request: &AthenzIdentityRequest{
				AthenzDomain:   "sports",
				AthenzService:  "api",
				AthenzProvider: "athenz.aws.us-west-2",
			},
			expectedError: "athenz domain, service, provider and zts url must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			siaCertData, err := GetAthenzServiceIdentity(tt.request)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
			assert.Nil(t, siaCertData)
		})
	}
}

func TestGetAthenzServiceIdentityUnknownAccount(t *testing.T) {
	stubAwsAccountIdFetcher(t, "")
	call := stubStsAttestationData(t, "", nil)

	siaCertData, err := GetAthenzServiceIdentity(&AthenzIdentityRequest{
		AthenzDomain:   "sports",
		AthenzService:  "api",
		AthenzProvider: "athenz.aws.us-west-2",
		ZTSUrl:         "http://localhost:4443",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to determine aws account id")
	assert.Nil(t, siaCertData)
	assert.False(t, call.called)
}

func TestGetAthenzServiceIdentityTempCredentials(t *testing.T) {
	ztsServer := newZtsTestServer(t)
	call := stubStsAttestationData(t, `{"role":"sports.api","access":"access-key","secret":"secret-key","token":"session-token"}`, nil)

	siaCertData, err := GetAthenzServiceIdentity(&AthenzIdentityRequest{
		AthenzDomain:   "Sports",
		AthenzService:  "API",
		AthenzProvider: "Athenz.AWS.us-west-2",
		ZTSUrl:         ztsServer.URL,
		AwsAccount:     "123456789012",
		Region:         "us-west-2",
		UseRegionalSTS: true,
		OmitDomain:     true,
		RolePath:       "athenz",
		SanDNSDomains:  []string{"athenz.io"},
		CsrSubjectFields: util.CsrSubjectFields{
			Country:      "US",
			Organization: "Athenz",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, siaCertData)
	assert.NotEmpty(t, siaCertData.X509CertificatePem)
	assert.NotEmpty(t, siaCertData.PrivateKeyPem)
	assert.Equal(t, ztsServer.caCertPem, siaCertData.X509CertificateSignerPem)
	assert.NotNil(t, siaCertData.TLSCertificate.Certificate)

	// the domain, service and provider names must have been lowercased and all
	// the aws specific attributes passed to the attestation data generator

	require.True(t, call.called)
	assert.Equal(t, "sports", call.domain)
	assert.Equal(t, "api", call.service)
	assert.Equal(t, "us-west-2", call.region)
	assert.Equal(t, "123456789012", call.account)
	assert.True(t, call.useRegionalSTS)
	assert.True(t, call.omitDomain)
	assert.Equal(t, "athenz", call.rolePath)
	// lambda functions have no ec2 identity document
	assert.Empty(t, call.ec2Document)
	assert.Empty(t, call.ec2Signature)

	info, data, csr := ztsServer.lastRequest(t)
	assert.Equal(t, "sports", string(info.Domain))
	assert.Equal(t, "api", string(info.Service))
	assert.Equal(t, "athenz.aws.us-west-2", string(info.Provider))
	assert.Equal(t, "access-key", data.Access)
	assert.Empty(t, data.IdentityToken)
	assert.Equal(t, "sports.api", csr.Subject.CommonName)
	assert.Equal(t, []string{"api.sports.athenz.io"}, csr.DNSNames)
	assert.Contains(t, csrUris(csr), "athenz://instanceid/athenz.aws.us-west-2/lambda-123456789012-api")
}

func TestGetAthenzServiceIdentityTempCredentialsError(t *testing.T) {
	ztsServer := newZtsTestServer(t)
	stubStsAttestationData(t, "", errors.New("unable to assume role"))

	siaCertData, err := GetAthenzServiceIdentity(&AthenzIdentityRequest{
		AthenzDomain:   "sports",
		AthenzService:  "api",
		AthenzProvider: "athenz.aws.us-west-2",
		ZTSUrl:         ztsServer.URL,
		AwsAccount:     "123456789012",
		SanDNSDomains:  []string{"athenz.io"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to assume role")
	assert.Nil(t, siaCertData)
	assert.Empty(t, ztsServer.requests)
}

func TestGetAthenzServiceIdentityAccountFromCallerIdentity(t *testing.T) {
	ztsServer := newZtsTestServer(t)
	stubAwsAccountIdFetcher(t, "098765432109")
	call := stubStsAttestationData(t, `{"role":"sports.api"}`, nil)

	siaCertData, err := GetAthenzServiceIdentity(&AthenzIdentityRequest{
		AthenzDomain:   "sports",
		AthenzService:  "api",
		AthenzProvider: "athenz.aws.us-west-2",
		ZTSUrl:         ztsServer.URL,
		SanDNSDomains:  []string{"athenz.io"},
	})
	require.NoError(t, err)
	require.NotNil(t, siaCertData)
	assert.Equal(t, "098765432109", call.account)

	_, _, csr := ztsServer.lastRequest(t)
	assert.Contains(t, csrUris(csr), "athenz://instanceid/athenz.aws.us-west-2/lambda-098765432109-api")
}

func TestGetAthenzServiceIdentityRegionFromEnv(t *testing.T) {
	ztsServer := newZtsTestServer(t)
	t.Setenv("AWS_REGION", "us-east-1")
	call := stubStsAttestationData(t, `{"role":"sports.api"}`, nil)

	_, err := GetAthenzServiceIdentity(&AthenzIdentityRequest{
		AthenzDomain:   "sports",
		AthenzService:  "api",
		AthenzProvider: "athenz.aws.us-east-1",
		ZTSUrl:         ztsServer.URL,
		AwsAccount:     "123456789012",
		SanDNSDomains:  []string{"athenz.io"},
	})
	require.NoError(t, err)
	assert.Equal(t, "us-east-1", call.region)
}

func TestGetAthenzServiceIdentityInstanceIdSanDNS(t *testing.T) {
	ztsServer := newZtsTestServer(t)
	stubStsAttestationData(t, `{"role":"sports.api"}`, nil)

	_, err := GetAthenzServiceIdentity(&AthenzIdentityRequest{
		AthenzDomain:     "sports",
		AthenzService:    "api",
		AthenzProvider:   "athenz.aws.us-west-2",
		ZTSUrl:           ztsServer.URL,
		AwsAccount:       "123456789012",
		SanDNSDomains:    []string{"athenz.io"},
		InstanceIdSanDNS: true,
	})
	require.NoError(t, err)

	_, _, csr := ztsServer.lastRequest(t)
	assert.Equal(t, []string{"api.sports.athenz.io", "lambda-123456789012-api.instanceid.athenz.athenz.io"}, csr.DNSNames)
}

func TestGetAthenzServiceIdentityWebIdentityDefaults(t *testing.T) {
	ztsServer := newZtsTestServer(t)
	call := stubWebIdentityTokenFetcher(t, "header.payload.signature", nil)
	stsCall := stubStsAttestationData(t, "", errors.New("temp credentials must not be used"))

	siaCertData, err := GetAthenzServiceIdentity(&AthenzIdentityRequest{
		AthenzDomain:        "sports",
		AthenzService:       "api",
		AthenzProvider:      "athenz.aws.us-west-2",
		ZTSUrl:              ztsServer.URL,
		AwsAccount:          "123456789012",
		Region:              "us-west-2",
		SanDNSDomains:       []string{"athenz.io"},
		UseWebIdentityToken: true,
	})
	require.NoError(t, err)
	require.NotNil(t, siaCertData)
	assert.False(t, stsCall.called)

	// audience defaults to the zts url, algorithm to ES384 and duration to 300 seconds

	require.True(t, call.called)
	assert.Equal(t, ztsServer.URL, call.audience)
	assert.Equal(t, "ES384", call.signingAlgorithm)
	assert.Equal(t, int32(300), call.durationSeconds)
	assert.Equal(t, "us-west-2", call.region)
	assert.False(t, call.useRegionalSTS)
	assert.Nil(t, call.tags)

	_, data, _ := ztsServer.lastRequest(t)
	assert.Equal(t, "header.payload.signature", data.IdentityToken)
	assert.Equal(t, "sports.api", data.Role)
	assert.Equal(t, "sports.api", data.CommonName)
	// the temporary credentials must not be included in the web identity token path
	assert.Empty(t, data.Access)
	assert.Empty(t, data.Secret)
	assert.Empty(t, data.Token)
}

func TestGetAthenzServiceIdentityWebIdentityCustomValues(t *testing.T) {
	ztsServer := newZtsTestServer(t)
	call := stubWebIdentityTokenFetcher(t, "header.payload.signature", nil)
	tags := []ststypes.Tag{
		{Key: aws.String("athenz-domain"), Value: aws.String("sports")},
	}

	siaCertData, err := GetAthenzServiceIdentity(&AthenzIdentityRequest{
		AthenzDomain:                "sports",
		AthenzService:               "api",
		AthenzProvider:              "athenz.aws.us-west-2",
		ZTSUrl:                      ztsServer.URL,
		AwsAccount:                  "123456789012",
		Region:                      "us-west-2",
		SanDNSDomains:               []string{"athenz.io"},
		UseRegionalSTS:              true,
		OmitDomain:                  true,
		UseWebIdentityToken:         true,
		WebIdentityAudience:         "https://zts.athenz.io",
		WebIdentitySigningAlgorithm: "RS256",
		WebIdentityDurationSeconds:  600,
		WebIdentityTags:             tags,
	})
	require.NoError(t, err)
	require.NotNil(t, siaCertData)

	require.True(t, call.called)
	assert.Equal(t, "https://zts.athenz.io", call.audience)
	assert.Equal(t, "RS256", call.signingAlgorithm)
	assert.Equal(t, int32(600), call.durationSeconds)
	assert.True(t, call.useRegionalSTS)
	assert.Equal(t, tags, call.tags)

	// with omit domain enabled the attestation role only carries the service name

	_, data, _ := ztsServer.lastRequest(t)
	assert.Equal(t, "api", data.Role)
	assert.Equal(t, "sports.api", data.CommonName)
	assert.Equal(t, "header.payload.signature", data.IdentityToken)
}

func TestGetAthenzServiceIdentityWebIdentityErrors(t *testing.T) {
	tests := []struct {
		name             string
		signingAlgorithm string
		durationSeconds  int32
		fetcherError     error
		expectedError    string
	}{
		{
			name:             "invalid signing algorithm",
			signingAlgorithm: "HS256",
			expectedError:    "invalid signing algorithm",
		},
		{
			name:            "duration below minimum",
			durationSeconds: 30,
			expectedError:   "invalid durationSeconds",
		},
		{
			name:            "duration above maximum",
			durationSeconds: 7200,
			expectedError:   "invalid durationSeconds",
		},
		{
			name:          "token fetch failure",
			fetcherError:  errors.New("sts failure"),
			expectedError: "sts failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ztsServer := newZtsTestServer(t)
			stubWebIdentityTokenFetcher(t, "", tt.fetcherError)

			siaCertData, err := GetAthenzServiceIdentity(&AthenzIdentityRequest{
				AthenzDomain:                "sports",
				AthenzService:               "api",
				AthenzProvider:              "athenz.aws.us-west-2",
				ZTSUrl:                      ztsServer.URL,
				AwsAccount:                  "123456789012",
				Region:                      "us-west-2",
				SanDNSDomains:               []string{"athenz.io"},
				UseWebIdentityToken:         true,
				WebIdentitySigningAlgorithm: tt.signingAlgorithm,
				WebIdentityDurationSeconds:  tt.durationSeconds,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
			assert.Nil(t, siaCertData)
			assert.Empty(t, ztsServer.requests)
		})
	}
}

func TestGetAthenzServiceIdentityZtsFailure(t *testing.T) {
	ztsServer := newZtsTestServer(t)
	ztsServer.statusCode = http.StatusForbidden
	stubStsAttestationData(t, `{"role":"sports.api"}`, nil)

	siaCertData, err := GetAthenzServiceIdentity(&AthenzIdentityRequest{
		AthenzDomain:   "sports",
		AthenzService:  "api",
		AthenzProvider: "athenz.aws.us-west-2",
		ZTSUrl:         ztsServer.URL,
		AwsAccount:     "123456789012",
		SanDNSDomains:  []string{"athenz.io"},
	})
	require.Error(t, err)
	assert.Nil(t, siaCertData)
	assert.Len(t, ztsServer.requests, 1)
}

func csrUris(csr *x509.CertificateRequest) []string {
	uris := make([]string, 0, len(csr.URIs))
	for _, uri := range csr.URIs {
		uris = append(uris, uri.String())
	}
	return uris
}
