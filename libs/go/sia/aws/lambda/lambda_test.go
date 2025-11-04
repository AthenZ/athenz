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
	"errors"
	"testing"

	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
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
