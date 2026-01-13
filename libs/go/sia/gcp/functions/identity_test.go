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

package functions

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/certificatemanager/apiv1/certificatemanagerpb"
	"github.com/AthenZ/athenz/libs/go/sia/util"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockCertificateOperation is a mock implementation of CertificateOperationInterface
type mockCertificateOperation struct {
	name     string
	waitErr  error
	waitResp *certificatemanagerpb.Certificate
}

func (m *mockCertificateOperation) Name() string {
	if m.name == "" {
		return "operations/test-operation"
	}
	return m.name
}

func (m *mockCertificateOperation) Wait(_ context.Context, _ ...gax.CallOption) (*certificatemanagerpb.Certificate, error) {
	return m.waitResp, m.waitErr
}

// mockCertificateManagerClient is a mock implementation of CertificateManagerClientInterface
type mockCertificateManagerClient struct {
	createErr    error
	updateErr    error
	createCalled bool
	updateCalled bool
	closeErr     error
	waitErr      error
}

// mockMetadataProvider is a mock implementation of MetadataProvider
type mockMetadataProvider struct {
	projectID string
	err       error
}

// GetProject returns the mocked project ID or error
func (m *mockMetadataProvider) GetProject(_ string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.projectID, nil
}

func (m *mockCertificateManagerClient) CreateCertificate(_ context.Context, _ *certificatemanagerpb.CreateCertificateRequest, _ ...gax.CallOption) (CertificateOperationInterface, error) {
	m.createCalled = true
	if m.createErr != nil {
		return nil, m.createErr
	}
	return &mockCertificateOperation{
		name:     "operations/test-operation",
		waitErr:  m.waitErr,
		waitResp: nil,
	}, nil
}

func (m *mockCertificateManagerClient) UpdateCertificate(_ context.Context, _ *certificatemanagerpb.UpdateCertificateRequest, _ ...gax.CallOption) (CertificateOperationInterface, error) {
	m.updateCalled = true
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	return &mockCertificateOperation{
		name:     "operations/test-update-operation",
		waitErr:  m.waitErr,
		waitResp: nil,
	}, nil
}

func (m *mockCertificateManagerClient) Close() error {
	return m.closeErr
}

// generateTestCertificate generates a test certificate for testing purposes
func generateTestCertificate() (*util.SiaCertData, error) {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %v", err)
	}

	// Create a simple certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"Athenz Test"},
			CommonName:         "test.example.com",
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"San Francisco"},
			OrganizationalUnit: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create certificate: %v", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return &util.SiaCertData{
		PrivateKey:         privateKey,
		PrivateKeyPem:      string(keyPEM),
		X509CertificatePem: string(certPEM),
	}, nil
}

func TestStoreAthenzIdentityInCertificateManager(t *testing.T) {
	tests := []struct {
		name           string
		athenzDomain   string
		athenzService  string
		certName       string
		location       string
		siaCertData    *util.SiaCertData
		resourceLabels map[string]string
		expectError    bool
		errorContains  string
	}{
		{
			name:           "nil certificate data",
			athenzDomain:   "test.domain",
			athenzService:  "test-service",
			certName:       "test-cert",
			location:       "global",
			siaCertData:    nil,
			resourceLabels: nil,
			expectError:    true,
			errorContains:  "invalid certificate data",
		},
		{
			name:          "empty certificate pem",
			athenzDomain:  "test.domain",
			athenzService: "test-service",
			certName:      "test-cert",
			location:      "global",
			siaCertData: &util.SiaCertData{
				X509CertificatePem: "",
				PrivateKeyPem:      "test-key",
			},
			resourceLabels: nil,
			expectError:    true,
			errorContains:  "invalid certificate data",
		},
		{
			name:          "empty private key pem",
			athenzDomain:  "test.domain",
			athenzService: "test-service",
			certName:      "test-cert",
			location:      "global",
			siaCertData: &util.SiaCertData{
				X509CertificatePem: "test-cert",
				PrivateKeyPem:      "",
			},
			resourceLabels: nil,
			expectError:    true,
			errorContains:  "invalid certificate data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := StoreAthenzIdentityInCertificateManager(
				tt.certName,
				tt.location,
				tt.siaCertData,
				0,
				tt.resourceLabels,
			)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got nil")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestStoreIdentityInCertificateManager tests the storeIdentityInCertificateManager function.
func TestStoreIdentityInCertificateManager(t *testing.T) {
	// Generate test certificate
	testCert, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("unable to generate test certificate: %v", err)
	}

	tests := []struct {
		name               string
		certName           string
		location           string
		siaCertData        *util.SiaCertData
		resourceLabels     map[string]string
		mockClient         *mockCertificateManagerClient
		metadataProvider   *mockMetadataProvider
		expectError        bool
		errorContains      string
		expectCreateCalled bool
		expectUpdateCalled bool
	}{
		{
			name:           "successful certificate creation",
			certName:       "test-cert",
			location:       "global",
			siaCertData:    testCert,
			resourceLabels: nil,
			mockClient: &mockCertificateManagerClient{
				createErr: nil,
				updateErr: nil,
			},
			metadataProvider: &mockMetadataProvider{
				projectID: "test-gcp-project",
				err:       nil,
			},
			expectError:        false,
			expectCreateCalled: true,
			expectUpdateCalled: false,
		},
		{
			name:        "certificate already exists - update",
			certName:    "test-cert",
			location:    "us-central1",
			siaCertData: testCert,
			resourceLabels: map[string]string{
				"domain":  "test.domain",
				"service": "test-service",
			},
			mockClient: &mockCertificateManagerClient{
				createErr: status.Error(codes.AlreadyExists, "certificate already exists"),
				updateErr: nil,
			},
			metadataProvider: &mockMetadataProvider{
				projectID: "test-gcp-project",
				err:       nil,
			},
			expectError:        false,
			expectCreateCalled: true,
			expectUpdateCalled: true,
		},
		{
			name:           "certificate already exists with ALREADY_EXISTS error",
			certName:       "test-cert",
			location:       "global",
			siaCertData:    testCert,
			resourceLabels: nil,
			mockClient: &mockCertificateManagerClient{
				createErr: status.Error(codes.AlreadyExists, "certificate already exists"),
				updateErr: nil,
			},
			metadataProvider: &mockMetadataProvider{
				projectID: "test-gcp-project",
				err:       nil,
			},
			expectError:        false,
			expectCreateCalled: true,
			expectUpdateCalled: true,
		},
		{
			name:           "create error - non-exists error",
			certName:       "test-cert",
			location:       "global",
			siaCertData:    testCert,
			resourceLabels: nil,
			mockClient: &mockCertificateManagerClient{
				createErr: status.Error(codes.PermissionDenied, "permission denied"),
				updateErr: nil,
			},
			metadataProvider: &mockMetadataProvider{
				projectID: "test-gcp-project",
				err:       nil,
			},
			expectError:        true,
			errorContains:      "permission denied",
			expectCreateCalled: true,
			expectUpdateCalled: false,
		},
		{
			name:           "update error after create fails",
			certName:       "test-cert",
			location:       "global",
			siaCertData:    testCert,
			resourceLabels: nil,
			mockClient: &mockCertificateManagerClient{
				createErr: status.Error(codes.AlreadyExists, "certificate already exists"),
				updateErr: errors.New("unable to update certificate"),
			},
			metadataProvider: &mockMetadataProvider{
				projectID: "test-gcp-project",
				err:       nil,
			},
			expectError:        true,
			errorContains:      "unable to update certificate",
			expectCreateCalled: true,
			expectUpdateCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tt.mockClient.createCalled = false
			tt.mockClient.updateCalled = false

			err := storeIdentityInCertificateManager(
				ctx,
				tt.mockClient,
				tt.metadataProvider,
				tt.certName,
				tt.location,
				tt.siaCertData,
				0,
				tt.resourceLabels,
			)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got nil")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if tt.expectCreateCalled && !tt.mockClient.createCalled {
				t.Errorf("expected CreateCertificate to be called but it wasn't")
			}
			if !tt.expectCreateCalled && tt.mockClient.createCalled {
				t.Errorf("expected CreateCertificate not to be called but it was")
			}

			if tt.expectUpdateCalled && !tt.mockClient.updateCalled {
				t.Errorf("expected UpdateCertificate to be called but it wasn't")
			}
			if !tt.expectUpdateCalled && tt.mockClient.updateCalled {
				t.Errorf("expected UpdateCertificate not to be called but it was")
			}
		})
	}
}

// TestStoreIdentityInCertificateManager_ProjectIdError tests the error path when GetProject fails.
func TestStoreIdentityInCertificateManager_ProjectIdError(t *testing.T) {
	// Generate test certificate
	testCert, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("unable to generate test certificate: %v", err)
	}

	ctx := context.Background()
	mockClient := &mockCertificateManagerClient{}
	mockMetadataProvider := &mockMetadataProvider{
		projectID: "",
		err:       errors.New("metadata server unavailable"),
	}

	err = storeIdentityInCertificateManager(
		ctx,
		mockClient,
		mockMetadataProvider,
		"test-cert",
		"global",
		testCert,
		0,
		nil,
	)

	if err == nil {
		t.Errorf("expected error when GetProject fails, but got nil")
	} else if !strings.Contains(err.Error(), "unable to extract project id") {
		t.Errorf("expected error about project id, got: %v", err)
	}

	if mockClient.createCalled {
		t.Errorf("CreateCertificate should not be called when GetProject fails")
	}
}

// TestStoreIdentityInCertificateManager_CertificateRequestCalled validates
// that the certificate creation request is called
func TestStoreIdentityInCertificateManager_CertificateRequestCalled(t *testing.T) {
	// Generate test certificate
	testCert, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("unable to generate test certificate: %v", err)
	}

	ctx := context.Background()
	mockClient := &mockCertificateManagerClient{
		createErr: nil,
		updateErr: nil,
	}
	mockMetadataProvider := &mockMetadataProvider{
		projectID: "test-gcp-project",
		err:       nil,
	}

	err = storeIdentityInCertificateManager(
		ctx,
		mockClient,
		mockMetadataProvider,
		"my-cert",
		"us-west1",
		testCert,
		0,
		nil,
	)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !mockClient.createCalled {
		t.Errorf("expected CreateCertificate to be called")
	}
}
