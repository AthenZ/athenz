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
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/util"
	certificatemanagerapi "google.golang.org/api/certificatemanager/v1"
	"google.golang.org/api/googleapi"
)

// mockCertificateManagerOperations is a mock implementation of CertificateManagerOperations
type mockCertificateManagerOperations struct {
	createErr     error
	patchErr      error
	getOpErr      error
	createCalled  bool
	patchCalled   bool
	getOpCalled   bool
	createOp      *certificatemanagerapi.Operation
	patchOp       *certificatemanagerapi.Operation
	operation     *certificatemanagerapi.Operation
	pollCount     int
	operationName string
}

func (m *mockCertificateManagerOperations) CreateCertificate(_ context.Context, parent string, _ *certificatemanagerapi.Certificate, _ string) (*certificatemanagerapi.Operation, error) {
	m.createCalled = true
	if m.createErr != nil {
		return nil, m.createErr
	}
	if m.createOp == nil {
		return &certificatemanagerapi.Operation{
			Name: fmt.Sprintf("%s/operations/test-create-op", parent),
			Done: false,
		}, nil
	}
	return m.createOp, nil
}

func (m *mockCertificateManagerOperations) PatchCertificate(_ context.Context, name string, _ *certificatemanagerapi.Certificate, _ string) (*certificatemanagerapi.Operation, error) {
	m.patchCalled = true
	if m.patchErr != nil {
		return nil, m.patchErr
	}
	if m.patchOp == nil {
		// Extract parent from name (format: projects/{project}/locations/{location}/certificates/{name})
		parts := strings.Split(name, "/certificates/")
		parent := parts[0]
		return &certificatemanagerapi.Operation{
			Name: fmt.Sprintf("%s/operations/test-patch-op", parent),
			Done: false,
		}, nil
	}
	return m.patchOp, nil
}

func (m *mockCertificateManagerOperations) GetOperation(_ context.Context, operationName string) (*certificatemanagerapi.Operation, error) {
	m.getOpCalled = true
	m.pollCount++
	m.operationName = operationName
	if m.getOpErr != nil {
		return nil, m.getOpErr
	}
	if m.operation == nil {
		// Simulate operation completion after first poll
		return &certificatemanagerapi.Operation{
			Name: operationName,
			Done: true,
		}, nil
	}
	// Return the configured operation, mark as done after first poll
	op := m.operation
	if m.pollCount > 1 {
		op.Done = true
	}
	return op, nil
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
				"CLIENT_AUTH",
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
		mockOperations     *mockCertificateManagerOperations
		metadataProvider   *mockMetadataProvider
		expectError        bool
		errorContains      string
		expectCreateCalled bool
		expectPatchCalled  bool
	}{
		{
			name:           "successful certificate creation",
			certName:       "test-cert",
			location:       "global",
			siaCertData:    testCert,
			resourceLabels: nil,
			mockOperations: &mockCertificateManagerOperations{
				createErr: nil,
				patchErr:  nil,
				getOpErr:  nil,
			},
			metadataProvider: &mockMetadataProvider{
				projectID: "test-gcp-project",
				err:       nil,
			},
			expectError:        false,
			expectCreateCalled: true,
			expectPatchCalled:  false,
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
			mockOperations: &mockCertificateManagerOperations{
				createErr: &googleapi.Error{
					Code:    http.StatusConflict,
					Message: "certificate already exists",
				},
				patchErr: nil,
				getOpErr: nil,
			},
			metadataProvider: &mockMetadataProvider{
				projectID: "test-gcp-project",
				err:       nil,
			},
			expectError:        false,
			expectCreateCalled: true,
			expectPatchCalled:  true,
		},
		{
			name:           "certificate already exists with HTTP 409 error",
			certName:       "test-cert",
			location:       "global",
			siaCertData:    testCert,
			resourceLabels: nil,
			mockOperations: &mockCertificateManagerOperations{
				createErr: &googleapi.Error{
					Code:    http.StatusConflict,
					Message: "certificate already exists",
				},
				patchErr: nil,
				getOpErr: nil,
			},
			metadataProvider: &mockMetadataProvider{
				projectID: "test-gcp-project",
				err:       nil,
			},
			expectError:        false,
			expectCreateCalled: true,
			expectPatchCalled:  true,
		},
		{
			name:           "create error - non-conflict error",
			certName:       "test-cert",
			location:       "global",
			siaCertData:    testCert,
			resourceLabels: nil,
			mockOperations: &mockCertificateManagerOperations{
				createErr: &googleapi.Error{
					Code:    http.StatusForbidden,
					Message: "permission denied",
				},
				patchErr: nil,
				getOpErr: nil,
			},
			metadataProvider: &mockMetadataProvider{
				projectID: "test-gcp-project",
				err:       nil,
			},
			expectError:        true,
			errorContains:      "permission denied",
			expectCreateCalled: true,
			expectPatchCalled:  false,
		},
		{
			name:           "patch error after create fails with conflict",
			certName:       "test-cert",
			location:       "global",
			siaCertData:    testCert,
			resourceLabels: nil,
			mockOperations: &mockCertificateManagerOperations{
				createErr: &googleapi.Error{
					Code:    http.StatusConflict,
					Message: "certificate already exists",
				},
				patchErr: errors.New("unable to update certificate"),
				getOpErr: nil,
			},
			metadataProvider: &mockMetadataProvider{
				projectID: "test-gcp-project",
				err:       nil,
			},
			expectError:        true,
			errorContains:      "unable to update certificate",
			expectCreateCalled: true,
			expectPatchCalled:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tt.mockOperations.createCalled = false
			tt.mockOperations.patchCalled = false
			tt.mockOperations.getOpCalled = false
			tt.mockOperations.pollCount = 0

			err := storeIdentityInCertificateManager(
				ctx,
				tt.mockOperations,
				tt.metadataProvider,
				tt.certName,
				tt.location,
				tt.siaCertData,
				"CLIENT_AUTH",
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

			if tt.expectCreateCalled && !tt.mockOperations.createCalled {
				t.Errorf("expected CreateCertificate to be called but it wasn't")
			}
			if !tt.expectCreateCalled && tt.mockOperations.createCalled {
				t.Errorf("expected CreateCertificate not to be called but it was")
			}

			if tt.expectPatchCalled && !tt.mockOperations.patchCalled {
				t.Errorf("expected PatchCertificate to be called but it wasn't")
			}
			if !tt.expectPatchCalled && tt.mockOperations.patchCalled {
				t.Errorf("expected PatchCertificate not to be called but it was")
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
	mockOperations := &mockCertificateManagerOperations{}
	mockMetadataProvider := &mockMetadataProvider{
		projectID: "",
		err:       errors.New("metadata server unavailable"),
	}

	err = storeIdentityInCertificateManager(
		ctx,
		mockOperations,
		mockMetadataProvider,
		"test-cert",
		"global",
		testCert,
		"CLIENT_AUTH",
		nil,
	)

	if err == nil {
		t.Errorf("expected error when GetProject fails, but got nil")
	} else if !strings.Contains(err.Error(), "unable to extract project id") {
		t.Errorf("expected error about project id, got: %v", err)
	}

	if mockOperations.createCalled {
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
	mockOperations := &mockCertificateManagerOperations{
		createErr: nil,
		patchErr:  nil,
		getOpErr:  nil,
	}
	mockMetadataProvider := &mockMetadataProvider{
		projectID: "test-gcp-project",
		err:       nil,
	}

	err = storeIdentityInCertificateManager(
		ctx,
		mockOperations,
		mockMetadataProvider,
		"my-cert",
		"us-west1",
		testCert,
		"CLIENT_AUTH",
		nil,
	)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !mockOperations.createCalled {
		t.Errorf("expected CreateCertificate to be called")
	}
}

// TestWaitForOperation tests the waitForOperation function
func TestWaitForOperation(t *testing.T) {
	tests := []struct {
		name          string
		mockOps       *mockCertificateManagerOperations
		operationName string
		expectError   bool
		errorContains string
		expectPolls   int
	}{
		{
			name: "operation completes immediately",
			mockOps: &mockCertificateManagerOperations{
				operation: &certificatemanagerapi.Operation{
					Name: "projects/test/locations/global/operations/test-op",
					Done: true,
				},
			},
			operationName: "projects/test/locations/global/operations/test-op",
			expectError:   false,
			expectPolls:   1,
		},
		{
			name: "operation completes after polling",
			mockOps: &mockCertificateManagerOperations{
				operation: &certificatemanagerapi.Operation{
					Name: "projects/test/locations/global/operations/test-op",
					Done: false,
				},
			},
			operationName: "projects/test/locations/global/operations/test-op",
			expectError:   false,
			expectPolls:   2, // First poll returns not done, second returns done
		},
		{
			name: "operation fails with error",
			mockOps: &mockCertificateManagerOperations{
				operation: &certificatemanagerapi.Operation{
					Name: "projects/test/locations/global/operations/test-op",
					Done: true,
					Error: &certificatemanagerapi.Status{
						Message: "operation failed",
					},
				},
			},
			operationName: "projects/test/locations/global/operations/test-op",
			expectError:   true,
			errorContains: "operation failed",
			expectPolls:   1,
		},
		{
			name: "get operation fails",
			mockOps: &mockCertificateManagerOperations{
				getOpErr: errors.New("network error"),
			},
			operationName: "projects/test/locations/global/operations/test-op",
			expectError:   true,
			errorContains: "failed to get operation status",
			expectPolls:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tt.mockOps.pollCount = 0
			tt.mockOps.getOpCalled = false

			err := waitForOperation(ctx, tt.mockOps, tt.operationName)

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

			if tt.expectPolls > 0 && tt.mockOps.pollCount != tt.expectPolls {
				t.Errorf("expected %d polls, got %d", tt.expectPolls, tt.mockOps.pollCount)
			}
		})
	}
}
