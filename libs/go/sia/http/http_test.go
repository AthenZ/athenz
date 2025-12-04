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

package http

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	sc "github.com/AthenZ/athenz/libs/go/sia/config"
)

// Helper function to create a temporary certificate file
func createTempCertFile(t *testing.T, expiryTime time.Time) string {
	t.Helper()

	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-cert"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              expiryTime,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	// Encode to PEM
	err = pem.Encode(tmpFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		t.Fatalf("Failed to encode certificate: %v", err)
	}

	return tmpFile.Name()
}

// Helper function to reset the global tracker for testing
func resetGlobalTracker() {
	globalTracker = nil
	trackerOnce = sync.Once{}
}

func TestGetStatusTracker(t *testing.T) {
	// Reset global tracker before each test
	resetGlobalTracker()

	// First call should create a new tracker
	tracker1 := GetStatusTracker()
	if tracker1 == nil {
		t.Fatal("GetStatusTracker returned nil")
	}

	// Second call should return the same instance (singleton)
	tracker2 := GetStatusTracker()
	if tracker1 != tracker2 {
		t.Error("GetStatusTracker should return the same instance (singleton pattern)")
	}

	// Verify it's initialized with empty map
	tracker1.mu.RLock()
	if tracker1.certStatuses == nil {
		t.Error("certStatuses map should be initialized")
	}
	if len(tracker1.certStatuses) != 0 {
		t.Error("certStatuses map should be empty initially")
	}
	tracker1.mu.RUnlock()
}

func TestInitialize(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	opts := &sc.Options{
		Services: []sc.Service{
			{Name: "service1"},
			{Name: "service2"},
		},
		Roles: []sc.Role{
			{Name: "role1"},
			{Name: "role2"},
		},
	}

	tracker.Initialize(opts)

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	// check we have an empty map after initialization
	expectedCount := 0
	if len(tracker.certStatuses) != expectedCount {
		t.Errorf("Expected %d cert statuses, got %d", expectedCount, len(tracker.certStatuses))
	}
}

func TestInitialize_EmptyOptions(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	opts := &sc.Options{
		Services: []sc.Service{},
		Roles:    []sc.Role{},
	}

	tracker.Initialize(opts)

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	if len(tracker.certStatuses) != 0 {
		t.Errorf("Expected 0 cert statuses, got %d", len(tracker.certStatuses))
	}
}

func TestRecordRefreshSuccess(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	certIdentity := "test-service"
	expiryTime := time.Now().Add(24 * time.Hour)
	certFile := createTempCertFile(t, expiryTime)
	defer os.Remove(certFile)

	beforeTime := time.Now()
	tracker.RecordRefreshSuccess(certIdentity, certFile)
	afterTime := time.Now()

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	status, exists := tracker.certStatuses[certIdentity]
	if !exists {
		t.Fatal("certIdentity should exist after RecordRefreshSuccess")
	}

	if status.LastRefreshTime == nil {
		t.Error("LastRefreshTime should be set")
	} else if status.LastRefreshTime.Before(beforeTime) || status.LastRefreshTime.After(afterTime) {
		t.Error("LastRefreshTime should be set to current time")
	}

	if status.LastFailureTime != nil {
		t.Error("LastFailureTime should be nil after successful refresh")
	}

	if status.LastFailureError != "" {
		t.Error("LastFailureError should be empty after successful refresh")
	}

	// Check expiry time is set (with some tolerance for time differences)
	if status.ExpiryTime.IsZero() {
		t.Error("ExpiryTime should be set from certificate")
	}
	expectedExpiry := expiryTime
	diff := status.ExpiryTime.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("ExpiryTime should match certificate expiry. Expected ~%v, got %v", expectedExpiry, status.ExpiryTime)
	}
}

func TestRecordRefreshSuccess_InvalidCertFile(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	certIdentity := "test-service"
	invalidCertFile := "/nonexistent/file.pem"

	tracker.RecordRefreshSuccess(certIdentity, invalidCertFile)

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	status, exists := tracker.certStatuses[certIdentity]
	if !exists {
		t.Fatal("certIdentity should exist even with invalid cert file")
	}

	if status.LastRefreshTime == nil {
		t.Error("LastRefreshTime should still be set even if cert file is invalid")
	}

	// ExpiryTime should remain zero if cert file is invalid
	if !status.ExpiryTime.IsZero() {
		t.Error("ExpiryTime should remain zero when cert file is invalid")
	}
}

func TestRecordRefreshSuccess_NewCertIdentity(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	certIdentity := "new-service"
	expiryTime := time.Now().Add(48 * time.Hour)
	certFile := createTempCertFile(t, expiryTime)
	defer os.Remove(certFile)

	tracker.RecordRefreshSuccess(certIdentity, certFile)

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	_, exists := tracker.certStatuses[certIdentity]
	if !exists {
		t.Fatal("New certIdentity should be created")
	}
}

func TestRecordRefreshFailure(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	certIdentity := "test-service"
	testError := errors.New("test error message")

	beforeTime := time.Now()
	tracker.RecordRefreshFailure(certIdentity, testError)
	afterTime := time.Now()

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	status, exists := tracker.certStatuses[certIdentity]
	if !exists {
		t.Fatal("certIdentity should exist after RecordRefreshFailure")
	}

	if status.LastFailureTime == nil {
		t.Error("LastFailureTime should be set")
	} else if status.LastFailureTime.Before(beforeTime) || status.LastFailureTime.After(afterTime) {
		t.Error("LastFailureTime should be set to current time")
	}

	if status.LastFailureError != testError.Error() {
		t.Errorf("Expected LastFailureError '%s', got '%s'", testError.Error(), status.LastFailureError)
	}
}

func TestRecordRefreshFailure_NilError(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	certIdentity := "test-service"

	tracker.RecordRefreshFailure(certIdentity, nil)

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	status, exists := tracker.certStatuses[certIdentity]
	if !exists {
		t.Fatal("certIdentity should exist after RecordRefreshFailure")
	}

	if status.LastFailureTime == nil {
		t.Error("LastFailureTime should be set even with nil error")
	}

	if status.LastFailureError != "" {
		t.Error("LastFailureError should be empty string when error is nil")
	}
}

func TestRecordRefreshFailure_NewCertIdentity(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	certIdentity := "new-service"
	testError := errors.New("new error")

	tracker.RecordRefreshFailure(certIdentity, testError)

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	_, exists := tracker.certStatuses[certIdentity]
	if !exists {
		t.Fatal("New certIdentity should be created")
	}
}

func TestGetStatus_AllValid(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	// Add certificates with future expiry times
	expiryTime1 := time.Now().Add(24 * time.Hour)
	expiryTime2 := time.Now().Add(48 * time.Hour)
	certFile1 := createTempCertFile(t, expiryTime1)
	certFile2 := createTempCertFile(t, expiryTime2)
	defer os.Remove(certFile1)
	defer os.Remove(certFile2)

	tracker.RecordRefreshSuccess("service1", certFile1)
	tracker.RecordRefreshSuccess("service2", certFile2)

	status := tracker.GetStatus()
	if !status {
		t.Error("GetStatus should return true when all certificates are valid")
	}
}

func TestGetStatus_AllExpired(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	// Add certificates with past expiry times
	expiryTime1 := time.Now().Add(-24 * time.Hour)
	expiryTime2 := time.Now().Add(-48 * time.Hour)
	certFile1 := createTempCertFile(t, expiryTime1)
	certFile2 := createTempCertFile(t, expiryTime2)
	defer os.Remove(certFile1)
	defer os.Remove(certFile2)

	tracker.RecordRefreshSuccess("service1", certFile1)
	tracker.RecordRefreshSuccess("service2", certFile2)

	status := tracker.GetStatus()
	if status {
		t.Error("GetStatus should return false when all certificates are expired")
	}
}

func TestGetStatus_Mixed(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	// Add one valid and one expired certificate
	expiryTime1 := time.Now().Add(24 * time.Hour)
	expiryTime2 := time.Now().Add(-24 * time.Hour)
	certFile1 := createTempCertFile(t, expiryTime1)
	certFile2 := createTempCertFile(t, expiryTime2)
	defer os.Remove(certFile1)
	defer os.Remove(certFile2)

	tracker.RecordRefreshSuccess("service1", certFile1)
	tracker.RecordRefreshSuccess("service2", certFile2)

	status := tracker.GetStatus()
	if status {
		t.Error("GetStatus should return false when at least one certificate is expired")
	}
}

func TestGetStatus_EmptyMap(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	// Empty map should return true (all valid, since there are none)
	status := tracker.GetStatus()
	if !status {
		t.Error("GetStatus should return true when certStatuses map is empty")
	}
}

func TestGetStatus_ZeroExpiryTime(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	// Add a certificate with zero expiry time (not set)
	tracker.RecordRefreshSuccess("service1", "/nonexistent/file.pem")

	status := tracker.GetStatus()
	if status {
		t.Error("GetStatus should return false when expiry time is zero (not set)")
	}
}

func TestGetCerts(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	expiryTime1 := time.Now().Add(24 * time.Hour)
	expiryTime2 := time.Now().Add(48 * time.Hour)
	certFile1 := createTempCertFile(t, expiryTime1)
	certFile2 := createTempCertFile(t, expiryTime2)
	defer os.Remove(certFile1)
	defer os.Remove(certFile2)

	testError := errors.New("test error")
	now := time.Now()

	tracker.RecordRefreshSuccess("service1", certFile1)
	tracker.RecordRefreshFailure("service2", testError)

	// Manually set times for service2 to test copying
	tracker.mu.Lock()
	if status, exists := tracker.certStatuses["service2"]; exists {
		status.LastFailureTime = &now
		status.LastRefreshTime = &now
	}
	tracker.mu.Unlock()

	certs := tracker.GetCerts()

	// Verify it's a copy (not the same map)
	tracker.mu.RLock()
	if &certs == &tracker.certStatuses {
		t.Error("GetCerts should return a copy of the map, not the original")
	}
	tracker.mu.RUnlock()

	// Verify contents
	if len(certs) != 2 {
		t.Errorf("Expected 2 certificates, got %d", len(certs))
	}

	// Verify service1
	status1, exists := certs["service1"]
	if !exists {
		t.Fatal("service1 should exist in returned map")
	}
	if status1.LastRefreshTime == nil {
		t.Error("service1 LastRefreshTime should be set")
	}
	if status1.LastFailureTime != nil {
		t.Error("service1 LastFailureTime should be nil")
	}

	// Verify service2
	status2, exists := certs["service2"]
	if !exists {
		t.Fatal("service2 should exist in returned map")
	}
	if status2.LastFailureError != testError.Error() {
		t.Errorf("Expected LastFailureError '%s', got '%s'", testError.Error(), status2.LastFailureError)
	}
	if status2.LastFailureTime == nil {
		t.Error("service2 LastFailureTime should be set")
	}
}

func TestGetCerts_DeepCopy(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	expiryTime := time.Now().Add(24 * time.Hour)
	certFile := createTempCertFile(t, expiryTime)
	defer os.Remove(certFile)

	tracker.RecordRefreshSuccess("service1", certFile)

	certs := tracker.GetCerts()

	newTime := time.Now().Add(72 * time.Hour)

	// Modify the returned copy
	certs["service1"].ExpiryTime = newTime

	// Verify original is not modified
	tracker.mu.RLock()
	originalStatus := tracker.certStatuses["service1"]
	tracker.mu.RUnlock()

	if originalStatus.ExpiryTime == newTime {
		t.Error("Modifying returned map should not affect original")
	}
}

func TestGetCerts_EmptyMap(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	certs := tracker.GetCerts()

	if len(certs) != 0 {
		t.Errorf("Expected empty map, got %d entries", len(certs))
	}
}

func TestStartHttpServer_StatusEndpoint(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	// Set up valid certificates
	expiryTime := time.Now().Add(24 * time.Hour)
	certFile := createTempCertFile(t, expiryTime)
	defer os.Remove(certFile)
	tracker.RecordRefreshSuccess("service1", certFile)

	// Create a test server
	port := 8888
	stop := make(chan struct{})

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- StartHttpServer(port, stop)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test GET /status with valid certificates
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/status", port))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Test POST /status (should return MethodNotAllowed)
	resp2, err := http.Post(fmt.Sprintf("http://localhost:%d/status", port), "application/json", nil)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status code %d, got %d", http.StatusMethodNotAllowed, resp2.StatusCode)
	}

	// Stop server
	close(stop)
	time.Sleep(100 * time.Millisecond)
}

func TestStartHttpServer_StatusEndpoint_InvalidCerts(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	// Set up expired certificates
	expiryTime := time.Now().Add(-24 * time.Hour)
	certFile := createTempCertFile(t, expiryTime)
	defer os.Remove(certFile)
	tracker.RecordRefreshSuccess("service1", certFile)

	port := 8889
	stop := make(chan struct{})

	errChan := make(chan error, 1)
	go func() {
		errChan <- StartHttpServer(port, stop)
	}()

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/status", port))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, resp.StatusCode)
	}

	close(stop)
	time.Sleep(100 * time.Millisecond)
}

func TestStartHttpServer_CertsEndpoint(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	expiryTime := time.Now().Add(24 * time.Hour)
	certFile := createTempCertFile(t, expiryTime)
	defer os.Remove(certFile)
	tracker.RecordRefreshSuccess("service1", certFile)
	tracker.RecordRefreshFailure("service2", errors.New("test error"))

	port := 8890
	stop := make(chan struct{})

	errChan := make(chan error, 1)
	go func() {
		errChan <- StartHttpServer(port, stop)
	}()

	time.Sleep(100 * time.Millisecond)

	// Test GET /certs
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/certs", port))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Verify JSON response
	var certs map[string]*CertStatus
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&certs); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("Expected 2 certificates in response, got %d", len(certs))
	}

	if _, exists := certs["service1"]; !exists {
		t.Error("service1 should exist in response")
	}

	if _, exists := certs["service2"]; !exists {
		t.Error("service2 should exist in response")
	}

	// Test POST /certs (should return MethodNotAllowed)
	resp2, err := http.Post(fmt.Sprintf("http://localhost:%d/certs", port), "application/json", nil)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status code %d, got %d", http.StatusMethodNotAllowed, resp2.StatusCode)
	}

	close(stop)
	time.Sleep(100 * time.Millisecond)
}

func TestStartHttpServer_Shutdown(t *testing.T) {
	resetGlobalTracker()
	port := 8891
	stop := make(chan struct{})

	errChan := make(chan error, 1)
	go func() {
		errChan <- StartHttpServer(port, stop)
	}()

	time.Sleep(100 * time.Millisecond)

	// Verify server is running
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/status", port))
	if err != nil {
		t.Fatalf("Server should be running: %v", err)
	}
	resp.Body.Close()

	// Shutdown server
	close(stop)

	// Wait for shutdown
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Shutdown should not return error, got: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Shutdown should complete within timeout")
	}

	// Verify server is no longer accepting connections
	time.Sleep(100 * time.Millisecond)
	_, err = http.Get(fmt.Sprintf("http://localhost:%d/status", port))
	if err == nil {
		t.Error("Server should be shut down")
	}
}

func TestStartHttpServer_ConcurrentAccess(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	expiryTime := time.Now().Add(24 * time.Hour)
	certFile := createTempCertFile(t, expiryTime)
	defer os.Remove(certFile)

	// Initialize with multiple services
	opts := &sc.Options{
		Services: []sc.Service{
			{Name: "service1"},
			{Name: "service2"},
			{Name: "service3"},
		},
	}
	tracker.Initialize(opts)

	// Concurrently record successes and failures
	var wg sync.WaitGroup
	numGoroutines := 10
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			serviceName := fmt.Sprintf("service%d", (id%3)+1)
			if id%2 == 0 {
				tracker.RecordRefreshSuccess(serviceName, certFile)
			} else {
				tracker.RecordRefreshFailure(serviceName, fmt.Errorf("error %d", id))
			}
		}(i)
	}

	wg.Wait()

	// Verify all services have status
	certs := tracker.GetCerts()
	if len(certs) < 3 {
		t.Errorf("Expected at least 3 certificates, got %d", len(certs))
	}

	// Concurrently call GetStatus and GetCerts
	wg = sync.WaitGroup{}
	for i := 0; i < numGoroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = tracker.GetStatus()
		}()
		go func() {
			defer wg.Done()
			_ = tracker.GetCerts()
		}()
	}

	wg.Wait()
}

func TestRecordRefreshSuccess_OverwritesFailure(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	certIdentity := "test-service"
	testError := errors.New("initial error")

	// Record a failure first
	tracker.RecordRefreshFailure(certIdentity, testError)

	// Then record a success
	expiryTime := time.Now().Add(24 * time.Hour)
	certFile := createTempCertFile(t, expiryTime)
	defer os.Remove(certFile)
	tracker.RecordRefreshSuccess(certIdentity, certFile)

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	status := tracker.certStatuses[certIdentity]
	if status.LastFailureTime != nil {
		t.Error("LastFailureTime should be nil after successful refresh")
	}
	if status.LastFailureError != "" {
		t.Error("LastFailureError should be cleared after successful refresh")
	}
	if status.LastRefreshTime == nil {
		t.Error("LastRefreshTime should be set after successful refresh")
	}
}

func TestRecordRefreshFailure_OverwritesSuccess(t *testing.T) {
	resetGlobalTracker()
	tracker := GetStatusTracker()

	certIdentity := "test-service"
	expiryTime := time.Now().Add(24 * time.Hour)
	certFile := createTempCertFile(t, expiryTime)
	defer os.Remove(certFile)

	// Record a success first
	tracker.RecordRefreshSuccess(certIdentity, certFile)

	// Then record a failure
	testError := errors.New("subsequent error")
	tracker.RecordRefreshFailure(certIdentity, testError)

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	status := tracker.certStatuses[certIdentity]
	// LastRefreshTime should still be set (not cleared by failure)
	if status.LastRefreshTime == nil {
		t.Error("LastRefreshTime should remain set even after failure")
	}
	// But failure information should be added
	if status.LastFailureTime == nil {
		t.Error("LastFailureTime should be set after failure")
	}
	if status.LastFailureError != testError.Error() {
		t.Errorf("Expected LastFailureError '%s', got '%s'", testError.Error(), status.LastFailureError)
	}
}
