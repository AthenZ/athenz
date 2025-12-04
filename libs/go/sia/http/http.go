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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	sc "github.com/AthenZ/athenz/libs/go/sia/config"
	"github.com/AthenZ/athenz/libs/go/sia/pki/cert"
)

// CertStatus represents the status of a certificate
type CertStatus struct {
	ExpiryTime       time.Time  `json:"expiry_time"`
	LastRefreshTime  *time.Time `json:"last_refresh_time,omitempty"`
	LastFailureTime  *time.Time `json:"last_failure_time,omitempty"`
	LastFailureError string     `json:"last_failure_error,omitempty"`
}

// StatusTracker tracks certificate status information
type StatusTracker struct {
	mu           sync.RWMutex
	certStatuses map[string]*CertStatus
}

var globalTracker *StatusTracker
var trackerOnce sync.Once

// GetStatusTracker returns the global status tracker instance
func GetStatusTracker() *StatusTracker {
	trackerOnce.Do(func() {
		globalTracker = &StatusTracker{
			certStatuses: make(map[string]*CertStatus),
		}
	})
	return globalTracker
}

// Initialize initializes the status tracker with options
func (st *StatusTracker) Initialize(opts *sc.Options) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.certStatuses = make(map[string]*CertStatus)
}

// RecordRefreshSuccess records a successful certificate refresh
func (st *StatusTracker) RecordRefreshSuccess(certIdentity, certFile string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	status, exists := st.certStatuses[certIdentity]
	if !exists {
		status = &CertStatus{}
		st.certStatuses[certIdentity] = status
	}

	status.LastRefreshTime = &now
	status.LastFailureTime = nil
	status.LastFailureError = ""

	// Update expiry time from certificate file
	if certificate, err := cert.FromFile(certFile); err == nil {
		status.ExpiryTime = certificate.NotAfter
	}
}

// RecordRefreshFailure records a failed certificate refresh
func (st *StatusTracker) RecordRefreshFailure(certIdentity string, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	status, exists := st.certStatuses[certIdentity]
	if !exists {
		status = &CertStatus{}
		st.certStatuses[certIdentity] = status
	}

	status.LastFailureTime = &now
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	status.LastFailureError = errMsg
}

// GetStatus returns the current status of all certificates
func (st *StatusTracker) GetStatus() bool {
	st.mu.RLock()
	defer st.mu.RUnlock()

	// if all the certificates in the status map are valid
	// then return true, otherwise false. A certificate
	// is considered valid if the expiry time is in the future
	// regardless of when was the last refresh time or if there
	// were any recent failures

	for _, status := range st.certStatuses {
		if time.Now().After(status.ExpiryTime) || status.ExpiryTime.IsZero() {
			return false
		}
	}

	return true
}

// GetCerts returns the current status of all certificates
func (st *StatusTracker) GetCerts() map[string]*CertStatus {
	st.mu.RLock()
	defer st.mu.RUnlock()

	// Create a copy of the status map
	result := make(map[string]*CertStatus)
	for certIdentity, status := range st.certStatuses {
		// Create a copy of the status
		statusCopy := &CertStatus{
			ExpiryTime:       status.ExpiryTime,
			LastFailureError: status.LastFailureError,
			LastFailureTime:  status.LastFailureTime,
			LastRefreshTime:  status.LastRefreshTime,
		}
		result[certIdentity] = statusCopy
	}

	return result
}

// StartHttpServer starts the HTTP server with status endpoint
func StartHttpServer(port int, stop <-chan struct{}) error {
	mux := http.NewServeMux()

	// Status endpoint
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		tracker := GetStatusTracker()
		status := tracker.GetStatus()

		log.Printf("Status response: %t\n", status)
		httpStatus := http.StatusOK
		if !status {
			httpStatus = http.StatusBadRequest
		}
		w.WriteHeader(httpStatus)
	})
	mux.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		tracker := GetStatusTracker()
		certs := tracker.GetCerts()

		// Convert to JSON
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(certs); err != nil {
			log.Printf("Error encoding status response: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		log.Printf("HTTP status server listening on port %d\n", port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("Error starting HTTP server: %v\n", err)
			errChan <- err
		}
	}()

	// Wait for stop signal or error
	select {
	case err := <-errChan:
		return err
	case <-stop:
		log.Println("Shutting down HTTP status server...")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down HTTP status server: %v\n", err)
		} else {
			log.Println("HTTP Server successfully shutdown")
		}
		return nil
	}
}
