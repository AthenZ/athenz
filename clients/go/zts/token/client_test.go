package token

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/patrickmn/go-cache"
)

type fakeZTSClient struct {
	URLField            string
	TransportField      *http.Transport
	AccessTokenResponse *zts.AccessTokenResponse
	RoleTokenResponse   *zts.RoleToken
	Error               error
}

func (f *fakeZTSClient) PostAccessTokenRequest(req zts.AccessTokenRequest) (*zts.AccessTokenResponse, error) {
	return f.AccessTokenResponse, f.Error
}

func (f *fakeZTSClient) GetRoleToken(domain zts.DomainName, roles zts.EntityList, minExpiryTime *int32, maxExpiryTime *int32, proxyForPrincipal zts.EntityName) (*zts.RoleToken, error) {
	return f.RoleTokenResponse, f.Error
}

func (f *fakeZTSClient) SetTransport(t *http.Transport) {
	f.TransportField = t
}

func (f *fakeZTSClient) Transport() *http.Transport {
	return f.TransportField
}

func (f *fakeZTSClient) URL() string {
	return ""
}

func (f *fakeZTSClient) SetURL(url string) {
	f.URLField = url
}

type GetTokenFunc func(domain string, roles string, exp int32) (interface{}, error)

func (f GetTokenFunc) getToken(domain string, roles string, exp int32) (interface{}, error) {
	return f(domain, roles, exp)
}

func createTempCertFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	certFile, err := os.CreateTemp("", "testcert_*.pem")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	keyFile, err := os.CreateTemp("", "testkey_*.pem")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	return certFile.Name(), keyFile.Name()
}

func TestNewClient(t *testing.T) {
	validCert, validKey := createTempCertFiles(t)
	defer os.Remove(validCert)
	defer os.Remove(validKey)

	tests := []struct {
		name         string
		url          string
		certPath     string
		keyPath      string
		expectTLSCfg bool
	}{
		{
			name:         "Valid cert and key",
			url:          "http://example.com",
			certPath:     validCert,
			keyPath:      validKey,
			expectTLSCfg: true,
		},
		{
			name:         "Invalid cert and key",
			url:          "http://example.com",
			certPath:     "nonexistent_cert.pem",
			keyPath:      "nonexistent_key.pem",
			expectTLSCfg: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.url, tt.certPath, tt.keyPath)
			if client == nil {
				t.Fatal("Expected non-nil Client")
			}
			if client.Cache == nil {
				t.Error("Expected non-nil Cache")
			}
			if client.ZTS == nil {
				t.Error("Expected non-nil ZTS client")
			}
			tlsCfg := client.ZTS.Transport().TLSClientConfig
			if tt.expectTLSCfg {
				if tlsCfg == nil {
					t.Error("Expected TLSClientConfig to be set")
				}
			} else {
				if tlsCfg != nil {
					t.Error("Expected TLSClientConfig to be nil for invalid files")
				}
			}
		})
	}
}

func TestGetCacheKey(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		roles    []string
		exp      int32
		expected string
	}{
		{"Single role", "example", []string{"admin"}, 3600, "example:admin:3600"},
		{"Multiple roles unsorted", "example", []string{"user", "admin"}, 3600, "example:admin,user:3600"},
		{"Empty role", "example", []string{""}, 0, "example::0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := getCacheKey(tt.domain, tt.roles, tt.exp)
			if key != tt.expected {
				t.Errorf("Expected cache key %q, got %q", tt.expected, key)
			}
		})
	}
}

func TestCreateTLSConfig(t *testing.T) {
	validCert, validKey := createTempCertFiles(t)
	defer os.Remove(validCert)
	defer os.Remove(validKey)

	tests := []struct {
		name        string
		certPath    string
		keyPath     string
		expectError bool
		expectCerts bool
	}{
		{"Valid files", validCert, validKey, false, true},
		{"Invalid files", "nonexistent_cert.pem", "nonexistent_key.pem", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsCfg, err := createTLSConfig(tt.certPath, tt.keyPath)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tlsCfg == nil {
					t.Error("Expected non-nil TLS config")
				} else if tt.expectCerts && len(tlsCfg.Certificates) == 0 {
					t.Error("Expected certificates in TLS config")
				}
			}
		})
	}
}

func TestSetTLSConfig(t *testing.T) {
	tests := []struct {
		name             string
		initialTransport *http.Transport
		newCfg           *tls.Config
		expectInsecure   bool
	}{
		{
			name: "Transport not nil: update from false to true",
			initialTransport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
			newCfg:         &tls.Config{InsecureSkipVerify: true},
			expectInsecure: true,
		},
		{
			name: "Transport not nil: update from true to false",
			initialTransport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			newCfg:         &tls.Config{InsecureSkipVerify: false},
			expectInsecure: false,
		},
		{
			name:             "Transport is nil: new transport is created with new TLS config",
			initialTransport: nil,
			newCfg:           &tls.Config{InsecureSkipVerify: true},
			expectInsecure:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeZTSClient{
				TransportField: tt.initialTransport,
			}
			c := &Client{
				ZTS:   fake,
				Cache: cache.New(5*time.Minute, 10*time.Minute),
			}
			c.SetTLSConfig(tt.newCfg)
			tr := c.ZTS.Transport()
			if tr == nil {
				t.Fatal("Expected non-nil Transport after SetTLSConfig")
			}
			if tr.TLSClientConfig == nil {
				t.Fatal("Expected non-nil TLSClientConfig after SetTLSConfig")
			}
			if tr.TLSClientConfig.InsecureSkipVerify != tt.expectInsecure {
				t.Errorf("Expected InsecureSkipVerify %v, got %v", tt.expectInsecure, tr.TLSClientConfig.InsecureSkipVerify)
			}
		})
	}
}

func TestTransport(t *testing.T) {
	fake := &fakeZTSClient{
		TransportField: &http.Transport{},
	}
	c := &Client{
		ZTS:   fake,
		Cache: cache.New(5*time.Minute, 10*time.Minute),
	}
	if tr := c.Transport(); tr != fake.TransportField {
		t.Errorf("Expected transport %v, got %v", fake.TransportField, tr)
	}
}

func TestUpdateCachePeriodically(t *testing.T) {
	tests := []struct {
		name         string
		getter       func(domain string, roles string, exp int32) (interface{}, error)
		expectUpdate bool
	}{
		{
			name: "Successful update",
			getter: func(domain string, roles string, exp int32) (interface{}, error) {
				return &AccessToken{
					Token: &zts.AccessTokenResponse{
						Access_token: "newToken",
					},
					ExpiryTime: time.Now().Unix() + 600,
				}, nil
			},
			expectUpdate: true,
		},
		{
			name: "Error fetching new token",
			getter: func(domain string, roles string, exp int32) (interface{}, error) {
				return nil, fmt.Errorf("simulated error")
			},
			expectUpdate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				Cache: cache.New(5*time.Minute, 10*time.Minute),
			}
			key := getCacheKey("test", []string{"role"}, 3600)
			oldToken := &AccessToken{
				Token: &zts.AccessTokenResponse{
					Access_token: "oldToken",
				},
				ExpiryTime: time.Now().Unix() + 100,
			}
			c.Cache.Set(key, oldToken, 200*time.Second)

			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.UpdateCachePeriodically(ctx, GetTokenFunc(tt.getter), 100*time.Millisecond)
			}()

			time.Sleep(300 * time.Millisecond)
			cancel()
			wg.Wait()

			cached, found := c.Cache.Get(key)
			if !found {
				t.Fatal("Cache key not found")
			}
			updatedToken, ok := cached.(*AccessToken)
			if !ok {
				t.Fatal("Cached item is not *AccessToken")
			}

			if tt.expectUpdate {
				if updatedToken.Token.Access_token == "oldToken" {
					t.Error("Expected token to be updated, but it remains unchanged")
				}
			} else {
				if updatedToken.Token.Access_token != "oldToken" {
					t.Error("Expected token to remain unchanged due to error, but it was updated")
				}
			}
		})
	}
}

type filePairFunc func(t *testing.T) (cert string, key string, cleanup func())

func validFilePair(t *testing.T) (string, string, func()) {
	cert, key := createTempCertFiles(t)
	cleanup := func() {
		os.Remove(cert)
		os.Remove(key)
	}
	return cert, key, cleanup
}
func invalidFilePair(t *testing.T) (string, string, func()) {
	createInvalid := func() (string, func()) {
		f, err := os.CreateTemp("", "invalid_*.pem")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		content := []byte("invalid content")
		if err := os.WriteFile(f.Name(), content, 0644); err != nil {
			t.Fatalf("failed to write invalid content: %v", err)
		}
		return f.Name(), func() { os.Remove(f.Name()) }
	}
	cert, cleanupCert := createInvalid()
	key, cleanupKey := createInvalid()
	cleanup := func() {
		cleanupCert()
		cleanupKey()
	}
	return cert, key, cleanup
}
func filePairCertMissing(t *testing.T) (string, string, func()) {
	_, key, cleanup := validFilePair(t)
	return "nonexistent_cert.pem", key, cleanup
}

func TestWatchCertificateFiles(t *testing.T) {
	tests := []struct {
		name                string
		filePair            filePairFunc
		modifyEvent         bool
		expectedErrContains string
	}{
		{
			name:                "immediate cancellation with valid files",
			filePair:            validFilePair,
			modifyEvent:         false,
			expectedErrContains: "",
		},
		{
			name:                "file add error (cert file missing)",
			filePair:            filePairCertMissing,
			modifyEvent:         false,
			expectedErrContains: "failed to watch file",
		},
		{
			name:                "valid file event with valid TLS config",
			filePair:            validFilePair,
			modifyEvent:         true,
			expectedErrContains: "",
		},
		{
			name:                "valid file event with invalid TLS config",
			filePair:            invalidFilePair,
			modifyEvent:         true,
			expectedErrContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, key, cleanup := tt.filePair(t)
			defer cleanup()

			client := &Client{
				Cache: cache.New(5*time.Minute, 10*time.Minute),
				ZTS:   &fakeZTSClient{TransportField: &http.Transport{}},
			}

			ctx, cancel := context.WithCancel(context.Background())
			errCh := make(chan error, 1)
			go func() {
				errCh <- client.WatchCertificateFiles(ctx, cert, key)
			}()

			if tt.modifyEvent {
				time.Sleep(100 * time.Millisecond)
				content, err := os.ReadFile(cert)
				if err != nil {
					t.Fatalf("failed to read cert file: %v", err)
				}
				if err := os.WriteFile(cert, content, 0644); err != nil {
					t.Fatalf("failed to rewrite cert file: %v", err)
				}
			}

			time.Sleep(200 * time.Millisecond)
			cancel()

			err := <-errCh
			if tt.expectedErrContains != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.expectedErrContains)
				} else if !strings.Contains(err.Error(), tt.expectedErrContains) {
					t.Errorf("expected error containing %q, got %q", tt.expectedErrContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %q", err.Error())
				}
			}
		})
	}
}

type dummyTransport struct{}

func (dt *dummyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestStartBackgroundTasks(t *testing.T) {
	dummyPem, dummyKey := createTempCertFiles(t)
	defer os.Remove(dummyPem)
	defer os.Remove(dummyKey)

	tests := []struct {
		name         string
		ctx          context.Context
		certPath     string
		keyPath      string
		watcherError bool
		expectedLog  string
	}{
		{
			name:         "nil context",
			ctx:          nil,
			certPath:     dummyPem,
			keyPath:      dummyKey,
			watcherError: false,
			expectedLog:  "",
		},
		{
			name:         "non-nil context",
			ctx:          context.Background(),
			certPath:     dummyPem,
			keyPath:      dummyKey,
			watcherError: false,
			expectedLog:  "",
		},
		{
			name:         "invalid cert/key path",
			ctx:          context.Background(),
			certPath:     "invalid_cert_path",
			keyPath:      "invalid_key_path",
			watcherError: true,
			expectedLog:  "Error watching certificate files:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var buf bytes.Buffer
			handler := slog.NewTextHandler(&buf, nil)
			testLogger := slog.New(handler)
			oldLogger := slog.Default()
			slog.SetDefault(testLogger)
			defer slog.SetDefault(oldLogger)

			client := NewClient("http://example.com", dummyPem, dummyKey)
			cancel := client.startBackgroundTasks(tt.ctx, tt.certPath, tt.keyPath, 100*time.Millisecond)
			if cancel == nil {
				t.Error("Expected non-nil cancel function")
			}
			time.Sleep(200 * time.Millisecond)
			cancel()
			time.Sleep(100 * time.Millisecond)

			logOutput := buf.String()
			if tt.watcherError {
				if !strings.Contains(logOutput, tt.expectedLog) {
					t.Errorf("expected log to contain %q, but got %q", tt.expectedLog, logOutput)
				}
			}
		})
	}
}

func TestSetProxy(t *testing.T) {
	tests := []struct {
		name             string
		initialTransport *http.Transport
		proxyURL         string
		expectSuccess    bool
	}{
		{
			name:             "Transport not nil, valid proxy",
			initialTransport: &http.Transport{},
			proxyURL:         "http://proxy.example.com:8080",
			expectSuccess:    true,
		},
		{
			name:             "Transport is nil, valid proxy",
			initialTransport: nil,
			proxyURL:         "http://proxy.example.com:8080",
			expectSuccess:    true,
		},
		{
			name:             "Transport not nil, invalid proxy",
			initialTransport: &http.Transport{},
			proxyURL:         "://invalid-proxy",
			expectSuccess:    false,
		},
		{
			name:             "Transport is nil, invalid proxy",
			initialTransport: nil,
			proxyURL:         "://invalid-proxy",
			expectSuccess:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeZTSClient{
				TransportField: tt.initialTransport,
			}
			c := &Client{
				ZTS:   fake,
				Cache: cache.New(5*time.Minute, 10*time.Minute),
			}

			c.SetProxy(tt.proxyURL)
			newTransport := c.ZTS.Transport()

			if tt.expectSuccess {
				if newTransport == nil {
					t.Fatal("Expected non-nil transport after SetProxy")
				}
				req, err := http.NewRequest("GET", "http://example.com", nil)
				if err != nil {
					t.Fatalf("Error creating request: %v", err)
				}
				proxy, err := newTransport.Proxy(req)
				if err != nil {
					t.Fatalf("Unexpected error calling Proxy: %v", err)
				}
				if proxy == nil {
					t.Fatal("Expected proxy to be set, got nil")
				}
				if proxy.String() != tt.proxyURL {
					t.Errorf("Expected proxy URL %q, got %q", tt.proxyURL, proxy.String())
				}
			} else {
				if tt.initialTransport == nil {
					if newTransport != nil {
						t.Errorf("Expected transport to remain nil for invalid proxy, got non-nil")
					}
				} else {
					if newTransport != tt.initialTransport {
						t.Errorf("Expected transport to remain unchanged for invalid proxy")
					}
				}
			}
		})
	}
}

func TestGetTokenWithExpire(t *testing.T) {
	domain := "testdomain"
	roles := []string{"admin"}
	exp := 14400
	now := time.Now().Unix()
	cacheKey := getCacheKey(domain, roles, int32(exp))

	tests := []struct {
		name                 string
		initialCacheToken    *AccessToken
		getTokenFunc         func(domain string, roles string, exp int32) (*AccessToken, error)
		expectedToken        string
		expectedExpiry       int64
		expectError          bool
		expectGetTokenCalled bool
	}{
		{
			name: "Cache hit with valid token",
			initialCacheToken: &AccessToken{
				Token: &zts.AccessTokenResponse{
					Access_token: "cachedToken",
				},
				ExpiryTime: now + int64(exp),
				Duration:   14400 * time.Second,
			},
			getTokenFunc: func(domain string, roles string, exp int32) (*AccessToken, error) {
				t.Fatal("getTokenFunc should not be called in cache hit case")
				return nil, nil
			},
			expectedToken:        "cachedToken",
			expectedExpiry:       now + int64(exp),
			expectError:          false,
			expectGetTokenCalled: false,
		},
		{
			name:              "Cache miss with getTokenFunc success",
			initialCacheToken: nil,
			getTokenFunc: func(domain string, roles string, exp int32) (*AccessToken, error) {
				return &AccessToken{
					Token: &zts.AccessTokenResponse{
						Access_token: "newToken",
					},
					ExpiryTime: now + int64(exp),
					Duration:   14400 * time.Second,
				}, nil
			},
			expectedToken:        "newToken",
			expectedExpiry:       now + int64(exp),
			expectError:          false,
			expectGetTokenCalled: true,
		},
		{
			name:              "Cache miss with getTokenFunc error and no cache",
			initialCacheToken: nil,
			getTokenFunc: func(domain string, roles string, exp int32) (*AccessToken, error) {
				return nil, fmt.Errorf("simulated error")
			},
			expectedToken:        "",
			expectError:          true,
			expectGetTokenCalled: true,
		},
		{
			name: "Cache present (expired) with getTokenFunc error",
			initialCacheToken: &AccessToken{
				Token: &zts.AccessTokenResponse{
					Access_token: "cachedTokenExpired",
				},
				ExpiryTime: now + 1000,
				Duration:   3000 * time.Second,
			},
			getTokenFunc: func(domain string, roles string, exp int32) (*AccessToken, error) {
				return nil, fmt.Errorf("simulated error")
			},
			expectedToken:        "cachedTokenExpired",
			expectedExpiry:       now + 1000,
			expectError:          true,
			expectGetTokenCalled: true,
		},
		{
			name: "Cache present (expired) with getTokenFunc success",
			initialCacheToken: &AccessToken{
				Token: &zts.AccessTokenResponse{
					Access_token: "cachedTokenExpired",
				},
				ExpiryTime: now + 1000,
				Duration:   3000 * time.Second,
			},
			getTokenFunc: func(domain string, roles string, exp int32) (*AccessToken, error) {
				return &AccessToken{
					Token: &zts.AccessTokenResponse{
						Access_token: "newTokenOverride",
					},
					ExpiryTime: time.Now().Unix() + int64(exp),
					Duration:   14400 * time.Second,
				}, nil
			},
			expectedToken:        "newTokenOverride",
			expectedExpiry:       now + int64(exp),
			expectError:          false,
			expectGetTokenCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var callCount int32
			wrappedFunc := func(domain string, roles string, exp int32) (*AccessToken, error) {
				atomic.AddInt32(&callCount, 1)
				return tt.getTokenFunc(domain, roles, exp)
			}

			c := cache.New(5*time.Minute, 10*time.Minute)
			if tt.initialCacheToken != nil {
				c.Set(cacheKey, tt.initialCacheToken, 1*time.Hour)
			}
			client := &Client{Cache: c}
			btc := &BaseTokenClient[*AccessToken]{
				Client:       client,
				getTokenFunc: wrappedFunc,
			}

			result, err := btc.GetTokenWithExpire(domain, roles, int32(exp))
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				if tt.initialCacheToken == nil {
					if result != nil {
						t.Error("expected nil result on error with no cache")
					}
				} else {
					if result == nil {
						t.Error("expected cached token, got nil")
					} else if result.GetToken().Access_token != tt.expectedToken {
						t.Errorf("expected token %q, got %q", tt.expectedToken, result.GetToken().Access_token)
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result == nil {
					t.Fatal("result is nil")
				}
				if result.GetToken().Access_token != tt.expectedToken {
					t.Errorf("expected token %q, got %q", tt.expectedToken, result.GetToken().Access_token)
				}

				if tt.expectedExpiry != result.GetExpiryTime() {
					t.Errorf("expected expiry time %d, but got %d", tt.expectedExpiry, result.GetExpiryTime())
				}
			}

			called := atomic.LoadInt32(&callCount) > 0
			if called != tt.expectGetTokenCalled {
				t.Errorf("expected getTokenFunc called = %v, got %v", tt.expectGetTokenCalled, called)
			}
		})
	}
}

func TestGetToken(t *testing.T) {
	domain := "testdomain"
	roles := []string{"admin"}
	var callCount int32
	wrappedFunc := func(domain string, roles string, exp int32) (*AccessToken, error) {
		atomic.AddInt32(&callCount, 1)
		return &AccessToken{
			Token: &zts.AccessTokenResponse{
				Access_token: "newToken",
			},
			ExpiryTime: time.Now().Unix() + 3600,
		}, nil
	}

	c := cache.New(5*time.Minute, 10*time.Minute)
	client := &Client{Cache: c}
	btc := &BaseTokenClient[*AccessToken]{
		Client:       client,
		getTokenFunc: wrappedFunc,
	}

	result, err := btc.GetToken(domain, roles)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.GetToken().Access_token != "newToken" {
		t.Errorf("expected token 'newToken', got %q", result.GetToken().Access_token)
	}
	if atomic.LoadInt32(&callCount) == 0 {
		t.Error("expected getTokenFunc to be called")
	}
}
