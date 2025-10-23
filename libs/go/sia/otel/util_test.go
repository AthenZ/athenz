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

package otel

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_isGRPCProtocol(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     bool
	}{
		{
			name:     "not grpc scheme",
			endpoint: "https://example.com:1234",
			want:     false,
		},
		{
			name:     "grpc scheme",
			endpoint: "grpc://example.com:1234",
			want:     true,
		},
		{
			name:     "4317 port",
			endpoint: "example.com:4317",
			want:     true,
		},
		{
			name:     "4317 port with http",
			endpoint: "http://example.com:4317",
			want:     false,
		},
		{
			name:     "edge case: grpc url name but for http TLS",
			endpoint: "grpc.example.com:4318",
			want:     false,
		},
		{
			name:     "no scheme no grpc port",
			endpoint: "host-4317:4318",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGRPCProtocol(tt.endpoint); got != tt.want {
				t.Errorf("isGRPCProtocol() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_TrimScheme(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "https scheme",
			s:    "https://example.com:1234",
			want: "example.com:1234",
		},
		{
			name: "grpc scheme",
			s:    "grpc://example.com:1234",
			want: "example.com:1234",
		},
		{
			name: "no scheme",
			s:    "example.com:1234",
			want: "example.com:1234",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trimScheme(tt.s); got != tt.want {
				t.Errorf("trimScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasProtocolScheme(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "https scheme",
			s:    "https://example.com:1234",
			want: true,
		},
		{
			name: "grpc scheme",
			s:    "grpc://example.com:1234",
			want: true,
		},
		{
			name: "no scheme",
			s:    "example.com:1234",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, hasProtocolScheme(tt.s), "hasProtocolScheme(%v)", tt.s)
		})
	}
}
