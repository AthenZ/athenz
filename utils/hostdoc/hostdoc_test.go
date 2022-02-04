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

package main

import (
	"path/filepath"
	"testing"
)

func TestProcess(t *testing.T) {
	type args struct {
		docFile string
		domain  bool
		service bool
		profile bool
		primary bool
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "test with single service",
			args: args {
				docFile: filepath.Join("testdata", "host_document"),
				domain: true,
			},
			want: "athenz.examples",
			wantErr: false,
		},
		{
			name: "test for primary service with multiple services",
			args: args {
				docFile: filepath.Join("testdata", "host_document.services"),
				primary: true,
			},
			want: "httpd",
			wantErr: false,
		},
		{
			name: "test for service with multiple services",
			args: args {
				docFile: filepath.Join("testdata", "host_document.services"),
				service: true,
			},
			want: "httpd,ftpd",
			wantErr: false,
		},
		{
			name: "test no selection",
			args: args {
				docFile: filepath.Join("testdata", "host_document"),
			},
			want: "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Process(tt.args.docFile, tt.args.domain, tt.args.service, tt.args.profile, tt.args.primary)
			if (err != nil) != tt.wantErr {
				t.Errorf("Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Process() got = %v, want %v", got, tt.want)
			}
		})
	}
}
