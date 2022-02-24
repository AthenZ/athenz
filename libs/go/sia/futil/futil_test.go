package futil

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "writeFile")
	require.Nilf(t, err, "unexpected err: %v", err)

	defer os.RemoveAll(dir)

	type args struct {
		name string
		data []byte
		perm fs.FileMode
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "write file successfully",
			args: args{
				name: filepath.Join(dir, "success"),
				data: []byte("sucess file"),
				perm: 0400,
			},
		},
		{
			name: "write file failure",
			args: args{
				name: filepath.Join("/nonexisting", "fail"),
				data: []byte("failure content"),
				perm: 0400,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := WriteFile(tt.args.name, tt.args.data, tt.args.perm); (err != nil) != tt.wantErr {
				t.Errorf("WriteFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMakeSiaDirs(t *testing.T) {
	dir, err := os.MkdirTemp("", "siaDir")
	require.Nilf(t, err, "unexpected err: %v", err)
	defer os.RemoveAll(dir)

	type args struct {
		dirs []string
		perm os.FileMode
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "dir exists",
			args: args{
				dirs: []string{
					dir,
					filepath.Join(dir, "certs"),
					filepath.Join(dir, "keys"),
				},
				perm: 0755,
			},
			wantErr: false,
		},
		{
			name: "dir fail",
			args: args{
				dirs: []string{ filepath.Join("/nonexisting1", "invalid")},
				perm: 0755,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := MakeDirs(tt.args.dirs, tt.args.perm); (err != nil) != tt.wantErr {
				t.Errorf("MakeSiaDirs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	assert.True(t, Exists(filepath.Join(dir, "certs")))
	assert.True(t, Exists(filepath.Join(dir, "keys")))
}