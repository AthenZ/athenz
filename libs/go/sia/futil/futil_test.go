package futil

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()

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
				name: filepath.Join("/proc", "fail"),
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
	dir := t.TempDir()

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
				dirs: []string{filepath.Join("/proc", "invalid")},
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

func TestSymlink(t *testing.T) {
	sshDir := t.TempDir()
	log.Printf("sshDir: %q", sshDir)

	source := filepath.Join(sshDir, "source")
	os.WriteFile(source, []byte("source file"), 0400)

	existingLink := filepath.Join(sshDir, "existingLink")
	existingSource := filepath.Join(sshDir, "existingSource")
	os.WriteFile(existingSource, []byte("earlier source file"), 0000)
	err := os.Symlink(existingSource, existingLink)
	require.Nilf(t, err, "unexpected err: %v", err)

	regularFile := filepath.Join(sshDir, "regular")
	os.WriteFile(regularFile, []byte("regular file"), 0400)

	linkToSource := filepath.Join(sshDir, "link-to-source")
	err = os.Symlink(source, linkToSource)
	require.Nilf(t, err, "unexpected err: %v", err)

	type args struct {
		source string
		link   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "link doesn't exist",
			args: args{
				source: source,
				link:   filepath.Join(sshDir, "link"),
			},
			wantErr: false,
		},
		{
			name: "existing link, target mismatch",
			args: args{
				source: source,
				link:   existingLink,
			},
			wantErr: false,
		},
		{
			name: "link is a regular file",
			args: args{
				source: source,
				link:   regularFile,
			},
			wantErr: true,
		},
		{
			name: "link and source match",
			args: args{
				source: source,
				link:   linkToSource,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Symlink(tt.args.source, tt.args.link)
			if (err != nil) != tt.wantErr {
				t.Errorf("Symlink() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if target, e := os.Readlink(tt.args.link); e != nil || target != tt.args.source {
					t.Errorf("unexpected link: %q, source: %q, target: %q, err: %v", tt.args.link, tt.args.source, target, err)
				}
			}
		})
	}
}
