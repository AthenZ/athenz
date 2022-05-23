// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package siafile

import (
	"net"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestExists(t *testing.T) {
	testFile := "./test.txt"
	a := assert.New(t)

	//false for non existing file
	fileExists := Exists(testFile)
	a.Equal(fileExists, false)

	_, err := os.Create(testFile)
	a.Nil(err)
	//true for existing file
	a.Equal(Exists(testFile), true)
	err = os.Remove(testFile)
	a.Nil(err)
}

func TestCreateFile(t *testing.T) {
	a := assert.New(t)

	// Generate a source file for testing
	dir := os.TempDir()
	filePath := dir + "/test123"

	ips := ipsContent()

	err := WriteFile(ips, filePath)
	defer os.Remove(filePath)
	require.Nilf(t, err, "should be able to write to temp file, err: %v", err)

	content := []net.IP{}
	err = ReadFile(filePath, &content)
	require.Nilf(t, err, "should be able to read temp file, err: %v", err)
	a.Equal(ips, content)
	a.True(reflect.DeepEqual(ips, content))
}

func ipsContent() []net.IP {
	ips := []net.IP{}
	ips = append(ips, net.IPv4(byte('1'), byte('1'), byte('1'), byte('1')))
	ips = append(ips, net.IPv4(byte('2'), byte('2'), byte('2'), byte('2')))
	return ips
}
