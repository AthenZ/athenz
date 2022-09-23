// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package util

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExists(t *testing.T) {
	testFile := "/tmp/test.txt"
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
