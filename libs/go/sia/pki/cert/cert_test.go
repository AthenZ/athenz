// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package cert

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFromFile(test *testing.T) {
	tests := []struct {
		name     string
		certFile string
		valid    bool
	}{
		{"id1", "data/service_identity1.cert", true},
		{"id2", "data/service_identity2.cert", true},
		{"notfoud", "data/not_found.cert", false},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			_, err := FromFile(tt.certFile)
			if tt.valid != (err == nil) {
				test.Errorf("not expected response from processing test case: %s", tt.name)
			}
		})
	}
}

func TestIsExpiryAfterThreshold(t *testing.T) {
	rotationThreshold := float64(10)

	// expiry is after threshold
	rotateCert, err := IsExpiryAfterThreshold("data/service_identity1.cert", rotationThreshold)
	assert.Nil(t, err)
	assert.Equal(t, rotateCert, true)

	// expiry is before threshold
	rotateCert, err = IsExpiryAfterThreshold("data/service_identity2.cert", rotationThreshold)
	assert.Nil(t, err)
	assert.Equal(t, rotateCert, false)

	// invalid cert file
	rotateCert, err = IsExpiryAfterThreshold("data/not_found.cert", rotationThreshold)
	assert.NotNil(t, err)
	assert.Equal(t, rotateCert, false)
}
