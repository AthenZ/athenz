// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmssvctoken

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const longBase64Input = `
Lorem ipsum dolor sit amet, consectetur adipiscing elit. 
Vestibulum vehicula, orci at efficitur pulvinar, nibh tortor facilisis ligula, 
ut commodo nisi nisl commodo turpis. Vestibulum eget tortor quis massa 
bibendum luctus id sed eros. Proin rhoncus elementum ipsum, vel imperdiet 
sem congue sit amet. Sed gravida, ipsum quis suscipit dapibus, sem ante 
fermentum eros, non porta est nisl quis tortor. Vestibulum ante ipsum 
primis in faucibus orci luctus et ultrices posuere cubilia Curae; Curabitur 
semper est et iaculis auctor. Donec eget mauris vitae massa tempus pharetra 
eget sed lacus. Proin id tortor mi. Mauris efficitur eu ex sit amet venenatis. 
Cras consectetur volutpat urna quis viverra. Fusce efficitur lectus eu dolor 
sodales interdum. Cras sit amet sem ac ligula aliquet auctor sit amet non 
justo. Sed nec vestibulum libero.
`

func testReplay(t *testing.T, input []byte) {
	a := assert.New(t)
	var lb64 YBase64
	s := lb64.EncodeToString(input)
	b, err := lb64.DecodeString(s)
	require.Nil(t, err)
	a.Equal(input, b)
}

func TestLongBase64Input(t *testing.T) {
	testReplay(t, []byte(longBase64Input))
}

func TestEdgeChars(t *testing.T) {
	a := assert.New(t)
	input := []byte{0x3f << 2, 0x00, 0x00, 0x3e << 2}
	testReplay(t, []byte(input))
	var lb64 YBase64
	a.Equal("/AAA+A==", base64.StdEncoding.EncodeToString(input))
	a.Equal("_AAA.A--", lb64.EncodeToString(input))
}

func TestBadPadding(t *testing.T) {
	a := assert.New(t)
	var lb64 YBase64
	s := lb64.EncodeToString([]byte("goobledegooks"))
	s = s + "--"
	_, err := lb64.DecodeString(s)
	require.NotNil(t, err)
	a.Contains(err.Error(), "illegal base64 data")
}
