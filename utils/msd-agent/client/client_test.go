// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package client

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestMsdClientGotError(t *testing.T) {
	domain := "someDomain"
	service := "someService"
	clientMock := mockMsdClient(t, domain, service, fmt.Errorf("msd error"))
	res := clientMock.PutWorkload(domain, service, nil)
	assert.NotNilf(t, res, "should get error here")
	assert.Equal(t, res.Error(), "msd error")
}

func TestMsdClientNoError(t *testing.T) {
	domain := "someDomain"
	service := "someService"
	clientMock := mockMsdClient(t, domain, service, nil)
	res := clientMock.PutWorkload(domain, service, nil)
	assert.Nilf(t, res, "should not get error here")
}

func mockMsdClient(t *testing.T, domain string, service string, result error) *MockMsdClient {
	mockCtrl := gomock.NewController(t)
	clientMock := NewMockMsdClient(mockCtrl)
	clientMock.EXPECT().PutWorkload(domain, service, nil).Return(result)
	return clientMock
}
