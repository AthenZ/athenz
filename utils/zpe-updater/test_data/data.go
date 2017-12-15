// Copyright 2017 Yahoo Holdings, Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

// Package test_data contains test data packed as Go files.
package test_data

var EndPoints = map[string]string{
	"/zts/v1/domain/test/signed_policy_data":         Domain1Policies,
	"/zts/v1/domain/test_expired/signed_policy_data": Domain2Policies,
}

var MetricEndPoints = []string{"/zts/v1/metrics/test", "/zts/v1/metrics/test1"}
