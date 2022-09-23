// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"testing"
	"time"
)

func TestFetchIdTokenExpiryTime(test *testing.T) {

	idToken := "eyJraWQiOiJ6dHMucnNhLmRldi4wIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ1c2VyLmpvaG4iLCJpYXQiOjE2NDM1NzU4NTAsImV4cCI6MTY0MzU3OTQ1MCwiaXNzIjoiaHR0cHM6Ly9hdGhlbnouaW8venRzL3YxIiwiYXVkIjoiYXRoZW56Lm9pZGMiLCJhdXRoX3RpbWUiOjE2NDM1NzU4NTAsInZlciI6MSwiZ3JvdXBzIjpbImVrcy1jbHVzdGVyLWFkbWlucyJdLCJub25jZSI6IjM0MTJhc2RmMyJ9Cg.CR6o_-F4GUH4IyY9aNygvYQmWM7"
	expiryTime, err := FetchIdTokenExpiryTime(idToken)
	if err != nil {
		test.Errorf("received an error when extracting expiry time: %v", err)
	}
	if *expiryTime != time.Unix(1643579450, 0) {
		test.Errorf("did not receive expected expiry time: %v", *expiryTime)
	}
}

func TestGetK8SClientAuthCredential(test *testing.T) {
	idToken := "eyJraWQiOiJ6dHMucnNhLmRldi4wIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ1c2VyLmpvaG4iLCJpYXQiOjE2NDM1NzU4NTAsImV4cCI6MTY0MzU3OTQ1MCwiaXNzIjoiaHR0cHM6Ly9hdGhlbnouaW8venRzL3YxIiwiYXVkIjoiYXRoZW56Lm9pZGMiLCJhdXRoX3RpbWUiOjE2NDM1NzU4NTAsInZlciI6MSwiZ3JvdXBzIjpbImVrcy1jbHVzdGVyLWFkbWlucyJdLCJub25jZSI6IjM0MTJhc2RmMyJ9Cg.CR6o_-F4GUH4IyY9aNygvYQmWM7"
	output, err := GetK8SClientAuthCredential(idToken)
	if err != nil {
		test.Errorf("received an error when extracting output: %v", err)
	}
	if output != "{\"kind\":\"ExecCredential\",\"apiVersion\":\"client.authentication.k8s.io/v1\",\"spec\":{\"interactive\":false},\"status\":{\"expirationTimestamp\":\"2022-01-30T21:50:50Z\",\"token\":\"eyJraWQiOiJ6dHMucnNhLmRldi4wIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ1c2VyLmpvaG4iLCJpYXQiOjE2NDM1NzU4NTAsImV4cCI6MTY0MzU3OTQ1MCwiaXNzIjoiaHR0cHM6Ly9hdGhlbnouaW8venRzL3YxIiwiYXVkIjoiYXRoZW56Lm9pZGMiLCJhdXRoX3RpbWUiOjE2NDM1NzU4NTAsInZlciI6MSwiZ3JvdXBzIjpbImVrcy1jbHVzdGVyLWFkbWlucyJdLCJub25jZSI6IjM0MTJhc2RmMyJ9Cg.CR6o_-F4GUH4IyY9aNygvYQmWM7\"}}" {
		test.Errorf("did not receive expected output: %v", output)
	}
}
