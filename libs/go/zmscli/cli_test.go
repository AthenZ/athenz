// Copyright 2017 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"testing"
)

func TestGetTimeStamp(t *testing.T) {
	data := "2017-03-02T15:04:00Z"
	value, err := getTimestamp(data)
	if err != nil {
		t.Error("could not parse timestamp:", err)
	} else {
		t.Log(value)
	}
}
