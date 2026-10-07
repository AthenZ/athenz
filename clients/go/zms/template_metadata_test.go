// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zms

import (
	"encoding/json"
	"testing"
)

func TestPreserveAdminAccessRoundTrip(t *testing.T) {
	for _, input := range []string{"{}", `{"preserveAdminAccess":false}`, `{"preserveAdminAccess":true}`} {
		t.Run(input, func(t *testing.T) {
			var metadata TemplateMetaData
			if err := json.Unmarshal([]byte(input), &metadata); err != nil {
				t.Fatal(err)
			}
			if (metadata.PreserveAdminAccess == nil) != (input == "{}") {
				t.Fatal("omitted preservation setting must remain distinct from false")
			}
			output, err := json.Marshal(&metadata)
			if err != nil {
				t.Fatal(err)
			}
			var expected, actual map[string]json.RawMessage
			if err := json.Unmarshal([]byte(input), &expected); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(output, &actual); err != nil {
				t.Fatal(err)
			}
			if string(actual["preserveAdminAccess"]) != string(expected["preserveAdminAccess"]) {
				t.Fatalf("preserveAdminAccess changed during round trip: %s", output)
			}
		})
	}
}
