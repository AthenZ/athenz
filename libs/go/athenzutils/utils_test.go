// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import "testing"

func TestParseAthenzRoleName(test *testing.T) {

	tests := []struct {
		name     string
		roleName string
		domain   string
		role     string
	}{
		{"empty-string", "", "", ""},
		{"missing-comp", "athenz.role.readers", "", ""},
		{"start-comp", ":role.readers", "", ""},
		{"end-comp", "athenz:role.", "", ""},
		{"valid-top-level-domain", "athenz:role.readers", "athenz", "readers"},
		{"valid-sub-domain", "athenz.prod:role.readers", "athenz.prod", "readers"},
		{"single-letter-domain", "a:role.readers", "a", "readers"},
		{"single-letter-role", "athenz:role.a", "athenz", "a"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			domain, role, _ := ParseAthenzRoleName(tt.roleName)
			if domain != tt.domain && role != tt.role {
				test.Errorf("incorrect parsing of role: %s (%s/%s)", tt.roleName, tt.domain, tt.role)
			}
		})
	}
}

func TestParseGCPResourceName(test *testing.T) {

	tests := []struct {
		name       string
		resource   string
		objectType string
		projectId  string
		objectName string
	}{
		{"empty-string", "", "", "", ""},
		{"missing-comp", "projects/id1/roles", "roles", "", ""},
		{"invalid-project", "newproject/id1/roles/admin-role", "roles", "", ""},
		{"invalid-type", "projects/id1/roles/admin-role", "services", "", ""},
		{"valid-role", "projects/id1/roles/admin-role", "roles", "id1", "admin-role"},
		{"valid-services", "projects/id1/services/api", "services", "id1", "api"},
	}
	for _, tt := range tests {
		test.Run(tt.name, func(t *testing.T) {
			projectId, objectName, _ := ParseGCPResourceName(tt.resource, tt.objectType)
			if projectId != tt.projectId && objectName != tt.objectName {
				test.Errorf("incorrect parsing of resources: %s type: %s (%s/%s)", tt.resource, tt.objectType, tt.projectId, tt.objectName)
			}
		})
	}
}
