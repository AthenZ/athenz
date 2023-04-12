// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package athenzutils

import (
	"fmt"
	"strings"
)

const athenzRoleComponent = ":role."
const gcpProjectComponent = "projects"

func ParseAthenzRoleName(roleName string) (string, string, error) {
	// expected format is <domain-name>:role.<role-name>
	idx := strings.Index(roleName, athenzRoleComponent)
	if idx == -1 || idx == 0 || idx == len(roleName)-len(athenzRoleComponent) {
		return "", "", fmt.Errorf("rolename %s does not have expected <domain>:role.<role> format", roleName)
	}
	return roleName[:idx], roleName[idx+len(athenzRoleComponent):], nil
}

func ParseGCPResourceName(resource, objectType string) (string, string, error) {
	// expected format is projects/<project-id>/<type: roles|services/<type-name>
	comps := strings.Split(resource, "/")
	if len(comps) < 4 {
		return "", "", fmt.Errorf("resource %s does not have expected number of components", resource)
	}
	if comps[0] != gcpProjectComponent || comps[2] != objectType {
		return "", "", fmt.Errorf("resource %s does not have the expected format for object-type %s", resource, objectType)
	}
	return comps[1], comps[3], nil
}
