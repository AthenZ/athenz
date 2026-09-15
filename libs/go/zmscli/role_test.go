// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AthenZ/athenz/clients/go/zms"
)

func TestProviderRoleName(t *testing.T) {

	// standard provider/resource group test cases

	rn := providerRoleName("coretech.storage", "articles", "read")
	if rn != "coretech.storage.res_group.articles.read" {
		t.Error("rolename coretech.storage/articles/read failed")
	}

	rn = providerRoleName("coretech.athenz.storage", "articles.docs", "read")
	if rn != "coretech.athenz.storage.res_group.articles.docs.read" {
		t.Error("rolename coretech.athenz.storage/articles.docs/read failed")
	}

	rn = providerRoleName("coretech-athenz.storage", "articles", "read")
	if rn != "coretech-athenz.storage.res_group.articles.read" {
		t.Error("rolename coretech-athenz.storage/articles/read failed")
	}
}

func TestDeleteRoles(t *testing.T) {
	transport := &deleteRequestTransport{
		t:             t,
		path:          "/domain/domain1/roles/role1,role2",
		auditRef:      "audit",
		resourceOwner: "owner",
	}

	cli := Zms{
		AuditRef:      "audit",
		ResourceOwner: "owner",
		OutputFormat:  DefaultOutputFormat,
		Zms:           zms.NewClient("http://zms", transport),
	}

	output, err := cli.DeleteRoles("domain1", []string{"role1", "role2"})
	if err != nil {
		t.Fatal(err)
	}
	transport.assertCalled()
	if *output != "[Deleted roles: role1, role2]" {
		t.Errorf("unexpected output: %s", *output)
	}
}

func TestDeleteRolesChunks(t *testing.T) {
	roleNames := make([]string, zms.BulkDeleteChunkSize+1)
	for idx := range roleNames {
		roleNames[idx] = fmt.Sprintf("role%d", idx)
	}

	transport := &deleteRequestTransport{
		t: t,
		paths: []string{
			"/domain/domain1/roles/" + strings.Join(roleNames[:zms.BulkDeleteChunkSize], ","),
			"/domain/domain1/roles/" + roleNames[zms.BulkDeleteChunkSize],
		},
		auditRef:      "audit",
		resourceOwner: "owner",
	}

	cli := Zms{
		AuditRef:      "audit",
		ResourceOwner: "owner",
		OutputFormat:  DefaultOutputFormat,
		Zms:           zms.NewClient("http://zms", transport),
	}

	if _, err := cli.DeleteRoles("domain1", roleNames); err != nil {
		t.Fatal(err)
	}
	transport.assertCalled()
}

func TestDeleteRolesAdmin(t *testing.T) {
	cli := Zms{}
	_, err := cli.DeleteRoles("domain1", []string{"role1", "admin"})
	if err == nil {
		t.Fatal("expected admin role error")
	}
	if err.Error() != "cannot delete 'admin' role" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDeleteRolesEmptyList(t *testing.T) {
	cli := Zms{}
	_, err := cli.DeleteRoles("domain1", []string{})
	if err == nil {
		t.Fatal("expected empty role names error")
	}
	if err.Error() != "no role names specified" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDeleteRolesOversizedName(t *testing.T) {
	cli := Zms{}
	_, err := cli.DeleteRoles("domain1", []string{strings.Repeat("a", zms.BulkDeleteMaxPathParamLength+1)})
	if err == nil {
		t.Fatal("expected oversized role name error")
	}
	if err.Error() != "role name exceeds maximum path parameter length" {
		t.Errorf("unexpected error: %v", err)
	}
}
