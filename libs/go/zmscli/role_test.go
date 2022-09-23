// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"testing"
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
