// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import "github.com/AthenZ/athenz/clients/go/zms"

func (cli Zms) GetRolesForReview(principal string) (*string, error) {
	reviewObjects, err := cli.Zms.GetRolesForReview(zms.ResourceName(principal))
	if err != nil {
		return nil, err
	}

	return cli.dumpByFormat(reviewObjects, cli.buildYAMLOutput)
}

func (cli Zms) GetGroupsForReview(principal string) (*string, error) {
	reviewObjects, err := cli.Zms.GetGroupsForReview(zms.ResourceName(principal))
	if err != nil {
		return nil, err
	}

	return cli.dumpByFormat(reviewObjects, cli.buildYAMLOutput)
}
