// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

func (cli Zms) GetRolesForReview(principal string) (*string, error) {
	reviewObjects, err := cli.GetRolesForReview(principal)
	if err != nil {
		return nil, err
	}

	return cli.dumpByFormat(reviewObjects, cli.buildYAMLOutput)
}

func (cli Zms) GetGroupsForReview(principal string) (*string, error) {
	reviewObjects, err := cli.GetGroupsForReview(principal)
	if err != nil {
		return nil, err
	}

	return cli.dumpByFormat(reviewObjects, cli.buildYAMLOutput)
}
