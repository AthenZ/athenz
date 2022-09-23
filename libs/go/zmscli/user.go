// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"github.com/AthenZ/athenz/clients/go/zms"
)

func (cli Zms) ListUsers(domainName string) (*string, error) {
	users, err := cli.Zms.GetUserList(zms.DomainName(domainName))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		users, err := cli.Zms.GetUserList(zms.DomainName(domainName))
		if err != nil {
			return nil, err
		}
		buf.WriteString("users:\n")
		for _, item := range users.Names {
			buf.WriteString("    - " + string(item) + "\n")
		}
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(users, oldYamlConverter)
}

func (cli Zms) DeleteUser(user string) (*string, error) {
	err := cli.Zms.DeleteUser(zms.SimpleName(user), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted user: " + user + "]"

	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}
