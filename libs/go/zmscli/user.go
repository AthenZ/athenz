// Copyright 2017 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"

	"github.com/AthenZ/athenz/clients/go/zms"
)

func (cli Zms) ListUsers(domainName string) (*string, error) {
	var buf bytes.Buffer
	users, err := cli.Zms.GetUserList(zms.DomainName(domainName))
	if err != nil {
		return nil, err
	}
	buf.WriteString("users:\n")
	for _, item := range users.Names {
		buf.WriteString("    - " + string(item) + "\n")
	}
	return cli.switchOverFormats(users, buf.String())
}

func (cli Zms) DeleteUser(user string) (*string, error) {
	err := cli.Zms.DeleteUser(zms.SimpleName(user), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted user: " + user + "]"
	return cli.switchOverFormats(s)
}
