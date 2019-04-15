// Copyright 2017 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"

	"github.com/yahoo/athenz/clients/go/zms"
)

func (cli Zms) ListUsers() (*string, error) {
	var buf bytes.Buffer
	users, err := cli.Zms.GetUserList()
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

func (cli Zms) DeleteUser(user string) (*string, error) {
	err := cli.Zms.DeleteUser(zms.SimpleName(user), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted user: " + user + "]"
	return &s, nil
}
