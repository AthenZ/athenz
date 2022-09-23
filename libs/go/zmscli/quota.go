// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zms"
)

func (cli Zms) DeleteQuota(dn string) (*string, error) {
	err := cli.Zms.DeleteQuota(zms.DomainName(dn), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Removed quota for domain " + dn + "]"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) GetQuota(dn string) (*string, error) {
	quota, err := cli.Zms.GetQuota(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		cli.dumpQuota(&buf, quota)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(quota, oldYamlConverter)
}

func (cli Zms) SetQuota(dn string, attrs []string) (*string, error) {
	quota, err := cli.Zms.GetQuota(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		idx := strings.Index(attr, "=")
		if idx == -1 {
			return nil, fmt.Errorf("bad quota syntax: zms-cli help set-quota")
		}
		key := attr[0:idx]
		value, err := strconv.Atoi(attr[idx+1:])
		if err != nil {
			return nil, fmt.Errorf("bad quota syntax: zms-cli help set-quota")
		}
		switch key {
		case "role":
			quota.Role = int32(value)
		case "role-member":
			quota.RoleMember = int32(value)
		case "group":
			quota.Group = int32(value)
		case "group-member":
			quota.GroupMember = int32(value)
		case "subdomain":
			quota.Subdomain = int32(value)
		case "policy":
			quota.Policy = int32(value)
		case "assertion":
			quota.Assertion = int32(value)
		case "service":
			quota.Service = int32(value)
		case "service-host":
			quota.ServiceHost = int32(value)
		case "public-key":
			quota.PublicKey = int32(value)
		case "entity":
			quota.Entity = int32(value)
		default:
			return nil, fmt.Errorf("bad quota syntax: zms-cli help set-quota")
		}
	}
	quota.Name = zms.DomainName(dn)
	err = cli.Zms.PutQuota(zms.DomainName(dn), cli.AuditRef, quota)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " quota successfully set]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}
