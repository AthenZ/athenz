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

func getQuotaValue(value string) (int32, error) {
	val, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(val), nil
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

		value, err := getQuotaValue(attr[idx+1:])
		if err != nil {
			return nil, err
		}
		switch key {
		case "role":
			quota.Role = value
		case "role-member":
			quota.RoleMember = value
		case "group":
			quota.Group = value
		case "group-member":
			quota.GroupMember = value
		case "subdomain":
			quota.Subdomain = value
		case "policy":
			quota.Policy = value
		case "assertion":
			quota.Assertion = value
		case "service":
			quota.Service = value
		case "service-host":
			quota.ServiceHost = value
		case "public-key":
			quota.PublicKey = value
		case "entity":
			quota.Entity = value
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
