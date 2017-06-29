// Copyright 2017 Oath Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
)

func (cli Zms) DeleteQuota(dn string) (*string, error) {
	err := cli.Zms.DeleteQuota(zms.DomainName(dn), cli.AuditRef)
	if err == nil {
		s := "[Removed quota for domain " + dn + "]"
		return &s, nil
	}
	return nil, err
}

func (cli Zms) GetQuota(dn string) (*string, error) {

	quota, err := cli.Zms.GetQuota(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	cli.dumpQuota(&buf, quota)
	s := buf.String()
	return &s, nil
}

func (cli Zms) SetQuota(dn string, attrs []string) (*string, error) {
	quota, err := cli.Zms.GetQuota(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		idx := strings.Index(attr, "=")
		if idx == -1 {
			continue
		}
		key := attr[0:idx]
		value, err := strconv.Atoi(attr[idx+1:])
		if err != nil {
			continue
		}
		switch key {
		case "role":
			quota.Role = int32(value)
		case "role-member":
			quota.RoleMember = int32(value)
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
		}
	}
	quota.Name = zms.DomainName(dn)
	err = cli.Zms.PutQuota(zms.DomainName(dn), cli.AuditRef, quota)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " quota successfully set]\n"
	return &s, nil
}
