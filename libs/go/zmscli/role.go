// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/yahoo/athenz/clients/go/zms"
)

func providerRoleName(provider, group, action string) string {
	// generate provider role group
	return provider + ".res_group." + group + "." + action
}

func (cli Zms) roleNames(dn string) ([]string, error) {
	roles := make([]string, 0)
	lst, err := cli.Zms.GetRoleList(zms.DomainName(dn), nil, "")
	if err != nil {
		return nil, err
	}
	for _, n := range lst.Names {
		roles = append(roles, string(n))
	}
	return roles, nil
}

func (cli Zms) ListRoles(dn string) (*string, error) {
	var buf bytes.Buffer
	roles, err := cli.roleNames(dn)
	if err != nil {
		return nil, err
	}
	buf.WriteString("roles:\n")
	cli.dumpObjectList(&buf, roles, dn, "role")
	s := buf.String()
	return &s, nil
}

func (cli Zms) ShowRole(dn string, rn string, auditLog, expand bool) (*string, error) {
	var log *bool
	if auditLog {
		log = &auditLog
	} else {
		log = nil
	}
	var expnd *bool
	if expand {
		expnd = &expand
	} else {
		expnd = nil
	}
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), log, expnd)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("role:\n")
	cli.dumpRole(&buf, *role, auditLog, indent_level1_dash, indent_level1_dash_lvl)
	s := buf.String()
	return &s, nil
}

func (cli Zms) AddDelegatedRole(dn string, rn string, trusted string) (*string, error) {
	fullResourceName := dn + ":role." + rn
	_, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil)
	if err == nil {
		return nil, fmt.Errorf("Role already exists: %v", fullResourceName)
	}
	switch v := err.(type) {
	case rdl.ResourceError:
		if v.Code != 404 {
			return nil, v
		}
	}
	if rn == "admin" {
		return nil, fmt.Errorf("Cannot replace reserved 'admin' role")
	}
	var role zms.Role
	role.Name = zms.ResourceName(fullResourceName)
	role.Trust = zms.DomainName(trusted)
	err = cli.Zms.PutRole(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, &role)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowRole(dn, rn, false, false)
}

func (cli Zms) AddGroupRole(dn string, rn string, roleMembers []*zms.RoleMember) (*string, error) {
	fullResourceName := dn + ":role." + rn
	var role zms.Role
	_, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil)
	if err == nil {
		return nil, fmt.Errorf("Role already exists: %v", fullResourceName)
	}
	switch v := err.(type) {
	case rdl.ResourceError:
		if v.Code != 404 {
			return nil, v
		}
	}
	if rn == "admin" {
		return nil, fmt.Errorf("Cannot replace reserved 'admin' role")
	}
	role.Name = zms.ResourceName(fullResourceName)
	role.RoleMembers = roleMembers
	cli.validateRoleMembers(role.RoleMembers)
	err = cli.Zms.PutRole(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, &role)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowRole(dn, rn, false, false)
}

func (cli Zms) DeleteRole(dn string, rn string) (*string, error) {
	if rn == "admin" {
		return nil, fmt.Errorf("Cannot delete 'admin' role")
	}
	err := cli.Zms.DeleteRole(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted role: " + rn + "]"
	return &s, nil
}

func (cli Zms) AddProviderRoleMembers(dn string, provider string, group string, action string, members []string) (*string, error) {
	rn := providerRoleName(provider, group, action)
	return cli.AddMembers(dn, rn, members)
}

func (cli Zms) ShowProviderRoleMembers(dn string, provider string, group string, action string) (*string, error) {
	rn := providerRoleName(provider, group, action)
	return cli.ShowRole(dn, rn, false, false)
}

func (cli Zms) DeleteProviderRoleMembers(dn string, provider string, group string, action string, members []string) (*string, error) {
	rn := providerRoleName(provider, group, action)
	return cli.DeleteMembers(dn, rn, members)
}

func (cli Zms) AddRoleMembers(dn string, rn string, members []*zms.RoleMember) (*string, error) {
	fullResourceName := dn + ":role." + rn
	cli.validateRoleMembers(members)
	var outputLine string
	for idx, mbr := range members {
		var member zms.Membership
		member.MemberName = zms.MemberName(mbr.MemberName)
		member.RoleName = zms.ResourceName(rn)
		member.Expiration = mbr.Expiration
		err := cli.Zms.PutMembership(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(mbr.MemberName), cli.AuditRef, &member)
		if err != nil {
			return nil, err
		}
		if idx != 0 {
			outputLine = ","
		}
		outputLine = outputLine + string(member.MemberName)
	}
	var s string
	if cli.Verbose {
		s = "[Added to " + fullResourceName + ": " + outputLine + "]"
	} else {
		s = "[Added to " + rn + ": " + outputLine + "]"
	}
	return &s, nil
}

func (cli Zms) AddMembers(dn string, rn string, members []string) (*string, error) {
	fullResourceName := dn + ":role." + rn
	ms := cli.validatedUsers(members, false)
	for _, m := range ms {
		var member zms.Membership
		member.MemberName = zms.MemberName(m)
		member.RoleName = zms.ResourceName(rn)
		err := cli.Zms.PutMembership(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(m), cli.AuditRef, &member)
		if err != nil {
			return nil, err
		}
	}
	var s string
	if cli.Verbose {
		s = "[Added to " + fullResourceName + ": " + strings.Join(ms, ",") + "]"
	} else {
		s = "[Added to " + rn + ": " + strings.Join(ms, ",") + "]"
	}
	return &s, nil
}

func (cli Zms) AddTemporaryMember(dn string, rn string, member string, expiration rdl.Timestamp) (*string, error) {
	fullResourceName := dn + ":role." + rn
	validatedUser := cli.validatedUser(member)

	var memberShip zms.Membership
	memberShip.MemberName = zms.MemberName(validatedUser)
	memberShip.RoleName = zms.ResourceName(rn)
	memberShip.Expiration = &expiration
	err := cli.Zms.PutMembership(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(validatedUser), cli.AuditRef, &memberShip)
	if err != nil {
		return nil, err
	}
	var s string
	if cli.Verbose {
		s = "[Added to " + fullResourceName + ": " + validatedUser + "]"
	} else {
		s = "[Added to " + rn + ": " + validatedUser + "]"
	}
	return &s, nil
}

func (cli Zms) DeleteMembers(dn string, rn string, members []string) (*string, error) {
	fullResourceName := dn + ":role." + rn
	ms := cli.validatedUsers(members, false)
	for _, m := range ms {
		err := cli.Zms.DeleteMembership(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(m), cli.AuditRef)
		if err != nil {
			return nil, err
		}
	}
	var s string
	if cli.Verbose {
		s = "[Deleted from " + fullResourceName + ": " + strings.Join(ms, ",") + "]"
	} else {
		s = "[Deleted from " + rn + ": " + strings.Join(ms, ",") + "]"
	}
	return &s, nil
}

func (cli Zms) CheckMembers(dn string, rn string, members []string) (*string, error) {
	var buf bytes.Buffer
	ms := cli.validatedUsers(members, false)
	for _, m := range ms {
		member, err := cli.Zms.GetMembership(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(m))
		cli.dumpRoleMembership(&buf, *member)
		if err != nil {
			return nil, err
		}
	}
	s := buf.String()
	return &s, nil
}

func (cli Zms) DeleteDomainRoleMember(dn, member string) (*string, error) {
	err := cli.Zms.DeleteDomainRoleMember(zms.DomainName(dn), zms.MemberName(member), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted member: " + member + "]"
	return &s, nil
}

func (cli Zms) ListDomainRoleMembers(dn string) (*string, error) {
	var buf bytes.Buffer
	roleMembers, err := cli.Zms.GetDomainRoleMembers(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	buf.WriteString("role members:\n")
	cli.dumpDomainRoleMembers(&buf, roleMembers)
	s := buf.String()
	return &s, nil
}
