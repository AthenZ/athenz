// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zms"
	"github.com/ardielle/ardielle-go/rdl"
	"log"
	"strings"
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
	roles, err := cli.roleNames(dn)
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("roles:\n")
		cli.dumpObjectList(&buf, roles, dn, "role")
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(roles, oldYamlConverter)
}

func (cli Zms) ShowRole(dn string, rn string, auditLog, expand bool, pending bool) (*string, error) {
	var roleAuditLog *bool
	if auditLog {
		roleAuditLog = &auditLog
	} else {
		roleAuditLog = nil
	}
	var roleExpand *bool
	if expand {
		roleExpand = &expand
	} else {
		roleExpand = nil
	}

	var pend *bool
	if pending {
		pend = &pending
	} else {
		pend = nil
	}
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), roleAuditLog, roleExpand, pend)
	if err != nil {
		return nil, err
	}
	return cli.ShowUpdatedRole(role, auditLog)
}

func (cli Zms) ShowUpdatedRole(role *zms.Role, auditLog bool) (*string, error) {
	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("role:\n")
		cli.dumpRole(&buf, *role, auditLog, indentLevel1Dash, indentLevel1DashLvl)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(role, oldYamlConverter)
}

func (cli Zms) AddDelegatedRole(dn string, rn string, trusted string) (*string, error) {
	fullResourceName := dn + ":role." + rn
	if !cli.Overwrite {
		_, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
		if err == nil {
			return nil, fmt.Errorf("role already exists: %v", fullResourceName)
		}
		switch v := err.(type) {
		case rdl.ResourceError:
			if v.Code != 404 {
				return nil, v
			}
		}
	}
	if rn == "admin" {
		return nil, fmt.Errorf("cannot replace reserved 'admin' role")
	}
	var role zms.Role
	role.Name = zms.ResourceName(fullResourceName)
	role.Trust = zms.DomainName(trusted)
	returnObject := true
	updatedRole, err := cli.Zms.PutRole(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, &returnObject, cli.ResourceOwner, &role)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowUpdatedRole(updatedRole, false)
}

func (cli Zms) AddRegularRole(dn string, rn string, auditEnabled bool, roleMembers []*zms.RoleMember) (*string, error) {
	fullResourceName := dn + ":role." + rn
	var role zms.Role
	if !cli.Overwrite {
		_, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
		if err == nil {
			return nil, fmt.Errorf("role already exists: %v", fullResourceName)
		}
		switch v := err.(type) {
		case rdl.ResourceError:
			if v.Code != 404 {
				return nil, v
			}
		}
	}
	if rn == "admin" {
		return nil, fmt.Errorf("cannot replace reserved 'admin' role")
	}
	role.Name = zms.ResourceName(fullResourceName)
	if auditEnabled {
		role.AuditEnabled = &auditEnabled
	}
	role.RoleMembers = roleMembers
	cli.validateRoleMembers(role.RoleMembers)
	returnObject := true
	updatedRole, err := cli.Zms.PutRole(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, &returnObject, cli.ResourceOwner, &role)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowUpdatedRole(updatedRole, false)
}

func (cli Zms) DeleteRole(dn string, rn string) (*string, error) {
	if rn == "admin" {
		return nil, fmt.Errorf("cannot delete 'admin' role")
	}
	err := cli.Zms.DeleteRole(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner)
	if err != nil {
		return nil, err
	}
	s := "[Deleted role: " + rn + "]"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddProviderRoleMembers(dn string, provider string, group string, action string, members []string) (*string, error) {
	rn := providerRoleName(provider, group, action)
	return cli.AddMembers(dn, rn, members)
}

func (cli Zms) ShowProviderRoleMembers(dn string, provider string, group string, action string) (*string, error) {
	rn := providerRoleName(provider, group, action)
	return cli.ShowRole(dn, rn, false, false, false)
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
		member.MemberName = mbr.MemberName
		member.RoleName = zms.ResourceName(rn)
		member.Expiration = mbr.Expiration
		returnObject := false
		_, err := cli.Zms.PutMembership(zms.DomainName(dn), zms.EntityName(rn), mbr.MemberName, cli.AuditRef, &returnObject, cli.ResourceOwner, &member)
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
		returnObject := false
		_, err := cli.Zms.PutMembership(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(m), cli.AuditRef, &returnObject, cli.ResourceOwner, &member)
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

	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddDueDateMember(dn string, rn string, member string, expiration *rdl.Timestamp, reviewDate *rdl.Timestamp) (*string, error) {
	fullResourceName := dn + ":role." + rn
	validatedUser := cli.validatedUser(member)

	var memberShip zms.Membership
	memberShip.MemberName = zms.MemberName(validatedUser)
	memberShip.RoleName = zms.ResourceName(rn)
	if reviewDate != nil {
		memberShip.ReviewReminder = reviewDate
	}
	if expiration != nil {
		memberShip.Expiration = expiration
	}
	returnObject := false
	_, err := cli.Zms.PutMembership(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(validatedUser), cli.AuditRef, &returnObject, cli.ResourceOwner, &memberShip)
	if err != nil {
		return nil, err
	}
	var s string
	if cli.Verbose {
		s = "[Added to " + fullResourceName + ": " + validatedUser + "]"
	} else {
		s = "[Added to " + rn + ": " + validatedUser + "]"
	}
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) DeleteMembers(dn string, rn string, members []string) (*string, error) {
	fullResourceName := dn + ":role." + rn
	ms := cli.validatedUsers(members, false)
	for _, m := range ms {
		err := cli.Zms.DeleteMembership(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(m), cli.AuditRef, cli.ResourceOwner)
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

	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) CheckMembers(dn string, rn string, members []string) (*string, error) {
	ms := cli.validatedUsers(members, false)
	var membership []*zms.Membership
	for _, m := range ms {
		member, err := cli.Zms.GetMembership(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(m), "")
		if err != nil {
			return nil, err
		}
		membership = append(membership, member)
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		for _, m := range membership {
			cli.dumpRoleMembership(&buf, *m)
		}
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(membership, oldYamlConverter)
}

func (cli Zms) CheckActiveMember(dn string, rn string, mbr string) (*string, error) {
	member, err := cli.Zms.GetMembership(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(mbr), "")
	if err != nil {
		return nil, err
	}
	if !*member.IsMember || !*member.Approved || !*member.Active {
		return nil, errors.New("Member " + mbr + " is not active")
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		cli.dumpRoleMembership(&buf, *member)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(member, oldYamlConverter)
}

func (cli Zms) DeleteDomainRoleMember(dn, member string) (*string, error) {
	err := cli.Zms.DeleteDomainRoleMember(zms.DomainName(dn), zms.MemberName(member), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted member: " + member + "]"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) ListDomainRoleMembers(dn string) (*string, error) {
	roleMembers, err := cli.Zms.GetDomainRoleMembers(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("role members:\n")
		cli.dumpDomainRoleMembers(&buf, roleMembers, false)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(roleMembers, oldYamlConverter)
}

func (cli Zms) ShowRolesPrincipal(principal string, dn string, expand *bool) (*string, error) {
	domainRoleMember, err := cli.Zms.GetPrincipalRoles(zms.ResourceName(principal), zms.DomainName(dn), expand)
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		cli.dumpRolesPrincipal(&buf, domainRoleMember)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(domainRoleMember, oldYamlConverter)
}

func (cli Zms) SetRoleAuditEnabled(dn string, rn string, auditEnabled bool) (*string, error) {
	// first we're going to try as system admin
	meta := zms.RoleSystemMeta{
		AuditEnabled: &auditEnabled,
	}
	err := cli.Zms.PutRoleSystemMeta(zms.DomainName(dn), zms.EntityName(rn), "auditenabled", cli.AuditRef, &meta)
	if err != nil {
		// if fails, we're going to try as regular domain admin
		role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
		if err != nil {
			return nil, err
		}
		meta := getRoleMetaObject(role)
		meta.AuditEnabled = &auditEnabled
		err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
		if err != nil {
			return nil, err
		}
	}
	s := "[domain " + dn + " role " + rn + " audit-enabled successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleReviewEnabled(dn string, rn string, reviewEnabled bool) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.ReviewEnabled = &reviewEnabled

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " review-enabled attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleDeleteProtection(dn string, rn string, deleteProtection bool) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.DeleteProtection = &deleteProtection

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " delete-protection attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func getRoleMetaObject(role *zms.Role) zms.RoleMeta {
	return zms.RoleMeta{
		MemberExpiryDays:        role.MemberExpiryDays,
		TokenExpiryMins:         role.TokenExpiryMins,
		SelfServe:               role.SelfServe,
		CertExpiryMins:          role.CertExpiryMins,
		SignAlgorithm:           role.SignAlgorithm,
		ReviewEnabled:           role.ReviewEnabled,
		AuditEnabled:            role.AuditEnabled,
		DeleteProtection:        role.DeleteProtection,
		NotifyRoles:             role.NotifyRoles,
		ServiceExpiryDays:       role.ServiceExpiryDays,
		GroupExpiryDays:         role.GroupExpiryDays,
		MemberReviewDays:        role.MemberReviewDays,
		ServiceReviewDays:       role.ServiceReviewDays,
		UserAuthorityExpiration: role.UserAuthorityExpiration,
		UserAuthorityFilter:     role.UserAuthorityFilter,
		Tags:                    role.Tags,
		MaxMembers:              role.MaxMembers,
		SelfRenew:               role.SelfRenew,
		SelfRenewMins:           role.SelfRenewMins,
	}
}

func (cli Zms) SetRoleSelfRenew(dn string, rn string, selfRenew bool) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.SelfRenew = &selfRenew

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " role-self-renew attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleSelfRenewMins(dn string, rn string, selfRenewMins int32) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.SelfRenewMins = &selfRenewMins

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " role-self-renew-mins attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleSelfServe(dn string, rn string, selfServe bool) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.SelfServe = &selfServe

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " self-serve attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleUserAuthorityFilter(dn string, rn, filter string) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.UserAuthorityFilter = filter

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " user-authority-filter attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleUserAuthorityExpiration(dn string, rn, filter string) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.UserAuthorityExpiration = filter

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " user-authority-expiration attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddRoleTags(dn string, rn, tagKey string, tagValues []string) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)

	tagValueArr := make([]zms.TagCompoundValue, 0)

	if meta.Tags == nil {
		meta.Tags = map[zms.TagKey]*zms.TagValueList{}
	} else {
		// append current tags
		currentTagValues := meta.Tags[zms.TagKey(tagKey)]
		if currentTagValues != nil {
			tagValueArr = append(tagValueArr, currentTagValues.List...)
		}
	}

	for _, tagValue := range tagValues {
		tagValueArr = append(tagValueArr, zms.TagCompoundValue(tagValue))
	}

	meta.Tags[zms.TagKey(tagKey)] = &zms.TagValueList{List: tagValueArr}

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " tags successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) DeleteRoleTags(dn string, rn, tagKey string, tagValue string) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)

	tagValueArr := make([]zms.TagCompoundValue, 0)

	if meta.Tags == nil {
		meta.Tags = map[zms.TagKey]*zms.TagValueList{}
	}

	// except given tagValue, set the same tags map
	if tagValue != "" && meta.Tags != nil {
		currentTagValues := meta.Tags[zms.TagKey(tagKey)]
		if currentTagValues != nil {
			for _, curTagValue := range currentTagValues.List {
				if tagValue != string(curTagValue) {
					tagValueArr = append(tagValueArr, curTagValue)
				}
			}
		}
	}

	meta.Tags[zms.TagKey(tagKey)] = &zms.TagValueList{List: tagValueArr}

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " tags successfully deleted]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) ShowRoles(dn string, tagKey string, tagValue string) (*string, error) {
	if cli.OutputFormat == JSONOutputFormat || cli.OutputFormat == YAMLOutputFormat {
		members := true
		roles, err := cli.Zms.GetRoles(zms.DomainName(dn), &members, zms.TagKey(tagKey), zms.TagCompoundValue(tagValue))
		if err != nil {
			log.Fatalf("Unable to get role list - error: %v", err)
		}
		return cli.dumpByFormat(roles, cli.buildYAMLOutput)
	} else {
		var buf bytes.Buffer
		cli.dumpRoles(&buf, dn, tagKey, tagValue)
		s := buf.String()
		return &s, nil
	}
}

func (cli Zms) SetRoleMemberExpiryDays(dn string, rn string, days int32) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.MemberExpiryDays = &days

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " member-expiry-days attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleServiceExpiryDays(dn string, rn string, days int32) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.ServiceExpiryDays = &days

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " service-expiry-days attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleGroupExpiryDays(dn string, rn string, days int32) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.GroupExpiryDays = &days

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " group-expiry-days attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleMemberReviewDays(dn string, rn string, days int32) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.MemberReviewDays = &days

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " member-review-days attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleServiceReviewDays(dn string, rn string, days int32) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.ServiceReviewDays = &days

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " service-review-days attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleGroupReviewDays(dn string, rn string, days int32) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.GroupReviewDays = &days

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " group-review-days attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleTokenExpiryMins(dn string, rn string, mins int32) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.TokenExpiryMins = &mins

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " token-expiry-mins attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleMaxMembers(dn string, rn string, maxMembers int32) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.MaxMembers = &maxMembers

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " role-max-members attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleCertExpiryMins(dn string, rn string, mins int32) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.CertExpiryMins = &mins

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " role-cert-expiry-mins attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleTokenSignAlgorithm(dn string, rn string, alg string) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.SignAlgorithm = alg

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " role-token-sign-algorithm attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleDescription(dn string, rn string, description string) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.Description = description

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " description attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetRoleNotifyRoles(dn string, rn string, notifyRoles string) (*string, error) {
	role, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getRoleMetaObject(role)
	meta.NotifyRoles = notifyRoles

	err = cli.Zms.PutRoleMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " notify-roles attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) PutTempMembershipDecision(dn string, rn string, mbr string, expiration rdl.Timestamp, approval bool) (*string, error) {
	validatedUser := cli.validatedUser(mbr)
	var member zms.Membership
	member.MemberName = zms.MemberName(validatedUser)
	member.RoleName = zms.ResourceName(rn)
	member.Expiration = &expiration
	member.Active = &approval
	err := cli.Zms.PutMembershipDecision(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(validatedUser), cli.AuditRef, &member)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " member " + mbr + " successfully"
	if approval == true {
		s = s + " approved temporarily."
	} else {
		s = s + " rejected."
	}
	s = s + "]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) PutMembershipDecision(dn string, rn string, mbr string, approval bool) (*string, error) {
	validatedUser := cli.validatedUser(mbr)
	var member zms.Membership
	member.MemberName = zms.MemberName(validatedUser)
	member.RoleName = zms.ResourceName(rn)
	member.Approved = &approval
	err := cli.Zms.PutMembershipDecision(zms.DomainName(dn), zms.EntityName(rn), zms.MemberName(validatedUser), cli.AuditRef, &member)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " role " + rn + " member " + mbr + " successfully"
	if approval == true {
		s = s + " approved."
	} else {
		s = s + " rejected."
	}
	s = s + "]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}
