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

func (cli Zms) groupNames(dn string) ([]string, error) {
	groups := make([]string, 0)
	members := false
	lst, err := cli.Zms.GetGroups(zms.DomainName(dn), &members, "", "")
	if err != nil {
		return nil, err
	}
	for _, n := range lst.List {
		groups = append(groups, localName(string(n.Name), ":group."))
	}
	return groups, nil
}

func (cli Zms) ListGroups(dn string) (*string, error) {
	groups, err := cli.groupNames(dn)
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("groups:\n")
		cli.dumpObjectList(&buf, groups, dn, "group")
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(groups, oldYamlConverter)
}

func (cli Zms) ShowGroup(dn string, gn string, auditLog, pending bool) (*zms.Group, *string, error) {
	var groupAuditLog *bool
	if auditLog {
		groupAuditLog = &auditLog
	} else {
		groupAuditLog = nil
	}
	var pend *bool
	if pending {
		pend = &pending
	} else {
		pend = nil
	}
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), groupAuditLog, pend)
	if err != nil {
		return nil, nil, err
	}

	output, err := cli.ShowUpdatedGroup(group, auditLog)
	return group, output, err
}

func (cli Zms) ShowUpdatedGroup(group *zms.Group, auditLog bool) (*string, error) {
	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("group:\n")
		cli.dumpGroup(&buf, *group, auditLog, indentLevel1Dash, indentLevel1DashLvl)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(group, oldYamlConverter)
}

func (cli Zms) SetGroupSelfRenew(dn string, gn string, selfRenew bool) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.SelfRenew = &selfRenew

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " group-self-renew attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetGroupSelfRenewMins(dn string, gn string, selfRenewMins int32) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.SelfRenewMins = &selfRenewMins

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " group-self-renew-mins attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetGroupMaxMembers(dn string, rn string, maxMembers int32) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(rn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.MaxMembers = &maxMembers

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + rn + " group-max-members attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetGroupMemberExpiryDays(dn string, rn string, days int32) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(rn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.MemberExpiryDays = &days

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + rn + " member-expiry-days attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetGroupServiceExpiryDays(dn string, rn string, days int32) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(rn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.ServiceExpiryDays = &days

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + rn + " service-expiry-days attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddGroup(dn string, gn string, auditEnabled bool, groupMembers []*zms.GroupMember) (*string, error) {
	fullResourceName := dn + ":group." + gn
	var group zms.Group
	if !cli.Overwrite {
		_, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
		if err == nil {
			return nil, fmt.Errorf("group already exists: %v", fullResourceName)
		}
		switch v := err.(type) {
		case rdl.ResourceError:
			if v.Code != 404 {
				return nil, v
			}
		}
	}
	group.Name = zms.ResourceName(fullResourceName)
	if auditEnabled {
		group.AuditEnabled = &auditEnabled
	}
	group.GroupMembers = groupMembers
	cli.validateGroupMembers(group.GroupMembers)
	returnObject := true
	updatedGroup, err := cli.Zms.PutGroup(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, &returnObject, cli.ResourceOwner, &group)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowUpdatedGroup(updatedGroup, false)
}

func (cli Zms) DeleteGroup(dn string, gn string) (*string, error) {
	err := cli.Zms.DeleteGroup(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner)
	if err != nil {
		return nil, err
	}
	s := "[Deleted group: " + gn + "]"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddGroupMembers(dn string, group string, members []string) (*string, error) {
	fullResourceName := dn + ":group." + group
	ms := cli.validatedUsers(members, false)
	for _, m := range ms {
		var member zms.GroupMembership
		member.MemberName = zms.GroupMemberName(m)
		member.GroupName = zms.ResourceName(group)
		returnObject := false
		_, err := cli.Zms.PutGroupMembership(zms.DomainName(dn), zms.EntityName(group), zms.GroupMemberName(m), cli.AuditRef, &returnObject, cli.ResourceOwner, &member)
		if err != nil {
			return nil, err
		}
	}
	var s string
	if cli.Verbose {
		s = "[Added to " + fullResourceName + ": " + strings.Join(ms, ",") + "]"
	} else {
		s = "[Added to " + group + ": " + strings.Join(ms, ",") + "]"
	}
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) DeleteGroupMembers(dn string, group string, members []string) (*string, error) {
	fullResourceName := dn + ":group." + group
	ms := cli.validatedUsers(members, false)
	for _, m := range ms {
		err := cli.Zms.DeleteGroupMembership(zms.DomainName(dn), zms.EntityName(group), zms.GroupMemberName(m), cli.AuditRef, cli.ResourceOwner)
		if err != nil {
			return nil, err
		}
	}
	var s string
	if cli.Verbose {
		s = "[Deleted from " + fullResourceName + ": " + strings.Join(ms, ",") + "]"
	} else {
		s = "[Deleted from " + group + ": " + strings.Join(ms, ",") + "]"
	}
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) CheckGroupMembers(dn string, group string, members []string) (*string, error) {
	ms := cli.validatedUsers(members, false)
	var groupMembership []*zms.GroupMembership
	for _, m := range ms {
		member, err := cli.Zms.GetGroupMembership(zms.DomainName(dn), zms.EntityName(group), zms.GroupMemberName(m), "")
		if err != nil {
			return nil, err
		}
		groupMembership = append(groupMembership, member)
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		for _, member := range groupMembership {
			cli.dumpGroupMembership(&buf, *member)
		}
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(groupMembership, oldYamlConverter)
}

func (cli Zms) CheckActiveGroupMember(dn string, group string, mbr string) (*string, error) {
	member, err := cli.Zms.GetGroupMembership(zms.DomainName(dn), zms.EntityName(group), zms.GroupMemberName(mbr), "")
	if err != nil {
		return nil, err
	}
	if !*member.IsMember || !*member.Approved || !*member.Active {
		return nil, errors.New("Member " + mbr + " is not active")
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		cli.dumpGroupMembership(&buf, *member)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(member, oldYamlConverter)
}

func (cli Zms) ShowGroupsPrincipal(principal string, dn string) (*string, error) {
	domainGroupMember, err := cli.Zms.GetPrincipalGroups(zms.EntityName(principal), zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		cli.dumpGroupsPrincipal(&buf, domainGroupMember)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(domainGroupMember, oldYamlConverter)
}

func (cli Zms) SetGroupAuditEnabled(dn string, gn string, auditEnabled bool) (*string, error) {
	// first we're going to try as system admin
	meta := zms.GroupSystemMeta{
		AuditEnabled: &auditEnabled,
	}
	err := cli.Zms.PutGroupSystemMeta(zms.DomainName(dn), zms.EntityName(gn), "auditenabled", cli.AuditRef, &meta)
	if err != nil {
		// if fails, we're going to try as regular domain admin
		group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
		if err != nil {
			return nil, err
		}
		meta := getGroupMetaObject(group)
		meta.AuditEnabled = &auditEnabled

		err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner, &meta)
		if err != nil {
			return nil, err
		}
	}
	s := "[domain " + dn + " group " + gn + " audit-enabled successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func getGroupMetaObject(group *zms.Group) zms.GroupMeta {
	return zms.GroupMeta{
		SelfServe:               group.SelfServe,
		ReviewEnabled:           group.ReviewEnabled,
		DeleteProtection:        group.DeleteProtection,
		AuditEnabled:            group.AuditEnabled,
		NotifyRoles:             group.NotifyRoles,
		UserAuthorityExpiration: group.UserAuthorityExpiration,
		UserAuthorityFilter:     group.UserAuthorityFilter,
		MemberExpiryDays:        group.MemberExpiryDays,
		ServiceExpiryDays:       group.ServiceExpiryDays,
		Tags:                    group.Tags,
		MaxMembers:              group.MaxMembers,
		SelfRenew:               group.SelfRenew,
		SelfRenewMins:           group.SelfRenewMins,
	}
}

func (cli Zms) SetGroupReviewEnabled(dn string, gn string, reviewEnabled bool) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.ReviewEnabled = &reviewEnabled

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " review-enabled attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetGroupDeleteProtection(dn string, gn string, deleteProtection bool) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.DeleteProtection = &deleteProtection

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " delete-protection attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetGroupSelfServe(dn string, gn string, selfServe bool) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.SelfServe = &selfServe

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " self-serve attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetGroupUserAuthorityFilter(dn string, gn, filter string) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.UserAuthorityFilter = filter

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " user-authority-filter attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetGroupUserAuthorityExpiration(dn string, gn, filter string) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.UserAuthorityExpiration = filter

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " user-authority-expiration attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetGroupNotifyRoles(dn string, gn string, notifyRoles string) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.NotifyRoles = notifyRoles

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " notify-roles attribute successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) PutGroupMembershipDecision(dn string, group string, mbr string, approval bool) (*string, error) {
	validatedUser := cli.validatedUser(mbr)
	var member zms.GroupMembership
	member.MemberName = zms.GroupMemberName(validatedUser)
	member.GroupName = zms.ResourceName(group)
	member.Approved = &approval
	err := cli.Zms.PutGroupMembershipDecision(zms.DomainName(dn), zms.EntityName(group), zms.GroupMemberName(validatedUser), cli.AuditRef, &member)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + group + " member " + mbr + " successfully"
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

func (cli Zms) ListPendingDomainGroupMembers(principal, domainName string) (*string, error) {
	domainMembership, err := cli.Zms.GetPendingDomainGroupMembersList(zms.EntityName(principal), domainName)
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("domains:\n")
		for _, domainGroupMembers := range domainMembership.DomainGroupMembersList {
			cli.dumpDomainGroupMembers(&buf, domainGroupMembers, true)
		}
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(domainMembership, oldYamlConverter)
}

func (cli Zms) AddGroupTags(dn string, gn, tagKey string, tagValues []string) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)

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

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " tags successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) DeleteGroupTags(dn string, gn, tagKey string, tagValue string) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)

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

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " tags successfully deleted]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) ShowGroups(dn, tagKey, tagValue string) (*string, error) {
	if cli.OutputFormat == JSONOutputFormat || cli.OutputFormat == YAMLOutputFormat {
		members := true
		groups, err := cli.Zms.GetGroups(zms.DomainName(dn), &members, zms.TagKey(tagKey), zms.TagCompoundValue(tagValue))
		if err != nil {
			log.Fatalf("Unable to get group list - error: %v", err)
		}
		return cli.dumpByFormat(groups, cli.buildYAMLOutput)
	} else {
		var buf bytes.Buffer
		cli.dumpGroups(&buf, dn, tagKey, tagValue)
		s := buf.String()
		return &s, nil
	}
}
