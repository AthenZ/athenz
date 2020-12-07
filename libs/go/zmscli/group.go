// Copyright 2020 Verizon Media
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/yahoo/athenz/clients/go/zms"
)

func (cli Zms) groupNames(dn string) ([]string, error) {
	groups := make([]string, 0)
	members := false
	lst, err := cli.Zms.GetGroups(zms.DomainName(dn), &members)
	if err != nil {
		return nil, err
	}
	for _, n := range lst.List {
		groups = append(groups, localName(string(n.Name), ":group."))
	}
	return groups, nil
}

func (cli Zms) ListGroups(dn string) (*string, error) {
	var buf bytes.Buffer
	groups, err := cli.groupNames(dn)
	if err != nil {
		return nil, err
	}
	buf.WriteString("groups:\n")
	cli.dumpObjectList(&buf, groups, dn, "group")
	s := buf.String()
	return &s, nil
}

func (cli Zms) ShowGroup(dn string, gn string, auditLog, pending bool) (*string, error) {
	var log *bool
	if auditLog {
		log = &auditLog
	} else {
		log = nil
	}
	var pend *bool
	if pending {
		pend = &pending
	} else {
		pend = nil
	}
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), log, pend)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("group:\n")
	cli.dumpGroup(&buf, *group, auditLog, indentLevel1Dash, indentLevel1DashLvl)
	s := buf.String()
	return &s, nil
}

func (cli Zms) AddGroup(dn string, gn string, groupMembers []*zms.GroupMember) (*string, error) {
	fullResourceName := dn + ":group." + gn
	var group zms.Group
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
	group.Name = zms.ResourceName(fullResourceName)
	group.GroupMembers = groupMembers
	cli.validateGroupMembers(group.GroupMembers)
	err = cli.Zms.PutGroup(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, &group)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	output, err := cli.ShowGroup(dn, gn, false, false)
	if err != nil {
		// due to mysql read after write issue it's possible that
		// we'll get 404 after writing our object so in that
		// case we're going to do a quick sleep and retry request
		time.Sleep(500 * time.Millisecond)
		output, err = cli.ShowGroup(dn, gn, false, false)
	}
	return output, err
}

func (cli Zms) DeleteGroup(dn string, gn string) (*string, error) {
	err := cli.Zms.DeleteGroup(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted group: " + gn + "]"
	return &s, nil
}

func (cli Zms) AddGroupMembers(dn string, group string, members []string) (*string, error) {
	fullResourceName := dn + ":group." + group
	ms := cli.validatedUsers(members, false)
	for _, m := range ms {
		var member zms.GroupMembership
		member.MemberName = zms.GroupMemberName(m)
		member.GroupName = zms.ResourceName(group)
		err := cli.Zms.PutGroupMembership(zms.DomainName(dn), zms.EntityName(group), zms.GroupMemberName(m), cli.AuditRef, &member)
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
	return &s, nil
}

func (cli Zms) DeleteGroupMembers(dn string, group string, members []string) (*string, error) {
	fullResourceName := dn + ":group." + group
	ms := cli.validatedUsers(members, false)
	for _, m := range ms {
		err := cli.Zms.DeleteGroupMembership(zms.DomainName(dn), zms.EntityName(group), zms.GroupMemberName(m), cli.AuditRef)
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
	return &s, nil
}

func (cli Zms) CheckGroupMembers(dn string, group string, members []string) (*string, error) {
	var buf bytes.Buffer
	ms := cli.validatedUsers(members, false)
	for _, m := range ms {
		member, err := cli.Zms.GetGroupMembership(zms.DomainName(dn), zms.EntityName(group), zms.GroupMemberName(m), "")
		if err != nil {
			return nil, err
		}
		cli.dumpGroupMembership(&buf, *member)
	}
	s := buf.String()
	return &s, nil
}

func (cli Zms) CheckActiveGroupMember(dn string, group string, mbr string) (*string, error) {
	var buf bytes.Buffer
	member, err := cli.Zms.GetGroupMembership(zms.DomainName(dn), zms.EntityName(group), zms.GroupMemberName(mbr), "")
	if err != nil {
		return nil, err
	}
	if !*member.IsMember || !*member.Approved || !*member.Active {
		return nil, errors.New("Member " + mbr + " is not active")
	}
	cli.dumpGroupMembership(&buf, *member)
	s := buf.String()
	return &s, nil
}

func (cli Zms) ShowGroupsPrincipal(principal string, dn string) (*string, error) {
	var buf bytes.Buffer
	domainGroupMember, err := cli.Zms.GetPrincipalGroups(zms.EntityName(principal), zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	cli.dumpGroupsPrincipal(&buf, domainGroupMember)
	s := buf.String()
	return &s, nil
}

func (cli Zms) SetGroupAuditEnabled(dn string, group string, auditEnabled bool) (*string, error) {
	meta := zms.GroupSystemMeta{
		AuditEnabled: &auditEnabled,
	}
	err := cli.Zms.PutGroupSystemMeta(zms.DomainName(dn), zms.EntityName(group), "auditenabled", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + group + " audit-enabled successfully updated]\n"
	return &s, nil
}

func getGroupMetaObject(group *zms.Group) zms.GroupMeta {
	return zms.GroupMeta{
		SelfServe:               group.SelfServe,
		ReviewEnabled:           group.ReviewEnabled,
		NotifyRoles:             group.NotifyRoles,
		UserAuthorityExpiration: group.UserAuthorityExpiration,
		UserAuthorityFilter:     group.UserAuthorityFilter,
	}
}

func (cli Zms) SetGroupReviewEnabled(dn string, gn string, reviewEnabled bool) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.ReviewEnabled = &reviewEnabled

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " review-enabled attribute successfully updated]\n"
	return &s, nil
}

func (cli Zms) SetGroupSelfServe(dn string, gn string, selfServe bool) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.SelfServe = &selfServe

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " self-serve attribute successfully updated]\n"
	return &s, nil
}

func (cli Zms) SetGroupUserAuthorityFilter(dn string, gn, filter string) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.UserAuthorityFilter = filter

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " user-authority-filter attribute successfully updated]\n"
	return &s, nil
}

func (cli Zms) SetGroupUserAuthorityExpiration(dn string, gn, filter string) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.UserAuthorityExpiration = filter

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " user-authority-expiration attribute successfully updated]\n"
	return &s, nil
}

func (cli Zms) SetGroupNotifyRoles(dn string, gn string, notifyRoles string) (*string, error) {
	group, err := cli.Zms.GetGroup(zms.DomainName(dn), zms.EntityName(gn), nil, nil)
	if err != nil {
		return nil, err
	}
	meta := getGroupMetaObject(group)
	meta.NotifyRoles = notifyRoles

	err = cli.Zms.PutGroupMeta(zms.DomainName(dn), zms.EntityName(gn), cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " group " + gn + " notify-roles attribute successfully updated]\n"
	return &s, nil
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
	return &s, nil
}

func (cli Zms) ListPendingDomainGroupMembers(principal string) (*string, error) {
	domainMembership, err := cli.Zms.GetPendingDomainGroupMembersList(zms.EntityName(principal))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("domains:\n")
	for _, domainGroupMembers := range domainMembership.DomainGroupMembersList {
		cli.dumpDomainGroupMembers(&buf, domainGroupMembers, true)
	}
	s := buf.String()

	return &s, nil
}
