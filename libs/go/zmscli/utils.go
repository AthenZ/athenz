// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bufio"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zms"
)

func split(data []byte, atEOF bool) (advance int, token []byte, err error) {

	// create a split function using the existing word scanner
	// we're going to look for the quoted strings and handle them accordingly

	advance, token, err = bufio.ScanWords(data, atEOF)
	if err == nil && token != nil {
		if token[0] == '"' {
			var advanceFwd int
			var tokenFwd []byte
			for {
				advanceFwd, tokenFwd, err = bufio.ScanWords(data[advance:], atEOF)
				if err != nil || tokenFwd == nil {
					return
				}
				advance += advanceFwd
				token = append(token, 32)
				token = append(token, tokenFwd...)
				if tokenFwd[len(tokenFwd)-1] == '"' {
					token = token[1 : len(token)-1]
					break
				}
			}
		}
	}
	return
}

func (cli Zms) createResourceList(items []string) []zms.ResourceName {
	list := make([]zms.ResourceName, 0)
	for _, item := range items {
		list = append(list, zms.ResourceName(item))
	}
	return list
}

func (cli Zms) createStringList(items []zms.ResourceName) []string {
	list := make([]string, 0)
	for _, item := range items {
		list = append(list, string(item))
	}
	return list
}

func (cli Zms) tokenizer(input string) ([]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Split(split)

	tokens := make([]string, 0)
	for scanner.Scan() {
		tokens = append(tokens, scanner.Text())
	}
	err := scanner.Err()
	return tokens, err
}

func indexOfString(s []string, match string) int {
	for i, ss := range s {
		if ss == match {
			return i
		}
	}
	return -1
}

func (cli Zms) validatedUser(user string) string {
	//special case to support adding * as a member
	if !strings.Contains(user, ".") && user != "*" {
		return cli.UserDomain + "." + user
	}
	return user
}

func (cli Zms) validatedUsers(users []string, forceSelf bool) []string {
	validatedUsers := make([]string, 0)
	for _, v := range users {
		validatedUsers = append(validatedUsers, cli.validatedUser(v))
	}
	if forceSelf && indexOfString(validatedUsers, cli.Identity) < 0 {
		validatedUsers = append(validatedUsers, cli.Identity)
	}
	return validatedUsers
}

func (cli Zms) contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (cli Zms) containsMember(roleMembers []*zms.RoleMember, member string) bool {
	for _, roleMember := range roleMembers {
		if string(roleMember.MemberName) == member {
			return true
		}
	}
	return false
}

func (cli Zms) validateRoleMembers(users []*zms.RoleMember) {
	for _, v := range users {
		v.MemberName = zms.MemberName(cli.validatedUser(string(v.MemberName)))
	}
}

func (cli Zms) validateGroupMembers(users []*zms.GroupMember) {
	for _, v := range users {
		v.MemberName = zms.GroupMemberName(cli.validatedUser(string(v.MemberName)))
	}
}

func (cli Zms) convertRoleMembers(users []string) []*zms.RoleMember {
	roleMembers := make([]*zms.RoleMember, 0)
	for _, v := range users {
		roleMember := zms.NewRoleMember()
		roleMember.MemberName = zms.MemberName(cli.validatedUser(v))
		roleMembers = append(roleMembers, roleMember)
	}
	return roleMembers
}

func (cli Zms) convertGroupMembers(users []string) []*zms.GroupMember {
	groupMembers := make([]*zms.GroupMember, 0)
	for _, v := range users {
		groupMember := zms.NewGroupMember()
		if !strings.Contains(v, ".") {
			groupMember.MemberName = zms.GroupMemberName(cli.UserDomain + "." + v)
		} else {
			groupMember.MemberName = zms.GroupMemberName(v)
		}
		groupMembers = append(groupMembers, groupMember)
	}
	return groupMembers
}

func (cli Zms) RemoveAll(fullList []string, removeList []string) []string {
	var newList []string
	for _, item := range fullList {
		if !cli.contains(removeList, item) {
			newList = append(newList, item)
		}
	}
	return newList
}

func (cli Zms) GetTagsAfterDeletion(resourceTags *zms.TagValueList, valuesToDelete []string) []zms.TagCompoundValue {
	tagValueArr := make([]zms.TagCompoundValue, 0)
	if resourceTags == nil || len(valuesToDelete) == 0 {
		return tagValueArr
	}
	// extract all the values that not in the valuesToDelete List
	for _, curTagValue := range resourceTags.List {
		if !cli.contains(valuesToDelete, string(curTagValue)) {
			tagValueArr = append(tagValueArr, curTagValue)
		}
	}

	return tagValueArr
}
