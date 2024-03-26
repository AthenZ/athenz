// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zms"
)

func parseRoleMember(memberStruct map[string]interface{}) *zms.RoleMember {
	roleMember := zms.NewRoleMember()
	roleMember.MemberName = zms.MemberName(memberStruct["name"].(string))

	if val, ok := memberStruct["expiration"]; ok {
		expiration := val.(string)
		exprTimeStamp, err := getTimestamp(expiration)
		if err != nil {
			fmt.Println("***", err)
		}
		roleMember.Expiration = &exprTimeStamp
	}

	if val, ok := memberStruct["review"]; ok {
		review := val.(string)
		reviewTimeStamp, err := getTimestamp(review)
		if err != nil {
			fmt.Println("***", err)
		}
		roleMember.ReviewReminder = &reviewTimeStamp
	}

	return roleMember
}

func parseGroupMember(memberStruct map[string]interface{}) *zms.GroupMember {
	groupMember := zms.NewGroupMember()
	groupMember.MemberName = zms.GroupMemberName(memberStruct["name"].(string))
	return groupMember
}

func shouldReportError(commandSkipErrors, clientSkipErrors bool, err error) bool {
	// if we have no error then there is nothing to check
	if err == nil {
		return false
	}
	// if the skip errors argument is false then we're going
	// to report the error
	if !commandSkipErrors {
		return true
	}
	// output the error
	fmt.Println("***", err)
	// if the client requested skip error option is disabled then
	// we're only going to skip any errors where the object already exists
	if clientSkipErrors {
		return false
	}
	return !strings.Contains(err.Error(), "already exists")
}

func groupExists(groupName zms.ResourceName, groups *zms.Groups) bool {
	if groups == nil {
		return false
	}
	for _, group := range groups.List {
		if group.Name == groupName {
			return true
		}
	}
	return false
}

func (cli Zms) importGroups(dn string, lstGroups []*zms.Group, existingGroups *zms.Groups, updateDomain bool) error {
	for _, group := range lstGroups {
		gn := localName(string(group.Name), ":group.")
		_, _ = fmt.Fprintf(os.Stdout, "Processing group "+gn+"...\n")
		b := cli.Verbose
		cli.Verbose = true
		groupAuditEnabled := false
		if group.AuditEnabled != nil {
			groupAuditEnabled = *group.AuditEnabled
		}
		var err error
		if updateDomain && groupExists(group.Name, existingGroups) {
			groupMembers := make([]string, 0)
			for _, groupMember := range group.GroupMembers {
				groupMembers = append(groupMembers, string(groupMember.MemberName))
			}
			_, err = cli.AddGroupMembers(dn, gn, groupMembers)
		} else {
			_, err = cli.AddGroup(dn, gn, groupAuditEnabled, group.GroupMembers)
		}
		cli.Verbose = b
		if shouldReportError(updateDomain, cli.SkipErrors, err) {
			return err
		}
	}
	return nil
}

func (cli Zms) importGroupsOld(dn string, lstGroups []interface{}, skipErrors bool) error {
	for _, group := range lstGroups {
		groupMap := group.(map[string]interface{})
		gn := groupMap["name"].(string)
		_, _ = fmt.Fprintf(os.Stdout, "Processing group "+gn+"...\n")
		groupMembers := make([]*zms.GroupMember, 0)
		if val, ok := groupMap["members"]; ok {
			mem := val.([]interface{})
			for _, m := range mem {
				groupMember := parseGroupMember(m.(map[string]interface{}))
				groupMembers = append(groupMembers, groupMember)
			}
		}
		b := cli.Verbose
		cli.Verbose = true
		_, err := cli.AddGroup(dn, gn, false, groupMembers)
		cli.Verbose = b
		if shouldReportError(skipErrors, cli.SkipErrors, err) {
			return err
		}
	}
	return nil
}

func roleExists(roleName zms.ResourceName, roles *zms.Roles) bool {
	if roles == nil {
		return false
	}
	for _, role := range roles.List {
		if role.Name == roleName {
			return true
		}
	}
	return false
}

func (cli Zms) importRoles(dn string, lstRoles []*zms.Role, existingRoles *zms.Roles, validatedAdmins []string, updateDomain bool) error {
	for _, role := range lstRoles {
		rn := localName(string(role.Name), ":role.")
		_, _ = fmt.Fprintf(os.Stdout, "Processing role "+rn+"...\n")
		roleAuditEnabled := false
		if role.AuditEnabled != nil {
			roleAuditEnabled = *role.AuditEnabled
		}
		if len(role.RoleMembers) > 0 {
			roleMembers := make([]*zms.RoleMember, 0)
			var err error
			var adminRole *zms.Role
			if rn == "admin" && validatedAdmins != nil {
				// need to retrieve the current admin role
				// and make sure to remove any existing admin
				adminRole, err = cli.Zms.GetRole(zms.DomainName(dn), "admin", nil, nil, nil)
				if err != nil {
					return err
				}
				for _, roleMember := range role.RoleMembers {
					if !cli.containsMember(adminRole.RoleMembers, string(roleMember.MemberName)) {
						roleMembers = append(roleMembers, roleMember)
					}
				}
				for _, admin := range validatedAdmins {
					roleMember := zms.NewRoleMember()
					roleMember.MemberName = zms.MemberName(admin)
					if !cli.containsMember(roleMembers, admin) && !cli.containsMember(adminRole.RoleMembers, admin) {
						roleMembers = append(roleMembers, roleMember)
					}
				}
				_, err = cli.AddRoleMembers(dn, rn, roleMembers)
			} else {
				for _, roleMember := range role.RoleMembers {
					roleMembers = append(roleMembers, roleMember)
				}
				b := cli.Verbose
				cli.Verbose = true
				if updateDomain && roleExists(role.Name, existingRoles) {
					_, err = cli.AddRoleMembers(dn, rn, roleMembers)
				} else {
					_, err = cli.AddRegularRole(dn, rn, roleAuditEnabled, roleMembers)
				}
				cli.Verbose = b
			}
			if shouldReportError(updateDomain, cli.SkipErrors, err) {
				return err
			}
		} else if role.Trust != "" {
			trust := string(role.Trust)
			_, err := cli.AddDelegatedRole(dn, rn, trust)
			if shouldReportError(updateDomain, cli.SkipErrors, err) {
				return err
			}
		} else {
			if !updateDomain || !roleExists(role.Name, existingRoles) {
				roleMembers := make([]*zms.RoleMember, 0)
				b := cli.Verbose
				cli.Verbose = true
				_, err := cli.AddRegularRole(dn, rn, roleAuditEnabled, roleMembers)
				cli.Verbose = b
				if shouldReportError(updateDomain, cli.SkipErrors, err) {
					return err
				}
			}
		}
	}
	return nil
}

func (cli Zms) importRolesOld(dn string, lstRoles []interface{}, validatedAdmins []string, skipErrors bool) error {
	for _, role := range lstRoles {
		roleMap := role.(map[string]interface{})
		rn := roleMap["name"].(string)
		_, _ = fmt.Fprintf(os.Stdout, "Processing role "+rn+"...\n")
		if val, ok := roleMap["members"]; ok {
			mem := val.([]interface{})
			roleMembers := make([]*zms.RoleMember, 0)
			var err error
			var adminRole *zms.Role
			if rn == "admin" && validatedAdmins != nil {
				// need to retrieve the current admin role
				// and make sure to remove any existing admin
				adminRole, err = cli.Zms.GetRole(zms.DomainName(dn), "admin", nil, nil, nil)
				if err != nil {
					return err
				}
				for _, mbr := range mem {
					roleMember := parseRoleMember(mbr.(map[string]interface{}))
					if !cli.containsMember(adminRole.RoleMembers, string(roleMember.MemberName)) {
						roleMembers = append(roleMembers, roleMember)
					}
				}
				for _, admin := range validatedAdmins {
					roleMember := zms.NewRoleMember()
					roleMember.MemberName = zms.MemberName(admin)
					if !cli.containsMember(roleMembers, admin) && !cli.containsMember(adminRole.RoleMembers, admin) {
						roleMembers = append(roleMembers, roleMember)
					}
				}
				_, err = cli.AddRoleMembers(dn, rn, roleMembers)
			} else {
				for _, m := range mem {
					roleMember := parseRoleMember(m.(map[string]interface{}))
					roleMembers = append(roleMembers, roleMember)
				}
				b := cli.Verbose
				cli.Verbose = true
				_, err = cli.AddRegularRole(dn, rn, false, roleMembers)
				cli.Verbose = b
			}
			if shouldReportError(skipErrors, cli.SkipErrors, err) {
				return err
			}
		} else if val, ok := roleMap["trust"]; ok {
			trust := val.(string)
			_, err := cli.AddDelegatedRole(dn, rn, trust)
			if shouldReportError(skipErrors, cli.SkipErrors, err) {
				return err
			}
		} else {
			roleMembers := make([]*zms.RoleMember, 0)
			b := cli.Verbose
			cli.Verbose = true
			_, err := cli.AddRegularRole(dn, rn, false, roleMembers)
			cli.Verbose = b
			if shouldReportError(skipErrors, cli.SkipErrors, err) {
				return err
			}
		}
	}
	return nil
}

func (cli Zms) importPolicies(dn string, lstPolicies []*zms.Policy, updateDomain bool) error {
	for _, policy := range lstPolicies {
		name := localName(string(policy.Name), ":policy.")
		_, _ = fmt.Fprintf(os.Stdout, "Processing policy "+name+"...\n")
		if len(policy.Assertions) == 0 {
			_, _ = fmt.Fprintf(os.Stdout, "Skipping empty policy: "+name+"\n")
			continue
		}
		if name == "admin" {
			_, _ = fmt.Fprintln(os.Stdout, "Skipping admin policy")
			continue
		}
		if updateDomain {
			// if the policy already exists then we're going to only apply
			// all the assertions
			_, err := cli.Zms.GetPolicy(zms.DomainName(dn), zms.EntityName(name))
			if err == nil {
				for _, assertion := range policy.Assertions {
					_, err := cli.Zms.PutAssertion(zms.DomainName(dn), zms.EntityName(name), cli.AuditRef, cli.ResourceOwner, assertion)
					if shouldReportError(updateDomain, cli.SkipErrors, err) {
						return err
					}
				}
				continue
			}
		}

		// otherwise we'll be adding the full policy with assertions
		_, err := cli.AddPolicyWithAssertions(dn, name, policy.Assertions)
		if shouldReportError(updateDomain, cli.SkipErrors, err) {
			return err
		}

	}
	return nil
}

func (cli Zms) importPoliciesOld(dn string, lstPolicies []interface{}, skipErrors bool) error {
	for _, policy := range lstPolicies {
		policyMap := policy.(map[string]interface{})
		name := policyMap["name"].(string)
		_, _ = fmt.Fprintf(os.Stdout, "Processing policy "+name+"...\n")
		assertions := make([]*zms.Assertion, 0)
		if val, ok := policyMap["assertions"]; ok {
			if val == nil {
				_, _ = fmt.Fprintf(os.Stdout, "Skipping empty policy: "+name+"\n")
				continue
			}
			lst := val.([]interface{})
			if len(lst) > 0 {
				for _, a := range lst {
					if name == "admin" && a.(string) == "grant * to admin on *" {
						continue
					}
					assertion := strings.Split(a.(string), " ")
					newAssertion, err := parseAssertion(dn, assertion)
					if shouldReportError(skipErrors, cli.SkipErrors, err) {
						return err
					}
					assertions = append(assertions, newAssertion)
				}
			}
		}
		if name != "admin" {
			_, err := cli.AddPolicyWithAssertions(dn, name, assertions)
			if shouldReportError(skipErrors, cli.SkipErrors, err) {
				return err
			}
		}
	}
	return nil
}

func (cli Zms) generatePublicKeys(lstPublicKeys []interface{}) []*zms.PublicKeyEntry {
	publicKeys := make([]*zms.PublicKeyEntry, 0)
	for _, pubKey := range lstPublicKeys {
		publicKeyMap := pubKey.(map[string]interface{})
		// if we're using just version numbers then yaml
		// will interpret the key id as integer
		var keyID string
		switch v := publicKeyMap["keyID"].(type) {
		case int:
			keyID = strconv.Itoa(v)
		case string:
			keyID = v
		default:
			panic("Unknown data type for keyid")
		}
		value := publicKeyMap["value"].(string)
		publicKey := zms.PublicKeyEntry{
			Key: value,
			Id:  keyID,
		}
		publicKeys = append(publicKeys, &publicKey)
	}
	return publicKeys
}

func (cli Zms) importServices(dn string, lstServices []*zms.ServiceIdentity, skipErrors bool) error {
	for _, service := range lstServices {
		name := string(service.Name)
		_, _ = fmt.Fprintf(os.Stdout, "Processing service "+name+"...\n")
		publicKeys := service.PublicKeys
		_, err := cli.AddServiceWithKeys(dn, name, publicKeys)
		if shouldReportError(skipErrors, cli.SkipErrors, err) {
			return err
		}
		if service.ProviderEndpoint != "" {
			_, err = cli.SetServiceEndpoint(dn, name, service.ProviderEndpoint)
			if shouldReportError(skipErrors, cli.SkipErrors, err) {
				return err
			}
		}
		if service.User != "" || service.Group != "" || service.Executable != "" {
			_, err = cli.SetServiceExe(dn, name, service.Executable, service.User, service.Group)
			if shouldReportError(skipErrors, cli.SkipErrors, err) {
				return err
			}
		}
		if len(service.Hosts) > 0 {
			_, err = cli.AddServiceHost(dn, name, service.Hosts)
			if shouldReportError(skipErrors, cli.SkipErrors, err) {
				return err
			}
		}
	}
	return nil
}

func (cli Zms) importServicesOld(dn string, lstServices []interface{}, skipErrors bool) error {
	for _, service := range lstServices {
		serviceMap := service.(map[string]interface{})
		name := serviceMap["name"].(string)
		_, _ = fmt.Fprintf(os.Stdout, "Processing service "+name+"...\n")
		var lstPublicKeys []interface{}
		if val, ok := serviceMap["publicKeys"]; ok {
			lstPublicKeys = val.([]interface{})
		}
		publicKeys := cli.generatePublicKeys(lstPublicKeys)
		_, err := cli.AddServiceWithKeys(dn, name, publicKeys)
		if err != nil {
			return err
		}
		if val, ok := serviceMap["providerEndpoint"]; ok {
			endpoint := val.(string)
			if endpoint != "" {
				_, err = cli.SetServiceEndpoint(dn, name, endpoint)
				if shouldReportError(skipErrors, cli.SkipErrors, err) {
					return err
				}
			}
		}
		user := ""
		if val, ok := serviceMap["user"]; ok {
			user = val.(string)
		}
		group := ""
		if val, ok := serviceMap["group"]; ok {
			group = val.(string)
		}
		exe := ""
		if val, ok := serviceMap["executable"]; ok {
			exe = val.(string)
		}
		if user != "" || group != "" || exe != "" {
			_, err = cli.SetServiceExe(dn, name, exe, user, group)
			if shouldReportError(skipErrors, cli.SkipErrors, err) {
				return err
			}
		}
		if val, ok := serviceMap["hosts"]; ok {
			hostList := val.([]interface{})
			hosts := make([]string, 0)
			for _, host := range hostList {
				hosts = append(hosts, host.(string))
			}
			_, err = cli.AddServiceHost(dn, name, hosts)
			if shouldReportError(skipErrors, cli.SkipErrors, err) {
				return err
			}
		}
	}
	return nil
}
