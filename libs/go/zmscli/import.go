// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/yahoo/athenz/clients/go/zms"
)

func parseRoleMember(memberLine string) *zms.RoleMember {
	memberFields := strings.Split(memberLine, " ")
	roleMember := zms.NewRoleMember()
	roleMember.MemberName = zms.ResourceName(memberFields[0])
	if len(memberFields) > 1 {
		expiration, err := rdl.TimestampParse(memberFields[1])
		if err != nil {
			fmt.Println("***", err)
		} else {
			roleMember.Expiration = &expiration
		}
	}
	return roleMember
}

func (cli Zms) importRoles(dn string, lstRoles []interface{}, validatedAdmins []string, skipErrors bool) error {
	for _, role := range lstRoles {
		roleMap := role.(map[interface{}]interface{})
		rn := roleMap["name"].(string)
		fmt.Fprintf(os.Stdout, "Processing role "+rn+"...\n")
		if val, ok := roleMap["members"]; ok {
			mem := val.([]interface{})
			roleMembers := make([]*zms.RoleMember, 0)
			var err error
			if rn == "admin" && validatedAdmins != nil {
				// need to retrieve the current admin role
				// and make sure to remove any existing admin
				role, err := cli.Zms.GetRole(zms.DomainName(dn), "admin", nil, nil)
				if err != nil {
					return err
				}
				for _, mbr := range mem {
					roleMember := parseRoleMember(mbr.(string))
					if !cli.containsMember(role.RoleMembers, string(roleMember.MemberName)) {
						roleMembers = append(roleMembers, roleMember)
					}
				}
				for _, admin := range validatedAdmins {
					roleMember := zms.NewRoleMember()
					roleMember.MemberName = zms.ResourceName(admin)
					if !cli.containsMember(roleMembers, admin) && !cli.containsMember(role.RoleMembers, admin) {
						roleMembers = append(roleMembers, roleMember)
					}
				}
				_, err = cli.AddRoleMembers(dn, rn, roleMembers)
			} else {
				for _, m := range mem {
					roleMember := parseRoleMember(m.(string))
					roleMembers = append(roleMembers, roleMember)
				}
				b := cli.Verbose
				cli.Verbose = true
				_, err = cli.AddGroupRole(dn, rn, roleMembers)
				cli.Verbose = b
			}
			if err != nil {
				if skipErrors {
					fmt.Println("***", err)
				} else {
					return err
				}
			}
		} else if val, ok := roleMap["trust"]; ok {
			trust := val.(string)
			_, err := cli.AddDelegatedRole(dn, rn, trust)
			if err != nil {
				if skipErrors {
					fmt.Println("***", err)
				} else {
					return err
				}
			}
		} else {
			roleMembers := make([]*zms.RoleMember, 0)
			b := cli.Verbose
			cli.Verbose = true
			_, err := cli.AddGroupRole(dn, rn, roleMembers)
			cli.Verbose = b
			if err != nil {
				if skipErrors {
					fmt.Println("***", err)
				} else {
					return err
				}
			}
		}
	}
	return nil
}

func (cli Zms) importPolicies(dn string, lstPolicies []interface{}, skipErrors bool) error {
	for _, policy := range lstPolicies {
		policyMap := policy.(map[interface{}]interface{})
		name := policyMap["name"].(string)
		fmt.Fprintf(os.Stdout, "Processing policy "+name+"...\n")
		assertions := make([]*zms.Assertion, 0)
		if val, ok := policyMap["assertions"]; ok {
			if val == nil {
				fmt.Fprintf(os.Stdout, "Skipping empty policy: "+name+"\n")
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
					if err != nil {
						if skipErrors {
							fmt.Println("***", err)
						} else {
							return err
						}
					}
					assertions = append(assertions, newAssertion)
				}
			}
		}
		if name != "admin" {
			_, err := cli.AddPolicyWithAssertions(dn, name, assertions)
			if err != nil {
				if skipErrors {
					fmt.Println("***", err)
				} else {
					return err
				}
			}
		}
	}
	return nil
}

func (cli Zms) generatePublicKeys(lstPublicKeys []interface{}) []*zms.PublicKeyEntry {
	publicKeys := make([]*zms.PublicKeyEntry, 0)
	if lstPublicKeys != nil {
		for _, pubKey := range lstPublicKeys {
			publicKeyMap := pubKey.(map[interface{}]interface{})
			// if we're using just version numbers then yaml
			// will interpret the key id as integer
			var keyId string
			switch v := publicKeyMap["keyId"].(type) {
			case int:
				keyId = strconv.Itoa(v)
			case string:
				keyId = v
			default:
				panic("Unknown data type for keyid")
			}
			value := publicKeyMap["value"].(string)
			publicKey := zms.PublicKeyEntry{
				Key: value,
				Id:  keyId,
			}
			publicKeys = append(publicKeys, &publicKey)
		}
	}
	return publicKeys
}

func (cli Zms) importServices(dn string, lstServices []interface{}, skipErrors bool) error {
	for _, service := range lstServices {
		serviceMap := service.(map[interface{}]interface{})
		name := serviceMap["name"].(string)
		fmt.Fprintf(os.Stdout, "Processing service "+name+"...\n")
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
				if err != nil {
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
			if err != nil {
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
			if err != nil {
				return err
			}
		}
	}
	return nil
}
