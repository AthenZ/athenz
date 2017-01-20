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

type Assertion []string

func (cli Zms) getProfilePolicies(name string) (string, string, map[string]Assertion) {
	userProfile := fmt.Sprintf("user.profile.%s", name)
	superUserProfile := fmt.Sprintf("superuser.profile.%s", name)

	policies := map[string]Assertion{
		userProfile:      []string{"grant", "node_user", "to", userProfile, "on", "node.*"},
		superUserProfile: []string{"grant", "node_sudo", "to", superUserProfile, "on", "node.*"},
	}
	return userProfile, superUserProfile, policies
}

func (cli Zms) addProfileRoles(dn string, names []string) error {
	for _, name := range names {
		// Add the role, if it doesn't exist
		_, err := cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(name), nil, nil)
		if err != nil {
			switch v := err.(type) {
			case rdl.ResourceError:
				if v.Code != 404 {
					return v
				}
			}

			_, err = cli.AddGroupRole(dn, name, []string{})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (cli Zms) addProfilePolicies(dn string, policies map[string]Assertion) error {
	for name, assertion := range policies {
		_, err := cli.Zms.GetPolicy(zms.DomainName(dn), zms.EntityName(name))
		if err != nil {
			switch v := err.(type) {
			case rdl.ResourceError:
				if v.Code != 404 {
					return v
				}
			}
			// Policy doesn't exist, add it
			_, err = cli.AddPolicy(dn, name, assertion)
			if err != nil {
				return err
			}
		} else {
			// Policy exists, add the assertion (note: ZMS overrides an existing assertion)
			_, err = cli.AddAssertion(dn, name, assertion)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (cli Zms) isValidProfilePolicy(dn, policyName string, assertion Assertion) (error, bool) {
	match := func(zmsAssertion *zms.Assertion) bool {
		effect := map[string]zms.AssertionEffect{
			"grant": zms.ALLOW,
			"deny":  zms.DENY,
		}
		if *zmsAssertion.Effect == effect[assertion[0]] &&
			zmsAssertion.Action == assertion[1] &&
			zmsAssertion.Role == dn+":role."+assertion[3] &&
			zmsAssertion.Resource == dn+":"+assertion[5] {
			return true
		}
		return false
	}

	policy, err := cli.Zms.GetPolicy(zms.DomainName(dn), zms.EntityName(policyName))
	if err != nil {
		return err, false
	}

	// Policy exists, check for the required assertion
	for _, a := range policy.Assertions {
		if match(a) {
			return nil, true
		}
	}
	return nil, false
}

func (cli Zms) AddProfile(dn, name string) (*string, error) {
	_, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	userProfile, superUserProfile, policies := cli.getProfilePolicies(name)

	err = cli.addProfileRoles(dn, []string{userProfile, superUserProfile})
	if err != nil {
		return nil, err
	}

	err = cli.addProfilePolicies(dn, policies)
	if err != nil {
		return nil, err
	}

	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowProfile(dn, name)
	}
}

func (cli Zms) ShowProfile(dn, name string) (*string, error) {
	userProfile, superUserProfile, policies := cli.getProfilePolicies(name)

	// Verify the expected profile policies and assertions in them
	for policyName, assertion := range policies {
		err, found := cli.isValidProfilePolicy(dn, policyName, assertion)
		if err != nil {
			return nil, fmt.Errorf("Profile error: %v", err)
		}
		if !found {
			return nil, fmt.Errorf("Profile error: Assertion (%s) not found in the policy: %s", strings.Join(assertion, " "), policyName)
		}
	}

	userRole, err := cli.ShowRole(dn, userProfile, false, false)
	if err != nil {
		return nil, err
	}

	superUserRole, err := cli.ShowRole(dn, superUserProfile, false, false)
	if err != nil {
		return nil, err
	}

	content := fmt.Sprintf("%s%s", *userRole, strings.TrimSuffix(*superUserRole, "\n"))
	var buf bytes.Buffer
	cli.dumpProfile(&buf, name, content)
	s := buf.String()
	return &s, nil
}
