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

func (cli Zms) policyNames(dn string) ([]string, error) {
	names := make([]string, 0)
	lst, err := cli.Zms.GetPolicyList(zms.DomainName(dn), nil, "")
	if err != nil {
		return nil, err
	}
	for _, n := range lst.Names {
		names = append(names, string(n))
	}
	return names, nil
}

func (cli Zms) ListPolicies(dn string) (*string, error) {
	var buf bytes.Buffer
	policies, err := cli.policyNames(dn)
	if err != nil {
		return nil, err
	}
	buf.WriteString("policies:\n")
	cli.dumpObjectList(&buf, policies, dn, "policy")
	s := buf.String()
	return &s, nil
}

func (cli Zms) ShowPolicy(dn string, name string) (*string, error) {
	policy, err := cli.Zms.GetPolicy(zms.DomainName(dn), zms.EntityName(name))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("policy:\n")
	cli.dumpPolicy(&buf, *policy, indent_level1_dash, indent_level1_dash_lvl)
	s := buf.String()
	return &s, nil
}

func parseAssertion(dn string, lst []string) (*zms.Assertion, error) {
	err := fmt.Errorf("Bad assertion syntax. Should be '<effect> <action> to <role> on <resource>'")
	n := len(lst)
	var assertion zms.Assertion
	if n != 6 {
		return nil, err
	}
	if strings.ToLower(lst[2]) != "to" {
		return nil, err
	}
	if strings.ToLower(lst[4]) != "on" {
		return nil, err
	}
	// we are using grant in our command line utility but the
	// actual effect in the spec is ALLOW
	effect := strings.ToUpper(lst[0])
	if effect != "GRANT" {
		if effect != "DENY" {
			return nil, err
		}
	} else {
		effect = "ALLOW"
	}
	var assertionEffect = zms.NewAssertionEffect(effect)
	assertion.Effect = &assertionEffect
	assertion.Action = lst[1]
	role := lst[3]
	if strings.Index(role, ":") < 0 {
		role = dn + ":role." + role
	}
	assertion.Role = role
	resource := lst[5]
	if strings.Index(resource, ":") < 0 {
		resource = dn + ":" + resource
	}
	assertion.Resource = resource
	return &assertion, nil
}

func (cli Zms) AddPolicyWithAssertions(dn string, pn string, assertions []*zms.Assertion) (*string, error) {
	fullResourceName := dn + ":policy." + pn
	policy := zms.Policy{
		Name:       zms.ResourceName(fullResourceName),
		Modified:   nil,
		Assertions: assertions,
	}
	err := cli.Zms.PutPolicy(zms.DomainName(dn), zms.EntityName(pn), cli.AuditRef, &policy)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowPolicy(dn, pn)
	}
}

func (cli Zms) AddPolicy(dn string, pn string, assertion []string) (*string, error) {
	fullResourceName := dn + ":policy." + pn
	_, err := cli.Zms.GetPolicy(zms.DomainName(dn), zms.EntityName(pn))
	if err == nil {
		return nil, fmt.Errorf("Policy already exists: %v", fullResourceName)
	} else {
		switch v := err.(type) {
		case rdl.ResourceError:
			if v.Code != 404 {
				return nil, v
			}
		}
	}
	policy := zms.Policy{}
	policy.Name = zms.ResourceName(fullResourceName)
	if assertion == nil || len(assertion) == 0 {
		policy.Assertions = make([]*zms.Assertion, 0)
	} else {
		newAssertion, err := parseAssertion(dn, assertion)
		if err != nil {
			return nil, err
		}
		tmp := [1]*zms.Assertion{newAssertion}
		policy.Assertions = tmp[:]
	}
	err = cli.Zms.PutPolicy(zms.DomainName(dn), zms.EntityName(pn), cli.AuditRef, &policy)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowPolicy(dn, pn)
	}
}

func (cli Zms) AddAssertion(dn string, pn string, assertion []string) (*string, error) {
	newAssertion, err := parseAssertion(dn, assertion)
	if err != nil {
		return nil, err
	}
	_, err = cli.Zms.PutAssertion(zms.DomainName(dn), zms.EntityName(pn), cli.AuditRef, newAssertion)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowPolicy(dn, pn)
	}
}

func (cli Zms) assertionMatch(assertion1 *zms.Assertion, assertion2 *zms.Assertion) bool {
	if assertion1.Action != assertion2.Action {
		return false
	}
	assert1Effect := "ALLOW"
	if assertion1.Effect != nil {
		assert1Effect = assertion1.Effect.String()
	}
	assert2Effect := "ALLOW"
	if assertion2.Effect != nil {
		assert2Effect = assertion2.Effect.String()
	}
	if assert1Effect != assert2Effect {
		return false
	}
	if assertion1.Resource != assertion2.Resource {
		return false
	}
	if assertion1.Role != assertion2.Role {
		return false
	}
	return true
}

func (cli Zms) removeAssertion(policy *zms.Policy, deleteAssertion *zms.Assertion) error {
	match_index := -1
	for index, assertion := range policy.Assertions {
		if cli.assertionMatch(assertion, deleteAssertion) {
			match_index = index
			break
		}
	}
	if match_index == -1 {
		return fmt.Errorf("Policy does not have the specified assertion")
	}
	policy.Assertions = append(policy.Assertions[:match_index], policy.Assertions[match_index+1:]...)
	return nil
}

func (cli Zms) DeleteAssertion(dn string, pn string, assertion []string) (*string, error) {
	policy, err := cli.Zms.GetPolicy(zms.DomainName(dn), zms.EntityName(pn))
	if err != nil {
		return nil, err
	}
	deleteAssertion, err := parseAssertion(dn, assertion)
	if err != nil {
		return nil, err
	}
	err = cli.removeAssertion(policy, deleteAssertion)
	if err != nil {
		return nil, err
	}
	err = cli.Zms.PutPolicy(zms.DomainName(dn), zms.EntityName(pn), cli.AuditRef, policy)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowPolicy(dn, pn)
	}
}

func (cli Zms) DeletePolicy(dn string, pn string) (*string, error) {
	err := cli.Zms.DeletePolicy(zms.DomainName(dn), zms.EntityName(pn), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted policy: " + pn + "]"
	return &s, nil
}
