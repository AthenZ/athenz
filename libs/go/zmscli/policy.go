// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zms"
	"github.com/ardielle/ardielle-go/rdl"
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
	policies, err := cli.policyNames(dn)
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("policies:\n")
		cli.dumpObjectList(&buf, policies, dn, "policy")
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(policies, oldYamlConverter)
}

func (cli Zms) ShowPolicy(dn string, name string) (*string, error) {
	policy, err := cli.Zms.GetPolicy(zms.DomainName(dn), zms.EntityName(name))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("policy:\n")
		cli.dumpPolicy(&buf, *policy, indentLevel1Dash, indentLevel1DashLvl)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(policy, oldYamlConverter)
}

func parseAssertion(dn string, lst []string) (*zms.Assertion, error) {
	err := fmt.Errorf("bad assertion syntax. should be '<effect> <action> to <role> on <resource>'")
	n := len(lst)
	var assertion zms.Assertion
	if n != 6 && n != 7 {
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
	if !strings.Contains(role, ":") {
		role = dn + ":role." + role
	}
	assertion.Role = role
	resource := lst[5]
	if !strings.Contains(resource, ":") {
		resource = dn + ":" + resource
	}
	assertion.Resource = resource

	if n == 7 {
		isCaseSensitive, err := strconv.ParseBool(lst[6])
		if err == nil {
			assertion.CaseSensitive = &isCaseSensitive
		}
	}
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
	}
	output, err := cli.ShowPolicy(dn, pn)
	if err != nil {
		// due to mysql read after write issue it's possible that
		// we'll get 404 after writing our object so in that
		// case we're going to do a quick sleep and retry request
		time.Sleep(500 * time.Millisecond)
		output, err = cli.ShowPolicy(dn, pn)
	}
	return output, err
}

func (cli Zms) AddPolicy(dn string, pn string, assertion []string) (*string, error) {
	fullResourceName := dn + ":policy." + pn
	_, err := cli.Zms.GetPolicy(zms.DomainName(dn), zms.EntityName(pn))
	if err == nil {
		return nil, fmt.Errorf("policy already exists: %v", fullResourceName)
	}
	switch v := err.(type) {
	case rdl.ResourceError:
		if v.Code != 404 {
			return nil, v
		}
	}
	policy := zms.Policy{}
	policy.Name = zms.ResourceName(fullResourceName)
	if len(assertion) == 0 {
		policy.Assertions = make([]*zms.Assertion, 0)
	} else {
		newAssertion, err := parseAssertion(dn, assertion)
		if err != nil {
			return nil, err
		}
		tmp := [1]*zms.Assertion{newAssertion}
		policy.Assertions = tmp[:]
		policy.CaseSensitive = newAssertion.CaseSensitive
	}
	err = cli.Zms.PutPolicy(zms.DomainName(dn), zms.EntityName(pn), cli.AuditRef, &policy)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	output, err := cli.ShowPolicy(dn, pn)
	if err != nil {
		// due to mysql read after write issue it's possible that
		// we'll get 404 after writing our object so in that
		// case we're going to do a quick sleep and retry request
		time.Sleep(500 * time.Millisecond)
		output, err = cli.ShowPolicy(dn, pn)
	}
	return output, err
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
	}
	return cli.ShowPolicy(dn, pn)
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
	matchIndex := -1
	for index, assertion := range policy.Assertions {
		if cli.assertionMatch(assertion, deleteAssertion) {
			matchIndex = index
			break
		}
	}
	if matchIndex == -1 {
		return fmt.Errorf("policy does not have the specified assertion")
	}
	policy.Assertions = append(policy.Assertions[:matchIndex], policy.Assertions[matchIndex+1:]...)
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
	}
	return cli.ShowPolicy(dn, pn)
}

func (cli Zms) DeletePolicy(dn string, pn string) (*string, error) {
	err := cli.Zms.DeletePolicy(zms.DomainName(dn), zms.EntityName(pn), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted policy: " + pn + "]"

	message := SuccessMessage{
		Status:  200,
		Message: s,
	}
	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}
