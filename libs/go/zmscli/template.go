// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"

	"github.com/yahoo/athenz/clients/go/zms"
)

func (cli Zms) ListServerTemplates() (*string, error) {
	var buf bytes.Buffer
	templates, err := cli.Zms.GetServerTemplateList()
	if err != nil {
		return nil, err
	}
	buf.WriteString("templates:\n")
	for _, name := range templates.TemplateNames {
		buf.WriteString(indent_level1_dash + string(name) + "\n")
	}
	s := buf.String()
	return &s, nil
}

func (cli Zms) ListDomainTemplates(dn string) (*string, error) {
	var buf bytes.Buffer
	templates, err := cli.Zms.GetDomainTemplateList(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	buf.WriteString("templates:\n")
	for _, name := range templates.TemplateNames {
		buf.WriteString(indent_level1_dash + string(name) + "\n")
	}
	s := buf.String()
	return &s, nil
}

func (cli Zms) ShowServerTemplate(templateName string) (*string, error) {
	template, err := cli.Zms.GetTemplate(zms.SimpleName(templateName))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("template:\n")
	buf.WriteString(indent_level1 + "roles:\n")
	for _, role := range template.Roles {
		cli.dumpRole(&buf, *role, false, indent_level2_dash, indent_level2_dash_lvl)
	}
	buf.WriteString(indent_level1 + "policies:\n")
	for _, policy := range template.Policies {
		cli.dumpPolicy(&buf, *policy, indent_level2_dash, indent_level2_dash_lvl)
	}

	s := buf.String()
	return &s, nil
}

func (cli Zms) SetDomainTemplate(dn string, templates []string) (*string, error) {
	templateNames := make([]zms.SimpleName, 0)
	for _, value := range templates {
		templateNames = append(templateNames, zms.SimpleName(value))
	}
	var domainTemplateList zms.DomainTemplate
	domainTemplateList.TemplateNames = templateNames
	err := cli.Zms.PutDomainTemplate(zms.DomainName(dn), cli.AuditRef, &domainTemplateList)
	if err != nil {
		return nil, err
	}
	s := "[Template(s) successfully applied to domain]"
	return &s, nil
}

func (cli Zms) DeleteDomainTemplate(dn string, template string) (*string, error) {
	err := cli.Zms.DeleteDomainTemplate(zms.DomainName(dn), zms.SimpleName(template), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted template: " + template + "]"
	return &s, nil
}
