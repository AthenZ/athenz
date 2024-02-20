// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zms"
)

func (cli Zms) ListServerTemplates() (*string, error) {
	templates, err := cli.Zms.GetServerTemplateList()
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("templates:\n")
		for _, name := range templates.TemplateNames {
			buf.WriteString(indentLevel1Dash + string(name) + "\n")
		}
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(templates, oldYamlConverter)
}

func (cli Zms) ListDomainTemplates(dn string) (*string, error) {
	templates, err := cli.Zms.GetDomainTemplateList(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("templates:\n")
		for _, name := range templates.TemplateNames {
			buf.WriteString(indentLevel1Dash + string(name) + "\n")
		}
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(templates, oldYamlConverter)
}

func (cli Zms) ShowServerTemplate(templateName string) (*string, error) {
	template, err := cli.Zms.GetTemplate(zms.SimpleName(templateName))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("template:\n")
		cli.dumpMetadata(&buf, template.Metadata, indentLevel2Dash, templateName)
		buf.WriteString(indentLevel1 + "roles:\n")
		for _, role := range template.Roles {
			cli.dumpRole(&buf, *role, false, indentLevel2Dash, indentLevel2DashLvl)
		}
		buf.WriteString(indentLevel1 + "policies:\n")
		for _, policy := range template.Policies {
			cli.dumpPolicy(&buf, *policy, indentLevel2Dash, indentLevel2DashLvl)
		}
		if len(template.Services) > 0 {
			buf.WriteString(indentLevel1 + "services:\n")
			for _, service := range template.Services {
				cli.dumpService(&buf, *service, indentLevel2Dash, indentLevel2DashLvl)
			}
		}
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(template, oldYamlConverter)
}

func (cli Zms) SetDomainTemplate(dn string, templateArgs []string) (*string, error) {
	templateNames := make([]zms.SimpleName, 0)
	templateParams := make([]*zms.TemplateParam, 0)
	for _, value := range templateArgs {
		idx := strings.Index(value, "=")
		if idx < 0 {
			templateNames = append(templateNames, zms.SimpleName(value))
		} else {
			param := zms.TemplateParam{
				Name:  zms.SimpleName(value[0:idx]),
				Value: value[idx+1:],
			}
			templateParams = append(templateParams, &param)
		}
	}
	//make sure we have some templates specified
	if len(templateNames) == 0 {
		return nil, fmt.Errorf("no template names specified")
	}
	var domainTemplateList zms.DomainTemplate
	domainTemplateList.TemplateNames = templateNames
	if len(templateParams) > 0 {
		domainTemplateList.Params = templateParams
	}
	err := cli.Zms.PutDomainTemplate(zms.DomainName(dn), cli.AuditRef, &domainTemplateList)
	if err != nil {
		return nil, err
	}
	s := "[Template(s) successfully applied to domain]"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) DeleteDomainTemplate(dn string, template string) (*string, error) {
	err := cli.Zms.DeleteDomainTemplate(zms.DomainName(dn), zms.SimpleName(template), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted template: " + template + "]"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}
