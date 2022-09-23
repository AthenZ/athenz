// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zms"
	"github.com/ardielle/ardielle-go/rdl"
)

func (cli Zms) ShowEntity(dn string, en string) (*string, error) {
	entity, err := cli.Zms.GetEntity(zms.DomainName(dn), zms.EntityName(en))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("entity:\n")
		cli.dumpEntity(&buf, *entity, indentLevel1Dash, indentLevel1DashLvl)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(entity, oldYamlConverter)
}

func (cli Zms) AddEntity(dn string, en string, values []string) (*string, error) {
	entityValue := make(map[rdl.Symbol]interface{})
	for _, item := range values {
		tokens := strings.Split(item, "=")
		if len(tokens) == 2 {
			entityValue[rdl.Symbol(tokens[0])] = tokens[1]
		}
	}
	var entity zms.Entity
	fullResourceName := dn + ":entity." + en
	entity.Name = zms.ResourceName(fullResourceName)
	entity.Value = entityValue
	err := cli.Zms.PutEntity(zms.DomainName(dn), zms.EntityName(en), cli.AuditRef, &entity)
	if err != nil {
		return nil, err
	}
	output, err := cli.ShowEntity(dn, en)
	if err != nil {
		// due to mysql read after write issue it's possible that
		// we'll get 404 after writing our object so in that
		// case we're going to do a quick sleep and retry request
		time.Sleep(500 * time.Millisecond)
		output, err = cli.ShowEntity(dn, en)
	}
	return output, err
}

func (cli Zms) DeleteEntity(dn string, en string) (*string, error) {
	err := cli.Zms.DeleteEntity(zms.DomainName(dn), zms.EntityName(en), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Deleted entity: " + dn + "." + en + "]"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) entityNames(dn string) ([]string, error) {
	entities := make([]string, 0)
	lst, err := cli.Zms.GetEntityList(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	for _, n := range lst.Names {
		entities = append(entities, string(n))
	}
	return entities, nil
}

func (cli Zms) ListEntities(dn string) (*string, error) {
	entities, err := cli.entityNames(dn)
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("entities:\n")
		cli.dumpObjectList(&buf, entities, dn, "entity")
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(entities, oldYamlConverter)
}
