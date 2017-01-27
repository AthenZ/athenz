// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"strings"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/yahoo/athenz/clients/go/zms"
)

func (cli Zms) ShowEntity(dn string, en string) (*string, error) {
	entity, err := cli.Zms.GetEntity(zms.DomainName(dn), zms.EntityName(en))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("entity:\n")
	cli.dumpEntity(&buf, *entity, indent_level1_dash, indent_level1_dash_lvl)
	s := buf.String()
	return &s, nil
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
	entity.Name = zms.EntityName(en)
	entity.Value = entityValue
	err := cli.Zms.PutEntity(zms.DomainName(dn), zms.EntityName(en), cli.AuditRef, &entity)
	if err != nil {
		return nil, err
	}
	return cli.ShowEntity(dn, en)
}

func (cli Zms) DeleteEntity(dn string, en string) (*string, error) {
	err := cli.Zms.DeleteEntity(zms.DomainName(dn), zms.EntityName(en), cli.AuditRef)
	if err != nil {
		return nil, err
	} else {
		s := "[Deleted entity: " + dn + "." + en + "]"
		return &s, nil
	}
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
	var buf bytes.Buffer
	entities, err := cli.entityNames(dn)
	if err != nil {
		return nil, err
	}
	buf.WriteString("entities:\n")
	cli.dumpObjectList(&buf, entities, dn, "entity")
	s := buf.String()
	return &s, nil
}
