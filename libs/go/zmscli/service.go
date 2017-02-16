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

func shortname(dn string, sn string) string {
	shortName := sn
	if strings.HasPrefix(shortName, dn+".") {
		shortName = shortName[len(dn)+1:]
	}
	return shortName
}

func (cli Zms) serviceNames(dn string) ([]string, error) {
	services := make([]string, 0)
	lst, err := cli.Zms.GetServiceIdentityList(zms.DomainName(dn), nil, "")
	if err != nil {
		return nil, err
	}
	for _, name := range lst.Names {
		services = append(services, string(name))
	}
	return services, nil
}

func (cli Zms) ListServices(dn string) (*string, error) {
	var buf bytes.Buffer
	services, err := cli.serviceNames(dn)
	if err != nil {
		return nil, err
	}
	if len(services) == 0 {
		buf.WriteString("services: []\n")
	} else {
		buf.WriteString("services:\n")
		cli.dumpObjectList(&buf, services, dn, "service")
	}
	s := buf.String()
	return &s, nil
}

func (cli Zms) ShowService(dn string, sn string) (*string, error) {
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(sn))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("service:\n")
	cli.dumpService(&buf, *service, indent_level1_dash, indent_level1_dash_lvl)
	s := buf.String()
	return &s, nil
}

func (cli Zms) AddService(dn string, sn string, keyId string, pubKey *string) (*string, error) {
	shortName := shortname(dn, sn)
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName))
	if err == nil {
		return nil, fmt.Errorf("Service identity already exists: " + string(service.Name) + " - use add-public-key to add a key")
	}
	longName := dn + "." + shortName
	publicKeys := make([]*zms.PublicKeyEntry, 0)
	publicKey := zms.PublicKeyEntry{
		Key: *pubKey,
		Id:  keyId,
	}
	publicKeys = append(publicKeys, &publicKey)
	detail := zms.ServiceIdentity{
		Name:             zms.ServiceName(longName),
		PublicKeys:       publicKeys,
		ProviderEndpoint: "",
		Modified:         nil,
		Executable:       "",
		Hosts:            nil,
		User:             "",
		Group:            "",
	}
	err = cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, &detail)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowService(dn, shortName)
	}
}

func (cli Zms) AddProviderService(dn string, sn string, keyId string, pubKey *string) (*string, error) {
	shortName := shortname(dn, sn)
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName))
	if err == nil {
		return nil, fmt.Errorf("Service identity already exists: " + string(service.Name) + " - use add-public-key to add a key")
	}
	longName := dn + "." + shortName
	publicKeys := make([]*zms.PublicKeyEntry, 0)
	publicKey := zms.PublicKeyEntry{
		Key: *pubKey,
		Id:  keyId,
	}
	publicKeys = append(publicKeys, &publicKey)
	detail := zms.ServiceIdentity{
		Name:             zms.ServiceName(longName),
		PublicKeys:       publicKeys,
		ProviderEndpoint: "",
		Modified:         nil,
		Executable:       "",
		Hosts:            nil,
		User:             "",
		Group:            "",
	}
	err = cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, &detail)
	if err != nil {
		return nil, err
	}
	// after our service has been created we are going to
	// create a self_serve role for this provider
	rn := shortName + "_self_serve"
	fullResourceName := dn + ":role." + rn
	var role zms.Role
	_, err = cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil)
	if err == nil {
		return nil, fmt.Errorf("Provider Service created but Self Serve Role already exists: %v", fullResourceName)
	} else {
		switch v := err.(type) {
		case rdl.ResourceError:
			if v.Code != 404 {
				return nil, v
			}
		}
	}
	role.Name = zms.ResourceName(fullResourceName)
	role.Members = make([]zms.ResourceName, 0)
	role.Members = append(role.Members, zms.ResourceName(longName))
	err = cli.Zms.PutRole(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, &role)
	if err != nil {
		return nil, err
	}
	// now that the self_serve role has been created we are
	// going to create the self_serve policy for this
	// provider that would give access to all tenants
	pn := shortName + "_self_serve"
	fullResourceName = dn + ":policy." + pn
	_, err = cli.Zms.GetPolicy(zms.DomainName(dn), zms.EntityName(pn))
	if err == nil {
		return nil, fmt.Errorf("Provider Service created but Self Serve Policy already exists: %v", fullResourceName)
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
	assertion := make([]string, 0)
	assertion = append(assertion, "grant")
	assertion = append(assertion, "update")
	assertion = append(assertion, "to")
	assertion = append(assertion, rn)
	assertion = append(assertion, "on")
	assertion = append(assertion, "tenant.*")
	newAssertion, err := parseAssertion(dn, assertion)
	if err != nil {
		return nil, err
	}
	tmp := [1]*zms.Assertion{newAssertion}
	policy.Assertions = tmp[:]
	err = cli.Zms.PutPolicy(zms.DomainName(dn), zms.EntityName(pn), cli.AuditRef, &policy)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowService(dn, shortName)
	}
}

func (cli Zms) AddServiceWithKeys(dn string, sn string, publicKeys []*zms.PublicKeyEntry) (*string, error) {
	shortName := shortname(dn, sn)
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName))
	if err == nil {
		return nil, fmt.Errorf("Service identity already exists: " + string(service.Name) + " - use add-public-key to add a key")
	}
	longName := dn + "." + shortName
	detail := zms.ServiceIdentity{
		Name:             zms.ServiceName(longName),
		PublicKeys:       publicKeys,
		ProviderEndpoint: "",
		Modified:         nil,
		Executable:       "",
		Hosts:            nil,
		User:             "",
		Group:            "",
	}
	err = cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, &detail)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowService(dn, shortName)
	}
}

func (cli Zms) SetServiceEndpoint(dn string, sn string, endpoint string) (*string, error) {
	shortName := shortname(dn, sn)
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName))
	if err != nil {
		return nil, err
	}
	service.ProviderEndpoint = endpoint
	err = cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, service)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowService(dn, shortName)
	}
}

func (cli Zms) SetServiceExe(dn string, sn string, exe string, user string, group string) (*string, error) {
	shortName := shortname(dn, sn)
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName))
	if err != nil {
		return nil, err
	}
	service.Executable = exe
	service.User = user
	service.Group = group
	err = cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, service)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowService(dn, shortName)
	}
}

func (cli Zms) AddServiceHost(dn string, sn string, hosts []string) (*string, error) {
	shortName := shortname(dn, sn)
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName))
	if err != nil {
		return nil, err
	}
	if service.Hosts == nil {
		service.Hosts = hosts
	} else {
		for _, host := range hosts {
			if !cli.contains(service.Hosts, host) {
				service.Hosts = append(service.Hosts, host)
			}
		}
	}
	err = cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, service)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowService(dn, shortName)
	}
}

func (cli Zms) DeleteServiceHost(dn string, sn string, hosts []string) (*string, error) {
	shortName := shortname(dn, sn)
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName))
	if err != nil {
		return nil, err
	}
	if service.Hosts != nil {
		service.Hosts = cli.RemoveAll(service.Hosts, hosts)
		err = cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, service)
		if err != nil {
			return nil, err
		}
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowService(dn, shortName)
	}
}

func (cli Zms) AddServicePublicKey(dn string, sn string, keyId string, pubKey *string) (*string, error) {
	shortName := shortname(dn, sn)
	publicKey := zms.PublicKeyEntry{
		Key: *pubKey,
		Id:  keyId,
	}
	err := cli.Zms.PutPublicKeyEntry(zms.DomainName(dn), zms.SimpleName(shortName), keyId, cli.AuditRef, &publicKey)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowService(dn, shortName)
	}
}

func (cli Zms) ShowServicePublicKey(dn string, sn string, keyId string) (*string, error) {
	var buf bytes.Buffer
	shortName := shortname(dn, sn)
	pkey, err := cli.Zms.GetPublicKeyEntry(zms.DomainName(dn), zms.SimpleName(shortName), keyId)
	if err != nil {
		return nil, err
	}
	buf.WriteString("public-key:\n")
	buf.WriteString(indent_level1 + "keyId: " + pkey.Id + "\n")
	buf.WriteString(indent_level1 + "value: " + pkey.Key + "\n")
	s := buf.String()
	return &s, nil
}

func (cli Zms) DeleteServicePublicKey(dn string, sn string, keyId string) (*string, error) {
	shortName := shortname(dn, sn)
	err := cli.Zms.DeletePublicKeyEntry(zms.DomainName(dn), zms.SimpleName(shortName), keyId, cli.AuditRef)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	} else {
		return cli.ShowService(dn, shortName)
	}
}

func (cli Zms) DeleteService(dn string, sn string) (*string, error) {
	err := cli.Zms.DeleteServiceIdentity(zms.DomainName(dn), zms.SimpleName(sn), cli.AuditRef)
	if err != nil {
		return nil, err
	} else {
		s := "[Deleted service identity: " + dn + "." + sn + "]"
		return &s, nil
	}
}
