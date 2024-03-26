// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zms"
	"github.com/ardielle/ardielle-go/rdl"
)

func shortname(dn string, sn string) string {
	shortName := sn
	if strings.HasPrefix(shortName, dn+".") {
		shortName = shortName[len(dn)+1:]
	}
	return shortName
}

func (cli Zms) ListServices(dn string) (*string, error) {
	services := make([]string, 0)
	lst, err := cli.Zms.GetServiceIdentityList(zms.DomainName(dn), nil, "")
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		for _, name := range lst.Names {
			services = append(services, string(name))
		}
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

	return cli.dumpByFormat(lst, oldYamlConverter)
}

func (cli Zms) ShowService(dn string, sn string) (*string, error) {
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(sn))
	if err != nil {
		return nil, err
	}
	return cli.ShowUpdatedService(service)
}

func (cli Zms) ShowUpdatedService(service *zms.ServiceIdentity) (*string, error) {
	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("service:\n")
		cli.dumpService(&buf, *service, indentLevel1Dash, indentLevel1DashLvl)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(service, oldYamlConverter)
}

func (cli Zms) DeleteServiceTags(dn string, sn, tagKey string, tagValues []string) (*string, error) {
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(sn))
	if err != nil {
		return nil, err
	}

	tagValueArr := make([]zms.TagCompoundValue, 0)
	if service.Tags == nil {
		s := "[domain " + dn + " Service " + sn + " has no tags]\n"
		message := SuccessMessage{
			Status:  200,
			Message: s,
		}
		return cli.dumpByFormat(message, cli.buildYAMLOutput)
	} else {
		tagValueArr = cli.GetTagsAfterDeletion(service.Tags[zms.TagKey(tagKey)], tagValues)
	}

	service.Tags[zms.TagKey(tagKey)] = &zms.TagValueList{List: tagValueArr}
	returnObj := false

	_, err = cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(sn), cli.AuditRef, &returnObj, cli.ResourceOwner, service)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " service " + sn + " tags successfully deleted]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddServiceTags(dn string, sn, tagKey string, tagValues []string) (*string, error) {
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(sn))
	if err != nil {
		return nil, err
	}

	tagValueArr := make([]zms.TagCompoundValue, 0)

	if service.Tags == nil {
		service.Tags = map[zms.TagKey]*zms.TagValueList{}
	} else {
		// append current tags
		currentTagValues := service.Tags[zms.TagKey(tagKey)]
		if currentTagValues != nil {
			tagValueArr = append(tagValueArr, currentTagValues.List...)
		}
	}

	for _, tagValue := range tagValues {
		tagValueArr = append(tagValueArr, zms.TagCompoundValue(tagValue))
	}

	service.Tags[zms.TagKey(tagKey)] = &zms.TagValueList{List: tagValueArr}
	returnObj := false
	_, err = cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(sn), cli.AuditRef, &returnObj, cli.ResourceOwner, service)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " service " + sn + " tags successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) ShowServices(dn string, tagKey string, tagValue string) (*string, error) {
	if cli.OutputFormat == JSONOutputFormat || cli.OutputFormat == YAMLOutputFormat {
		publicKeys := true
		hosts := true
		services, err := cli.Zms.GetServiceIdentities(zms.DomainName(dn), &publicKeys, &hosts, zms.TagKey(tagKey), zms.TagCompoundValue(tagValue))
		if err != nil {
			return nil, fmt.Errorf("unable to get service list - error: %v", err)
		}
		return cli.dumpByFormat(services, cli.buildYAMLOutput)
	} else {
		var buf bytes.Buffer
		cli.dumpServices(&buf, dn, tagKey, tagValue)
		s := buf.String()
		return &s, nil
	}
}

func (cli Zms) AddService(dn string, sn string, keyID string, pubKey *string) (*string, error) {
	shortName := shortname(dn, sn)
	if !cli.Overwrite {
		service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName))
		if err == nil {
			return nil, fmt.Errorf("Service identity already exists: " + string(service.Name) + " - use add-public-key to add a key")
		}
	}
	longName := dn + "." + shortName
	var publicKeys []*zms.PublicKeyEntry
	if pubKey != nil {
		publicKeys = make([]*zms.PublicKeyEntry, 0)
		publicKey := zms.PublicKeyEntry{
			Key: *pubKey,
			Id:  keyID,
		}
		publicKeys = append(publicKeys, &publicKey)
	}
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
	returnObject := true
	updatedService, err := cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, &returnObject, cli.ResourceOwner, &detail)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowUpdatedService(updatedService)
}

func (cli Zms) AddProviderService(dn string, sn string, keyID string, pubKey *string) (*string, error) {
	shortName := shortname(dn, sn)
	if !cli.Overwrite {
		service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName))
		if err == nil {
			return nil, fmt.Errorf("Service identity already exists: " + string(service.Name) + " - use add-public-key to add a key")
		}
	}
	longName := dn + "." + shortName
	publicKeys := make([]*zms.PublicKeyEntry, 0)
	publicKey := zms.PublicKeyEntry{
		Key: *pubKey,
		Id:  keyID,
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
	returnObject := false
	_, err := cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, &returnObject, cli.ResourceOwner, &detail)
	if err != nil {
		return nil, err
	}
	// after our service has been created we are going to
	// create a self_serve role for this provider
	rn := shortName + "_self_serve"
	fullResourceName := dn + ":role." + rn
	var role zms.Role
	if !cli.Overwrite {
		_, err = cli.Zms.GetRole(zms.DomainName(dn), zms.EntityName(rn), nil, nil, nil)
		if err == nil {
			return nil, fmt.Errorf("provider service created but self serve role already exists: %v", fullResourceName)
		}
		switch v := err.(type) {
		case rdl.ResourceError:
			if v.Code != 404 {
				return nil, v
			}
		}
	}
	role.Name = zms.ResourceName(fullResourceName)
	role.Members = make([]zms.MemberName, 0)
	role.Members = append(role.Members, zms.MemberName(longName))
	_, err = cli.Zms.PutRole(zms.DomainName(dn), zms.EntityName(rn), cli.AuditRef, &returnObject, cli.ResourceOwner, &role)
	if err != nil {
		return nil, err
	}
	// now that the self_serve role has been created we are
	// going to create the self_serve policy for this
	// provider that would give access to all tenants
	pn := shortName + "_self_serve"
	fullResourceName = dn + ":policy." + pn
	if !cli.Overwrite {
		_, err = cli.Zms.GetPolicy(zms.DomainName(dn), zms.EntityName(pn))
		if err == nil {
			return nil, fmt.Errorf("provider service created but self serve policy already exists: %v", fullResourceName)
		}
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
	_, err = cli.Zms.PutPolicy(zms.DomainName(dn), zms.EntityName(pn), cli.AuditRef, &returnObject, cli.ResourceOwner, &policy)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	output, err := cli.ShowService(dn, shortName)
	if err != nil {
		// due to mysql read after write issue it's possible that
		// we'll get 404 after writing our object so in that
		// case we're going to do a quick sleep and retry request
		time.Sleep(500 * time.Millisecond)
		output, err = cli.ShowService(dn, shortName)
	}
	return output, err
}

func (cli Zms) AddServiceWithKeys(dn string, sn string, publicKeys []*zms.PublicKeyEntry) (*string, error) {
	shortName := shortname(dn, sn)
	if !cli.Overwrite {
		service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName))
		if err == nil {
			return nil, fmt.Errorf("Service identity already exists: " + string(service.Name) + " - use add-public-key to add a key")
		}
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
	returnObject := true
	updatedService, err := cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, &returnObject, cli.ResourceOwner, &detail)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowUpdatedService(updatedService)
}

func (cli Zms) SetServiceEndpoint(dn string, sn string, endpoint string) (*string, error) {
	shortName := shortname(dn, sn)
	meta := zms.ServiceIdentitySystemMeta{
		ProviderEndpoint: endpoint,
	}
	err := cli.Zms.PutServiceIdentitySystemMeta(zms.DomainName(dn), zms.SimpleName(shortName), "providerendpoint", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " service " + sn + " service-endpoint successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
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
	returnObject := true
	updatedService, err := cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, &returnObject, cli.ResourceOwner, service)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowUpdatedService(updatedService)
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
	returnObject := true
	updatedService, err := cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, &returnObject, cli.ResourceOwner, service)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowUpdatedService(updatedService)
}

func (cli Zms) DeleteServiceHost(dn string, sn string, hosts []string) (*string, error) {
	shortName := shortname(dn, sn)
	service, err := cli.Zms.GetServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName))
	if err != nil {
		return nil, err
	}
	if service.Hosts != nil {
		service.Hosts = cli.RemoveAll(service.Hosts, hosts)
		returnObject := false
		_, err = cli.Zms.PutServiceIdentity(zms.DomainName(dn), zms.SimpleName(shortName), cli.AuditRef, &returnObject, cli.ResourceOwner, service)
		if err != nil {
			return nil, err
		}
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowService(dn, shortName)
}

func (cli Zms) AddServicePublicKey(dn string, sn string, keyID string, pubKey *string) (*string, error) {
	shortName := shortname(dn, sn)
	publicKey := zms.PublicKeyEntry{
		Key: *pubKey,
		Id:  keyID,
	}
	err := cli.Zms.PutPublicKeyEntry(zms.DomainName(dn), zms.SimpleName(shortName), keyID, cli.AuditRef, cli.ResourceOwner, &publicKey)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowService(dn, shortName)
}

func (cli Zms) ShowServicePublicKey(dn string, sn string, keyID string) (*string, error) {
	shortName := shortname(dn, sn)
	pkey, err := cli.Zms.GetPublicKeyEntry(zms.DomainName(dn), zms.SimpleName(shortName), keyID)
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("public-key:\n")
		buf.WriteString(indentLevel1 + "keyID: " + pkey.Id + "\n")
		buf.WriteString(indentLevel1 + "value: " + pkey.Key + "\n")
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(pkey, oldYamlConverter)
}

func (cli Zms) DeleteServicePublicKey(dn string, sn string, keyID string) (*string, error) {
	shortName := shortname(dn, sn)
	err := cli.Zms.DeletePublicKeyEntry(zms.DomainName(dn), zms.SimpleName(shortName), keyID, cli.AuditRef, cli.ResourceOwner)
	if err != nil {
		return nil, err
	}
	if cli.Bulkmode {
		s := ""
		return &s, nil
	}
	return cli.ShowService(dn, shortName)
}

func (cli Zms) DeleteService(dn string, sn string) (*string, error) {
	err := cli.Zms.DeleteServiceIdentity(zms.DomainName(dn), zms.SimpleName(sn), cli.AuditRef, cli.ResourceOwner)
	if err != nil {
		return nil, err
	}
	s := "[Deleted service identity: " + dn + "." + sn + "]"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}
