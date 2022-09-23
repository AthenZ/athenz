// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zms"
)

func (cli Zms) DeleteTenancy(dn string, provider string) (*string, error) {
	err := cli.Zms.DeleteTenancy(zms.DomainName(dn), zms.ServiceName(provider), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Successfully deleted tenant " + dn + " from provider " + provider + "]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddTenancy(dn string, provider string, createAdminRole bool) (*string, error) {
	tenancy := zms.Tenancy{
		Domain:          zms.DomainName(dn),
		Service:         zms.ServiceName(provider),
		ResourceGroups:  nil,
		CreateAdminRole: &createAdminRole,
	}
	err := cli.Zms.PutTenancy(zms.DomainName(dn), zms.ServiceName(provider), cli.AuditRef, &tenancy)
	if err != nil {
		return nil, err
	}
	s := "[Successfully added tenant " + dn + " to provider " + provider + "]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddTenant(provDomain string, provService string, tenantDomain string) (*string, error) {
	tenancy := zms.Tenancy{
		Domain:         zms.DomainName(tenantDomain),
		Service:        zms.ServiceName(provDomain + "." + provService),
		ResourceGroups: nil,
	}
	err := cli.Zms.PutTenant(zms.DomainName(provDomain), zms.SimpleName(provService), zms.DomainName(tenantDomain), cli.AuditRef, &tenancy)
	if err != nil {
		return nil, err
	}
	s := "[Successfully added tenant " + tenantDomain + " to provider " + provDomain + "." + provService + "]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) DeleteTenant(provDomain string, provService string, tenantDomain string) (*string, error) {
	err := cli.Zms.DeleteTenant(zms.DomainName(provDomain), zms.SimpleName(provService), zms.DomainName(tenantDomain), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Successfully deleted tenant " + tenantDomain + " from provider " + provDomain + "." + provService + "]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) ShowTenantResourceGroupRoles(provDomain string, provService string, tenantDomain string, resourceGroup string) (*string, error) {
	tenantRoles, err := cli.Zms.GetTenantResourceGroupRoles(zms.DomainName(provDomain), zms.SimpleName(provService), zms.DomainName(tenantDomain), zms.EntityName(resourceGroup))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("resource-group:\n")
		cli.dumpTenantResourceGroupRoles(&buf, tenantRoles, indentLevel1Dash, indentLevel1DashLvl)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(tenantRoles, oldYamlConverter)
}

func (cli Zms) DeleteTenantResourceGroupRoles(provDomain string, provService string, tenantDomain string, resourceGroup string) (*string, error) {
	err := cli.Zms.DeleteTenantResourceGroupRoles(zms.DomainName(provDomain), zms.SimpleName(provService), zms.DomainName(tenantDomain), zms.EntityName(resourceGroup), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Successfully deleted resource group " + resourceGroup + " roles for tenant: " + tenantDomain + "]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddTenantResourceGroupRoles(provDomain string, provService string, tenantDomain string, resourceGroup string, roleActions []string) (*string, error) {
	tenantRoleActions := make([]*zms.TenantRoleAction, 0)
	for _, item := range roleActions {
		tokens := strings.Split(item, "=")
		if len(tokens) == 2 {
			roleToken := zms.TenantRoleAction{
				Role:   zms.SimpleName(tokens[0]),
				Action: tokens[1],
			}
			tenantRoleActions = append(tenantRoleActions, &roleToken)
		}
	}
	tenantRoles := zms.TenantResourceGroupRoles{
		Domain:        zms.DomainName(provDomain),
		Service:       zms.SimpleName(provService),
		Tenant:        zms.DomainName(tenantDomain),
		Roles:         tenantRoleActions,
		ResourceGroup: zms.EntityName(resourceGroup),
	}
	_, err := cli.Zms.PutTenantResourceGroupRoles(zms.DomainName(provDomain), zms.SimpleName(provService), zms.DomainName(tenantDomain), zms.EntityName(resourceGroup), cli.AuditRef, &tenantRoles)
	if err != nil {
		return nil, err
	}
	output, err := cli.ShowTenantResourceGroupRoles(provDomain, provService, tenantDomain, resourceGroup)
	if err != nil {
		// due to mysql read after write issue it's possible that
		// we'll get 404 after writing our object so in that
		// case we're going to do a quick sleep and retry request
		time.Sleep(500 * time.Millisecond)
		output, err = cli.ShowTenantResourceGroupRoles(provDomain, provService, tenantDomain, resourceGroup)
	}
	return output, err
}

func (cli Zms) ShowProviderResourceGroupRoles(tenantDomain string, providerDomain string, providerService string, resourceGroup string) (*string, error) {
	providerRoles, err := cli.Zms.GetProviderResourceGroupRoles(zms.DomainName(tenantDomain), zms.DomainName(providerDomain), zms.SimpleName(providerService), zms.EntityName(resourceGroup))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("resource-group:\n")
		cli.dumpProviderResourceGroupRoles(&buf, providerRoles, indentLevel1Dash, indentLevel1DashLvl)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(providerRoles, oldYamlConverter)
}

func (cli Zms) DeleteProviderResourceGroupRoles(tenantDomain string, providerDomain string, providerService string, resourceGroup string) (*string, error) {
	err := cli.Zms.DeleteProviderResourceGroupRoles(zms.DomainName(tenantDomain), zms.DomainName(providerDomain), zms.SimpleName(providerService), zms.EntityName(resourceGroup), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Successfully deleted resource group " + resourceGroup + " roles for tenant: " + tenantDomain + "]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddProviderResourceGroupRoles(tenantDomain string, providerDomain string, providerService string, resourceGroup string, createAdminRole bool, roleActions []string) (*string, error) {
	tenantRoleActions := make([]*zms.TenantRoleAction, 0)
	for _, item := range roleActions {
		tokens := strings.Split(item, "=")
		if len(tokens) == 2 {
			roleToken := zms.TenantRoleAction{
				Role:   zms.SimpleName(tokens[0]),
				Action: tokens[1],
			}
			tenantRoleActions = append(tenantRoleActions, &roleToken)
		}
	}
	providerRoles := zms.ProviderResourceGroupRoles{
		Domain:          zms.DomainName(providerDomain),
		Service:         zms.SimpleName(providerService),
		Tenant:          zms.DomainName(tenantDomain),
		Roles:           tenantRoleActions,
		ResourceGroup:   zms.EntityName(resourceGroup),
		CreateAdminRole: &createAdminRole,
	}

	_, err := cli.Zms.PutProviderResourceGroupRoles(zms.DomainName(tenantDomain), zms.DomainName(providerDomain), zms.SimpleName(providerService), zms.EntityName(resourceGroup), cli.AuditRef, &providerRoles)
	if err != nil {
		return nil, err
	}
	output, err := cli.ShowProviderResourceGroupRoles(tenantDomain, providerDomain, providerService, resourceGroup)
	if err != nil {
		// due to mysql read after write issue it's possible that
		// we'll get 404 after writing our object so in that
		// case we're going to do a quick sleep and retry request
		time.Sleep(500 * time.Millisecond)
		output, err = cli.ShowProviderResourceGroupRoles(tenantDomain, providerDomain, providerService, resourceGroup)
	}
	return output, err
}
