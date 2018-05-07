// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
)

func (cli Zms) DeleteTenancy(dn string, provider string) (*string, error) {
	err := cli.Zms.DeleteTenancy(zms.DomainName(dn), zms.ServiceName(provider), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Successfully deleted tenant " + dn + " from provider " + provider + "]\n"
	return &s, nil
}

func (cli Zms) AddTenancy(dn string, provider string) (*string, error) {
	tenancy := zms.Tenancy{
		Domain:         zms.DomainName(dn),
		Service:        zms.ServiceName(provider),
		ResourceGroups: nil,
	}
	err := cli.Zms.PutTenancy(zms.DomainName(dn), zms.ServiceName(provider), cli.AuditRef, &tenancy)
	if err != nil {
		return nil, err
	}
	s := "[Successfully added tenant " + dn + " to provider " + provider + "]\n"
	return &s, nil
}

func (cli Zms) ShowTenantResourceGroupRoles(provDomain string, provService string, tenantDomain string, resourceGroup string) (*string, error) {
	tenantRoles, err := cli.Zms.GetTenantResourceGroupRoles(zms.DomainName(provDomain), zms.SimpleName(provService), zms.DomainName(tenantDomain), zms.EntityName(resourceGroup))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("resource-group:\n")
	cli.dumpTenantResourceGroupRoles(&buf, tenantRoles, indent_level1_dash, indent_level1_dash_lvl)
	s := buf.String()
	return &s, nil
}

func (cli Zms) DeleteTenantResourceGroupRoles(provDomain string, provService string, tenantDomain string, resourceGroup string) (*string, error) {
	err := cli.Zms.DeleteTenantResourceGroupRoles(zms.DomainName(provDomain), zms.SimpleName(provService), zms.DomainName(tenantDomain), zms.EntityName(resourceGroup), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Successfully deleted resource group " + resourceGroup + " roles for tenant: " + tenantDomain + "]\n"
	return &s, nil
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
	return cli.ShowTenantResourceGroupRoles(provDomain, provService, tenantDomain, resourceGroup)
}

func (cli Zms) ShowProviderResourceGroupRoles(tenantDomain string, providerDomain string, providerService string, resourceGroup string) (*string, error) {
	providerRoles, err := cli.Zms.GetProviderResourceGroupRoles(zms.DomainName(tenantDomain), zms.DomainName(providerDomain), zms.SimpleName(providerService), zms.EntityName(resourceGroup))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("resource-group:\n")
	cli.dumpProviderResourceGroupRoles(&buf, providerRoles, indent_level1_dash, indent_level1_dash_lvl)
	s := buf.String()
	return &s, nil
}

func (cli Zms) DeleteProviderResourceGroupRoles(tenantDomain string, providerDomain string, providerService string, resourceGroup string) (*string, error) {
	err := cli.Zms.DeleteProviderResourceGroupRoles(zms.DomainName(tenantDomain), zms.DomainName(providerDomain), zms.SimpleName(providerService), zms.EntityName(resourceGroup), cli.AuditRef)
	if err != nil {
		return nil, err
	}
	s := "[Successfully deleted resource group " + resourceGroup + " roles for tenant: " + tenantDomain + "]\n"
	return &s, nil
}

func (cli Zms) AddProviderResourceGroupRoles(tenantDomain string, providerDomain string, providerService string, resourceGroup string, roleActions []string) (*string, error) {
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
		Domain:        zms.DomainName(providerDomain),
		Service:       zms.SimpleName(providerService),
		Tenant:        zms.DomainName(tenantDomain),
		Roles:         tenantRoleActions,
		ResourceGroup: zms.EntityName(resourceGroup),
	}
	_, err := cli.Zms.PutProviderResourceGroupRoles(zms.DomainName(tenantDomain), zms.DomainName(providerDomain), zms.SimpleName(providerService), zms.EntityName(resourceGroup), cli.AuditRef, &providerRoles)
	if err != nil {
		return nil, err
	}
	return cli.ShowProviderResourceGroupRoles(tenantDomain, providerDomain, providerService, resourceGroup)
}
