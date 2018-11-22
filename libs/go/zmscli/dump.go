// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"log"
	"strconv"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
)

var (
	indent_level1          = "    "
	indent_level1_dash     = "    - "
	indent_level1_dash_lvl = "      "
	indent_level2          = "        "
	indent_level2_dash     = "        - "
	indent_level2_dash_lvl = "          "
	indent_level3          = "            "
)

func (cli Zms) dumpDomain(buf *bytes.Buffer, domain *zms.Domain) {
	buf.WriteString("domain:\n")

	buf.WriteString(indent_level1)
	buf.WriteString("name: ")
	buf.WriteString(string(domain.Name))
	buf.WriteString("\n")

	if domain.Description != "" {
		buf.WriteString(indent_level1)
		buf.WriteString("description: ")
		buf.WriteString(domain.Description)
		buf.WriteString("\n")
	}
	if domain.Account != "" {
		buf.WriteString(indent_level1)
		buf.WriteString("aws_account: '")
		buf.WriteString(domain.Account)
		buf.WriteString("'\n")
	}
	productID := int(*domain.YpmId)
	if productID != 0 {
		buf.WriteString(indent_level1)
		buf.WriteString("product_id: ")
		buf.WriteString(strconv.Itoa(productID))
		buf.WriteString("\n")
	}
	if domain.Org != "" {
		buf.WriteString(indent_level1)
		buf.WriteString("org: ")
		buf.WriteString(string(domain.Org))
		buf.WriteString("\n")
	}
	if domain.AuditEnabled != nil {
		buf.WriteString(indent_level1)
		buf.WriteString("audit_enabled: ")
		buf.WriteString(strconv.FormatBool(*domain.AuditEnabled))
		buf.WriteString("\n")
	}
}

func (cli Zms) dumpDataCheck(buf *bytes.Buffer, dataCheck zms.DomainDataCheck) {
	if len(dataCheck.DanglingRoles) != 0 {
		buf.WriteString(indent_level1)
		buf.WriteString("Roles not referenced in any assertion or empty: \n")
		for _, item := range dataCheck.DanglingRoles {
			buf.WriteString(indent_level2 + string(item) + "\n")
		}
	}
	if dataCheck.DanglingPolicies != nil {
		buf.WriteString(indent_level1)
		buf.WriteString("Policies where assertion is referencing a non-existent role: \n")
		for _, item := range dataCheck.DanglingPolicies {
			buf.WriteString(indent_level2 + "policy: " + string(item.PolicyName) + " role: " + string(item.RoleName) + "\n")
		}
	}
	buf.WriteString(indent_level1)
	buf.WriteString("Number of policies:   " + strconv.Itoa(int(dataCheck.PolicyCount)) + "\n")
	buf.WriteString(indent_level1)
	buf.WriteString("Number of assertions: " + strconv.Itoa(int(dataCheck.AssertionCount)) + "\n")
	if len(dataCheck.ProvidersWithoutTrust) != 0 {
		buf.WriteString(indent_level1)
		buf.WriteString("On-boarded providers without trust relationship: \n")
		for _, item := range dataCheck.ProvidersWithoutTrust {
			buf.WriteString(indent_level2 + string(item) + "\n")
		}
	}
	if len(dataCheck.TenantsWithoutAssumeRole) != 0 {
		buf.WriteString(indent_level1)
		buf.WriteString("On-boarded tenants without assume_role assertions: \n")
		for _, item := range dataCheck.TenantsWithoutAssumeRole {
			buf.WriteString(indent_level2 + string(item) + "\n")
		}
	}
}

func (cli Zms) displayObjectName(buf *bytes.Buffer, fullResourceName string, objType string, indent1 string) {
	buf.WriteString(indent1)
	buf.WriteString("name: ")
	if cli.Verbose || objType == "" {
		buf.WriteString(fullResourceName)
	} else {
		buf.WriteString(localName(fullResourceName, objType))
	}
	buf.WriteString("\n")
}

func (cli Zms) dumpRole(buf *bytes.Buffer, role zms.Role, auditLog bool, indent1 string, indent2 string) {
	cli.displayObjectName(buf, string(role.Name), ":role.", indent1)
	if role.RoleMembers != nil && len(role.RoleMembers) > 0 {
		buf.WriteString(indent2)
		buf.WriteString("members:\n")
		indent3 := indent2 + "  - "
		for _, memberItem := range role.RoleMembers {
			buf.WriteString(indent3)
			cli.dumpUserName(buf, string(memberItem.MemberName), true)
			if memberItem.Expiration != nil {
				buf.WriteString(" " + memberItem.Expiration.String())
			}
			buf.WriteString("\n")
		}
	}
	if auditLog {
		buf.WriteString(indent2)
		buf.WriteString("changes: \n")
		indent3_dash := indent2 + "  - "
		indent3_dash_lvl := indent2 + "    "
		for _, logItem := range role.AuditLog {
			buf.WriteString(indent3_dash + "Action: " + logItem.Action + "\n")
			buf.WriteString(indent3_dash_lvl + "Admin: " + string(logItem.Admin) + "\n")
			buf.WriteString(indent3_dash_lvl + "Member: " + string(logItem.Member) + "\n")
			buf.WriteString(indent3_dash_lvl + "Date: " + logItem.Created.String() + "\n")
			buf.WriteString(indent3_dash_lvl + "Ref: " + logItem.AuditRef + "\n")
		}
	}
	if role.Trust != "" {
		buf.WriteString(indent2)
		buf.WriteString("trust: ")
		buf.WriteString(string(role.Trust))
		buf.WriteString("\n")
	}
}

func (cli Zms) dumpRoles(buf *bytes.Buffer, dn string) {
	buf.WriteString(indent_level1)
	buf.WriteString("roles:\n")
	members := true
	roles, err := cli.Zms.GetRoles(zms.DomainName(dn), &members)
	if err != nil {
		log.Fatalf("Unable to get role list - error: %v", err)
	}
	for _, role := range roles.List {
		cli.dumpRole(buf, *role, false, indent_level2_dash, indent_level2_dash_lvl)
	}
}

func localName(fullResourceName string, prefix string) string {
	idx := strings.Index(fullResourceName, prefix)
	s := fullResourceName
	if idx != -1 {
		s = fullResourceName[idx+len(prefix):]
	}
	return s
}

func (cli Zms) dumpAssertion(buf *bytes.Buffer, assertion *zms.Assertion, dn string, indent1 string) {
	showFullResourceName := cli.Verbose
	buf.WriteString(indent1)
	effect := "grant"
	if assertion.Effect != nil {
		effect = strings.ToLower(assertion.Effect.String())
		if effect == "allow" {
			effect = "grant"
		}
	}
	buf.WriteString(effect)
	buf.WriteString(" ")
	buf.WriteString(assertion.Action)
	buf.WriteString(" to ")
	if showFullResourceName {
		buf.WriteString(assertion.Role)
	} else {
		buf.WriteString(localName(assertion.Role, ":role."))
	}
	buf.WriteString(" on ")
	if showFullResourceName {
		buf.WriteString(assertion.Resource)
	} else {
		prefix := dn + ":"
		if strings.HasPrefix(assertion.Resource, prefix) {
			buf.WriteString(assertion.Resource[len(prefix):])
		} else {
			buf.WriteString(assertion.Resource)
		}
	}
	buf.WriteString("\n")
}

func (cli Zms) dumpPolicy(buf *bytes.Buffer, policy zms.Policy, indent1 string, indent2 string) {
	resourceName := string(policy.Name)
	cli.displayObjectName(buf, resourceName, ":policy.", indent1)
	dn := resourceName[0:strings.LastIndex(resourceName, ":")]
	buf.WriteString(indent2)
	if len(policy.Assertions) == 0 {
		buf.WriteString("assertions: []\n")
	} else {
		buf.WriteString("assertions:\n")
		indent3 := indent2 + "  - "
		for _, assertion := range policy.Assertions {
			cli.dumpAssertion(buf, assertion, dn, indent3)
		}
	}
}

func (cli Zms) dumpPolicies(buf *bytes.Buffer, dn string) {
	buf.WriteString(indent_level1)
	buf.WriteString("policies:\n")
	assertions := true
	policies, err := cli.Zms.GetPolicies(zms.DomainName(dn), &assertions)
	if err != nil {
		log.Fatalf("Unable to get policy list - error: %v", err)
	}
	for _, policy := range policies.List {
		cli.dumpPolicy(buf, *policy, indent_level2_dash, indent_level2_dash_lvl)
	}
}

func (cli Zms) dumpEntities(buf *bytes.Buffer, dn string, entitynames []string) {
	if len(entitynames) > 0 {
		buf.WriteString(indent_level1)
		buf.WriteString("entities:\n")
		for _, en := range entitynames {
			entity, err := cli.Zms.GetEntity(zms.DomainName(dn), zms.EntityName(en))
			if err != nil {
				return
			}
			cli.dumpEntity(buf, *entity, indent_level2_dash, indent_level2_dash_lvl)
		}
	}
}

func (cli Zms) dumpEntity(buf *bytes.Buffer, entity zms.Entity, indent1 string, indent2 string) {
	cli.displayObjectName(buf, string(entity.Name), "", indent1)
	buf.WriteString(indent2)
	buf.WriteString("value:\n")
	indent3_dash := indent2 + "  - "
	indent3_dash_lvl := indent2 + "    "
	for key, data := range entity.Value {
		buf.WriteString(indent3_dash + "key: " + string(key) + "\n")
		buf.WriteString(indent3_dash_lvl + "data: " + data.(string) + "\n")
	}
}

func (cli Zms) dumpService(buf *bytes.Buffer, svc zms.ServiceIdentity, indent1 string, indent2 string) {
	cli.displayObjectName(buf, string(svc.Name), "", indent1)
	if svc.Modified != nil {
		buf.WriteString(indent2)
		buf.WriteString("modified: ")
		buf.WriteString(svc.Modified.String())
		buf.WriteString("\n")
	}
	if svc.Executable != "" {
		buf.WriteString(indent2)
		buf.WriteString("executable: ")
		buf.WriteString(svc.Executable)
		buf.WriteString("\n")
	}
	if svc.User != "" {
		buf.WriteString(indent2)
		buf.WriteString("user: ")
		buf.WriteString(svc.User)
		buf.WriteString("\n")
	}
	if svc.Group != "" {
		buf.WriteString(indent2)
		buf.WriteString("group: ")
		buf.WriteString(svc.Group)
		buf.WriteString("\n")
	}
	if svc.ProviderEndpoint != "" {
		buf.WriteString(indent2)
		buf.WriteString("providerEndpoint: ")
		buf.WriteString(svc.ProviderEndpoint)
		buf.WriteString("\n")
	}
	if svc.Hosts != nil {
		buf.WriteString(indent2)
		buf.WriteString("hosts: [")
		buf.WriteString(strings.Join(svc.Hosts, ", "))
		buf.WriteString("]\n")
	}
	buf.WriteString(indent2)
	if len(svc.PublicKeys) == 0 {
		buf.WriteString("publicKeys: []\n")
	} else {
		buf.WriteString("publicKeys: \n")
		for _, publicKey := range svc.PublicKeys {
			buf.WriteString(indent2 + "  - keyId: " + publicKey.Id + "\n")
			buf.WriteString(indent2 + "    value: " + publicKey.Key + "\n")
		}
	}
}

func (cli Zms) dumpObjectList(buf *bytes.Buffer, list []string, dn string, object string) {
	for _, item := range list {
		if cli.Verbose {
			buf.WriteString(indent_level1_dash + dn + ":" + object + "." + item + "\n")
		} else {
			buf.WriteString(indent_level1_dash + item + "\n")
		}
	}
}

func (cli Zms) dumpServices(buf *bytes.Buffer, dn string) {
	publickeys := true
	hosts := true
	services, err := cli.Zms.GetServiceIdentities(zms.DomainName(dn), &publickeys, &hosts)
	if err != nil {
		log.Fatalf("Unable to get service list - error: %v", err)
	}
	if len(services.List) > 0 {
		buf.WriteString(indent_level1)
		buf.WriteString("services:\n")
		for _, service := range services.List {
			cli.dumpService(buf, *service, indent_level2_dash, indent_level2_dash_lvl)
		}
	}
}

func (cli Zms) dumpMultilineString(buf *bytes.Buffer, s string, indent string) {
	lst := strings.Split(s, "\n")
	if len(lst) > 0 {
		buf.WriteString("\n")
		for _, ss := range lst {
			buf.WriteString(indent)
			buf.WriteString(ss)
			buf.WriteString("\n")
		}
	} else {
		buf.WriteString(s)
	}
}

func (cli Zms) dumpTenancy(buf *bytes.Buffer, tenancy *zms.Tenancy, indent string) {
	buf.WriteString(indent + "tenant: " + string(tenancy.Domain) + "\n")
	buf.WriteString(indent + "provider: " + string(tenancy.Service) + "\n")
	for _, resourceGroup := range tenancy.ResourceGroups {
		buf.WriteString(indent + "resource-group: " + string(resourceGroup) + "\n")
	}
}

func (cli Zms) dumpTenantResourceGroupRoles(buf *bytes.Buffer, tenantRoles *zms.TenantResourceGroupRoles, indent1 string, indent2 string) {
	buf.WriteString(indent1 + "name: " + string(tenantRoles.ResourceGroup) + "\n")
	buf.WriteString(indent2 + "tenant-roles:\n")
	indent3_dash := indent2 + "  - "
	indent3_dash_lvl := indent2 + "    "
	for _, roleAction := range tenantRoles.Roles {
		buf.WriteString(indent3_dash + "role: " + string(roleAction.Role) + "\n")
		buf.WriteString(indent3_dash_lvl + "action: " + roleAction.Action + "\n")
	}
}

func (cli Zms) dumpProviderResourceGroupRoles(buf *bytes.Buffer, providerRoles *zms.ProviderResourceGroupRoles, indent1 string, indent2 string) {
	buf.WriteString(indent1 + "name: " + string(providerRoles.ResourceGroup) + "\n")
	buf.WriteString(indent2 + "provider-roles:\n")
	for _, roleAction := range providerRoles.Roles {
		buf.WriteString(indent2 + "  - " + string(roleAction.Role) + "\n")
	}
}

func (cli Zms) dumpUserName(buf *bytes.Buffer, user string, showFullResourceName bool) {
	if showFullResourceName {
		buf.WriteString(user)
	} else {
		buf.WriteString(strings.Replace(user, cli.UserDomain+".", "", -1))
	}
}

func (cli Zms) dumpRoleMembership(buf *bytes.Buffer, member zms.Membership) {
	buf.WriteString(indent_level1_dash + "member: ")
	cli.dumpUserName(buf, string(member.MemberName), true)
	buf.WriteString("\n")
	if member.Expiration != nil {
		buf.WriteString(indent_level1_dash + "expiration: " + member.Expiration.String() + "\n")
	}
	buf.WriteString(indent_level1_dash_lvl + "result: " + strconv.FormatBool(*member.IsMember) + "\n")
}

func (cli Zms) dumpSignedDomain(buf *bytes.Buffer, signedDomain *zms.SignedDomain, showDomain bool) {

	domainData := signedDomain.Domain
	if !showDomain {
		buf.WriteString("domain: ")
		buf.WriteString("\n")
		buf.WriteString(indent_level1)
		buf.WriteString("name: ")
		buf.WriteString(string(domainData.Name))
		buf.WriteString("\n")
		if domainData.Account != "" {
			buf.WriteString(indent_level1)
			buf.WriteString("account: ")
			buf.WriteString(domainData.Account)
			buf.WriteString("\n")
		}
		buf.WriteString(indent_level1)
		buf.WriteString("signature: ")
		buf.WriteString(signedDomain.Signature)
		buf.WriteString("\n")
		buf.WriteString(indent_level1)
		buf.WriteString("keyId: ")
		buf.WriteString(signedDomain.KeyId)
		buf.WriteString("\n")
	}
	buf.WriteString(indent_level1)
	buf.WriteString("modified: ")
	buf.WriteString(domainData.Modified.String())
	buf.WriteString("\n")

	buf.WriteString(indent_level1)
	buf.WriteString("roles:\n")
	for _, role := range domainData.Roles {
		cli.dumpRole(buf, *role, false, indent_level2_dash, indent_level2_dash_lvl)
	}

	buf.WriteString(indent_level1)
	buf.WriteString("policies:\n")
	signedPolicies := domainData.Policies
	domainPolicies := signedPolicies.Contents
	for _, policy := range domainPolicies.Policies {
		cli.dumpPolicy(buf, *policy, indent_level2_dash, indent_level2_dash_lvl)
	}

	if len(domainData.Services) > 0 {
		buf.WriteString(indent_level1)
		buf.WriteString("services:\n")
		for _, service := range domainData.Services {
			cli.dumpService(buf, *service, indent_level2_dash, indent_level2_dash_lvl)
		}
	}
}

func (cli Zms) dumpProfile(buf *bytes.Buffer, name, content string) {
	buf.WriteString("profile:\n")
	buf.WriteString(indent_level1)
	buf.WriteString("name: ")
	buf.WriteString(name)
	cli.dumpMultilineString(buf, content, indent_level1)
}

func (cli Zms) dumpQuota(buf *bytes.Buffer, quota *zms.Quota) {
	buf.WriteString("quota:\n")
	buf.WriteString(indent_level1)
	buf.WriteString("subdomain: ")
	buf.WriteString(strconv.Itoa(int(quota.Subdomain)))
	buf.WriteString("\n")
	buf.WriteString(indent_level1)
	buf.WriteString("role: ")
	buf.WriteString(strconv.Itoa(int(quota.Role)))
	buf.WriteString("\n")
	buf.WriteString(indent_level1)
	buf.WriteString("role-member: ")
	buf.WriteString(strconv.Itoa(int(quota.RoleMember)))
	buf.WriteString("\n")
	buf.WriteString(indent_level1)
	buf.WriteString("policy: ")
	buf.WriteString(strconv.Itoa(int(quota.Policy)))
	buf.WriteString("\n")
	buf.WriteString(indent_level1)
	buf.WriteString("assertion: ")
	buf.WriteString(strconv.Itoa(int(quota.Assertion)))
	buf.WriteString("\n")
	buf.WriteString(indent_level1)
	buf.WriteString("service: ")
	buf.WriteString(strconv.Itoa(int(quota.Service)))
	buf.WriteString("\n")
	buf.WriteString(indent_level1)
	buf.WriteString("service-host: ")
	buf.WriteString(strconv.Itoa(int(quota.ServiceHost)))
	buf.WriteString("\n")
	buf.WriteString(indent_level1)
	buf.WriteString("public-key: ")
	buf.WriteString(strconv.Itoa(int(quota.PublicKey)))
	buf.WriteString("\n")
	buf.WriteString(indent_level1)
	buf.WriteString("entity: ")
	buf.WriteString(strconv.Itoa(int(quota.Entity)))
	buf.WriteString("\n")
	buf.WriteString(indent_level1)
	buf.WriteString("modified: ")
	buf.WriteString(quota.Modified.String())
	buf.WriteString("\n")
}

func (cli Zms) dumpDomainRoleMembers(buf *bytes.Buffer, domainRoleMembers *zms.DomainRoleMembers) {
	for _, roleMember := range domainRoleMembers.Members {
		buf.WriteString(indent_level1_dash + string(roleMember.MemberName) + "\n")
		for _, role := range roleMember.MemberRoles {
			buf.WriteString(indent_level2_dash + string(role.RoleName))
			if role.Expiration != nil {
				buf.WriteString(" " + role.Expiration.String())
			}
			buf.WriteString("\n")
		}
	}
}
