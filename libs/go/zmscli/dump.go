// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"log"
	"strconv"
	"strings"

	"github.com/AthenZ/athenz/clients/go/zms"
)

var (
	indentLevel1        = "    "
	indentLevel1Dash    = "    - "
	indentLevel1DashLvl = "      "
	indentLevel2        = "        "
	indentLevel2Dash    = "        - "
	indentLevel2DashLvl = "          "
)

func (cli Zms) dumpDomain(buf *bytes.Buffer, domain *zms.Domain) {
	buf.WriteString("domain:\n")

	dumpStringValue(buf, indentLevel1, "name", string(domain.Name))
	dumpStringValue(buf, indentLevel1, "description", domain.Description)
	dumpStringValue(buf, indentLevel1, "aws_account", domain.Account)
	dumpStringValue(buf, indentLevel1, "azure_subscription", domain.AzureSubscription)
	dumpStringValue(buf, indentLevel1, "gcp_project", domain.GcpProject)
	dumpStringValue(buf, indentLevel1, "gcp_project_number", domain.GcpProjectNumber)
	dumpStringValue(buf, indentLevel1, "application_id", domain.ApplicationId)
	dumpStringValue(buf, indentLevel1, "business_service", domain.BusinessService)
	if domain.ProductId != "" {
		dumpStringValue(buf, indentLevel1, "product_id", domain.ProductId)
		dumpInt32Value(buf, indentLevel1, "ypm_id", domain.YpmId)
	} else {
		dumpInt32Value(buf, indentLevel1, "product_id", domain.YpmId)
	}
	dumpStringValue(buf, indentLevel1, "org", string(domain.Org))
	dumpBoolValue(buf, indentLevel1, "audit_enabled", domain.AuditEnabled)
	dumpStringValue(buf, indentLevel1, "user_authority_filter", domain.UserAuthorityFilter)
	dumpInt32Value(buf, indentLevel1, "member_expiry_days", domain.MemberExpiryDays)
	dumpInt32Value(buf, indentLevel1, "service_expiry_days", domain.ServiceExpiryDays)
	dumpInt32Value(buf, indentLevel1, "token_expiry_mins", domain.TokenExpiryMins)
	dumpInt32Value(buf, indentLevel1, "service_cert_expiry_mins", domain.ServiceCertExpiryMins)
	dumpInt32Value(buf, indentLevel1, "role_cert_expiry_mins", domain.RoleCertExpiryMins)
	dumpStringValue(buf, indentLevel1, "sign_algorithm", string(domain.SignAlgorithm))
	dumpInt32Value(buf, indentLevel1, "member_purge_expiry_days", domain.MemberPurgeExpiryDays)
}

func dumpStringValue(buf *bytes.Buffer, indent, label, value string) {
	if value != "" {
		buf.WriteString(indent)
		buf.WriteString(label)
		buf.WriteString(": ")
		buf.WriteString(value)
		buf.WriteString("\n")
	}
}

func dumpInt32Value(buf *bytes.Buffer, indent, label string, value *int32) {
	if value != nil {
		intValue := int(*value)
		if intValue != 0 {
			buf.WriteString(indent)
			buf.WriteString(label)
			buf.WriteString(": ")
			buf.WriteString(strconv.Itoa(intValue))
			buf.WriteString("\n")
		}
	}
}

func dumpBoolValue(buf *bytes.Buffer, indent, label string, value *bool) {
	if value != nil {
		buf.WriteString(indent)
		buf.WriteString(label)
		buf.WriteString(": ")
		buf.WriteString(strconv.FormatBool(*value))
		buf.WriteString("\n")
	}
}

func (cli Zms) dumpDataCheck(buf *bytes.Buffer, dataCheck zms.DomainDataCheck) {
	if len(dataCheck.DanglingRoles) != 0 {
		buf.WriteString(indentLevel1)
		buf.WriteString("Roles not referenced in any assertion or empty: \n")
		for _, item := range dataCheck.DanglingRoles {
			buf.WriteString(indentLevel2 + string(item) + "\n")
		}
	}
	if dataCheck.DanglingPolicies != nil {
		buf.WriteString(indentLevel1)
		buf.WriteString("Policies where assertion is referencing a non-existent role: \n")
		for _, item := range dataCheck.DanglingPolicies {
			buf.WriteString(indentLevel2 + "policy: " + string(item.PolicyName) + " role: " + string(item.RoleName) + "\n")
		}
	}
	buf.WriteString(indentLevel1)
	buf.WriteString("Number of policies:   " + strconv.Itoa(int(dataCheck.PolicyCount)) + "\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("Number of assertions: " + strconv.Itoa(int(dataCheck.AssertionCount)) + "\n")
	if len(dataCheck.ProvidersWithoutTrust) != 0 {
		buf.WriteString(indentLevel1)
		buf.WriteString("On-boarded providers without trust relationship: \n")
		for _, item := range dataCheck.ProvidersWithoutTrust {
			buf.WriteString(indentLevel2 + string(item) + "\n")
		}
	}
	if len(dataCheck.TenantsWithoutAssumeRole) != 0 {
		buf.WriteString(indentLevel1)
		buf.WriteString("On-boarded tenants without assume_role assertions: \n")
		for _, item := range dataCheck.TenantsWithoutAssumeRole {
			buf.WriteString(indentLevel2 + string(item) + "\n")
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
	dumpInt32Value(buf, indent2, "member_expiry_days", role.MemberExpiryDays)
	dumpInt32Value(buf, indent2, "service_expiry_days", role.ServiceExpiryDays)
	dumpInt32Value(buf, indent2, "token_expiry_mins", role.TokenExpiryMins)
	dumpInt32Value(buf, indent2, "cert_expiry_mins", role.CertExpiryMins)
	dumpInt32Value(buf, indent2, "member_review_days", role.MemberReviewDays)
	dumpInt32Value(buf, indent2, "service_review_days", role.ServiceReviewDays)
	dumpInt32Value(buf, indent2, "group_expiry_days", role.GroupExpiryDays)
	dumpInt32Value(buf, indent2, "group_review_days", role.GroupReviewDays)
	dumpBoolValue(buf, indent2, "audit_enabled", role.AuditEnabled)
	dumpBoolValue(buf, indent2, "review_enabled", role.ReviewEnabled)
	dumpBoolValue(buf, indent2, "self_serve", role.SelfServe)
	dumpStringValue(buf, indent2, "sign_algorithm", string(role.SignAlgorithm))
	dumpStringValue(buf, indent2, "notify_roles", role.NotifyRoles)
	dumpStringValue(buf, indent2, "user_authority_filter", role.UserAuthorityFilter)
	dumpStringValue(buf, indent2, "user_authority_expiration", role.UserAuthorityExpiration)
	dumpStringValue(buf, indent2, "description", role.Description)
	if role.RoleMembers != nil && len(role.RoleMembers) > 0 {
		buf.WriteString(indent2)
		buf.WriteString("members:\n")
		indent3 := indent2 + "  - "
		indent4 := indent2 + "    "
		for _, memberItem := range role.RoleMembers {
			buf.WriteString(indent3 + "name: ")
			cli.dumpUserName(buf, string(memberItem.MemberName), true)
			if memberItem.Expiration != nil {
				buf.WriteString("\n" + indent4 + "expiration: " + memberItem.Expiration.String())
			}
			if memberItem.ReviewReminder != nil {
				buf.WriteString("\n" + indent4 + "review: " + memberItem.ReviewReminder.String())
			}
			if memberItem.Approved != nil && *memberItem.Approved == false {
				buf.WriteString("\n" + indent4 + "pending: true")
			}
			if memberItem.SystemDisabled != nil && *memberItem.SystemDisabled != 0 {
				buf.WriteString("\n" + indent4 + "system-disabled: true")
			}
			buf.WriteString("\n")
		}
	}
	cli.dumpTags(buf, true, "", indent2, role.Tags)
	if auditLog {
		buf.WriteString(indent2)
		buf.WriteString("changes: \n")
		indent3Dash := indent2 + "  - "
		indent3DashLvl := indent2 + "    "
		for _, logItem := range role.AuditLog {
			buf.WriteString(indent3Dash + "action: " + logItem.Action + "\n")
			buf.WriteString(indent3DashLvl + "admin: " + string(logItem.Admin) + "\n")
			buf.WriteString(indent3DashLvl + "member: " + string(logItem.Member) + "\n")
			buf.WriteString(indent3DashLvl + "date: " + logItem.Created.String() + "\n")
			buf.WriteString(indent3DashLvl + "ref: " + logItem.AuditRef + "\n")
		}
	}
	if role.Trust != "" {
		buf.WriteString(indent2)
		buf.WriteString("trust: ")
		buf.WriteString(string(role.Trust))
		buf.WriteString("\n")
	}
}

func (cli Zms) dumpTags(buf *bytes.Buffer, indentFirst bool, indent1, indent2 string, tags map[zms.TagKey]*zms.TagValueList) {
	if tags != nil {
		if indentFirst {
			buf.WriteString(indent2)
		}
		buf.WriteString("tags:\n")
		indent3 := indent2 + indent1 + "  - "
		indent4 := indent2 + indent1 + "    "
		indent5 := indent4 + "  - "
		for tagKey, tagValues := range tags {
			buf.WriteString(indent3 + "key: ")
			buf.WriteString(string(tagKey) + "\n")
			buf.WriteString(indent4 + "values:\n")
			for _, tagValue := range tagValues.List {
				buf.WriteString(indent5 + string(tagValue) + "\n")
			}
		}
	}
}

func (cli Zms) dumpRoles(buf *bytes.Buffer, dn string, tagKey string, tagValue string) {
	buf.WriteString(indentLevel1)
	buf.WriteString("roles:\n")
	members := true
	roles, err := cli.Zms.GetRoles(zms.DomainName(dn), &members, zms.TagKey(tagKey), zms.TagCompoundValue(tagValue))
	if err != nil {
		log.Fatalf("Unable to get role list - error: %v", err)
	}
	for _, role := range roles.List {
		cli.dumpRole(buf, *role, false, indentLevel2Dash, indentLevel2DashLvl)
	}
}

func (cli Zms) dumpGroups(buf *bytes.Buffer, dn string, tagKey string, tagValue string) {
	buf.WriteString(indentLevel1)
	buf.WriteString("groups:\n")
	members := true
	groups, err := cli.Zms.GetGroups(zms.DomainName(dn), &members, zms.TagKey(tagKey), zms.TagCompoundValue(tagValue))
	if err != nil {
		log.Fatalf("Unable to get group list - error: %v", err)
	}
	for _, group := range groups.List {
		cli.dumpGroup(buf, *group, false, indentLevel2Dash, indentLevel2DashLvl)
	}
}

func (cli Zms) dumpGroup(buf *bytes.Buffer, group zms.Group, auditLog bool, indent1 string, indent2 string) {
	cli.displayObjectName(buf, string(group.Name), ":group.", indent1)
	dumpInt32Value(buf, indent2, "member_expiry_days", group.MemberExpiryDays)
	dumpInt32Value(buf, indent2, "service_expiry_days", group.ServiceExpiryDays)
	dumpBoolValue(buf, indent2, "audit_enabled", group.AuditEnabled)
	dumpBoolValue(buf, indent2, "review_enabled", group.ReviewEnabled)
	dumpBoolValue(buf, indent2, "self_serve", group.SelfServe)
	dumpStringValue(buf, indent2, "notify_roles", group.NotifyRoles)
	dumpStringValue(buf, indent2, "user_authority_filter", group.UserAuthorityFilter)
	dumpStringValue(buf, indent2, "user_authority_expiration", group.UserAuthorityExpiration)
	if group.GroupMembers != nil && len(group.GroupMembers) > 0 {
		buf.WriteString(indent2)
		buf.WriteString("members:\n")
		indent3 := indent2 + "  - "
		indent4 := indent2 + "    "
		for _, memberItem := range group.GroupMembers {
			buf.WriteString(indent3 + "name: ")
			cli.dumpUserName(buf, string(memberItem.MemberName), true)
			if memberItem.Expiration != nil {
				buf.WriteString("\n" + indent4 + "expiration: " + memberItem.Expiration.String())
			}
			if memberItem.Approved != nil && *memberItem.Approved == false {
				buf.WriteString("\n" + indent4 + "pending: true")
			}
			if memberItem.SystemDisabled != nil && *memberItem.SystemDisabled != 0 {
				buf.WriteString("\n" + indent4 + "system-disabled: true")
			}
			buf.WriteString("\n")
		}
	}
	cli.dumpTags(buf, true, "", indent2, group.Tags)
	if auditLog {
		buf.WriteString(indent2)
		buf.WriteString("changes: \n")
		indent3Dash := indent2 + "  - "
		indent3DashLvl := indent2 + "    "
		for _, logItem := range group.AuditLog {
			buf.WriteString(indent3Dash + "Action: " + logItem.Action + "\n")
			buf.WriteString(indent3DashLvl + "Admin: " + string(logItem.Admin) + "\n")
			buf.WriteString(indent3DashLvl + "Member: " + string(logItem.Member) + "\n")
			buf.WriteString(indent3DashLvl + "Date: " + logItem.Created.String() + "\n")
			buf.WriteString(indent3DashLvl + "Ref: " + logItem.AuditRef + "\n")
		}
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
	dumpStringValue(buf, indent2, "version", string(policy.Version))
	dumpBoolValue(buf, indent2, "active", policy.Active)
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

func (cli Zms) dumpMetadata(buf *bytes.Buffer, data *zms.TemplateMetaData, indent1 string, templateName string) {
	buf.WriteString(indentLevel1 + "metadata:\n")
	dumpStringValue(buf, indent1, "template-name", templateName)
	dumpStringValue(buf, indent1, "description", data.Description)
	dumpStringValue(buf, indent1, "keywords-to-replace", data.KeywordsToReplace)
	dumpInt32Value(buf, indent1, "latest-version", data.LatestVersion)
	dumpBoolValue(buf, indent1, "auto-update", data.AutoUpdate)
}

func (cli Zms) dumpPolicies(buf *bytes.Buffer, dn string, tagkey string, tagValue string) {
	buf.WriteString(indentLevel1)
	buf.WriteString("policies:\n")
	assertions := true
	versions := false
	policies, err := cli.Zms.GetPolicies(zms.DomainName(dn), &assertions, &versions, zms.TagKey(tagkey), zms.TagCompoundValue(tagValue))
	if err != nil {
		log.Fatalf("Unable to get policy list - error: %v", err)
	}
	for _, policy := range policies.List {
		cli.dumpPolicy(buf, *policy, indentLevel2Dash, indentLevel2DashLvl)
	}
}

func (cli Zms) dumpEntities(buf *bytes.Buffer, dn string, entitynames []string) {
	if len(entitynames) > 0 {
		buf.WriteString(indentLevel1)
		buf.WriteString("entities:\n")
		for _, en := range entitynames {
			entity, err := cli.Zms.GetEntity(zms.DomainName(dn), zms.EntityName(en))
			if err != nil {
				return
			}
			cli.dumpEntity(buf, *entity, indentLevel2Dash, indentLevel2DashLvl)
		}
	}
}

func (cli Zms) dumpEntity(buf *bytes.Buffer, entity zms.Entity, indent1 string, indent2 string) {
	cli.displayObjectName(buf, string(entity.Name), ":entity.", indent1)
	buf.WriteString(indent2)
	buf.WriteString("value:\n")
	indent3Dash := indent2 + "  - "
	indent3DashLvl := indent2 + "    "
	for key, data := range entity.Value {
		buf.WriteString(indent3Dash + "key: " + string(key) + "\n")
		buf.WriteString(indent3DashLvl + "data: " + data.(string) + "\n")
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
			buf.WriteString(indentLevel1Dash + dn + ":" + object + "." + item + "\n")
		} else {
			buf.WriteString(indentLevel1Dash + item + "\n")
		}
	}
}

func (cli Zms) dumpServices(buf *bytes.Buffer, dn string, tagKey string, tagValue string) {
	publickeys := true
	hosts := true
	services, err := cli.Zms.GetServiceIdentities(zms.DomainName(dn), &publickeys, &hosts, zms.TagKey(tagKey), zms.TagCompoundValue(tagValue))
	if err != nil {
		log.Fatalf("Unable to get service list - error: %v", err)
	}
	if len(services.List) > 0 {
		buf.WriteString(indentLevel1)
		buf.WriteString("services:\n")
		for _, service := range services.List {
			cli.dumpService(buf, *service, indentLevel2Dash, indentLevel2DashLvl)
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
	indent3Dash := indent2 + "  - "
	indent3DashLvl := indent2 + "    "
	for _, roleAction := range tenantRoles.Roles {
		buf.WriteString(indent3Dash + "role: " + string(roleAction.Role) + "\n")
		buf.WriteString(indent3DashLvl + "action: " + roleAction.Action + "\n")
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
	buf.WriteString(indentLevel1Dash + "member: ")
	cli.dumpUserName(buf, string(member.MemberName), true)
	buf.WriteString("\n")
	if member.Expiration != nil {
		buf.WriteString(indentLevel1DashLvl + "expiration: " + member.Expiration.String() + "\n")
	}
	if member.ReviewReminder != nil {
		buf.WriteString(indentLevel1DashLvl + "review: " + member.ReviewReminder.String() + "\n")
	}
	if member.SystemDisabled != nil && *member.SystemDisabled != 0 {
		buf.WriteString(indentLevel1DashLvl + "system-disabled: " + strconv.Itoa(int(*member.SystemDisabled)) + "\n")
	}
	if member.Approved != nil && !*member.Approved {
		buf.WriteString(indentLevel1DashLvl + "pending: " + strconv.FormatBool(*member.IsMember) + "\n")
	}
	buf.WriteString(indentLevel1DashLvl + "result: " + strconv.FormatBool(*member.IsMember) + "\n")
}

func (cli Zms) dumpGroupMembership(buf *bytes.Buffer, member zms.GroupMembership) {
	buf.WriteString(indentLevel1Dash + "member: ")
	cli.dumpUserName(buf, string(member.MemberName), true)
	buf.WriteString("\n")
	if member.Expiration != nil {
		buf.WriteString(indentLevel1Dash + "expiration: " + member.Expiration.String() + "\n")
	}
	if member.SystemDisabled != nil && *member.SystemDisabled != 0 {
		buf.WriteString(indentLevel1DashLvl + "system-disabled: " + strconv.Itoa(int(*member.SystemDisabled)) + "\n")
	}
	if member.Approved != nil && !*member.Approved {
		buf.WriteString(indentLevel1DashLvl + "pending: " + strconv.FormatBool(*member.IsMember) + "\n")
	}
	buf.WriteString(indentLevel1DashLvl + "result: " + strconv.FormatBool(*member.IsMember) + "\n")
}

func (cli Zms) dumpSignedDomain(buf *bytes.Buffer, signedDomain *zms.SignedDomain, showDomain bool) {

	domainData := signedDomain.Domain
	if !showDomain {
		buf.WriteString("domain: ")
		buf.WriteString("\n")
		buf.WriteString(indentLevel1)
		buf.WriteString("name: ")
		buf.WriteString(string(domainData.Name))
		buf.WriteString("\n")
		if domainData.Account != "" {
			buf.WriteString(indentLevel1)
			buf.WriteString("aws_account: ")
			buf.WriteString(domainData.Account)
			buf.WriteString("\n")
		}
		if domainData.AzureSubscription != "" {
			buf.WriteString(indentLevel1)
			buf.WriteString("azure_subscription: ")
			buf.WriteString(domainData.AzureSubscription)
			buf.WriteString("\n")
		}
		if domainData.GcpProject != "" {
			buf.WriteString(indentLevel1)
			buf.WriteString("gcp_project: ")
			buf.WriteString(domainData.GcpProject)
			buf.WriteString("\n")
		}
		if domainData.GcpProjectNumber != "" {
			buf.WriteString(indentLevel1)
			buf.WriteString("gcp_project_number: ")
			buf.WriteString(domainData.GcpProjectNumber)
			buf.WriteString("\n")
		}
		if domainData.BusinessService != "" {
			buf.WriteString(indentLevel1)
			buf.WriteString("business_service: ")
			buf.WriteString(domainData.BusinessService)
			buf.WriteString("\n")
		}
		buf.WriteString(indentLevel1)
		buf.WriteString("signature: ")
		buf.WriteString(signedDomain.Signature)
		buf.WriteString("\n")
		buf.WriteString(indentLevel1)
		buf.WriteString("keyId: ")
		buf.WriteString(signedDomain.KeyId)
		buf.WriteString("\n")
	}
	buf.WriteString(indentLevel1)
	buf.WriteString("modified: ")
	buf.WriteString(domainData.Modified.String())
	buf.WriteString("\n")

	if domainData.Tags != nil {
		buf.WriteString(indentLevel1)
		cli.dumpTags(buf, false, "  ", indentLevel1, domainData.Tags)
	}
	buf.WriteString(indentLevel1)
	buf.WriteString("roles:\n")
	for _, role := range domainData.Roles {
		cli.dumpRole(buf, *role, false, indentLevel2Dash, indentLevel2DashLvl)
	}

	buf.WriteString(indentLevel1)
	buf.WriteString("groups:\n")
	for _, group := range domainData.Groups {
		cli.dumpGroup(buf, *group, false, indentLevel2Dash, indentLevel2DashLvl)
	}

	buf.WriteString(indentLevel1)
	buf.WriteString("policies:\n")
	signedPolicies := domainData.Policies
	domainPolicies := signedPolicies.Contents
	for _, policy := range domainPolicies.Policies {
		cli.dumpPolicy(buf, *policy, indentLevel2Dash, indentLevel2DashLvl)
	}

	if len(domainData.Services) > 0 {
		buf.WriteString(indentLevel1)
		buf.WriteString("services:\n")
		for _, service := range domainData.Services {
			cli.dumpService(buf, *service, indentLevel2Dash, indentLevel2DashLvl)
		}
	}
}

func (cli Zms) dumpDomainData(buf *bytes.Buffer, domainData zms.DomainData) {

	buf.WriteString(indentLevel1)
	buf.WriteString("modified: ")
	buf.WriteString(domainData.Modified.String())
	buf.WriteString("\n")

	if domainData.Tags != nil {
		buf.WriteString(indentLevel1)
		cli.dumpTags(buf, false, "  ", indentLevel1, domainData.Tags)
	}
	buf.WriteString(indentLevel1)
	buf.WriteString("roles:\n")
	for _, role := range domainData.Roles {
		cli.dumpRole(buf, *role, false, indentLevel2Dash, indentLevel2DashLvl)
	}

	buf.WriteString(indentLevel1)
	buf.WriteString("groups:\n")
	for _, group := range domainData.Groups {
		cli.dumpGroup(buf, *group, false, indentLevel2Dash, indentLevel2DashLvl)
	}

	buf.WriteString(indentLevel1)
	buf.WriteString("policies:\n")
	signedPolicies := domainData.Policies
	domainPolicies := signedPolicies.Contents
	for _, policy := range domainPolicies.Policies {
		cli.dumpPolicy(buf, *policy, indentLevel2Dash, indentLevel2DashLvl)
	}

	if len(domainData.Services) > 0 {
		buf.WriteString(indentLevel1)
		buf.WriteString("services:\n")
		for _, service := range domainData.Services {
			cli.dumpService(buf, *service, indentLevel2Dash, indentLevel2DashLvl)
		}
	}
}

func (cli Zms) dumpProfile(buf *bytes.Buffer, name, content string) {
	buf.WriteString("profile:\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("name: ")
	buf.WriteString(name)
	cli.dumpMultilineString(buf, content, indentLevel1)
}

func (cli Zms) dumpQuota(buf *bytes.Buffer, quota *zms.Quota) {
	buf.WriteString("quota:\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("subdomain: ")
	buf.WriteString(strconv.Itoa(int(quota.Subdomain)))
	buf.WriteString("\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("role: ")
	buf.WriteString(strconv.Itoa(int(quota.Role)))
	buf.WriteString("\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("role-member: ")
	buf.WriteString(strconv.Itoa(int(quota.RoleMember)))
	buf.WriteString("\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("group: ")
	buf.WriteString(strconv.Itoa(int(quota.Group)))
	buf.WriteString("\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("group-member: ")
	buf.WriteString(strconv.Itoa(int(quota.GroupMember)))
	buf.WriteString("\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("policy: ")
	buf.WriteString(strconv.Itoa(int(quota.Policy)))
	buf.WriteString("\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("assertion: ")
	buf.WriteString(strconv.Itoa(int(quota.Assertion)))
	buf.WriteString("\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("service: ")
	buf.WriteString(strconv.Itoa(int(quota.Service)))
	buf.WriteString("\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("service-host: ")
	buf.WriteString(strconv.Itoa(int(quota.ServiceHost)))
	buf.WriteString("\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("public-key: ")
	buf.WriteString(strconv.Itoa(int(quota.PublicKey)))
	buf.WriteString("\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("entity: ")
	buf.WriteString(strconv.Itoa(int(quota.Entity)))
	buf.WriteString("\n")
	buf.WriteString(indentLevel1)
	buf.WriteString("modified: ")
	buf.WriteString(quota.Modified.String())
	buf.WriteString("\n")
}

func (cli Zms) dumpDomainRoleMembers(buf *bytes.Buffer, domainRoleMembers *zms.DomainRoleMembers, displayName bool) {
	if displayName {
		buf.WriteString("  - name: " + string(domainRoleMembers.DomainName) + "\n")
		buf.WriteString("    members:\n")
	}
	for _, roleMember := range domainRoleMembers.Members {
		buf.WriteString(indentLevel1Dash + "member: " + string(roleMember.MemberName) + "\n")
		buf.WriteString(indentLevel1DashLvl + "roles:\n")
		for _, role := range roleMember.MemberRoles {
			buf.WriteString(indentLevel2Dash + string(role.RoleName))
			if role.Expiration != nil {
				buf.WriteString(" expiration: " + role.Expiration.String())
			}
			if role.ReviewReminder != nil {
				buf.WriteString(" review: " + role.ReviewReminder.String())
			}
			buf.WriteString("\n")
		}
	}
}

func (cli Zms) dumpDomainGroupMembers(buf *bytes.Buffer, domainGroupMembers *zms.DomainGroupMembers, displayName bool) {
	if displayName {
		buf.WriteString("  - name: " + string(domainGroupMembers.DomainName) + "\n")
		buf.WriteString("    members:\n")
	}
	for _, groupMember := range domainGroupMembers.Members {
		buf.WriteString(indentLevel1Dash + "member: " + string(groupMember.MemberName) + "\n")
		buf.WriteString(indentLevel1DashLvl + "groups:\n")
		for _, group := range groupMember.MemberGroups {
			buf.WriteString(indentLevel2Dash + string(group.GroupName))
			if group.Expiration != nil {
				buf.WriteString(" expiration: " + group.Expiration.String())
			}
			buf.WriteString("\n")
		}
	}
}

func (cli Zms) dumpRolesPrincipal(buf *bytes.Buffer, roleMember *zms.DomainRoleMember) {
	buf.WriteString("member: " + string(roleMember.MemberName) + "\n")
	buf.WriteString("roles:\n")
	for _, role := range roleMember.MemberRoles {
		buf.WriteString(indentLevel1Dash + "name: " + string(role.RoleName) + "\n")
		buf.WriteString(indentLevel1 + "  domain: " + string(role.DomainName) + "\n")
		if role.Expiration != nil {
			buf.WriteString(indentLevel1 + "  expiration: " + role.Expiration.String() + "\n")
		}
		if role.ReviewReminder != nil {
			buf.WriteString(indentLevel1 + "  review: " + role.ReviewReminder.String() + "\n")
		}
		if role.SystemDisabled != nil && *role.SystemDisabled != 0 {
			buf.WriteString(indentLevel1 + "  system-disabled: true\n")
		}
		if string(role.MemberName) != "" {
			buf.WriteString(indentLevel1 + "  member-name: " + string(role.MemberName) + "\n")
		}
		if string(role.TrustRoleName) != "" {
			buf.WriteString(indentLevel1 + "  trust-role-name: " + string(role.TrustRoleName) + "\n")
		}
	}
}

func (cli Zms) dumpGroupsPrincipal(buf *bytes.Buffer, groupMember *zms.DomainGroupMember) {
	buf.WriteString("member: " + string(groupMember.MemberName) + "\n")
	buf.WriteString("groups:\n")
	for _, group := range groupMember.MemberGroups {
		buf.WriteString(indentLevel1Dash + "name: " + string(group.GroupName) + "\n")
		buf.WriteString(indentLevel1 + "  domain: " + string(group.DomainName) + "\n")
		if group.Expiration != nil {
			buf.WriteString(indentLevel1 + "  expiration: " + group.Expiration.String() + "\n")
		}
		if group.SystemDisabled != nil && *group.SystemDisabled != 0 {
			buf.WriteString(indentLevel1 + "  system-disabled: true\n")
		}
	}
}
