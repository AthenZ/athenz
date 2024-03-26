// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AthenZ/athenz/clients/go/zms"
)

// DeleteDomain deletes the given ZMS domain.
func (cli Zms) DeleteDomain(dn string) (*string, error) {
	_, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err == nil {
		i := strings.LastIndex(dn, ".")
		name := dn
		parent := ""
		if i < 0 {
			err = cli.Zms.DeleteTopLevelDomain(zms.SimpleName(dn), cli.AuditRef, cli.ResourceOwner)
		} else {
			parent = dn[0:i]
			name = dn[i+1:]
			// special case for top level user domains
			// where parent is just the user domain
			if parent == cli.HomeDomain {
				err = cli.Zms.DeleteUserDomain(zms.SimpleName(name), cli.AuditRef, cli.ResourceOwner)
			} else {
				err = cli.Zms.DeleteSubDomain(zms.DomainName(parent), zms.SimpleName(name), cli.AuditRef, cli.ResourceOwner)
			}
		}
		if err == nil {
			s := "[Deleted domain " + dn + "]"
			message := SuccessMessage{
				Status:  200,
				Message: s,
			}
			return cli.dumpByFormat(message, cli.buildYAMLOutput)
		}
	}
	return nil, err
}

func (cli Zms) SetDomainState(dn string, enabled bool) (*string, error) {
	meta := zms.DomainMeta{
		Enabled: &enabled,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), "enabled", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) ImportDomain(dn string, filename string, admins []string) (*string, error) {

	if cli.OutputFormat == JSONOutputFormat || cli.OutputFormat == YAMLOutputFormat {
		return cli.ImportDomainNew(dn, filename, admins, true)
	} else {
		return cli.ImportDomainOld(dn, filename, admins)
	}
}

func (cli Zms) getDomainGroups(dn string, newDomain bool) *zms.Groups {
	// if this is for a new domain then we don't need to fetch
	// the existing list of groups
	if newDomain {
		return nil
	}
	members := false
	groups, err := cli.Zms.GetGroups(zms.DomainName(dn), &members, "", "")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "Unable to get list of groups - %v\n", err)
		groups = nil
	}
	return groups
}

func (cli Zms) getDomainRoles(dn string, newDomain bool) *zms.Roles {
	// if this is for a new domain then we don't need to fetch
	// the existing list of roles
	if newDomain {
		return nil
	}
	members := false
	roles, err := cli.Zms.GetRoles(zms.DomainName(dn), &members, "", "")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, "Unable to get list of roles - %v\n", err)
		roles = nil
	}
	return roles
}

func (cli Zms) ImportDomainNew(dn string, filename string, admins []string, newDomain bool) (*string, error) {
	var validatedAdmins []string = nil
	if newDomain {
		validatedAdmins = cli.validatedUsers(admins, true)
	}
	var signedDomain zms.DomainData
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if cli.OutputFormat == YAMLOutputFormat {
		err = yaml.Unmarshal(data, &signedDomain)
	} else {
		err = json.Unmarshal(data, &signedDomain)
	}
	if err != nil {
		return nil, err
	}

	if dn != string(signedDomain.Name) {
		return nil, fmt.Errorf("Domain name mismatch. Expected " + dn + ", encountered " + string(signedDomain.Name))
	}

	if newDomain {
		if signedDomain.YpmId == nil && signedDomain.ProductId == "" && cli.ProductIdSupport && strings.LastIndex(dn, ".") < 0 {
			return nil, fmt.Errorf("top level domains require Product ID to be specified")
		}
		_, err = cli.AddDomain(dn, signedDomain.YpmId, signedDomain.ProductId, true, admins)
		if err != nil {
			return nil, err
		}
	}

	auditEnabled := false
	if signedDomain.AuditEnabled != nil && *signedDomain.AuditEnabled {
		auditEnabled = *signedDomain.AuditEnabled
	}

	err = cli.SetCompleteDomainMeta(dn, signedDomain.Description, string(signedDomain.Org), auditEnabled, signedDomain.ApplicationId, signedDomain.BusinessService)
	if err != nil {
		return nil, err
	}

	err = cli.importServices(dn, signedDomain.Services, !newDomain)
	if err != nil {
		return nil, err
	}

	err = cli.importGroups(dn, signedDomain.Groups, cli.getDomainGroups(dn, newDomain), !newDomain)
	if err != nil {
		return nil, err
	}

	err = cli.importRoles(dn, signedDomain.Roles, cli.getDomainRoles(dn, newDomain), validatedAdmins, !newDomain)
	if err != nil {
		return nil, err
	}

	err = cli.importPolicies(dn, signedDomain.Policies.Contents.Policies, !newDomain)
	if err != nil {
		return nil, err
	}

	s := "[imported domain '" + dn + "' successfully]"
	if !newDomain {
		s = "[updated domain '" + dn + "' successfully]"
	}

	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) ImportDomainOld(dn string, filename string, admins []string) (*string, error) {
	validatedAdmins := cli.validatedUsers(admins, true)
	var spec map[string]interface{}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(data, &spec)
	if err != nil {
		return nil, err
	}
	dnSpec := spec["domain"].(map[string]interface{})
	dn2 := dnSpec["name"].(string)
	if dn2 != dn {
		return nil, fmt.Errorf("Domain name mismatch. Expected " + dn + ", encountered " + dn2)
	}
	productIDNumber := -1
	productIDString := ""
	if val, ok := dnSpec["ypm_id"]; ok {
		productIDNumber = val.(int)
		productIDString = dnSpec["product_id"].(string)
	} else {
		if val, ok := dnSpec["product_id"]; ok {
			productIDNumber = val.(int)
		}
	}
	if productIDNumber == -1 && productIDString == "" && cli.ProductIdSupport && strings.LastIndex(dn, ".") < 0 {
		return nil, fmt.Errorf("top level domains require a Product ID")
	}
	productIDNumber32 := int32(productIDNumber)
	_, err = cli.AddDomain(dn, &productIDNumber32, productIDString, true, admins)
	if err != nil {
		return nil, err
	}
	var descr string
	if val, ok := dnSpec["description"]; ok {
		switch val.(type) {
		case int:
			descr = strconv.Itoa(val.(int))
		case string:
			descr = val.(string)
		}
	}
	var org string
	if val, ok := dnSpec["org"]; ok {
		org = val.(string)
	}
	var auditEnabled bool
	if val, ok := dnSpec["audit_enabled"]; ok {
		auditEnabled = val.(bool)
	}
	var applicationID string
	if val, ok := dnSpec["application_id"]; ok {
		applicationID = val.(string)
	}
	var businessService string
	if val, ok := dnSpec["business_service"]; ok {
		businessService = val.(string)
	}
	err = cli.SetCompleteDomainMeta(dn, descr, org, auditEnabled, applicationID, businessService)
	if err != nil {
		return nil, err
	}
	if lstServices, ok := dnSpec["services"].([]interface{}); ok {
		err = cli.importServicesOld(dn, lstServices, false)
		if err != nil {
			return nil, err
		}
	}
	lstGroups := dnSpec["groups"].([]interface{})
	err = cli.importGroupsOld(dn, lstGroups, false)
	if err != nil {
		return nil, err
	}
	lstRoles := dnSpec["roles"].([]interface{})
	err = cli.importRolesOld(dn, lstRoles, validatedAdmins, false)
	if err != nil {
		return nil, err
	}
	lstPolicies := dnSpec["policies"].([]interface{})
	err = cli.importPoliciesOld(dn, lstPolicies, false)
	if err != nil {
		return nil, err
	}
	s := "[imported domain '" + dn + "' successfully]"
	return &s, nil
}

func (cli Zms) UpdateDomain(dn string, filename string) (*string, error) {
	if cli.OutputFormat == JSONOutputFormat || cli.OutputFormat == YAMLOutputFormat {
		return cli.ImportDomainNew(dn, filename, nil, false)
	} else {
		return cli.UpdateDomainOld(dn, filename)
	}
}

func (cli Zms) UpdateDomainOld(dn string, filename string) (*string, error) {
	var spec map[string]interface{}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(data, &spec)
	if err != nil {
		return nil, err
	}
	dnSpec := spec["domain"].(map[string]interface{})
	dn2 := dnSpec["name"].(string)
	if dn2 != dn {
		return nil, fmt.Errorf("Domain name mismatch. Expected " + dn + ", encountered " + dn2)
	}
	var descr string
	if val, ok := dnSpec["description"]; ok {
		switch val.(type) {
		case int:
			descr = strconv.Itoa(val.(int))
		case string:
			descr = val.(string)
		}
	}
	var org string
	if val, ok := dnSpec["org"]; ok {
		org = val.(string)
	}
	var auditEnabled bool
	if val, ok := dnSpec["audit_enabled"]; ok {
		auditEnabled = val.(bool)
	}
	var applicationID string
	if val, ok := dnSpec["application_id"]; ok {
		applicationID = val.(string)
	}
	var businessService string
	if val, ok := dnSpec["business_service"]; ok {
		businessService = val.(string)
	}
	err = cli.SetCompleteDomainMeta(dn, descr, org, auditEnabled, applicationID, businessService)
	if err != nil {
		return nil, err
	}
	if lstServices, ok := dnSpec["services"].([]interface{}); ok {
		err = cli.importServicesOld(dn, lstServices, true)
		if err != nil {
			return nil, err
		}
	}
	if lstGroups, ok := dnSpec["groups"].([]interface{}); ok {
		err = cli.importGroupsOld(dn, lstGroups, true)
		if err != nil {
			return nil, err
		}
	}
	if lstRoles, ok := dnSpec["roles"].([]interface{}); ok {
		err = cli.importRolesOld(dn, lstRoles, nil, true)
		if err != nil {
			return nil, err
		}
	}
	if lstPolicies, ok := dnSpec["policies"].([]interface{}); ok {
		err = cli.importPoliciesOld(dn, lstPolicies, true)
		if err != nil {
			return nil, err
		}
	}
	s := "[updated domain '" + dn + "' successfully]"
	return &s, nil
}

func (cli Zms) ExportDomain(dn string, filename string) (*string, error) {
	verbose := cli.Verbose
	cli.Verbose = false
	data, err := cli.showDomain(dn)
	cli.Verbose = verbose
	if err == nil && data != nil {
		if filename == "-" {
			fmt.Println(*data)
		} else {
			err = os.WriteFile(filename, []byte(*data), 0644)
		}
	}
	return nil, err
}

func (cli Zms) SystemBackup(dir string) (*string, error) {
	res, err := cli.Zms.GetDomainList(nil, "", "", nil, "", nil, "", "", "", "", "", "", "", "", "")
	if err != nil {
		return nil, err
	}
	verbose := cli.Verbose
	cli.Verbose = false
	for _, name := range res.Names {
		_, _ = fmt.Fprintf(os.Stdout, "Processing domain "+string(name)+"...\n")
		filename := dir + "/" + string(name)
		data, err := cli.showDomain(string(name))
		if err == nil && data != nil {
			s := *data
			err = os.WriteFile(filename, []byte(s), 0644)
			if err != nil {
				return nil, err
			}
		}
	}
	cli.Verbose = verbose
	s := "[exported " + strconv.Itoa(len(res.Names)) + " domains to " + dir + " directory]"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddDomain(dn string, productIDNumber *int32, productIDString string, addSelf bool, admins []string) (*string, error) {
	validatedAdmins := cli.validatedUsers(admins, addSelf)
	s, err := cli.createDomain(dn, productIDNumber, productIDString, validatedAdmins)
	if err != nil {
		return nil, err
	}
	message := SuccessMessage{
		Status:  200,
		Message: *s,
	}
	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) createDomain(dn string, productIDNumber *int32, productIDString string, admins []string) (*string, error) {
	i := strings.LastIndex(dn, ".")
	name := dn
	parent := ""
	if i == -1 {
		tld := zms.TopLevelDomain{}
		tld.Name = zms.SimpleName(dn)
		tld.AdminUsers = cli.createResourceList(admins)
		if productIDNumber != nil && *productIDNumber != -1 {
			tld.YpmId = productIDNumber
		}
		tld.ProductId = productIDString
		_, err := cli.Zms.PostTopLevelDomain(cli.AuditRef, cli.ResourceOwner, &tld)
		if err == nil {
			s := "[domain created: " + dn + "]"
			return &s, nil
		}
		return nil, err
	}
	parent = dn[0:i]
	name = dn[i+1:]
	// special case for top level user domains
	// where parent is just the user domain
	if parent == cli.HomeDomain {
		d := zms.UserDomain{}
		d.Name = zms.SimpleName(name)
		_, err := cli.Zms.PostUserDomain(zms.SimpleName(name), cli.AuditRef, cli.ResourceOwner, &d)
		if err == nil {
			s := "[domain created: " + dn + "]"
			return &s, nil
		}
		return nil, err
	}
	d := zms.SubDomain{}
	d.Name = zms.SimpleName(name)
	d.Parent = zms.DomainName(parent)
	d.AdminUsers = cli.createResourceList(admins)
	_, err := cli.Zms.PostSubDomain(zms.DomainName(parent), cli.AuditRef, cli.ResourceOwner, &d)
	if err == nil {
		s := "[subdomain created: " + dn + "]"
		return &s, nil
	}
	return nil, err
}

func (cli Zms) LookupDomainByRole(roleMember string, roleName string) (*string, error) {
	res, err := cli.Zms.GetDomainList(nil, "", "", nil, "", nil, zms.ResourceName(roleMember), zms.ResourceName(roleName), "", "", "", "", "", "", "")
	if err != nil {
		return nil, err
	}

	return cli.dumpDomainListByFormat(res)
}

func (cli Zms) dumpDomainListByFormat(res *zms.DomainList) (*string, error) {
	oldYamlConverter := func(res interface{}) (*string, error) {
		jsonbody, err := json.Marshal(res)
		if err != nil {
			return nil, err
		}
		domainList := zms.DomainList{}
		if err := json.Unmarshal(jsonbody, &domainList); err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		buf.WriteString("domains:\n")
		for _, name := range domainList.Names {
			buf.WriteString(indentLevel1Dash + string(name) + "\n")
		}
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(res, oldYamlConverter)
}

func (cli Zms) LookupDomainByBusinessService(businessService string) (*string, error) {
	res, err := cli.Zms.GetDomainList(nil, "", "", nil, "", nil, "", "", "", "", "", "", businessService, "", "")
	if err != nil {
		return nil, err
	}
	return cli.dumpDomainListByFormat(res)
}

func (cli Zms) LookupDomainByNumber(account, subscription, project string, productNumber *int32) (*string, error) {
	res, err := cli.Zms.GetDomainList(nil, "", "", nil, account, productNumber, "", "", subscription, project, "", "", "", "", "")
	if err != nil {
		return nil, err
	}
	return cli.dumpDomainListByFormat(res)
}

func (cli Zms) LookupDomainById(account, subscription, project, productID string) (*string, error) {
	res, err := cli.Zms.GetDomainList(nil, "", "", nil, account, nil, "", "", subscription, project, "", "", "", productID, "")
	if err != nil {
		return nil, err
	}
	return cli.dumpDomainListByFormat(res)
}

func (cli Zms) LookupDomainByTag(tagKey string, tagValue string) (*string, error) {
	res, err := cli.Zms.GetDomainList(nil, "", "", nil, "", nil, "", "", "", "", zms.TagKey(tagKey), zms.TagCompoundValue(tagValue), "", "", "")
	if err != nil {
		return nil, err
	}
	return cli.dumpDomainListByFormat(res)
}

func (cli Zms) ListDomains(limit *int32, skip string, prefix string, depth *int32) (*string, error) {
	res, err := cli.Zms.GetDomainList(limit, skip, prefix, depth, "", nil, "", "", "", "", "", "", "", "", "")
	if err != nil {
		return nil, err
	}

	return cli.dumpDomainListByFormat(res)
}

func (cli Zms) GetSignedDomains(dn string, matchingTag string) (*string, error) {
	master := true
	conditions := true
	signedDomains, etag, err := cli.Zms.GetSignedDomains(zms.DomainName(dn), "false", "", &master, &conditions, matchingTag)
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("ETag: " + etag + "\n")
		for _, domain := range signedDomains.Domains {
			cli.dumpSignedDomain(&buf, domain, false)
		}
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(signedDomains, oldYamlConverter)
}

func (cli Zms) ShowOverdueReview(dn string) (*string, error) {

	domainRoleMembers, err := cli.Zms.GetOverdueReview(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		_, err = buf.WriteString("Overdue review members:\n")
		if err != nil {
			return nil, err
		}

		cli.dumpDomainRoleMembers(&buf, domainRoleMembers, true)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(domainRoleMembers, oldYamlConverter)
}

func (cli Zms) ShowDomain(dn string) (*string, error) {
	signatureP1363Format := false
	signedDomains, _, err := cli.Zms.GetJWSDomain(zms.DomainName(dn), &signatureP1363Format, "")
	if err != nil {
		return nil, err
	}

	decodedPayload, err := base64.RawURLEncoding.DecodeString(signedDomains.Payload)
	if err != nil {
		return nil, err
	}

	var domainData zms.DomainData
	if err := json.Unmarshal(decodedPayload, &domainData); err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
		if err != nil {
			return nil, err
		}
		cli.dumpDomain(&buf, domain)

		// make sure we have a domain
		if res != nil {
			cli.dumpDomainData(&buf, domainData)
		}
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(domainData, oldYamlConverter)
}

func (cli Zms) ShowDomainAttrs(dn string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	domain.Id = nil

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		cli.dumpDomain(&buf, domain)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(domain, oldYamlConverter)
}

func (cli Zms) CheckDomain(dn string) (*string, error) {
	domainDataCheck, err := cli.Zms.GetDomainDataCheck(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("checked data:\n")
		cli.dumpDataCheck(&buf, *domainDataCheck)
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(domainDataCheck, oldYamlConverter)
}

func (cli Zms) showDomainOld(dn string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	cli.dumpDomain(&buf, domain)
	cli.dumpTags(&buf, true, "  ", indentLevel1, domain.Tags)
	cli.dumpRoles(&buf, dn, "", "")
	cli.dumpGroups(&buf, dn, "", "")
	cli.dumpPolicies(&buf, dn, "", "")
	cli.dumpServices(&buf, dn, "", "")

	var names []string
	names, err = cli.entityNames(dn)
	if err != nil {
		return nil, err
	}
	cli.dumpEntities(&buf, dn, names)

	s := buf.String()
	return &s, nil
}

func (cli Zms) showDomainNew(dn string) (*string, error) {
	conditions := true
	domains, _, err := cli.Zms.GetSignedDomains(zms.DomainName(dn), "false", "all", &conditions, &conditions, "")
	if err != nil {
		return nil, err
	}

	if domains == nil || len(domains.Domains) != 1 {
		return nil, fmt.Errorf("Domain with name " + dn + " wasn't found")
	}

	return cli.dumpByFormat(domains.Domains[0].Domain, nil)
}

func (cli Zms) showDomain(dn string) (*string, error) {

	if cli.OutputFormat == JSONOutputFormat || cli.OutputFormat == YAMLOutputFormat {
		return cli.showDomainNew(dn)
	} else {
		return cli.showDomainOld(dn)
	}
}

func (cli Zms) showDomainTags(dn string) (string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return "", err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		cli.dumpTags(&buf, false, "", indentLevel1, domain.Tags)
		s := buf.String()
		return &s, nil
	}

	tagsDump, err := cli.dumpByFormat(domain.Tags, oldYamlConverter)
	return *tagsDump, err
}

func getDomainMetaObject(domain *zms.Domain) zms.DomainMeta {
	return zms.DomainMeta{
		Description:           domain.Description,
		ApplicationId:         domain.ApplicationId,
		TokenExpiryMins:       domain.TokenExpiryMins,
		ServiceCertExpiryMins: domain.ServiceCertExpiryMins,
		RoleCertExpiryMins:    domain.RoleCertExpiryMins,
		SignAlgorithm:         domain.SignAlgorithm,
		MemberExpiryDays:      domain.MemberExpiryDays,
		ServiceExpiryDays:     domain.ServiceExpiryDays,
		GroupExpiryDays:       domain.GroupExpiryDays,
		Tags:                  domain.Tags,
		MemberPurgeExpiryDays: domain.MemberPurgeExpiryDays,
	}
}

func (cli Zms) SetCompleteDomainMeta(dn, descr, org string, auditEnabled bool, applicationID, businessService string) error {
	meta := zms.DomainMeta{
		Description:     descr,
		Org:             zms.ResourceName(org),
		Enabled:         nil,
		AuditEnabled:    &auditEnabled,
		ApplicationId:   applicationID,
		BusinessService: businessService,
	}
	return cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
}

func (cli Zms) SetDomainMeta(dn string, descr string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := getDomainMetaObject(domain)
	meta.Description = descr

	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainAuditEnabled(dn string, auditEnabled bool) (*string, error) {
	meta := zms.DomainMeta{
		AuditEnabled: &auditEnabled,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), "auditenabled", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainUserAuthorityFilter(dn, filter string) (*string, error) {
	meta := zms.DomainMeta{
		UserAuthorityFilter: filter,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), "userauthorityfilter", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainEnvironment(dn, environment string) (*string, error) {
	meta := zms.DomainMeta{
		Environment: environment,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), "environment", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainContact(dn, contactType, contactUser string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	domainContacts := domain.Contacts
	if domainContacts == nil {
		domainContacts = make(map[zms.SimpleName]string)
	}
	domainContacts[zms.SimpleName(contactType)] = contactUser
	meta := zms.DomainMeta{
		Contacts: domainContacts,
	}
	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " contacts successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainFeatureFlags(dn string, flags int32) (*string, error) {
	meta := zms.DomainMeta{
		FeatureFlags: &flags,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), "featureflags", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainMemberExpiryDays(dn string, days int32) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := getDomainMetaObject(domain)
	meta.MemberExpiryDays = &days

	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainMemberPurgeExpiryDays(dn string, days int32) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := getDomainMetaObject(domain)
	meta.MemberPurgeExpiryDays = &days

	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainServiceExpiryDays(dn string, days int32) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := getDomainMetaObject(domain)
	meta.ServiceExpiryDays = &days

	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainGroupExpiryDays(dn string, days int32) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := getDomainMetaObject(domain)
	meta.GroupExpiryDays = &days

	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainTokenExpiryMins(dn string, mins int32) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := getDomainMetaObject(domain)
	meta.TokenExpiryMins = &mins

	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainTokenSignAlgorithm(dn string, alg string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := getDomainMetaObject(domain)
	meta.SignAlgorithm = alg

	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainServiceCertExpiryMins(dn string, mins int32) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := getDomainMetaObject(domain)
	meta.ServiceCertExpiryMins = &mins

	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainRoleCertExpiryMins(dn string, mins int32) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := getDomainMetaObject(domain)
	meta.RoleCertExpiryMins = &mins

	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) AddDomainTags(dn string, tagKey string, tagValues []string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	meta := getDomainMetaObject(domain)

	tagValueArr := make([]zms.TagCompoundValue, 0)

	if meta.Tags == nil {
		meta.Tags = map[zms.TagKey]*zms.TagValueList{}
	} else {
		// append current tags
		currentTagValues := meta.Tags[zms.TagKey(tagKey)]
		if currentTagValues != nil {
			tagValueArr = append(tagValueArr, currentTagValues.List...)
		}
	}

	for _, tagValue := range tagValues {
		tagValueArr = append(tagValueArr, zms.TagCompoundValue(tagValue))
	}

	meta.Tags[zms.TagKey(tagKey)] = &zms.TagValueList{List: tagValueArr}

	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}

	output, err := cli.showDomainTags(dn)
	if err != nil {
		// due to mysql read after write issue it's possible that
		// we'll get 404 after writing our object so in that
		// case we're going to do a quick sleep and retry request
		time.Sleep(500 * time.Millisecond)
		output, err = cli.showDomainTags(dn)
	}
	return &output, err

}

func (cli Zms) DeleteDomainTags(dn string, tagKey string, tagValue string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := getDomainMetaObject(domain)

	tagValueArr := make([]zms.TagCompoundValue, 0)

	if meta.Tags == nil {
		meta.Tags = map[zms.TagKey]*zms.TagValueList{}
	}

	// except given tagValue, set the same tags map
	if tagValue != "" && meta.Tags != nil {
		currentTagValues := meta.Tags[zms.TagKey(tagKey)]
		if currentTagValues != nil {
			for _, curTagValue := range currentTagValues.List {
				if tagValue != string(curTagValue) {
					tagValueArr = append(tagValueArr, curTagValue)
				}
			}
		}
	}

	meta.Tags[zms.TagKey(tagKey)] = &zms.TagValueList{List: tagValueArr}

	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, cli.ResourceOwner, &meta)
	if err != nil {
		return nil, err
	}

	output, err := cli.showDomainTags(dn)
	if err != nil {
		// due to mysql read after write issue it's possible that
		// we'll get 404 after writing our object so in that
		// case we're going to do a quick sleep and retry request
		time.Sleep(500 * time.Millisecond)
		output, err = cli.showDomainTags(dn)
	}
	return &output, err
}

func (cli Zms) SetDomainAccount(dn string, account string) (*string, error) {
	meta := zms.DomainMeta{
		Account: account,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), "account", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " account successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainSubscription(dn string, subscription string) (*string, error) {
	meta := zms.DomainMeta{
		AzureSubscription: subscription,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), "azuresubscription", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " subscription successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainProject(dn, projectId, projectNumber string) (*string, error) {
	meta := zms.DomainMeta{
		GcpProject:       projectId,
		GcpProjectNumber: projectNumber,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), "gcpproject", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " project successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainOrgName(dn string, org string) (*string, error) {
	meta := zms.DomainMeta{
		Org: zms.ResourceName(org),
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), "org", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " org name successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainProductId(dn string, productIDNumber int32, productIDString string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := zms.DomainMeta{
		YpmId:     domain.YpmId,
		ProductId: domain.ProductId,
	}
	if productIDNumber != -1 {
		meta.YpmId = &productIDNumber
	} else {
		meta.ProductId = productIDString
	}
	err = cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), "productid", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " product-id successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainApplicationId(dn string, applicationID string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	domainAuditEnabled := false
	if domain.AuditEnabled != nil {
		domainAuditEnabled = *domain.AuditEnabled
	}
	err = cli.SetCompleteDomainMeta(dn, domain.Description, string(domain.Org), domainAuditEnabled, applicationID, domain.BusinessService)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " application-id successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainBusinessService(dn string, businessService string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	domainAuditEnabled := false
	if domain.AuditEnabled != nil {
		domainAuditEnabled = *domain.AuditEnabled
	}
	err = cli.SetCompleteDomainMeta(dn, domain.Description, string(domain.Org), domainAuditEnabled, domain.ApplicationId, businessService)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " business-service successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDomainCertDnsDomain(dn string, dnsDomain string) (*string, error) {
	meta := zms.DomainMeta{
		CertDnsDomain: dnsDomain,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), "certdnsdomain", cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " cert-dns-domain successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) SetDefaultAdmins(dn string, admins []string) (*string, error) {
	validatedAdmins := cli.createResourceList(cli.validatedUsers(admins, false))
	defaultAdmins := zms.DefaultAdmins{Admins: validatedAdmins}
	err := cli.Zms.PutDefaultAdmins(zms.DomainName(dn), cli.AuditRef, &defaultAdmins)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " administrators successfully set]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}
	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) ListPendingDomainRoleMembers(principal, domainName string) (*string, error) {
	domainMembership, err := cli.Zms.GetPendingDomainRoleMembersList(zms.EntityName(principal), domainName)
	if err != nil {
		return nil, err
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("domains:\n")
		for _, domainRoleMembers := range domainMembership.DomainRoleMembersList {
			cli.dumpDomainRoleMembers(&buf, domainRoleMembers, true)
		}
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(domainMembership, oldYamlConverter)
}

func (cli Zms) PutDomainDependency(dn string, service string) (*string, error) {
	var dependentService zms.DependentService
	dependentService.Service = zms.ServiceName(service)
	err := cli.Zms.PutDomainDependency(zms.DomainName(dn), cli.AuditRef, &dependentService)
	if err != nil {
		return nil, err
	}

	s := "[domain " + dn + " service " + service + " domain-dependency successfully updated]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) DeleteDomainDependency(dn string, service string) (*string, error) {
	err := cli.Zms.DeleteDomainDependency(zms.DomainName(dn), zms.ServiceName(service), cli.AuditRef)
	if err != nil {
		return nil, err
	}

	s := "[domain " + dn + " service " + service + " domain-dependency successfully deleted]\n"
	message := SuccessMessage{
		Status:  200,
		Message: s,
	}

	return cli.dumpByFormat(message, cli.buildYAMLOutput)
}

func (cli Zms) GetDependentServiceList(dn string) (*string, error) {
	dependentServicelist, err := cli.Zms.GetDependentServiceList(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	dependentServices := make([]string, 0)
	for _, n := range dependentServicelist.Names {
		dependentServices = append(dependentServices, string(n))
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("dependent-services:\n")
		cli.dumpObjectList(&buf, dependentServices, dn, "service")
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(dependentServices, oldYamlConverter)
}

func (cli Zms) GetDependentDomainList(service string) (*string, error) {
	domainList, err := cli.Zms.GetDependentDomainList(zms.ServiceName(service))
	if err != nil {
		return nil, err
	}
	dependentDomains := make([]string, 0)
	for _, n := range domainList.Names {
		dependentDomains = append(dependentDomains, string(n))
	}

	oldYamlConverter := func(res interface{}) (*string, error) {
		var buf bytes.Buffer
		buf.WriteString("dependent-domains:\n")
		cli.dumpObjectList(&buf, dependentDomains, service, "domain")
		s := buf.String()
		return &s, nil
	}

	return cli.dumpByFormat(dependentDomains, oldYamlConverter)
}

func (cli Zms) GetAuthHistoryDependencies(dn string) (*string, error) {
	authHistoryDependencies, err := cli.Zms.GetAuthHistoryDependencies(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	if cli.OutputFormat == DefaultOutputFormat {
		cli.OutputFormat = YAMLOutputFormat
	}

	return cli.dumpByFormat(authHistoryDependencies, nil)
}
