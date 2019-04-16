// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
	"gopkg.in/yaml.v2"
)

// DeleteDomain deletes the given ZMS domain.
func (cli Zms) DeleteDomain(dn string) (*string, error) {
	_, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err == nil {
		i := strings.LastIndex(dn, ".")
		name := dn
		parent := ""
		if i < 0 {
			err = cli.Zms.DeleteTopLevelDomain(zms.SimpleName(dn), cli.AuditRef)
		} else {
			parent = dn[0:i]
			name = dn[i+1:]
			// special case for top level user domains
			// where parent is just the user domain
			if parent == cli.HomeDomain {
				err = cli.Zms.DeleteUserDomain(zms.SimpleName(name), cli.AuditRef)
			} else {
				err = cli.Zms.DeleteSubDomain(zms.DomainName(parent), zms.SimpleName(name), cli.AuditRef)
			}
		}
		if err == nil {
			s := "[Deleted domain " + dn + "]"
			return &s, nil
		}
	}
	return nil, err
}

func (cli Zms) ImportDomain(dn string, filename string, admins []string) (*string, error) {
	validatedAdmins := cli.validatedUsers(admins, true)
	var spec map[string]interface{}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(data, &spec)
	if err != nil {
		return nil, err
	}
	dnSpec := spec["domain"].(map[interface{}]interface{})
	dn2 := dnSpec["name"].(string)
	if dn2 != dn {
		return nil, fmt.Errorf("Domain name mismatch. Expected " + dn + ", encountered " + dn2)
	}
	var productID int
	if val, ok := dnSpec["product_id"]; ok {
		productID = val.(int)
	} else if cli.ProductIdSupport && strings.LastIndex(dn, ".") < 0 {
		return nil, fmt.Errorf("Top Level Domains require an integer number specified for the Product ID")
	}
	productID32 := int32(productID)
	_, err = cli.AddDomain(dn, &productID32, admins)
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
	err = cli.SetCompleteDomainMeta(dn, descr, org, auditEnabled, applicationID)
	if err != nil {
		return nil, err
	}
	lstRoles := dnSpec["roles"].([]interface{})
	err = cli.importRoles(dn, lstRoles, validatedAdmins, false)
	if err != nil {
		return nil, err
	}
	lstPolicies := dnSpec["policies"].([]interface{})
	err = cli.importPolicies(dn, lstPolicies, false)
	if err != nil {
		return nil, err
	}
	if lstServices, ok := dnSpec["services"].([]interface{}); ok {
		err = cli.importServices(dn, lstServices, false)
		if err != nil {
			return nil, err
		}
	}
	s := "[imported domain '" + dn + "' successfully]"
	return &s, nil
}

func (cli Zms) UpdateDomain(dn string, filename string) (*string, error) {
	var spec map[string]interface{}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(data, &spec)
	if err != nil {
		return nil, err
	}
	dnSpec := spec["domain"].(map[interface{}]interface{})
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
	err = cli.SetCompleteDomainMeta(dn, descr, org, auditEnabled, applicationID)
	if err != nil {
		return nil, err
	}
	if lstRoles, ok := dnSpec["roles"].([]interface{}); ok {
		err = cli.importRoles(dn, lstRoles, nil, true)
		if err != nil {
			return nil, err
		}
	}
	if lstPolicies, ok := dnSpec["policies"].([]interface{}); ok {
		err = cli.importPolicies(dn, lstPolicies, true)
		if err != nil {
			return nil, err
		}
	}
	if lstServices, ok := dnSpec["services"].([]interface{}); ok {
		err = cli.importServices(dn, lstServices, true)
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
	data, err := cli.showDomain(dn, true)
	cli.Verbose = verbose
	if err == nil && data != nil {
		s := *data
		if filename == "-" {
			fmt.Println(s)
		} else {
			err = ioutil.WriteFile(filename, []byte(s), 0644)
		}
	}
	return nil, err
}

func (cli Zms) SystemBackup(dir string) (*string, error) {
	res, err := cli.Zms.GetDomainList(nil, "", "", nil, "", nil, "", "", "")
	if err != nil {
		return nil, err
	}
	verbose := cli.Verbose
	cli.Verbose = false
	for _, name := range res.Names {
		fmt.Fprintf(os.Stdout, "Processing domain "+string(name)+"...\n")
		filename := dir + "/" + string(name)
		data, err := cli.showDomain(string(name), true)
		if err == nil && data != nil {
			s := *data
			err = ioutil.WriteFile(filename, []byte(s), 0644)
		}
	}
	cli.Verbose = verbose
	s := "[exported " + strconv.Itoa(len(res.Names)) + " domains to " + dir + " directory]"
	return &s, nil
}

func (cli Zms) AddDomain(dn string, productID *int32, admins []string) (*string, error) {
	// sanity check cli usage: sub domain admin list should not contain a productID
	if productID == nil && admins != nil && len(admins) > 0 {
		// just checking the first admin to decide if productID was actually added
		_, err := cli.getInt32(admins[0])
		if err == nil {
			s := "Do not specify Product ID when creating a sub domain. Only top level domains require a Product ID. Bad value: " + admins[0]
			return nil, fmt.Errorf(s)
		}
	}
	validatedAdmins := cli.validatedUsers(admins, true)
	s, err := cli.createDomain(dn, productID, validatedAdmins)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (cli Zms) createDomain(dn string, productID *int32, admins []string) (*string, error) {
	i := strings.LastIndex(dn, ".")
	name := dn
	parent := ""
	if i < 0 {
		tld := zms.TopLevelDomain{}
		tld.Name = zms.SimpleName(dn)
		tld.AdminUsers = cli.createResourceList(admins)
		tld.YpmId = productID
		_, err := cli.Zms.PostTopLevelDomain(cli.AuditRef, &tld)
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
		_, err := cli.Zms.PostUserDomain(zms.SimpleName(name), cli.AuditRef, &d)
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
	_, err := cli.Zms.PostSubDomain(zms.DomainName(parent), cli.AuditRef, &d)
	if err == nil {
		s := "[subdomain created: " + dn + "]"
		return &s, nil
	}
	return nil, err
}

func (cli Zms) LookupDomainByRole(roleMember string, roleName string) (*string, error) {
	var buf bytes.Buffer
	res, err := cli.Zms.GetDomainList(nil, "", "", nil, "", nil, zms.ResourceName(roleMember), zms.ResourceName(roleName), "")
	if err == nil {
		buf.WriteString("domains:\n")
		for _, name := range res.Names {
			buf.WriteString(indent_level1_dash + string(name) + "\n")
		}
		s := buf.String()
		return &s, nil
	}
	return nil, err
}

func (cli Zms) LookupDomainById(account string, productID *int32) (*string, error) {
	var buf bytes.Buffer
	res, err := cli.Zms.GetDomainList(nil, "", "", nil, account, productID, "", "", "")
	if err == nil {
		buf.WriteString("domain:\n")
		for _, name := range res.Names {
			buf.WriteString(indent_level1_dash + string(name) + "\n")
		}
		s := buf.String()
		return &s, nil
	}
	return nil, err
}

func (cli Zms) ListDomains(limit *int32, skip string, prefix string, depth *int32) (*string, error) {
	var buf bytes.Buffer
	res, err := cli.Zms.GetDomainList(limit, skip, prefix, depth, "", nil, "", "", "")
	if err == nil {
		buf.WriteString("domains:\n")
		for _, name := range res.Names {
			buf.WriteString(indent_level1_dash + string(name) + "\n")
		}
		s := buf.String()
		return &s, nil
	}
	return nil, err
}

func (cli Zms) GetSignedDomains(dn string, matchingTag string) (*string, error) {
	var buf bytes.Buffer
	res, etag, err := cli.Zms.GetSignedDomains(zms.DomainName(dn), "false", "", matchingTag)
	if err != nil {
		return nil, err
	}
	buf.WriteString("ETag: " + etag + "\n")
	if res != nil {
		for _, domain := range res.Domains {
			cli.dumpSignedDomain(&buf, domain, false)
		}
	}
	s := buf.String()
	return &s, nil
}

func (cli Zms) ShowDomain(dn string) (*string, error) {

	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	cli.dumpDomain(&buf, domain)

	// now retrieve the full domain in one call
	res, _, err := cli.Zms.GetSignedDomains(zms.DomainName(dn), "false", "", "")
	if err != nil {
		return nil, err
	}

	// make sure we have a domain and it must be only one
	if res != nil && len(res.Domains) == 1 {
		cli.dumpSignedDomain(&buf, res.Domains[0], true)
	}
	s := buf.String()
	return &s, nil
}

func (cli Zms) CheckDomain(dn string) (*string, error) {
	domainDataCheck, err := cli.Zms.GetDomainDataCheck(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("checked data:\n")
	cli.dumpDataCheck(&buf, *domainDataCheck)
	s := buf.String()
	return &s, nil
}

func (cli Zms) showDomain(dn string, export bool) (*string, error) {

	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	cli.dumpDomain(&buf, domain)
	cli.dumpRoles(&buf, dn)
	cli.dumpPolicies(&buf, dn)
	cli.dumpServices(&buf, dn)

	var names []string
	names, err = cli.entityNames(dn)
	if err != nil {
		return nil, err
	}
	cli.dumpEntities(&buf, dn, names)

	s := buf.String()
	return &s, nil
}

func (cli Zms) SetCompleteDomainMeta(dn string, descr string, org string, auditEnabled bool, applicationID string) error {
	meta := zms.DomainMeta{
		Description:   descr,
		Org:           zms.ResourceName(org),
		Enabled:       nil,
		AuditEnabled:  &auditEnabled,
		ApplicationId: applicationID,
	}
	return cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, &meta)
}

func (cli Zms) SetDomainMeta(dn string, descr string, org string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	meta := zms.DomainMeta{
		Description:   descr,
		Org:           zms.ResourceName(org),
		ApplicationId: domain.ApplicationId,
	}
	err = cli.Zms.PutDomainMeta(zms.DomainName(dn), cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	return &s, nil
}

func (cli Zms) SetDomainAuditEnabled(dn string, auditEnabled bool) (*string, error) {
	meta := zms.DomainMeta{
		AuditEnabled: &auditEnabled,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), zms.SimpleName("auditenabled"), cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " metadata successfully updated]\n"
	return &s, nil
}

func (cli Zms) SetDomainAccount(dn string, account string) (*string, error) {
	meta := zms.DomainMeta{
		Account: account,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), zms.SimpleName("account"), cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " account successfully updated]\n"
	return &s, nil
}

func (cli Zms) SetDomainProductId(dn string, productID int32) (*string, error) {
	meta := zms.DomainMeta{
		YpmId: &productID,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), zms.SimpleName("productid"), cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " product-id successfully updated]\n"
	return &s, nil
}

func (cli Zms) SetDomainApplicationId(dn string, applicationID string) (*string, error) {
	domain, err := cli.Zms.GetDomain(zms.DomainName(dn))
	if err != nil {
		return nil, err
	}
	err = cli.SetCompleteDomainMeta(dn, domain.Description, string(domain.Org), *domain.AuditEnabled, applicationID)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " application-id successfully updated]\n"
	return &s, nil
}

func (cli Zms) SetDomainCertDnsDomain(dn string, dnsDomain string) (*string, error) {
	meta := zms.DomainMeta{
		CertDnsDomain: dnsDomain,
	}
	err := cli.Zms.PutDomainSystemMeta(zms.DomainName(dn), zms.SimpleName("certdnsdomain"), cli.AuditRef, &meta)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " cert-dns-domain successfully updated]\n"
	return &s, nil
}

func (cli Zms) SetDefaultAdmins(dn string, admins []string) (*string, error) {
	validatedAdmins := cli.createResourceList(cli.validatedUsers(admins, false))
	defaultAdmins := zms.DefaultAdmins{Admins: validatedAdmins}
	err := cli.Zms.PutDefaultAdmins(zms.DomainName(dn), cli.AuditRef, &defaultAdmins)
	if err != nil {
		return nil, err
	}
	s := "[domain " + dn + " administrators successfully set]\n"
	return &s, nil
}
