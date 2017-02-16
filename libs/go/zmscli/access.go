// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
)

func (cli Zms) getAccessParameters(dn string, action string, resource string, altIdent *string, altDomain *string) (string, string, string, error) {
	fullResourceName := resource
	idx := strings.Index(resource, ":")
	if idx < 0 {
		fullResourceName = dn + ":" + resource
	} else {
		// special handling for assume_role case where the domain in
		// the resource does not have to match the value specified
		// in the domain argument.
		action = strings.ToLower(action)
		if action != "assume_role" {
			resDomain := resource[0:idx]
			if resDomain != dn {
				return "", "", "", fmt.Errorf("Domain name mismatch. Expected " + dn + ", encountered in resource " + resDomain)
			}
		}
	}
	altPrincipal := ""
	if altIdent != nil {
		altPrincipal = *altIdent
		if strings.Index(altPrincipal, ".") < 0 {
			altPrincipal = cli.UserDomain + "." + altPrincipal
		}
	}
	trustDomain := ""
	if altDomain != nil {
		trustDomain = *altDomain
	}
	return fullResourceName, trustDomain, altPrincipal, nil
}

func (cli Zms) ShowAccess(dn string, action string, resource string, altIdent *string, altDomain *string) (*string, error) {
	fullResourceName, trustDomain, altPrincipal, err := cli.getAccessParameters(dn, action, resource, altIdent, altDomain)
	if err != nil {
		return nil, err
	}
	access, err := cli.Zms.GetAccess(zms.ActionName(action), zms.ResourceName(fullResourceName), zms.DomainName(trustDomain), zms.EntityName(altPrincipal))
	if err != nil {
		return nil, err
	}
	s := "access: granted"
	if !access.Granted {
		s = "access: denied"
	}
	return &s, nil
}

func (cli Zms) ShowAccessExt(dn string, action string, resource string, altIdent *string, altDomain *string) (*string, error) {
	fullResourceName, trustDomain, altPrincipal, err := cli.getAccessParameters(dn, action, resource, altIdent, altDomain)
	if err != nil {
		return nil, err
	}
	access, err := cli.Zms.GetAccessExt(zms.ActionName(action), fullResourceName, zms.DomainName(trustDomain), zms.EntityName(altPrincipal))
	if err != nil {
		return nil, err
	}
	s := "access: granted"
	if !access.Granted {
		s = "access: denied"
	}
	return &s, nil
}

func (cli Zms) ShowResourceAccess(principal string, action string) (*string, error) {
	rsrcAccessList, err := cli.Zms.GetResourceAccessList(zms.EntityName(principal), zms.ActionName(action))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString("resource-access:\n")
	for _, rsrc := range rsrcAccessList.Resources {
		buf.WriteString(indent_level1_dash + "principal: " + string(rsrc.Principal) + "\n")
		buf.WriteString(indent_level1 + "  assertions:\n")
		indent2 := indent_level1 + "    - "
		for _, assertion := range rsrc.Assertions {
			cli.dumpAssertion(&buf, assertion, "", indent2)
		}
	}
	s := buf.String()
	return &s, nil
}
