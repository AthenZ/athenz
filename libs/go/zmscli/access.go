// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/yahoo/athenz/clients/go/zms"
)

func (cli Zms) ShowAccess(dn string, action string, resource string, altIdent *string, altDomain *string) (*string, error) {
	yrn := resource
	idx := strings.Index(resource, ":")
	if idx < 0 {
		yrn = dn + ":" + resource
	} else {
		// special handling for assume_role case where the domain in
		// the resource does not have to match the value specified
		// in the domain argument.
		action = strings.ToLower(action)
		if action != "assume_role" {
			resDomain := resource[0:idx]
			if resDomain != dn {
				return nil, fmt.Errorf("Domain name mismatch. Expected " + dn + ", encountered in resource " + resDomain)
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
	access, err := cli.Zms.GetAccess(zms.ActionName(action), zms.YRN(yrn), zms.DomainName(trustDomain), zms.EntityName(altPrincipal))
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
