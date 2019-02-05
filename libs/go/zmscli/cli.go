// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/yahoo/athenz/clients/go/zms"
	"golang.org/x/net/proxy"
)

type Zms struct {
	ZmsUrl           string
	Identity         string
	Verbose          bool
	Bulkmode         bool
	Interactive      bool
	Zms              zms.ZMSClient
	Domain           string
	AuditRef         string
	UserDomain       string
	HomeDomain       string
	ProductIdSupport bool
	Debug            bool
}

func (cli *Zms) SetClient(tr *http.Transport, authHeader, ntoken *string) {
	cli.Zms = zms.NewClient(cli.ZmsUrl, tr)
	cli.Zms.AddCredentials(*authHeader, *ntoken)
}

func (cli Zms) interactiveSingleQuoteString(interactive bool, value string) string {
	retValue := value
	if !interactive {
		retValue = "'" + value + "'"
	}
	return retValue
}

func (cli Zms) getInt32(str string) (int32, error) {
	value, err := strconv.ParseInt(str, 10, 32)
	if err != nil {
		return -1, err
	}
	return int32(value), nil
}

func getTimestamp(str string) (rdl.Timestamp, error) {
	value, err := rdl.TimestampParse(str)
	return value, err
}

func (cli *Zms) EvalCommand(params []string) (*string, error) {
	if len(params) >= 1 {
		cmd := params[0]
		args := params[1:]
		argc := len(args)
		dn := cli.Domain
		//first do commands that do not require the domain to be set in the context
		switch cmd {
		case "list-domain", "list-domains", "domain", "domains":
			if argc == 0 {
				return cli.ListDomains(nil, "", "", nil)
			} else if argc == 1 {
				prefix := args[0]
				return cli.ListDomains(nil, "", prefix, nil)
			} else if argc == 4 {
				var err error
				var limit, depth int32
				limit, err = cli.getInt32(args[0])
				if err != nil {
					return nil, err
				}
				skip := args[1]
				prefix := args[2]
				depth, err = cli.getInt32(args[3])
				if err != nil {
					return nil, err
				}
				return cli.ListDomains(&limit, skip, prefix, &depth)
			}
			return cli.helpCommand(params)
		case "lookup-domain-by-role":
			if argc == 2 {
				return cli.LookupDomainByRole(args[0], args[1])
			}
			return cli.helpCommand(params)
		case "lookup-domain-by-aws-account", "lookup-domain-by-account":
			if argc == 1 {
				return cli.LookupDomainById(args[0], nil)
			}
			return cli.helpCommand(params)
		case "lookup-domain-by-product-id":
			if argc == 1 {
				productID, err := cli.getInt32(args[0])
				if err != nil {
					return nil, err
				}
				return cli.LookupDomainById("", &productID)
			}
			return cli.helpCommand(params)
		case "use-domain":
			var s string
			if argc > 0 {
				cli.Domain = args[0]
				s = "[now working with the " + cli.Domain + " domain]"
			} else {
				cli.Domain = ""
				s = "[not using any domain]"
			}
			return &s, nil
		case "show-domain":
			if argc == 1 {
				//override the default domain, this command can show any of them
				dn = args[0]
			}
			if dn != "" {
				return cli.ShowDomain(dn)
			}
			return nil, fmt.Errorf("No domain specified")
		case "check-domain":
			if argc == 1 {
				//override the default domain, this command can check any of them
				dn = args[0]
			}
			if dn != "" {
				return cli.CheckDomain(dn)
			}
			return nil, fmt.Errorf("No domain specified")
		case "export-domain":
			if argc == 1 || argc == 2 {
				dn = args[0]
				yamlfile := "-"
				if argc == 2 {
					yamlfile = args[1]
				}
				return cli.ExportDomain(dn, yamlfile)
			}
			return cli.helpCommand(params)
		case "import-domain":
			if argc >= 1 {
				dn = args[0]
				yamlfile := "-"
				admins := args[0:0]
				if argc >= 2 {
					yamlfile = args[1]
					admins = args[2:]
				}
				cli.Bulkmode = true
				return cli.ImportDomain(dn, yamlfile, admins)
			}
			return cli.helpCommand(params)
		case "update-domain":
			if argc >= 1 {
				dn = args[0]
				yamlfile := "-"
				if argc >= 2 {
					yamlfile = args[1]
				}
				cli.Bulkmode = true
				return cli.UpdateDomain(dn, yamlfile)
			}
			return cli.helpCommand(params)
		case "system-backup":
			if argc == 1 {
				return cli.SystemBackup(args[0])
			}
			return cli.helpCommand(params)
		case "add-domain":
			if argc > 0 {
				dn = args[0]
				if cli.ProductIdSupport && strings.LastIndex(dn, ".") < 0 {
					if argc < 2 {
						return nil, fmt.Errorf("Top Level Domains require a number specified for the product id")
					}
					productID, err := cli.getInt32(args[1])
					if err != nil {
						return nil, fmt.Errorf("Top Level Domains require an integer number specified for the product id")
					}
					return cli.AddDomain(dn, &productID, args[2:])
				}
				return cli.AddDomain(dn, nil, args[1:])
			}
			return cli.helpCommand(params)
		case "delete-domain":
			if argc == 1 {
				if args[0] == dn {
					return nil, fmt.Errorf("Cannot delete domain while using it")
				}
				return cli.DeleteDomain(args[0])
			}
			return cli.helpCommand(params)
		case "set-default-admins":
			if argc >= 1 {
				return cli.SetDefaultAdmins(args[0], args[1:])
			}
		case "get-signed-domains":
			matchingTag := ""
			if argc == 1 {
				matchingTag = args[0]
			}
			return cli.GetSignedDomains("", matchingTag)
		case "list-server-template", "list-server-templates":
			return cli.ListServerTemplates()
		case "list-domain-template", "list-domain-templates":
			if argc == 1 {
				//override the default domain, this command can show any of them
				dn = args[0]
			}
			if dn != "" {
				return cli.ListDomainTemplates(dn)
			}
			return nil, fmt.Errorf("No domain specified")
		case "show-server-template":
			if argc == 1 {
				return cli.ShowServerTemplate(args[0])
			}
		case "show-resource":
			if argc == 2 {
				return cli.ShowResourceAccess(args[0], args[1])
			}
		case "list-user":
			return cli.ListUsers()
		case "delete-user":
			if argc == 1 {
				return cli.DeleteUser(args[0])
			}
		case "help":
			return cli.helpCommand(args)
		default:
			//the rest all rely on the domain being defined
			if dn == "" {
				var err error
				if cli.Interactive {
					err = fmt.Errorf("No domain specified. Use use-domain command to set the domain")
				} else {
					err = fmt.Errorf("No domain specified. Use -d argument to specify the domain. Type 'zms-cli' to see help information")
				}
				return nil, err
			}
			//and fall through
		}

		switch cmd {

		case "list-policy", "list-policies":
			return cli.ListPolicies(dn)
		case "show-policy":
			if argc == 1 {
				return cli.ShowPolicy(dn, args[0])
			}
		case "add-policy", "set-policy":
			if argc >= 1 {
				return cli.AddPolicy(dn, args[0], args[1:])
			}
		case "add-assertion":
			if argc >= 1 {
				return cli.AddAssertion(dn, args[0], args[1:])
			}
		case "delete-assertion":
			if argc >= 1 {
				return cli.DeleteAssertion(dn, args[0], args[1:])
			}
		case "delete-policy":
			if argc == 1 {
				return cli.DeletePolicy(dn, args[0])
			}
		case "show-access":
			if argc >= 2 {
				var trustDomain *string
				var altPrincipal *string
				if argc > 2 {
					altPrincipal = &args[2]
					if argc > 3 {
						trustDomain = &args[3]
					}
				}
				return cli.ShowAccess(dn, args[0], args[1], altPrincipal, trustDomain)
			}
		case "show-access-ext":
			if argc >= 2 {
				var trustDomain *string
				var altPrincipal *string
				if argc > 2 {
					altPrincipal = &args[2]
					if argc > 3 {
						trustDomain = &args[3]
					}
				}
				return cli.ShowAccessExt(dn, args[0], args[1], altPrincipal, trustDomain)
			}
		case "list-role", "list-roles":
			return cli.ListRoles(dn)
		case "show-role":
			if argc == 1 {
				return cli.ShowRole(dn, args[0], false, false)
			} else if argc == 2 && args[1] == "log" {
				return cli.ShowRole(dn, args[0], true, false)
			} else if argc == 2 && args[1] == "expand" {
				return cli.ShowRole(dn, args[0], false, true)
			}
		case "add-delegated-role", "add-trusted-role":
			if argc == 2 {
				return cli.AddDelegatedRole(dn, args[0], args[1])
			}
		case "add-group-role":
			if argc >= 1 {
				roleMembers := cli.convertRoleMembers(args[1:])
				return cli.AddGroupRole(dn, args[0], roleMembers)
			}
		case "add-provider-role-member", "add-provider-role-members":
			if argc >= 4 {
				return cli.AddProviderRoleMembers(dn, args[0], args[1], args[2], args[3:])
			}
		case "show-provider-role-member", "show-provider-role-members":
			if argc == 3 {
				return cli.ShowProviderRoleMembers(dn, args[0], args[1], args[2])
			}
		case "delete-provider-role-member", "delete-provider-role-members":
			if argc >= 4 {
				return cli.DeleteProviderRoleMembers(dn, args[0], args[1], args[2], args[3:])
			}
		case "add-member", "add-members":
			if argc >= 2 {
				return cli.AddMembers(dn, args[0], args[1:])
			}
		case "add-temporary-member":
			if argc == 3 {
				value, err := getTimestamp(args[2])
				if err == nil {
					return cli.AddTemporaryMember(dn, args[0], args[1], value)
				}
				return nil, err
			}
		case "delete-member", "delete-members":
			if argc >= 2 {
				return cli.DeleteMembers(dn, args[0], args[1:])
			}
		case "check-member", "check-members", "show-member", "show-members":
			if argc >= 2 {
				return cli.CheckMembers(dn, args[0], args[1:])
			}
		case "delete-role":
			if argc == 1 {
				return cli.DeleteRole(dn, args[0])
			}
		case "delete-domain-role-member":
			if argc == 1 {
				return cli.DeleteDomainRoleMember(dn, args[0])
			}
		case "list-domain-role-members":
			if argc == 0 {
				return cli.ListDomainRoleMembers(dn)
			}
		case "list-service", "list-services":
			if argc == 0 {
				return cli.ListServices(dn)
			}
		case "show-service":
			if argc == 1 {
				return cli.ShowService(dn, args[0])
			}
		case "add-service":
			if argc == 3 {
				pubkey, err := cli.getPublicKey(args[2])
				if err == nil {
					return cli.AddService(dn, args[0], args[1], pubkey)
				}
				return nil, err
			} else if argc == 1 {
				return cli.AddService(dn, args[0], "", nil)
			}
		case "add-provider-service":
			if argc == 3 {
				pubkey, err := cli.getPublicKey(args[2])
				if err == nil {
					return cli.AddProviderService(dn, args[0], args[1], pubkey)
				}
				return nil, err
			}
		case "set-service-endpoint":
			if argc == 2 {
				return cli.SetServiceEndpoint(dn, args[0], args[1])
			}
		case "set-service-exe":
			if argc == 4 {
				return cli.SetServiceExe(dn, args[0], args[1], args[2], args[3])
			}
		case "add-service-host":
			if argc >= 2 {
				return cli.AddServiceHost(dn, args[0], args[1:])
			}
		case "delete-service-host":
			if argc >= 2 {
				return cli.DeleteServiceHost(dn, args[0], args[1:])
			}
		case "add-public-key":
			if argc == 3 {
				pubkey, err := cli.getPublicKey(args[2])
				if err == nil {
					return cli.AddServicePublicKey(dn, args[0], args[1], pubkey)
				}
				return nil, err
			}
		case "show-public-key":
			if argc == 2 {
				return cli.ShowServicePublicKey(dn, args[0], args[1])
			}
		case "delete-public-key":
			if argc == 2 {
				return cli.DeleteServicePublicKey(dn, args[0], args[1])
			}
		case "delete-service":
			if argc == 1 {
				return cli.DeleteService(dn, args[0])
			}
		case "list-entity", "list-entities":
			if argc == 0 {
				return cli.ListEntities(dn)
			}
		case "add-entity":
			if argc > 1 {
				return cli.AddEntity(dn, args[0], args[1:])
			}
		case "delete-entity":
			if argc == 1 {
				return cli.DeleteEntity(dn, args[0])
			}
		case "show-entity":
			if argc == 1 {
				return cli.ShowEntity(dn, args[0])
			}
		case "add-tenancy":
			if argc == 1 {
				return cli.AddTenancy(dn, args[0])
			}
		case "delete-tenancy":
			if argc == 1 {
				return cli.DeleteTenancy(dn, args[0])
			}
		case "show-tenant-resource-group-roles":
			if argc == 3 {
				return cli.ShowTenantResourceGroupRoles(dn, args[0], args[1], args[2])
			}
		case "add-tenant-resource-group-roles":
			if argc > 3 {
				return cli.AddTenantResourceGroupRoles(dn, args[0], args[1], args[2], args[3:])
			}
		case "delete-tenant-resource-group-roles":
			if argc == 3 {
				return cli.DeleteTenantResourceGroupRoles(dn, args[0], args[1], args[2])
			}
		case "show-provider-resource-group-roles":
			if argc == 3 {
				return cli.ShowProviderResourceGroupRoles(dn, args[0], args[1], args[2])
			}
		case "add-provider-resource-group-roles":
			if argc > 3 {
				return cli.AddProviderResourceGroupRoles(dn, args[0], args[1], args[2], args[3:])
			}
		case "delete-provider-resource-group-roles":
			if argc == 3 {
				return cli.DeleteProviderResourceGroupRoles(dn, args[0], args[1], args[2])
			}
		case "set-domain-meta":
			if argc == 2 || argc == 3 {
				descr := args[0]
				org := args[1]
				return cli.SetDomainMeta(dn, descr, org)
			}
		case "set-aws-account", "set-domain-account":
			if argc == 1 {
				return cli.SetDomainAccount(dn, args[0])
			}
		case "set-audit-enabled":
			if argc == 1 {
				auditEnabled, err := strconv.ParseBool(args[0])
				if err != nil {
					return nil, err
				}
				return cli.SetDomainAuditEnabled(dn, auditEnabled)
			}
		case "set-product-id", "set-domain-product-id":
			if argc == 1 {
				productID, err := cli.getInt32(args[0])
				if err != nil {
					return nil, err
				}
				return cli.SetDomainProductId(dn, productID)
			}
		case "set-application-id":
			if argc == 1 {
				return cli.SetDomainApplicationId(dn, args[0])
			}
		case "set-cert-dns-domain":
			if argc == 1 {
				return cli.SetDomainCertDnsDomain(dn, args[0])
			}
		case "set-domain-template":
			if argc >= 1 {
				return cli.SetDomainTemplate(dn, args[0:])
			}
		case "delete-domain-template":
			if argc == 1 {
				return cli.DeleteDomainTemplate(dn, args[0])
			}
		case "get-quota":
			if argc == 0 {
				return cli.GetQuota(dn)
			}
		case "set-quota":
			if argc >= 1 {
				return cli.SetQuota(dn, args[0:])
			}
		case "delete-quota":
			if argc == 0 {
				return cli.DeleteQuota(dn)
			}
		default:
			return nil, fmt.Errorf("Unrecognized command '%v'. Type 'zms-cli help' to see help information", cmd)
		}
		return nil, fmt.Errorf("Bad command syntax. Type 'zms-cli help' to see help information")
	}
	return cli.helpCommand(params)
}

func (cli Zms) helpCommand(params []string) (*string, error) {
	s := ""
	if len(params) == 1 {
		s = cli.HelpSpecificCommand(cli.Interactive, params[0])
	} else {
		s = cli.HelpListCommand()
	}
	return &s, nil
}

// HelpSpecificCommand returns the help string for the given command.
func (cli Zms) HelpSpecificCommand(interactive bool, cmd string) string {
	var buf bytes.Buffer

	// we are going to display the required domain argument
	// only in non-interactive mode
	domain_param := "-d domain"
	domain_example := "-d coretech"
	tenant_example := "-d sports"
	if interactive {
		domain_param = ""
		domain_example = "coretech> "
		tenant_example = "sports> "
	}

	switch cmd {
	case "list-domain":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   list-domain [prefix]\n")
		buf.WriteString("   list-domain [limit skip prefix depth]\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   prefix : return domains starting with this value \n")
		buf.WriteString("   limit  : return specified number of domains only\n")
		buf.WriteString("   skip   : exclude all the domains including the specified one from the return set\n")
		buf.WriteString("   depth  : maximum depth of the domains returned (0 - top level domains only)\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   list-domain cd\n")
		buf.WriteString("     return all domains who names start with cd\n")
	case "show-domain":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   show-domain domain\n")
		buf.WriteString("   " + domain_param + " show-domain\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   domain : retrieve roles, policies and services for this domain\n")
		buf.WriteString("          : this argument is required unless -d <domain> is specified or\n")
		buf.WriteString("          : running in repl/interactive mode with use-domain specified\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   show-domain coretech.hosted\n")
		buf.WriteString("   " + domain_example + " show-domain\n")
	case "lookup-domain-by-account", "lookup-domain-by-aws-account":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   lookup-domain-by-aws-account account-id\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   account-id  : lookup domain with specified account id\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   lookup-domain-by-aws-account 1234567890\n")
	case "lookup-domain-by-product-id":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   lookup-domain-by-product-id product-id\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   product-id  : lookup domain with specified product id\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   lookup-domain-by-product-id 10001\n")
	case "lookup-domain-by-role":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   lookup-domain-by-role role-member role-name\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   role-member  : name of the principal\n")
		buf.WriteString("   role-name    : name of the role where the principal is a member of\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   lookup-domain-by-role " + cli.UserDomain + ".joe admin\n")
	case "check-domain":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   check-domain domain\n")
		buf.WriteString("   " + domain_param + " check-domain\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   domain : verify domain resources and report any issues\n")
		buf.WriteString("          : this argument is required unless -d <domain> is specified or\n")
		buf.WriteString("          : running in repl/interactive mode with use-domain specified\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   check-domain coretech.hosted\n")
		buf.WriteString("   " + domain_example + " check-domain\n")
	case "use-domain":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   use-domain [domain]\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   domain : when running in repl mode sets the domain value for all operations\n")
		buf.WriteString("          : passing \"\" domain will reset the client's saved domain value\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   use-domain coretech\n")
	case "add-domain":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   add-domain domain [product-id] [admin ...]\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   domain     : name of the domain to be added\n")
		buf.WriteString("              : The name can be either a top level domain or a subdomain\n")
		buf.WriteString("   product-id : unique product id number required when creating top level domains\n")
		buf.WriteString("   admin      : list of domain administrators separated by a space\n")
		buf.WriteString("              : the user creating the domain will be added as an administrator\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   add-domain coretech john jane\n")
		buf.WriteString("     add a top level domain called coretech with " + cli.UserDomain + ".john, " + cli.UserDomain + ".jane and the caller as administrators\n")
		buf.WriteString("   add-domain coretech.hosted john jane\n")
		buf.WriteString("     add a subdomain hosted in domain coretech with " + cli.UserDomain + ".john, " + cli.UserDomain + ".jane and the caller as administrators\n")
	case "set-domain-meta":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " set-domain-meta description org\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain        : name of the domain being updated\n")
		}
		buf.WriteString("   description   : set the description for the domain\n")
		buf.WriteString("   org           : set the organization of the domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " set-domain-meta \"Coretech Hosted\" cloud.services\n")
	case "set-aws-account", "set-domain-account":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " set-aws-account account-id\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain        : name of the domain being updated\n")
		}
		buf.WriteString("   account-id    : set the aws account id for the domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " set-aws-account \"134901934383\"\n")
	case "set-audit-enabled":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " set-audit-enabled audit-enabled\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain        : name of the domain being updated\n")
		}
		buf.WriteString("   audit-enabled : enable/disable audit flag for the domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " set-audit-enabled true\n")
	case "set-product-id", "set-domain-product-id":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " set-product-id product-id\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain        : name of the domain being updated\n")
		}
		buf.WriteString("   product-id    : set the Product ID for the domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " set-product-id 10001\n")
	case "set-application-id":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " set-application-id application-id\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain        : name of the domain being updated\n")
		}
		buf.WriteString("   application-id        : set the Application ID for the domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " set-application-id 0oabg8pelxhjh0tcs0h7\n")
	case "set-cert-dns-domain":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " set-cert-dns-domain cert-domain-name\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain        : name of the domain being updated\n")
		}
		buf.WriteString("   cert-domain-name      : set the x.509 certificate dns domain name for the domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " set-cert-dns-domain athenz.cloud\n")
	case "import-domain":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   import-domain domain [file.yaml [admin ...]] - no file means stdin\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   domain    : name of the domain being imported\n")
		buf.WriteString("   file.yaml : file that contains domain contents in yaml format\n")
		buf.WriteString("   admin     : additional list of administrators to be added to the domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   import-domain coretech coretech.yaml " + cli.UserDomain + ".john\n")
	case "export-domain":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   export-domain domain [file.yaml] - no file means stdout\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   domain    : name of the domain to be exported\n")
		buf.WriteString("   file.yaml : filename where the domain data is stored\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   export-domain coretech /tmp/coretech.yaml\n")
	case "delete-domain":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   delete-domain domain\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   domain : name of the domain to be deleted\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   delete-domain coretech\n")
	case "set-default-admins":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   set-default-admins domain admin [admin ...]\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   domain : name of the domain to restore admin access\n")
		buf.WriteString("   admin  : list of administrators to be set for domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   set-default-admins coretech.hosted " + cli.UserDomain + ".john " + cli.UserDomain + ".jane\n")
	case "get-signed-domains":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   get-signed-domains [matching_tag]\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   matching-tag : value of ETag header retrieved from previous get-signed-domain call\n")
		buf.WriteString("                : server will return changes since this timestamp only\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   get-signed-domains\n")
		buf.WriteString("   get-signed-domains \"2015-04-10T20:43:34.023Z-gzip\"\n")
	case "list-policy":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " list-policy\n")
		if !interactive {
			buf.WriteString(" parameters:\n")
			buf.WriteString("   domain : name of the domain to retrieve the list of policies from\n")
		}
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " list-policy\n")
	case "show-policy":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " show-policy policy\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain : name of the domain that policy belongs to\n")
		}
		buf.WriteString("   policy : name of the policy to be displayed\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " show-policy admin\n")
	case "add-policy", "set-policy":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-policy policy [assertion]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain    : name of the domain to add policy to\n")
		}
		buf.WriteString("   policy    : name of the policy\n")
		buf.WriteString("   assertion : <effect> <action> to <role> on <resource>\n")
		buf.WriteString("             : effect - grant or deny\n")
		buf.WriteString("             : action - domain admin defined action available for the resource (e.g. read, write, delete)\n")
		buf.WriteString("             : role - which role this assertion applies to\n")
		buf.WriteString("             :        client will prepend 'domain:role.' to role name if not specified\n")
		buf.WriteString("             : resource - which resource this assertion applies to\n")
		buf.WriteString("             :            client will prepend 'domain:' to resource if not specified\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-policy writers_policy grant write to writers_role on articles.sports\n")
		buf.WriteString("   " + domain_example + " add-policy readers_policy grant read to readers_role on " + cli.interactiveSingleQuoteString(interactive, "articles.*") + "\n")
	case "add-assertion":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-assertion policy assertion\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain    : name of the domain that policy belongs to\n")
		}
		buf.WriteString("   policy    : name of the policy to add this assertion to\n")
		buf.WriteString("   assertion : <effect> <action> to <role> on <resource>\n")
		buf.WriteString("             : effect - grant or deny\n")
		buf.WriteString("             : action - domain admin defined action available for the resource (e.g. read, write, delete)\n")
		buf.WriteString("             : role - which role this assertion applies to\n")
		buf.WriteString("             :        client will prepend 'domain:role.' to role name if not specified\n")
		buf.WriteString("             : resource - which resource this assertion applies to\n")
		buf.WriteString("             :            client will prepend 'domain:' to resource if not specified\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-assertion writers_policy grant write to writers_role on articles.sports\n")
		buf.WriteString("   " + domain_example + " add-assertion readers_policy grant read to readers_role on " + cli.interactiveSingleQuoteString(interactive, "articles.*") + "\n")
	case "delete-assertion":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-assertion policy assertion\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain     : name of the domain that policy belongs to\n")
		}
		buf.WriteString("   policy     : name of the policy to delete this assertion from\n")
		buf.WriteString("   assertion  : existing assertion in the policy in the '<effect> <action> to <role> on <resource>' format\n")
		buf.WriteString("              : the value must be exactly what's displayed when executing the show-policy command\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-assertion writers_policy grant write to writers_role on articles.sports\n")
		buf.WriteString("   " + domain_example + " delete-assertion readers_policy grant read to readers_role on " + cli.interactiveSingleQuoteString(interactive, "articles.*") + "\n")
	case "delete-policy":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-policy policy\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain : name of the domain that policy belongs to\n")
		}
		buf.WriteString("   policy : name of the policy to be deleted\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-policy readers\n")
	case "show-access":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " show-access action resource [alt_identity [trust_domain]]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain       : name of the domain that resource belongs to\n")
		}
		buf.WriteString("   action       : access check action value\n")
		buf.WriteString("   resource     : access check resource (resource name)\n")
		buf.WriteString("                : client will prepend 'domain:' to resource if not specified\n")
		buf.WriteString("   alt_identity : run the access check for this identity instead of the caller\n")
		buf.WriteString("   trust_domain : when checking for cross-domain trust relationship\n")
		buf.WriteString("                : only check this trusted domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " show-access node_sudo node.host1\n")
		buf.WriteString("   " + domain_example + " show-access node_sudo coretech:node.host1\n")
		buf.WriteString("   " + domain_example + " show-access node_sudo coretech:node.host1 " + cli.UserDomain + ".john\n")
	case "show-access-ext":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " show-access-ext action resource [alt_identity [trust_domain]]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain       : name of the domain that resource belongs to\n")
		}
		buf.WriteString("   action       : access check action value\n")
		buf.WriteString("   resource     : access check resource (resource name)\n")
		buf.WriteString("                : client will prepend 'domain:' to resource if not specified\n")
		buf.WriteString("   alt_identity : run the access check for this identity instead of the caller\n")
		buf.WriteString("   trust_domain : when checking for cross-domain trust relationship\n")
		buf.WriteString("                : only check this trusted domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " show-access-ext node_sudo node.host1\n")
		buf.WriteString("   " + domain_example + " show-access-ext node_sudo coretech:node.host1\n")
		buf.WriteString("   " + domain_example + " show-access-ext node_sudo coretech:node.host1 " + cli.UserDomain + ".john\n")
	case "show-resource":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   show-resource principal action\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   principal    : show resources for this principal only\n")
		buf.WriteString("   action       : assertion action value to filter on\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   show-resource " + cli.UserDomain + ".user1 update\n")
		buf.WriteString("   show-resource " + cli.UserDomain + ".user1 \"\"\n")
		buf.WriteString("   show-resource \"\" assume_aws_role\n")
	case "list-role":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " list-role\n")
		if !interactive {
			buf.WriteString(" parameters:\n")
			buf.WriteString("   domain : name of the domain to retrieve the list of roles from\n")
		}
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " list-role\n")
	case "show-role":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " show-role role [log | expand]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain : name of the domain that role belongs to\n")
		}
		buf.WriteString("   role   : name of the role to be displayed\n")
		buf.WriteString("   log    : option argument to specify to display audit logs for role\n")
		buf.WriteString("   expand : option argument to specify to display delegated members\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " show-role admin\n")
		buf.WriteString("   " + domain_example + " show-role admin log\n")
		buf.WriteString("   " + domain_example + " show-role delegated-role expand\n")
	case "add-delegated-role":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-delegated-role role trusted_domain\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain       : name of the domain that role belongs to\n")
		}
		buf.WriteString("   role         : name of the cross-domain/trust delegated role\n")
		buf.WriteString("   trust_domain : name of the cross/trusted domain name\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-delegated-role tenant.sports.readers sports\n")
	case "add-group-role":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-group-role role member [member ... ]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain  : name of the domain that role belongs to\n")
		}
		buf.WriteString("   role    : name of the standard group role\n")
		buf.WriteString("   member  : list of group members that could be either users or services\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-group-role readers " + cli.UserDomain + ".john " + cli.UserDomain + ".joe media.sports.storage\n")
	case "add-member":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-member group_role user_or_service [user_or_service ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain          : name of the domain that role belongs to\n")
		}
		buf.WriteString("   group-role      : name of the standard group role to add members to\n")
		buf.WriteString("   user_or_service : users or services to be added as members\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-member readers " + cli.UserDomain + ".john " + cli.UserDomain + ".joe media.sports.storage\n")
	case "add-temporary-member":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-temporary-member group_role user_or_service expiration\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain          : name of the domain that role belongs to\n")
		}
		buf.WriteString("   group-role      : name of the standard group role to add a temporary member to\n")
		buf.WriteString("   user_or_service : user or service to be added as member\n")
		buf.WriteString("   expiration      : expiration date format yyyy-mm-ddThh:mm:ss.msecZ\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-temporary-member readers " + cli.UserDomain + ",john 2017-03-02T15:04:05.999Z\n")
	case "check-member":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " check-member group_role user_or_service [user_or_service ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain          : name of the domain that role belongs to\n")
		}
		buf.WriteString("   group-role      : name of the standard group role to check membership\n")
		buf.WriteString("   user_or_service : users or services to be checked if they are members\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " check-member readers " + cli.UserDomain + ".john " + cli.UserDomain + ".joe media.sports.storage\n")
	case "delete-member":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-member group_role user_or_service [user_or_service ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain          : name of the domain that role belongs to\n")
		}
		buf.WriteString("   group-role      : name of the standard group role to remove members from\n")
		buf.WriteString("   user_or_service : users or services to be removed as members\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-member readers " + cli.UserDomain + ".john " + cli.UserDomain + ".joe media.sports.storage\n")
	case "add-provider-role-member":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-provider-role-member provider_service resource_group provider_role user_or_service [user_or_service ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain            : name of the domain that role belongs to\n")
		}
		buf.WriteString("   provider_service  : name of the provider service\n")
		buf.WriteString("   resource_group    : name of the resource group\n")
		buf.WriteString("   provider_role     : the provider role name\n")
		buf.WriteString("   user_or_service   : users or services to be added as members\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-provider-role-member storage.db stats_db access media.sports.storage\n")
	case "show-provider-role-member":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " show-provider-role-member provider_service resource_group provider_role\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain            : name of the domain that role belongs to\n")
		}
		buf.WriteString("   provider_service  : name of the provider service\n")
		buf.WriteString("   resource_group    : name of the resource group\n")
		buf.WriteString("   provider_role     : the provider role name\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " show-provider-role-member storage.db stats_db access\n")
	case "delete-provider-role-member":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-provider-role-member provider_service resource_group provider_role user_or_service [user_or_service ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain            : name of the domain that role belongs to\n")
		}
		buf.WriteString("   provider_service  : name of the provider service\n")
		buf.WriteString("   resource_group    : name of the resource group\n")
		buf.WriteString("   provider_role     : the provider role name\n")
		buf.WriteString("   user_or_service   : users or services to be removed as members\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-provider-role-member storage.db stats_db access media.sports.storage\n")
	case "list-domain-role-members":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " list-domain-role-members\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain            : name of the domain\n")
		}
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " list-domain-role-members\n")
	case "delete-domain-role-member":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-domain-role-member member\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain            : name of the domain\n")
		}
		buf.WriteString("   member            : name of the member to be removed from all roles in the domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-domain-role-member media.sports.storage\n")
		buf.WriteString("   " + domain_example + " delete-domain-role-member user.johndoe\n")
	case "delete-role":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-role role\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain : name of the domain that role belongs to\n")
		}
		buf.WriteString("   role   : name of the role to be deleted\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-role readers\n")
	case "list-service":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " list-service\n")
		if !interactive {
			buf.WriteString(" parameters:\n")
			buf.WriteString("   domain : name of the domain to retrieve the list of services from\n")
		}
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " list-service\n")
	case "show-service":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " show-service service\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain  : name of the domain that service belongs to\n")
		}
		buf.WriteString("   service : name of the service to be displayed\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " show-service storage\n")
	case "add-service":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-service service key_id identity_pubkey.pem|identity_key_ybase64\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain               : name of the domain that service belongs to\n")
		}
		buf.WriteString("   service              : name of the service to be added to the domain\n")
		buf.WriteString("   key_id               : identifier of the service's public key\n")
		buf.WriteString("   identity_pubkey.pem  : the filename of the service's public key\n")
		buf.WriteString("                        : either the filename or ybase64 value must be specified\n")
		buf.WriteString("   identity_key_ybase64 : ybase64 encoded value of service's public key\n")
		buf.WriteString("                        : either the filename or ybase64 value must be specified\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-service storage v0 /tmp/storage_pub.pem\n")
		buf.WriteString("   " + domain_example + " add-service storage v0 \"MIIBOgIBAAJBAOf62yl04giXbiirU8Ck\"\n")
	case "add-provider-service":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-provider-service service key_id identity_pubkey.pem|identity_key_ybase64\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain               : name of the domain that service belongs to\n")
		}
		buf.WriteString("   service              : name of the service to be added to the domain\n")
		buf.WriteString("   key_id               : identifier of the service's public key\n")
		buf.WriteString("   identity_pubkey.pem  : the filename of the service's public key\n")
		buf.WriteString("                        : either the filename or ybase64 value must be specified\n")
		buf.WriteString("   identity_key_ybase64 : ybase64 encoded value of service's public key\n")
		buf.WriteString("                        : either the filename or ybase64 value must be specified\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-provider-service storage v0 /tmp/storage_pub.pem\n")
		buf.WriteString("   " + domain_example + " add-provider-service storage v0 \"MIIBOgIBAAJBAOf62yl04giXbiirU8Ck\"\n")
	case "set-service-endpoint":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " set-service-endpoint service endpoint\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain   : name of the domain that service belongs to\n")
		}
		buf.WriteString("   service  : name of the service to set the tenant auto-provisioning endpoint\n")
		buf.WriteString("   endpoint : the url of the provider's service to support auto-provisioning of tenants\n")
		buf.WriteString("            : To remove the endpoint pass \"\" as its value\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " set-service-endpoint storage http://coretech.athenzcompany.com:4080/tableProvider\n")
	case "set-service-exe":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " set-service-exe service executable user group\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain     : name of the domain that service belongs to\n")
		}
		buf.WriteString("   service    : name of the service to set executable info\n")
		buf.WriteString("   executable : full path of the service's executable\n")
		buf.WriteString("              : To remove the setting pass \"\" as its value\n")
		buf.WriteString("   user       : the user name that the service's process runs as\n")
		buf.WriteString("              : To remove the setting pass \"\" as its value\n")
		buf.WriteString("   group      : the group name that the service's process runs as\n")
		buf.WriteString("              : To remove the setting pass \"\" as its value\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " set-service-exe storage /usr/bin/httpd nobody wheel\n")
		buf.WriteString("   " + domain_example + " set-service-exe storage \"\" nobody wheel\n")
	case "add-service-host":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-service-host service host [host ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain  : name of the domain that service belongs to\n")
		}
		buf.WriteString("   service : name of the service to add hosts to\n")
		buf.WriteString("   host    : fully qualified list of hosts the service is allowed to run on\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-service-host storage ct1.athenzcompany.com ct2.athenzcompany.com\n")
	case "delete-service-host":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-service-host service host [host ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain  : name of the domain that service belongs to\n")
		}
		buf.WriteString("   service : name of the service to delete hosts from\n")
		buf.WriteString("   host    : fully qualified list of hosts to remove from service's allowed run list\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-service-host storage ct1.athenzcompany.com ct2.athenzcompany.com\n")
	case "add-public-key":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-public-key service key_id identity_pubkey.pem|identity_key_ybase64\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain               : name of the domain that service belongs to\n")
		}
		buf.WriteString("   service              : name of the service to add a new public key\n")
		buf.WriteString("   key_id               : identifier of the service's public key\n")
		buf.WriteString("   identity_pubkey.pem  : the filename of the service's public key\n")
		buf.WriteString("                        : either the filename or ybase64 value must be specified\n")
		buf.WriteString("   identity_key_ybase64 : ybase64 encoded value of service's public key\n")
		buf.WriteString("                        : either the filename or ybase64 value must be specified\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-public-key storage v1 /tmp/storage_pub.pem\n")
		buf.WriteString("   " + domain_example + " add-public-key storage v1 \"MIIBOgIBAAJBAOf62yl04giXbiirU8Ck\"\n")
	case "show-public-key":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " show-public-key service key_id\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain  : name of the domain that service belongs to\n")
		}
		buf.WriteString("   service : name of the service to retrieve public key from\n")
		buf.WriteString("   key_id  : identifier of the service's public key\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " show-public-key storage v0\n")
	case "delete-public-key":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-public-key service key_id\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain  : name of the domain that service belongs to\n")
		}
		buf.WriteString("   service : name of the service to delete public key from\n")
		buf.WriteString("   key_id  : identifier of the service's public key to be deleted\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-public-key storage v0\n")
	case "delete-service":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-service service\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain  : name of the domain that service belongs to\n")
		}
		buf.WriteString("   service : name of the service to be deleted\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-service storage\n")
	case "list-entity":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " list-entity\n")
		if !interactive {
			buf.WriteString(" parameters:\n")
			buf.WriteString("   domain : name of the domain to retrieve the list of entities from\n")
		}
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " list-entity\n")
	case "show-entity":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " show-entity entity\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain : name of the domain that entity belongs to\n")
		}
		buf.WriteString("   entity : name of the entity to be retrieved from the domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " show-entity profile\n")
	case "add-entity":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-entity entity key=value [key=value ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain : name of the domain that entity belongs to\n")
		}
		buf.WriteString("   entity : name of the entity to be added\n")
		buf.WriteString("   key    : entity field name\n")
		buf.WriteString("   value  : entity field value\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-entity profile name=security active=yes\n")
	case "delete-entity":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-entity entity\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain : name of the domain that entity belongs to\n")
		}
		buf.WriteString("   entity : name of the entity to be deleted\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-entity profile\n")
	case "add-tenancy":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-tenancy provider\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain   : name of the tenant's domain\n")
		}
		buf.WriteString("   provider : provider's service name to auto-provision tenancy for the domain\n")
		buf.WriteString("            : the provider's name must be service common name in <domain>.<service> format\n")
		buf.WriteString("            : the provider must support auto-provisioning and have configured endpoint in the service\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " add-tenancy weather.storage\n")
	case "delete-tenancy":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-tenancy provider\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain   : name of the tenant's domain\n")
		}
		buf.WriteString("   provider : provider's service name to remove the tenant from\n")
		buf.WriteString("            : the provider's name must be service common name in <domain>.<service> format\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-tenancy weather.storage\n")
	case "show-tenant-resource-group-roles":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " show-tenant-resource-group-roles service tenant_domain resource_group\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain         : provider's domain name\n")
		}
		buf.WriteString("   service        : provider's service name\n")
		buf.WriteString("   tenant_domain  : name of the tenant's domain to list roles for\n")
		buf.WriteString("   resource_group : name of the tenant's resource group\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   tenant domain: coretech\n")
		buf.WriteString("   provider domain: sports\n")
		buf.WriteString("   provider service: hosted\n")
		buf.WriteString("   resource group: dev_group\n")
		buf.WriteString("   " + tenant_example + " show-tenant-resource-group-roles hosted coretech dev_group\n")
	case "add-tenant-resource-group-roles":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-tenant-resource-group-roles service tenant_domain resource_group role=action [role=action ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain         : provider's domain name\n")
		}
		buf.WriteString("   service        : provider's service name\n")
		buf.WriteString("   tenant_domain  : name of the tenant's domain to add roles for\n")
		buf.WriteString("   resource_group : name of the tenant's resource group\n")
		buf.WriteString("   role           : name of the role to be added\n")
		buf.WriteString("   action         : the action value for the role\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   tenant domain: coretech\n")
		buf.WriteString("   provider domain: sports\n")
		buf.WriteString("   provider service: hosted\n")
		buf.WriteString("   resource group: dev_group\n")
		buf.WriteString("   " + tenant_example + " add-tenant-resource-group-roles hosted coretech dev_group readers=read writers=modify\n")
	case "delete-tenant-resource-group-roles":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-tenant-resource-group-roles service tenant_domain resource_group\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain        : provider's domain name\n")
		}
		buf.WriteString("   service       : provider's service name\n")
		buf.WriteString("   tenant_domain : name of the tenant's domain\n")
		buf.WriteString("   resource_group : name of the tenant's resource group\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   tenant domain: coretech\n")
		buf.WriteString("   provider domain: sports\n")
		buf.WriteString("   provider service: hosted\n")
		buf.WriteString("   resource group: dev_group\n")
		buf.WriteString("   " + tenant_example + " delete-tenant-resource-group-roles hosted coretech dev_group\n")
	case "show-provider-resource-group-roles":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " show-provider-resource-group-roles provider_domain provider_service resource_group\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain           : tenant's domain name\n")
		}
		buf.WriteString("   provider_domain  : provider's domain name\n")
		buf.WriteString("   provider_service : provider's service name\n")
		buf.WriteString("   resource_group   : name of the tenant's resource group\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   tenant domain: coretech\n")
		buf.WriteString("   provider domain: sports\n")
		buf.WriteString("   provider service: hosted\n")
		buf.WriteString("   resource group: dev_group\n")
		buf.WriteString("   " + domain_example + " show-provider-resource-group-roles sports hosted dev_group\n")
	case "add-provider-resource-group-roles":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " add-provider-resource-group-roles provider_domain provider_service resource_group role=action [role=action ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain           : tenant's domain name\n")
		}
		buf.WriteString("   provider_domain  : provider's domain name\n")
		buf.WriteString("   provider_service : provider's service name\n")
		buf.WriteString("   resource_group   : name of the tenant's resource group\n")
		buf.WriteString("   role             : name of the role to be added\n")
		buf.WriteString("   action           : the action value for the role\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   tenant domain: coretech\n")
		buf.WriteString("   provider domain: sports\n")
		buf.WriteString("   provider service: hosted\n")
		buf.WriteString("   resource group: dev_group\n")
		buf.WriteString("   " + domain_example + " add-provider-resource-group-roles sports hosted dev_group readers=read writers=modify\n")
	case "delete-provider-resource-group-roles":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-provider-resource-group-roles provider_domain provider_service resource_group\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain          : tenant's domain name\n")
		}
		buf.WriteString("   provider_domain  : provider's domain name\n")
		buf.WriteString("   provider_service : provider's service name\n")
		buf.WriteString("   resource_group   : name of the tenant's resource group\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   tenant domain: coretech\n")
		buf.WriteString("   provider domain: sports\n")
		buf.WriteString("   provider service: hosted\n")
		buf.WriteString("   resource group: dev_group\n")
		buf.WriteString("   " + domain_example + " delete-provider-resource-group-roles sports hosted dev_group\n")
	case "get-user-token":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   get-user-token [authorized_service]\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   get-user-token\n")
		buf.WriteString("   get-user-token iaas.athenz.api\n")
	case "version":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   version\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   version\n")
	case "repl":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   repl\n")
		buf.WriteString(" description:\n")
		buf.WriteString("   starts zms-cli client in interactive shell mode where the administrator can specify\n")
		buf.WriteString("   the domain to be used for all commands using the use-domain command\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   repl\n")
		buf.WriteString("   > use-domain corecommit\n")
		buf.WriteString("   corecommit> list-role\n")
	case "system-backup":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   system-backup dir\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   dir : directory path to store all exported domain's yaml files\n")
		buf.WriteString("       : each filename will have the same filename as the domain name\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   system-backup /home/athenz/var/backups/zms_data\n")
	case "list-server-template":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   list-server-template\n")
		buf.WriteString(" description:\n")
		buf.WriteString("   lists the solution templates defined on the server\n")
		buf.WriteString(" example:\n")
		buf.WriteString("   list-server-template\n")
	case "show-server-template":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   show-server-template template\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   template       : solution template name to be displayed\n")
		buf.WriteString(" example:\n")
		buf.WriteString("   show-server-template vipng\n")
	case "list-domain-template":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   list-domain-template domain\n")
		buf.WriteString("   " + domain_param + " list-domain-template\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   domain : retrieve templates applied to this domain\n")
		buf.WriteString("          : this argument is required unless -d <domain> is specified or\n")
		buf.WriteString("          : running in repl/interactive mode with use-domain specified\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   list-domain-template coretech.hosted\n")
		buf.WriteString("   " + domain_example + " list-domain-template\n")
	case "set-domain-template":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " set-domain-template template [template ...] [param-key=param-value ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain     : name of the domain to apply the template to\n")
		}
		buf.WriteString("   template    : name of the template to be applied to the domain\n")
		buf.WriteString("   param-key   : optional parameter key name if template requires it\n")
		buf.WriteString("   param-value : value for the specified parameter key\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " set-domain-template vipng\n")
		buf.WriteString("   " + domain_example + " set-domain-template vipng cm3\n")
		buf.WriteString("   " + domain_example + " set-domain-template vipng service=api\n")
	case "delete-domain-template":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-domain-template template\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain     : name of the domain to delete the template from\n")
		}
		buf.WriteString("   template   : name of the template to be deleted from the domain\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-domain-template vipng\n")
	case "list-user":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   list-user\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   list-user\n")
	case "delete-user":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   delete-user user\n")
		buf.WriteString(" parameters:\n")
		buf.WriteString("   user   : id of the user to be deleted\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   delete-user jdoe\n")
	case "get-quota":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " get-quota\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain        : name of the domain\n")
		}
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " get-quota\n")
	case "delete-quota":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " delete-quota\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain        : name of the domain\n")
		}
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " delete-quota\n")
	case "set-quota":
		buf.WriteString(" syntax:\n")
		buf.WriteString("   " + domain_param + " set-quota [quota-attributes ...]\n")
		buf.WriteString(" parameters:\n")
		if !interactive {
			buf.WriteString("   domain        : name of the domain\n")
		}
		buf.WriteString("   quota-attributes   : object=<n> values specifying limits. Valid object values are:\n")
		buf.WriteString("                      :     subdomain (applies to top level domains ony)\n")
		buf.WriteString("                      :     role\n")
		buf.WriteString("                      :     role-member\n")
		buf.WriteString("                      :     policy\n")
		buf.WriteString("                      :     assertion (total number across all policies)\n")
		buf.WriteString("                      :     entity\n")
		buf.WriteString("                      :     service\n")
		buf.WriteString("                      :     service-host\n")
		buf.WriteString("                      :     public-key\n")
		buf.WriteString(" examples:\n")
		buf.WriteString("   " + domain_example + " set-quota role=100 policy=50 service=25\n")
	default:
		if interactive {
			buf.WriteString("Unknown command. Type 'help' to see available commands")
		} else {
			buf.WriteString("Unknown command. Type 'zms-cli help' to see available commands")
		}
	}
	return buf.String()
}

// HelpListCommand builds and returns the overall help text
// for all commands.
func (cli Zms) HelpListCommand() string {
	var buf bytes.Buffer
	buf.WriteString(" Domain commands:\n")
	buf.WriteString("   list-domain [prefix] | [limit skip prefix depth]\n")
	buf.WriteString("   show-domain [domain]\n")
	buf.WriteString("   lookup-domain-by-aws-account account-id\n")
	buf.WriteString("   lookup-domain-by-product-id product-id\n")
	buf.WriteString("   lookup-domain-by-role role-member role-name\n")
	buf.WriteString("   add-domain domain product-id [admin ...] - to add top level domains\n")
	buf.WriteString("   add-domain domain [admin ...] - to add sub domains\n")
	buf.WriteString("   set-domain-meta description org\n")
	buf.WriteString("   set-audit-enabled audit-enabled\n")
	buf.WriteString("   set-aws-account account-id\n")
	buf.WriteString("   set-product-id product-id\n")
	buf.WriteString("   set-application-id application-id\n")
	buf.WriteString("   set-cert-dns-domain cert-dns-domain\n")
	buf.WriteString("   import-domain domain [file.yaml [admin ...]] - no file means stdin\n")
	buf.WriteString("   export-domain domain [file.yaml] - no file means stdout\n")
	buf.WriteString("   delete-domain domain\n")
	buf.WriteString("   get-signed-domains [matching_tag]\n")
	buf.WriteString("   use-domain [domain]\n")
	buf.WriteString("   check-domain [domain]\n")
	buf.WriteString("   get-quota\n")
	buf.WriteString("   set-quota [attrs ...]\n")
	buf.WriteString("   delete-quota\n")
	buf.WriteString("\n")
	buf.WriteString(" Policy commands:\n")
	buf.WriteString("   list-policy\n")
	buf.WriteString("   show-policy policy\n")
	buf.WriteString("   add-policy policy [assertion]\n")
	buf.WriteString("   add-assertion policy assertion\n")
	buf.WriteString("   delete-assertion policy assertion\n")
	buf.WriteString("   delete-policy policy\n")
	buf.WriteString("   show-access action resource [alt_identity [trust_domain]]\n")
	buf.WriteString("   show-access-ext action resource [alt_identity [trust_domain]]\n")
	buf.WriteString("   show-resource principal action\n")
	buf.WriteString("\n")
	buf.WriteString(" Role commands:\n")
	buf.WriteString("   list-role\n")
	buf.WriteString("   show-role role [log | expand]\n")
	buf.WriteString("   add-delegated-role role trusted_domain\n")
	buf.WriteString("   add-group-role role member [member ... ]\n")
	buf.WriteString("   add-member group_role user_or_service [user_or_service ...]\n")
	buf.WriteString("   add-temporary-member group_role user_or_service expiration\n")
	buf.WriteString("   check-member group_role user_or_service [user_or_service ...]\n")
	buf.WriteString("   delete-member group_role user_or_service [user_or_service ...]\n")
	buf.WriteString("   add-provider-role-member provider_service resource_group provider_role user_or_service [user_or_service ...]\n")
	buf.WriteString("   show-provider-role-member provider_service resource_group provider_role\n")
	buf.WriteString("   delete-provider-role-member provider_service resource_group provider_role user_or_service [user_or_service ...]\n")
	buf.WriteString("   list-domain-role-members\n")
	buf.WriteString("   delete-domain-role-member member\n")
	buf.WriteString("   delete-role role\n")
	buf.WriteString("\n")
	buf.WriteString(" Service commands:\n")
	buf.WriteString("   list-service\n")
	buf.WriteString("   show-service service\n")
	buf.WriteString("   add-service service key_id identity_pubkey.pem|identity_key_ybase64\n")
	buf.WriteString("   add-provider-service service key_id identity_pubkey.pem|identity_key_ybase64\n")
	buf.WriteString("   set-service-endpoint service endpoint\n")
	buf.WriteString("   set-service-exe service executable user group\n")
	buf.WriteString("   add-service-host service host [host ...]\n")
	buf.WriteString("   delete-service-host service host [host ...]\n")
	buf.WriteString("   add-public-key service key_id identity_pubkey.pem|identity_key_ybase64\n")
	buf.WriteString("   show-public-key service key_id\n")
	buf.WriteString("   delete-public-key service key_id\n")
	buf.WriteString("   delete-service service\n")
	buf.WriteString("   list-host-services host\n")
	buf.WriteString("\n")
	buf.WriteString(" Entity commands:\n")
	buf.WriteString("   list-entity\n")
	buf.WriteString("   show-entity entity\n")
	buf.WriteString("   add-entity entity key=value [key=value ...]\n")
	buf.WriteString("   delete-entity entity\n")
	buf.WriteString("\n")
	buf.WriteString(" Tenancy commands:\n")
	buf.WriteString("   add-tenancy provider\n")
	buf.WriteString("   delete-tenancy provider\n")
	buf.WriteString("   show-tenant-resource-group-roles service tenant_domain resource_group\n")
	buf.WriteString("   add-tenant-resource-group-roles service tenant_domain resource_group role=action [role=action ...]\n")
	buf.WriteString("   delete-tenant-resource-group-roles service tenant_domain resource_group\n")
	buf.WriteString("   show-provider-resource-group-roles provider_domain provider_service resource_group\n")
	buf.WriteString("   add-provider-resource-group-roles provider_domain provider_service resource_group role=action [role=action ...]\n")
	buf.WriteString("   delete-provider-resource-group-roles provider_domain provider_service resource_group\n")
	buf.WriteString("\n")
	buf.WriteString(" Template commands:\n")
	buf.WriteString("   list-server-template\n")
	buf.WriteString("   list-domain-template\n")
	buf.WriteString("   show-server-template template\n")
	buf.WriteString("   set-domain-template template [template ...] [param-key=param-value ...]\n")
	buf.WriteString("   delete-domain-template template\n")
	buf.WriteString("\n")
	buf.WriteString(" System Administrator commands:\n")
	buf.WriteString("   set-default-admins domain admin [admin ...]\n")
	buf.WriteString("   list-user\n")
	buf.WriteString("   delete-user user\n")
	buf.WriteString("\n")
	buf.WriteString(" Other commands:\n")
	buf.WriteString("   get-user-token [authorized_service]\n")
	buf.WriteString("   repl\n")
	buf.WriteString("   version\n")
	buf.WriteString("\n")
	return buf.String()
}

func (cli Zms) getPublicKey(s string) (*string, error) {
	if strings.HasSuffix(s, ".pem") || strings.HasSuffix(s, ".key") {
		bytes, err := ioutil.ReadFile(s)
		if err != nil {
			return nil, err
		}
		var lb64 yBase64
		yb64 := lb64.EncodeToString(bytes)
		return &yb64, nil
	}
	return &s, nil
}

func (cli *Zms) SetX509CertClient(keyFile, certFile, caCertFile, socksProxy string, httpProxy, skipVerify bool) error {
	keypem, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err
	}
	certpem, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}
	var cacertpem []byte
	if caCertFile != "" {
		cacertpem, err = ioutil.ReadFile(caCertFile)
		if err != nil {
			return err
		}
	}
	config, err := tlsConfiguration(keypem, certpem, cacertpem)
	if err != nil {
		return err
	}
	if skipVerify {
		config.InsecureSkipVerify = skipVerify
	}
	tr := &http.Transport{
		TLSClientConfig: config,
	}
	if httpProxy {
		tr.Proxy = http.ProxyFromEnvironment
	}
	if socksProxy != "" {
		dialer := &net.Dialer{}
		dialSocksProxy, err := proxy.SOCKS5("tcp", socksProxy, nil, dialer)
		if err == nil {
			tr.Dial = dialSocksProxy.Dial
		}
	}
	cli.Zms = zms.NewClient(cli.ZmsUrl, tr)
	return nil
}

func tlsConfiguration(keypem, certpem, cacertpem []byte) (*tls.Config, error) {
	config := &tls.Config{}
	if certpem != nil && keypem != nil {
		mycert, err := tls.X509KeyPair(certpem, keypem)
		if err != nil {
			return nil, err
		}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0] = mycert
	}
	if cacertpem != nil {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(cacertpem)
		config.RootCAs = certPool
	}
	return config, nil
}
