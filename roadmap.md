The following is the list of features that the Athenz team is working or
planning to work on. At Verizon Media, we review our list every quarter
and decide which features will be implemented during that quarter. Additionally,
we implement several smaller features as they're requested by our customers.

# Q1 2020

- Provide workflow in Athenz UI to approve role membership to satisfy
  auditing and governance requirements.
- Support self-serve and review enabled roles which would require
  2 domain administrator approvals before a member becomes active.
- Provide auto expiry support at both role and domain level with
  separate values for human users and services.
- Email notification support for any active hosts not refreshing their
  service identity certificates.

# Q2 2020

- Review Reminder (soft expiry) support for role members. The role members
  and the domain administrators still get expiry notifications, but the user
  is not expired from the role causing a service outage.
- Extend support to include additional SAN DNS values in the Service
  Identity X.509 Certificate requests.
- Support versioning of server templates. Provide support to auto-update
  all domains that have a given template applied. Update Athenz UI to
  display applied templates on a domain.

# Q3 2020

- Principal Group feature. The feature allows grouping users and services
  and including those groups as principals in roles. Provides easier management
  of groups, especially from external domains (rather than using delegated roles)
- UI: Redesign Athenz UI to have better user experience when managing roles
- Lookup all roles in all domains for given principal
- Update feature documentation
- Support saving case-sensitive action/resource values in policy assertions
- Reduced Scope Service Identity Certificate Support - mark a provider service
  with this scope such that those certificates cannot be used to make changes
  in Athenz domains or request further tokens from ZTS.
- Extend User Authority Filter feature to set at a domain level

# Q4 2020

- Athenz Service Identity Provider for Azure to allow VMs deployed within Azure
  to have unique, short-lived identity x.509 certificates
- Extend AWS EKS service identity agent to support IRSA.
- Auto Generate API Guide based on configured RDL files.
- UI: Implement support for Principals Groups
- Implement metric notifications in addition to email ones. This would allow teams
  to look at metrics and generate alerts if their services are about to expire
  and immediate action is needed to extend their role membership.
- Introduce suspended user support in Athenz. The User Authority can mark
  a user as suspended, and the user will be automatically excluded from any
  access until the User Authority reports otherwise.
- Improve rate limiting support per principal.

# Future

- Athenz Service Identity Provider for GCP
- Athenz Client libraries multi-release supporting JDK 8/11
- Build and require use of JDK 11 for server components

