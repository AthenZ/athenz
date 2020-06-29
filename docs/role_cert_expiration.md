By default, Athenz ZTS server allows principals to request role certificates
with a maximum expiry of 30 days. However, the domain administrator has the capability
to specify a maximum expiry limit for a given role or the full domain. This allows
the domain administrators to control access to specific roles (or domains) such that
the principals do not request role certificates that are valid for up-to 30 days but instead
are valid only for the configured number of minutes.

## Role Level Certificate Expiry Support

The domain administrator may specify maximum role certificate expiry setting in minutes
for a specific role:

```
zms-cli -d <domain-name> set-role-cert-expiry-mins <role-name> <max-expiry-mins>
```

If the domain administrator has specified a max role certificate expiry mins of 120 to `db.writers` role,
then ZTS will only issue a role certificate with a maximum expiry of 120 mins even if
the principal is requesting a longer one. If the principal is requesting a role certificate with a
smaller expiry that 120 mins, for example 60 mins, then it will be honored and the role certificate
will be issued for 60 mins.

If the role does not have a max certificate expiry setting configured, then ZTS will lookup
to see if there is a max role certificate expiry setting specified for the domain and use that
if it's smaller than the requested certificate expiry value.

If the domain administrator specifies a role certificate expiry at both role and domain levels, then
the role level always overrides the domain setting for the role - regardless if it's shorter
or longer than the domain configured value.

You can look at the currently configured value for a specific role using
`zms-cli -d <domain-name> show-role <role-name>` command.
 
To reset the configured limit back to its default behavior, set the limit to 0:

```
zms-cli -d <domain-name> set-role-cert-expiry-mins <role-name> 0
```

## Domain Level Role Certificate Expiry Support

The domain administrator may specify maximum role certificate expiry setting in minutes
for the full domain:

```
zms-cli -d <domain-name> set-domain-role-cert-expiry-mins <max-expiry-mins>
```

If the domain administrator has specified a max role certificate expiry mins of 360 to `sales` domain,
then ZTS will only issue role certificates with a maximum expiry of 360 mins even if
the principal is requesting a longer one.

The exception to this rule is if the domain administrator has also specified a value for
the role. If the domain administrator specifies a role certificate expiry at both role and domain levels,
then the role level always overrides the domain setting for the role - regardless if it's shorter or
longer than the domain configured value.
 
If the principal is requesting a role certificate with a smaller expiry that 360 mins configured for the domain,
for example 120 mins, and there are no per-role certificate expiry settings configured, then it will
be honored and the role certificate will be issued for 120 mins.

You can look at the currently configured value for a specific domain using
`zms-cli -d <domain-name> show-domain` command.

To reset the configured limit back to its default behavior, set the limit to 0:

```
zms-cli -d <domain-name> set-domain-role-cert-expiry-mins 0
```
