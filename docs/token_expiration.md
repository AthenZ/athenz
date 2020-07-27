By default, Athenz ZTS server allows principals to request access tokens
with a maximum expiry of 30 days. However, the domain administrator has the capability
to specify a maximum expiry limit for a given role or the full domain. This allows
the domain administrators to control access to specific roles (or domains) such that
the principals do not request tokens that are valid for up-to 30 days but instead
are valid only for the configured number of minutes.

## Role Level Token Expiry Support

The domain administrator may specify maximum token expiry setting in minutes
for a specific role:

```
zms-cli -d <domain-name> set-role-token-expiry-mins <role-name> <max-expiry-mins>
```

If the domain administrator has specified a max token expiry mins of 30 to `db.writers` role,
then ZTS will only issue access tokens with a maximum expiry of 30 mins even if
the principal is requesting a longer one. If the principal is requesting a token with a
smaller expiry that 30 mins, for example 15 mins, then it will be honored and the token
will be issued for 15 mins.

If the principal is requesting a token for multiple roles, then ZTS will lookup the max
expiry setting for all the roles and issue a token with the smallest configured value.

If none of the roles have a max token expiry setting configured, then ZTS will lookup
to see if there is a max token expiry setting specified for the domain and use that
if it's smaller than the requested token expiry value.

If the domain administrator specifies a token expiry at both role and domain levels, then
the role level always overrides the domain setting for the role - regardless if it's shorter
or longer than the domain configured value.

You can look at the currently configured value for a specific role using
`zms-cli -d <domain-name> show-role <role-name>` command.

To reset the configured limit back to its default behavior, set the limit to 0:

```
zms-cli -d <domain-name> set-role-token-expiry-mins <role-name> 0
```

## Domain Level Token Expiry Support

The domain administrator may specify maximum token expiry setting in minutes
for the full domain:

```
zms-cli -d <domain-name> set-domain-token-expiry-mins <max-expiry-mins>
```

If the domain administrator has specified a max token expiry mins of 90 to `sales` domain,
then ZTS will only issue access tokens with a maximum expiry of 90 mins even if
the principal is requesting a longer one. 

The exception to this rule is if the domain administrator has also specified a value for
one of the roles requested in the token. If the domain administrator specifies a token
expiry at both role and domain levels, then the role level always overrides the domain
setting for the role - regardless if it's shorter or longer than the domain configured value.
 
If the principal is requesting a token with a smaller expiry that 90 mins configured for the domain,
for example 60 mins, and there are no per-role token expiry settings configured, then it will
be honored and the token will be issued for 60 mins.

You can look at the currently configured value for a specific domain using
`zms-cli -d <domain-name> show-domain` command.

To reset the configured limit back to its default behavior, set the limit to 0:

```
zms-cli -d <domain-name> set-domain-token-expiry-mins 0
```
