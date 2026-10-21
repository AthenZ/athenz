# ZMS Authorized Services Configuration

ZMS reads the configured `authorized_services.json` file at startup. The file
lists services that may request authorized service user tokens and the ZMS
operations each service may perform. The sample file is at
`servers/zms/conf/authorized_services.json`.

Set `athenz.zms.authz_service_fname` to choose the file. By default, changes
to that file take effect after a ZMS restart. To reload it while ZMS is
running, set `athenz.zms.authz_service_dynamic_reload=true`. ZMS then checks
the file's last-modified timestamp in a background task every 60 seconds by
default. Set `athenz.zms.authz_service_reload_frequency_seconds` to change
that interval.

The updated list is used only after the whole document parses and its service,
operation, and item definitions are validated. An invalid or unreadable file
leaves the last successfully loaded list active. Failed attempts are retried
with exponential backoff, up to 300 seconds by default. Set
`athenz.zms.authz_service_reload_max_backoff_seconds` to change that limit.
A new modification timestamp causes ZMS to retry at the next check even if a
previous version is still in its backoff period. An empty `services` object is
valid and revokes access for every previously listed service.

Dynamic reload is disabled by default. With the flag disabled, ZMS keeps the
startup-only loading behavior.
