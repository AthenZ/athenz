# Athenz Component System Properties
-----------------------------------------

* [ZMS Server](#zms-server)

## ZMS Server
-------------

| Property Name | Default Value | Description |
| ------------- | ------------- | ----------- |
| athenz.zms.access_log_dir                | $ROOT/logs/zms_server               | Directory to store access log files |
| athenz.zms.access_log_name               | access.yyyy_MM_dd.log               | Format of the access log filename |
| athenz.zms.access_log_retain_days        | 31                                  | Set the number of days before rotated access log files are deleted |
| athenz.zms.access_slf4j_logger           | none                                | If specified, the server will use SLF4J logger with the specified name to log events instead of using Jetty's NCSARequestLog class. The administrator then must configure the specified logger in the logback.xml |
| athenz.zms.authz_service_fname           | none                                | Specifies the authorized service json configuration file path. Without any configured value, the server will default to reading /home/athenz/conf/zms_server/authorized_services.json file |
| athenz.zms.conflict_retry_timeout        | 60                                  | In case there is a concurrent update conflict, the server will retry the operation multiple times until this timeout is reached before returning a conflict status code back to the client |
| athenz.db.pool_evict_idle_interval       | 1000 * 60 * 30                      | The number of milliseconds to sleep between runs of the idle object evictor thread. When non-positive, no idle object evictor thread will be run. The pool default is -1, but we're using 30 minutes to make sure the evictor thread is running |
| athenz.db.pool_evict_idle_timeout        | 1000 * 60 * 30                      | The minimum amount of time (in milliseconds) an object may sit idle in the pool before it is eligible for eviction by the idle object evictor (if any) |
| athenz.db.pool_max_idle                  | 8                                   | The maximum number of connections that can remain idle in the pool, without extra ones being released, or negative for no limit |
| athenz.db.pool_max_total                 | 8                                   | The maximum number of active connections that can be allocated from this pool at the same time, or negative for no limit |
| athenz.db.pool_max_ttl                   | 1000 * 60 * 10                      | The maximum lifetime in milliseconds of a connection. After this time is exceeded the connection will fail the next activation, passivation or validation test. A value of zero or less means the connection has an infinite lifetime. |
| athenz.db.pool_max_wait                  | -1                                  | The maximum number of milliseconds that the pool will wait (when there are no available connections) for a connection to be returned before throwing an exception, or -1 to wait indefinitely |
| athenz.db.pool_min_idle                  | 0                                   | The minimum number of connections that can remain idle in the pool, without extra ones being created, or zero to create none |
| athenz.zms.debug.principal_authority     | false                               | Boolean setting to specify whether or not debug Principal authority is used instead of the real one. If the | athenz.zms.debug is set to true, then this setting has no impact and the the debug authority is used. |
| athenz.zms.debug.role_authority          | false                               | Boolean setting to specify whether or not debug Role authority is used instead of the real one. If the | athenz.zms.debug is set to true, then this setting has no impact and the the debug authority is used. |
| athenz.zms.domain_admin                  | none                                | If the datastore does not contain any domains during startup, the server will automatically create sys, sys.auth and user domains and assign the specified user as the admin for those domains |
| athenz.zms.enable_stats                  | true                                | Boolean setting to configure whether or not stat counters are enabled or not |
| athenz.zms.filestore                     | zms_root                            | This specifies the subdirectory name where domain files will be stored. The parent directory is identified by the athenz.zms.home property |
| athenz.zms.home                          | $ROOT/var/zms_server                | Default home directory for ZMS Server. |
| athenz.zms.hostname                      | none                                | Specify the FQDN/hostname of the server. This value will be used as the h parameter in the ZMS generated UserTokens. It is also reported as part of the server banner notification in logs. |
| athenz.zms.http_idle_timeout             | 30000                               | In milliseconds how long that connector will be allowed to remain idle with no traffic before it is shutdown|
| athenz.zms.http_max_threads              | 1024                                | Max number of threads Jetty is allowed to spawn to handle incoming requests |
| athenz.zms.http_output_buffer_size       | 32768                               | The size in bytes of the output buffer used to aggregate HTTP output |
| athenz.zms.http_reqeust_header_size      | 8192                                | The maximum allowed size in bytes for a HTTP request header |
| athenz.zms.http_response_header_size     | 8192                                | The maximum allowed size in bytes for a HTTP response header |
| athenz.zms.http_send_date_header         | false                               | Boolean setting to specify whether or not the server should include the Date in HTTP headers. |
| athenz.zms.http_send_server_version      | false                               | Boolean setting to specify whether or not the server should send the Server header in response |
| athenz.zms.jdbcstore                     | none                                | URL where the ZMS Server will store domain json documents. jdbc:mysql://localhost:3306/zms - specifies MySQL instance |
| athenz.zms.jdbc_password                 | none                                | If the jdbcstore is pointing to a MySQL server then this specifies the password for the jdbc user |
| athenz.zms.jdbc_user                     | none                                | If the jdbcstore is pointing to a MySQL server then this specifies the name of the user that has full access to the zms db table |
| athenz.zms.listen_host                   | none                                | For HTTP access specifies the IP address/Host for service to listen on. This could be necessary, for example, if the system administrator wants ATS to handle TLS traffic and configure Jetty to listen on 127.0.0.1 loopback address only for HTTP connections from ATS. |
| athenz.zms.port                          | 10080                               | Default port for HTTP access |
| athenz.zms.privatekey                    | none                                | Specifies the path to the ZMS Server's private key |
| athenz.zms.privatekey_id                 | 0                                   | Specifies the identifier of the private key |
| athenz.zms.publickey                     | none                                | Specifies the path to the ZMS Server's public key |
| athenz.zms.read_only_mode                | false                               | If enabled, ZMS will be in maintenance read only mode where only get operations will succeed and all other put, post and delete operations will be rejected with invalid request error. |
| athenz.zms.retry_delay_timeout           | 50                                  | When ZMS determines that updating a domain json document will cause a concurrent update issue and needs to retry the operation, it will sleep configured number of milliseconds before retrying. |
| athenz.zms.signed_policy_timeout         | 604800                              | Specified in seconds how long the signed policy documents are valid for |
| athenz.zms.ssl_excluded_protocols        | SSLv2,SSLv3                         | Comma separated list of excluded ssl protocols |
| athenz.zms.ssl_key_manager_password      | none                                | Key Manager password |
| athenz.zms.ssl_key_store                 | none                                | The path to the keystore file that contains the server's certificate |
| athenz.zms.ssl_key_store_password        | none                                | Keystore password |
| athenz.zms.ssl_key_store_type            | PKCS12                              | Specifies the keystore type |
| athenz.zms.ssl_trust_store               | none                                | The path to the trust store file that contains CA certificates |
| athenz.zms.ssl_trust_store_password      | none                                | Trust store password |
| athenz.zms.ssl_trust_store_type          | PKCS12                              | Specifies the trust store type |
| athenz.zms.tls_port                      | 0                                   | Default port for HTTPS access |
| athenz.zms.user_token_timeout            | 3600                                | Specifies in seconds how long would the User Tokens be valid for |
| athenz.zms.virtual_domain_limit          | 2                                   | If virtual domain support is enabled, this setting specifies the number of sub domains in the user's virtual namespace that are allowed to be created. Value of 0 indicates no limit.|
| athenz.zms.virtual_domain_support        | true                                | Boolean setting to configure whether or not virtual domains are supported or not. These are domains created in the user's own "user" namespace |
