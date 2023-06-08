/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.container;

/**
 * Contains constants shared by classes throughout the service.
 **/
public final class AthenzConsts {

    // System property names with defaults(where applicable)

    public static final String ATHENZ_PROP_ROOT_DIR               = "athenz.root_dir";
    public static final String ATHENZ_PROP_FILE_NAME              = "athenz.prop_file";
    public static final String ATHENZ_PROP_ACCESS_LOG_RETAIN_DAYS = "athenz.access_log_retain_days";
    public static final String ATHENZ_PROP_ACCESS_LOG_NAME        = "athenz.access_log_name";
    public static final String ATHENZ_PROP_ACCESS_SLF4J_LOGGER    = "athenz.access_slf4j_logger";
    public static final String ATHENZ_PROP_ACCESS_LOG_DIR         = "athenz.access_log_dir";
    public static final String ATHENZ_PROP_AWS_PARAM_STORE_PATH   = "athenz.aws_param_store_path";

    public static final String ATHENZ_PROP_KEYSTORE_PASSWORD      = "athenz.ssl_key_store_password";
    public static final String ATHENZ_PROP_KEYMANAGER_PASSWORD    = "athenz.ssl_key_manager_password";
    public static final String ATHENZ_PROP_TRUSTSTORE_PASSWORD    = "athenz.ssl_trust_store_password";
    public static final String ATHENZ_PROP_KEYSTORE_PATH          = "athenz.ssl_key_store";
    public static final String ATHENZ_PROP_KEYSTORE_TYPE          = "athenz.ssl_key_store_type";
    public static final String ATHENZ_PROP_KEYSTORE_RELOAD_SEC    = "athenz.ssl_key_store_reload_seconds";
    public static final String ATHENZ_PROP_TRUSTSTORE_PATH        = "athenz.ssl_trust_store";
    public static final String ATHENZ_PROP_TRUSTSTORE_TYPE        = "athenz.ssl_trust_store_type";
    public static final String ATHENZ_PROP_EXCLUDED_CIPHER_SUITES = "athenz.ssl_excluded_cipher_suites";
    public static final String ATHENZ_PROP_INCLUDED_CIPHER_SUITES = "athenz.ssl_included_cipher_suites";
    public static final String ATHENZ_PROP_EXCLUDED_PROTOCOLS     = "athenz.ssl_excluded_protocols";
    public static final String ATHENZ_PROP_CLIENT_AUTH            = "athenz.ssl_need_client_auth";
    public static final String ATHENZ_PROP_RENEGOTIATION_ALLOWED  = "athenz.ssl_renegotiation_allowed";
    public static final String ATHENZ_PROP_SSL_LOG_FAILURES       = "athenz.ssl_log_failures";
    public static final String ATHENZ_PROP_SNI_REQUIRED           = "athenz.ssl_sni_required";
    public static final String ATHENZ_PROP_SNI_HOSTCHECK          = "athenz.ssl_sni_hostcheck";
    public static final String ATHENZ_PROP_IDLE_TIMEOUT           = "athenz.http_idle_timeout";
    public static final String ATHENZ_PROP_PROXY_PROTOCOL         = "athenz.proxy_protocol";
    public static final String ATHENZ_PROP_SEND_SERVER_VERSION    = "athenz.http_send_server_version";
    public static final String ATHENZ_PROP_SEND_DATE_HEADER       = "athenz.http_send_date_header";
    public static final String ATHENZ_PROP_OUTPUT_BUFFER_SIZE     = "athenz.http_output_buffer_size";
    public static final String ATHENZ_PROP_REQUEST_HEADER_SIZE    = "athenz.http_request_header_size";
    public static final String ATHENZ_PROP_RESPONSE_HEADER_SIZE   = "athenz.http_response_header_size";
    public static final String ATHENZ_PROP_LISTEN_HOST            = "athenz.listen_host";
    public static final String ATHENZ_PROP_KEEP_ALIVE             = "athenz.keep_alive";
    public static final String ATHENZ_PROP_RESPONSE_HEADERS_JSON  = "athenz.response_headers_json";
    public static final String ATHENZ_PROP_GZIP_SUPPORT           = "athenz.gzip_support";
    public static final String ATHENZ_PROP_GZIP_MIN_SIZE          = "athenz.gzip_min_size";
    public static final String ATHENZ_PROP_MAX_THREADS            = "athenz.http_max_threads";
    public static final String ATHENZ_PROP_HOSTNAME               = "athenz.hostname";
    public static final String ATHENZ_PROP_JETTY_HOME             = "athenz.jetty_home";
    public static final String ATHENZ_PROP_JETTY_TEMP             = "athenz.jetty_temp";
    public static final String ATHENZ_PROP_DEBUG                  = "athenz.debug";
    public static final String ATHENZ_PROP_HEALTH_CHECK_URI_LIST  = "athenz.health_check_uri_list";
    public static final String ATHENZ_PROP_HEALTH_CHECK_PATH      = "athenz.health_check_path";
    public static final String ATHENZ_PROP_LOG_FORWARDED_FOR_ADDR = "athenz.log_forwarded_for_addr";

    public static final String ATHENZ_PROP_RATE_LIMIT_FACTORY_CLASS        = "athenz.ratelimit_factory_class";
    public static final String ATHENZ_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS = "athenz.private_keystore_factory_class";

    public static final String ATHENZ_PROP_SERVER_POOL_SET_ENABLED       = "athenz.server.pool.set_enabled";
    public static final String ATHENZ_PROP_SERVER_POOL_MAX_HEAP_MEMORY   = "athenz.server.pool.max_heap_memory";
    public static final String ATHENZ_PROP_SERVER_POOL_MAX_DIRECT_MEMORY = "athenz.server.pool.max_direct_memory";
    public static final String ATHENZ_PROP_SERVER_POOL_MIN_CAPACITY      = "athenz.server.pool.min_capacity";
    public static final String ATHENZ_PROP_SERVER_POOL_MAX_CAPACITY      = "athenz.server.pool.max_capacity";
    public static final String ATHENZ_PROP_SERVER_POOL_FACTOR            = "athenz.server.pool.factor";
    public static final String ATHENZ_PROP_SERVER_POOL_MAX_BUCKET_SIZE   = "athenz.server.pool.max_bucket_size";

    public static final String STR_DEF_ROOT     = "/home/athenz";

    public static final String ATHENZ_PROP_HTTP_PORT   = "athenz.port";
    public static final String ATHENZ_PROP_HTTPS_PORT  = "athenz.tls_port";
    public static final String ATHENZ_PROP_OIDC_PORT   = "athenz.oidc_port";
    public static final String ATHENZ_PROP_STATUS_PORT = "athenz.status_port";
    
    public static final int ATHENZ_HTTPS_PORT_DEFAULT = 4443;
    public static final int ATHENZ_HTTP_PORT_DEFAULT  = 4080;
    public static final int ATHENZ_HTTP_MAX_THREADS   = 1024;
    
    public static final String ATHENZ_RATE_LIMIT_FACTORY_CLASS = "com.yahoo.athenz.common.filter.impl.NoOpRateLimitFactory";
    public static final String ATHENZ_PKEY_STORE_FACTORY_CLASS = "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";
    
    public static final String ATHENZ_PROP_KEYSTORE_PASSWORD_APPNAME   = "athenz.ssl_key_store_password_appname";
    public static final String ATHENZ_PROP_KEYMANAGER_PASSWORD_APPNAME = "athenz.ssl_key_manager_password_appname";
    public static final String ATHENZ_PROP_TRUSTSTORE_PASSWORD_APPNAME = "athenz.ssl_trust_store_password_appname";

    public static final String ATHENZ_PROP_GRACEFUL_SHUTDOWN = "athenz.graceful_shutdown";
    public static final String ATHENZ_PROP_GRACEFUL_SHUTDOWN_TIMEOUT = "athenz.graceful_shutdown_timeout";
}
