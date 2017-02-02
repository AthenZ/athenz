/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zts;

/**
 * Contains constants shared by classes throughout the service.
 **/
public final class ZTSConsts {
    // System property names with defaults(where applicable)
    
    public static final String ZTS_PROP_HTTP_PORT          = "athenz.zts.port";
    public static final String ZTS_PROP_HTTPS_PORT         = "athenz.zts.tls_port";

    public static final int    ZTS_HTTP_PORT_DEFAULT       = 4080;
    public static final int    ZTS_HTTPS_PORT_DEFAULT      = 0;
    
    public static final String ZTS_PROP_ACCESS_LOG_RETAIN_DAYS = "athenz.zts.access_log_retain_days";
    public static final String ZTS_PROP_SEND_SERVER_VERSION    = "athenz.zts.http_send_server_version";
    public static final String ZTS_PROP_SEND_DATE_HEADER       = "athenz.zts.http_send_date_header";
    public static final String ZTS_PROP_OUTPUT_BUFFER_SIZE     = "athenz.zts.http_output_buffer_size";
    public static final String ZTS_PROP_REQUEST_HEADER_SIZE    = "athenz.zts.http_reqeust_header_size";
    public static final String ZTS_PROP_RESPONSE_HEADER_SIZE   = "athenz.zts.http_response_header_size";
    public static final String ZTS_PROP_IDLE_TIMEOUT           = "athenz.zts.http_idle_timeout";
    public static final String ZTS_PROP_LISTEN_HOST            = "athenz.zts.listen_host";
    public static final String ZTS_PROP_KEEP_ALIVE             = "athenz.zts.keep_alive";
    public static final String ZTS_PROP_ACCESS_SLF4J_LOGGER    = "athenz.zts.access_slf4j_logger";
    public static final String ZTS_PROP_ACCESS_LOG_DIR         = "athenz.zts.access_log_dir";
    public static final String ZTS_PROP_ACCESS_LOG_NAME        = "athenz.zts.access_log_name";
    
    public static final String ZTS_PROP_CA_PRIVATE_KEY            = "athenz.zts.ca_privatekey";
    public static final String ZTS_PROP_CA_PRIVATE_KEY_PASSWORD   = "athenz.zts.ca_privatekey_password";
    public static final String ZTS_PROP_CA_CERTIFICATE            = "athenz.zts.ca_certificate";
    
    public static final String ZTS_PROP_STATS_ENABLED          = "athenz.zts.enable_stats";
    public static final String ZTS_PROP_METRIC_FACTORY_CLASS   = "athenz.zts.metric_factory_class";
    
    public static final String ZTS_PROP_KEYSTORE_PASSWORD      = "athenz.zts.ssl_key_store_password";
    public static final String ZTS_PROP_KEYMANAGER_PASSWORD    = "athenz.zts.ssl_key_manager_password";
    public static final String ZTS_PROP_TRUSTSTORE_PASSWORD    = "athenz.zts.ssl_trust_store_password";
    public static final String ZTS_PROP_KEYSTORE_PATH          = "athenz.zts.ssl_key_store";
    public static final String ZTS_PROP_KEYSTORE_TYPE          = "athenz.zts.ssl_key_store_type";
    public static final String ZTS_PROP_TRUSTSTORE_PATH        = "athenz.zts.ssl_trust_store";
    public static final String ZTS_PROP_TRUSTSTORE_TYPE        = "athenz.zts.ssl_trust_store_type";
    public static final String ZTS_PROP_EXCLUDED_CIPHER_SUITES = "athenz.zts.ssl_excluded_cipher_suites";
    public static final String ZTS_PROP_EXCLUDED_PROTOCOLS     = "athenz.zts.ssl_excluded_protocols";
    public static final String ZTS_PROP_DATASTORE_REGEX_CACHE  = "athenz.zts.cache.regex.size";
    public static final String ZTS_PROP_WANT_CLIENT_CERT       = "athenz.zts.want_client_cert";
    
    // properties used to over-ride default Audit logger
    //
    public static final String ZTS_PROP_AUDIT_LOGGER_CLASS       = "athenz.zts.audit_logger_class";
    public static final String ZTS_PROP_AUDIT_LOGGER_CLASS_PARAM = "athenz.zts.audit_logger_class_param";
    public static final String ZTS_PROP_AUDIT_LOG_MSG_BLDR_CLASS = "athenz.zts.audit_log_msg_builder_class";
    
    public static final String ZTS_PROP_HOME     = "athenz.zts.home";
    public static final String ZTS_PROP_HOSTNAME = "athenz.zts.hostname";
    
    public static final String ZTS_PROP_AUTHORITY_CLASSES           = "athenz.zts.authority_classes";
    public static final String ZTS_PROP_CERT_SIGNER_FACTORY_CLASS   = "athenz.zts.cert_signer_factory_class";
    public static final String ZTS_PROP_MAX_THREADS                 = "athenz.zts.http_max_threads";
    public static final String ZTS_PROP_LEAST_PRIVILEGE_PRINCIPLE   = "athenz.zts.least_privilege_principle";

    public static final String ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT     = "athenz.zts.role_token_max_timeout";
    public static final String ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT = "athenz.zts.role_token_default_timeout";
    public static final String ZTS_PROP_SIGNED_POLICY_TIMEOUT      = "athenz.zts.signed_policy_timeout";
    public static final String ZTS_PROP_AWS_BOOT_TIME_OFFSET       = "athenz.zts.aws_boot_time_offset";
    public static final String ZTS_PROP_SERVICE_TOKEN_TIME_OFFSET  = "athenz.zts.service_token_time_offset";
    public static final String ZTS_PROP_AUTHORIZED_PROXY_USERS     = "athenz.zts.authorized_proxy_users";

    public static final String ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME    = "athenz.zts.self_signer_private_key_fname";
    public static final String ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD = "athenz.zts.self_signer_private_key_password";
    public static final String ZTS_PROP_SELF_SIGNER_CERT_DN              = "athenz.zts.self_signer_cert_dn";

    public static final String ZTS_PROP_DATA_CHANGE_LOG_STORE_FACTORY_CLASS   = "athenz.zts.data_change_log_store_factory_class";
    public static final String ZTS_PROP_INSTANCE_IDENTITY_STORE_FACTORY_CLASS = "athenz.zts.instance_identity_store_factory_class";
    public static final String ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS       = "athenz.zts.private_key_store_factory_class";

    public static final String ZTS_PROP_USER_DOMAIN   = "athenz.user_domain";
    public static final String ZTS_PROP_ATHENZ_CONF   = "athenz.athenz_conf";
    public static final String ZTS_SERVICE            = "zts";
    public static final String ZTS_UNKNOWN_DOMAIN     = "unknown_domain";
    public static final String ATHENZ_SYS_DOMAIN      = "sys.auth";

    public static final String STR_DEF_ROOT = "/home/athenz";
    public static final String STR_ENV_ROOT = "ROOT";
    
    public static final String ZTS_PROP_AWS_ENABLED     = "athenz.zts.aws_enabled";
    
    public static final String ZTS_METRIC_FACTORY_CLASS   = "com.yahoo.athenz.common.metrics.impl.NoOpMetricFactory";
}

