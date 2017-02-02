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
package com.yahoo.athenz.zms;

/**
 * Contains constants shared by classes throughout the service.
 **/
public final class ZMSConsts {

    // System property names with defaults(where applicable)
    //
    public static final String ZMS_PROP_HOME          = "athenz.zms.home";
    public static final String ZMS_PROP_HOSTNAME      = "athenz.zms.hostname";
    public static final String ZMS_PROP_DOMAIN_ADMIN  = "athenz.zms.domain_admin";
    public static final String ZMS_PROP_HTTPS_PORT    = "athenz.zms.tls_port";
    public static final String ZMS_PROP_HTTP_PORT     = "athenz.zms.port";

    public static final String ZMS_PROP_ACCESS_LOG_DIR       = "athenz.zms.access_log_dir";
    public static final String ZMS_PROP_STATS_ENABLED        = "athenz.zms.enable_stats";
    public static final String ZMS_PROP_VIRTUAL_DOMAIN       = "athenz.zms.virtual_domain_support";
    public static final String ZMS_PROP_VIRTUAL_DOMAIN_LIMIT = "athenz.zms.virtual_domain_limit";
    public static final String ZMS_PROP_READ_ONLY_MODE       = "athenz.zms.read_only_mode";
    public static final String ZMS_PROP_DOMAIN_NAME_MAX_SIZE = "athenz.zms.domain_name_max_len";
    public static final String ZMS_PROP_METRIC_FACTORY_CLASS = "athenz.zms.metric_factory_class";
    
    public static final String ZMS_PROP_CONFLICT_RETRY_COUNT      = "athenz.zms.request_conflict_retry_count";
    public static final String ZMS_PROP_CONFLICT_RETRY_SLEEP_TIME = "athenz.zms.request_conflict_retry_sleep_time";

    public static final String ZMS_PROP_JDBC_STORE        = "athenz.zms.jdbc_store";
    public static final String ZMS_PROP_JDBC_USER         = "athenz.zms.jdbc_user";
    public static final String ZMS_PROP_JDBC_PASSWORD     = "athenz.zms.jdbc_password";
    public static final String ZMS_PROP_FILE_STORE        = "athenz.zms.file_store";
    public static final String ZMS_PROP_MAX_THREADS       = "athenz.zms.http_max_threads";
    public static final String ZMS_PROP_AUTHORITY_CLASSES = "athenz.zms.authority_classes";

    public static final String ZMS_PROP_TIMEOUT                 = "athenz.zms.user_token_timeout";
    public static final String ZMS_PROP_SIGNED_POLICY_TIMEOUT   = "athenz.zms.signed_policy_timeout";
    public static final String ZMS_PROP_AUTHZ_SERVICE_FNAME     = "athenz.zms.authz_service_fname";
    public static final String ZMS_PROP_SOLUTION_TEMPLATE_FNAME = "athenz.zms.solution_templates_fname";
    
    public static final String ZMS_PROP_USER_DOMAIN             = "athenz.user_domain";
    
    public static final String ZMS_PROP_ACCESS_LOG_RETAIN_DAYS = "athenz.zms.access_log_retain_days";
    public static final String ZMS_PROP_ACCESS_LOG_NAME        = "athenz.zms.access_log_name";
    public static final String ZMS_PROP_ACCESS_SLF4J_LOGGER    = "athenz.zms.access_slf4j_logger";

    public static final String ZMS_PROP_KEYSTORE_PASSWORD      = "athenz.zms.ssl_key_store_password";
    public static final String ZMS_PROP_KEYMANAGER_PASSWORD    = "athenz.zms.ssl_key_manager_password";
    public static final String ZMS_PROP_TRUSTSTORE_PASSWORD    = "athenz.zms.ssl_trust_store_password";
    public static final String ZMS_PROP_KEYSTORE_PATH          = "athenz.zms.ssl_key_store";
    public static final String ZMS_PROP_KEYSTORE_TYPE          = "athenz.zms.ssl_key_store_type";
    public static final String ZMS_PROP_TRUSTSTORE_PATH        = "athenz.zms.ssl_trust_store";
    public static final String ZMS_PROP_TRUSTSTORE_TYPE        = "athenz.zms.ssl_trust_store_type";
    public static final String ZMS_PROP_EXCLUDED_CIPHER_SUITES = "athenz.zms.ssl_excluded_cipher_suites";
    public static final String ZMS_PROP_EXCLUDED_PROTOCOLS     = "athenz.zms.ssl_excluded_protocols";
    public static final String ZMS_PROP_IDLE_TIMEOUT           = "athenz.zms.http_idle_timeout";
    public static final String ZMS_PROP_SEND_SERVER_VERSION    = "athenz.zms.http_send_server_version";
    public static final String ZMS_PROP_SEND_DATE_HEADER       = "athenz.zms.http_send_date_header";
    public static final String ZMS_PROP_OUTPUT_BUFFER_SIZE     = "athenz.zms.http_output_buffer_size";
    public static final String ZMS_PROP_REQUEST_HEADER_SIZE    = "athenz.zms.http_reqeust_header_size";
    public static final String ZMS_PROP_RESPONSE_HEADER_SIZE   = "athenz.zms.http_response_header_size";
    public static final String ZMS_PROP_LISTEN_HOST            = "athenz.zms.listen_host";
    public static final String ZMS_PROP_KEEP_ALIVE             = "athenz.zms.keep_alive";
    public static final String ZMS_PROP_PROVIDER_ENDPOINTS     = "athenz.zms.provider_endpoints";
    public static final String ZMS_PROP_PRODUCT_ID_SUPPORT     = "athenz.zms.product_id_support";
    
    // properties used to over-ride default Audit logger
 
    public static final String ZMS_PROP_AUDIT_LOGGER_CLASS       = "athenz.zms.audit_logger_class";
    public static final String ZMS_PROP_AUDIT_LOGGER_CLASS_PARAM = "athenz.zms.audit_logger_class_param";
    public static final String ZMS_PROP_AUDIT_LOG_MSG_BLDR_CLASS = "athenz.zms.audit_log_msg_builder_class";

    public static final String ZMS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS = "athenz.zms.private_key_store_factory_class";
    
    public static final String ZMS_METRIC_FACTORY_CLASS         = "com.yahoo.athenz.common.metrics.impl.NoOpMetricFactory";

    public static final String ZMS_UNKNOWN_DOMAIN     = "unknown_domain";
    public static final String ZMS_INVALID_DOMAIN     = "invalid_domain";
    public static final String ZMS_SERVICE            = "zms";

    public static final int    ZMS_HTTPS_PORT_DEFAULT = 0;
    public static final int    ZMS_HTTP_PORT_DEFAULT  = 10080;
    public static final String ZMS_STATS_SCOREBOARD   = "zms_core";
    
    public static final String ZMS_DOMAIN_NAME_MAX_SIZE_DEFAULT = "128";

    public static final String USER_DOMAIN        = "user";
    public static final String USER_DOMAIN_PREFIX = "user.";
    
    public static final String HTTP_ORIGIN              = "Origin";
    public static final String HTTP_RFC1123_DATE_FORMAT = "EEE, d MMM yyyy HH:mm:ss zzz";
    public static final String HTTP_DATE_GMT_ZONE       = "GMT";
    
    public static final String HTTP_ACCESS_CONTROL_ALLOW_ORIGIN      = "Access-Control-Allow-Origin";
    public static final String HTTP_ACCESS_CONTROL_ALLOW_METHODS     = "Access-Control-Allow-Methods";
    public static final String HTTP_ACCESS_CONTROL_ALLOW_HEADERS     = "Access-Control-Allow-Headers";
    public static final String HTTP_ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
    public static final String HTTP_ACCESS_CONTROL_MAX_AGE           = "Access-Control-Max-Age";
    public static final String HTTP_ACCESS_CONTROL_REQUEST_HEADERS   = "Access-Control-Request-Headers";
    
    public static final String LOCALHOST    = "localhost";
    public static final String HTTP_SCHEME  = "http";
    public static final String HTTPS_SCHEME = "https";
    
    public static final String DB_COLUMN_DESCRIPTION       = "description";
    public static final String DB_COLUMN_ORG               = "org";
    public static final String DB_COLUMN_UUID              = "uuid";
    public static final String DB_COLUMN_ENABLED           = "enabled";
    public static final String DB_COLUMN_AUDIT_ENABLED     = "audit_enabled";
    public static final String DB_COLUMN_MODIFIED          = "modified";
    public static final String DB_COLUMN_NAME              = "name";
    public static final String DB_COLUMN_TRUST             = "trust";
    public static final String DB_COLUMN_MEMBER            = "member";
    public static final String DB_COLUMN_ROLE              = "role";
    public static final String DB_COLUMN_RESOURCE          = "resource";
    public static final String DB_COLUMN_ACTION            = "action";
    public static final String DB_COLUMN_EFFECT            = "effect";
    public static final String DB_COLUMN_KEY_VALUE         = "key_value";
    public static final String DB_COLUMN_KEY_ID            = "key_id";
    public static final String DB_COLUMN_SVC_USER          = "svc_user";
    public static final String DB_COLUMN_SVC_GROUP         = "svc_group";
    public static final String DB_COLUMN_EXECTUABLE        = "executable";
    public static final String DB_COLUMN_PROVIDER_ENDPOINT = "provider_endpoint";
    public static final String DB_COLUMN_VALUE             = "value";
    public static final String DB_COLUMN_DOMAIN_ID         = "domain_id";
    public static final String DB_COLUMN_DOMAIN            = "domain";
    public static final String DB_COLUMN_ACCOUNT           = "account";
    public static final String DB_COLUMN_PRODUCT_ID        = "ypm_id";
    public static final String DB_COLUMN_ADMIN             = "admin";
    public static final String DB_COLUMN_CREATED           = "created";
    public static final String DB_COLUMN_AUDIT_REF         = "audit_ref";
    public static final String DB_COLUMN_ROLE_NAME         = "role_name";
    public static final String DB_COLUMN_ASSERT_DOMAIN_ID  = "assert_domain_id";
    public static final String DB_COLUMN_ASSERT_ID         = "assertion_id";
    
    public static final String ADMIN_POLICY_NAME = "admin";
    public static final String ADMIN_ROLE_NAME   = "admin";
    
    public static final String ROLE_PREFIX   = "role.";
    public static final String POLICY_PREFIX = "policy.";
    
    public static final String ASSERTION_EFFECT_ALLOW = "ALLOW";
    public static final String ACTION_ASSUME_ROLE     = "assume_role";
    public static final String ACTION_ASSUME_AWS_ROLE = "assume_aws_role";
    public static final String ACTION_UPDATE          = "update";

    public static final String OBJECT_DOMAIN    = "domain";
    public static final String OBJECT_ROLE      = "role";
    public static final String OBJECT_POLICY    = "policy";
    public static final String OBJECT_SERVICE   = "service";
    public static final String OBJECT_PRINCIPAL = "principal";
    public static final String OBJECT_HOST      = "host";
    
    // HTTP operation types used in metrics
    public static final String HTTP_GET     = "GET";
    public static final String HTTP_PUT     = "PUT";
    public static final String HTTP_POST    = "POST";
    public static final String HTTP_DELETE  = "DELETE";
    public static final String HTTP_OPTIONS = "OPTIONS";
    public static final String HTTP_REQUEST = "REQUEST";
    
    public static final String STR_DEF_ROOT     = "/home/athenz";
    public static final String STR_ENV_ROOT     = "ROOT";
    
    public static final int STRING_BLDR_SIZE_DEFAULT = 512;
}

