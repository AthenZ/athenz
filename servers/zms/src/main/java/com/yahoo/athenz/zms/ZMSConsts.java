/*
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

    public static final String ZMS_PROP_USER_DOMAIN       = "athenz.user_domain";
    public static final String ZMS_PROP_HOME_DOMAIN       = "athenz.home_domain";
    public static final String ZMS_PROP_USER_DOMAIN_ALIAS = "athenz.user_domain_alias";
    public static final String ZMS_PROP_HTTP_PORT         = "athenz.port";
    public static final String ZMS_PROP_HTTPS_PORT        = "athenz.tls_port";
    public static final String ZMS_PROP_STATUS_PORT       = "athenz.status_port";

    public static final String ZMS_PROP_ADDL_USER_CHECK_DOMAINS = "athenz.zms.addl_user_check_domains";

    public static final String ZMS_PROP_ROOT_DIR      = "athenz.zms.root_dir";
    public static final String ZMS_PROP_HOSTNAME      = "athenz.zms.hostname";
    public static final String ZMS_PROP_DOMAIN_ADMIN  = "athenz.zms.domain_admin";
    public static final String ZMS_PROP_FILE_NAME     = "athenz.zms.prop_file";

    public static final String ZMS_PROP_VIRTUAL_DOMAIN       = "athenz.zms.virtual_domain_support";
    public static final String ZMS_PROP_VIRTUAL_DOMAIN_LIMIT = "athenz.zms.virtual_domain_limit";
    public static final String ZMS_PROP_READ_ONLY_MODE       = "athenz.zms.read_only_mode";
    public static final String ZMS_PROP_DOMAIN_NAME_MAX_SIZE = "athenz.zms.domain_name_max_len";
    public static final String ZMS_PROP_HEALTH_CHECK_PATH    = "athenz.zms.health_check_path";
    public static final String ZMS_PROP_SERVER_REGION        = "athenz.zms.server_region";
    public static final String ZMS_PROP_CONFLICT_RETRY_COUNT      = "athenz.zms.request_conflict_retry_count";
    public static final String ZMS_PROP_CONFLICT_RETRY_SLEEP_TIME = "athenz.zms.request_conflict_retry_sleep_time";

    public static final String ZMS_PROP_JDBC_RW_STORE           = "athenz.zms.jdbc_store";
    public static final String ZMS_PROP_JDBC_RW_USER            = "athenz.zms.jdbc_user";
    public static final String ZMS_PROP_JDBC_RW_PASSWORD        = "athenz.zms.jdbc_password";
    public static final String ZMS_PROP_JDBC_RO_STORE           = "athenz.zms.jdbc_ro_store";
    public static final String ZMS_PROP_JDBC_RO_USER            = "athenz.zms.jdbc_ro_user";
    public static final String ZMS_PROP_JDBC_RO_PASSWORD        = "athenz.zms.jdbc_ro_password";
    public static final String ZMS_PROP_JDBC_APP_NAME           = "athenz.zms.jdbc_app_name";
    public static final String ZMS_PROP_JDBC_VERIFY_SERVER_CERT = "athenz.zms.jdbc_verify_server_certificate";
    public static final String ZMS_PROP_JDBC_USE_SSL            = "athenz.zms.jdbc_use_ssl";
    public static final String ZMS_PROP_JDBC_TLS_VERSIONS       = "athenz.zms.jdbc_tls_versions";

    public static final String ZMS_PROP_FILE_STORE_NAME   = "athenz.zms.file_store_name";
    public static final String ZMS_PROP_FILE_STORE_QUOTA  = "athenz.zms.file_store_quota";
    public static final String ZMS_PROP_FILE_STORE_PATH   = "athenz.zms.file_store_path";
    public static final String ZMS_PROP_AUTHORITY_CLASSES = "athenz.zms.authority_classes";
    public static final String ZMS_PROP_STORE_OP_TIMEOUT  = "athenz.zms.store_operation_timeout";
    public static final String ZMS_PROP_NOAUTH_URI_LIST   = "athenz.zms.no_auth_uri_list";
    public static final String ZMS_PROP_CORS_ORIGIN_LIST  = "athenz.zms.cors_origin_list";
    public static final String ZMS_PROP_CORS_HEADER_LIST  = "athenz.zms.cors_header_list";

    public static final String ZMS_PROP_AWS_RDS_USER               = "athenz.zms.aws_rds_user";
    public static final String ZMS_PROP_AWS_RDS_IAM_ROLE           = "athenz.zms.aws_rds_iam_role";
    public static final String ZMS_PROP_AWS_RDS_ENGINE             = "athenz.zms.aws_rds_engine";
    public static final String ZMS_PROP_AWS_RDS_DATABASE           = "athenz.zms.aws_rds_database";
    public static final String ZMS_PROP_AWS_RDS_MASTER_INSTANCE    = "athenz.zms.aws_rds_master_instance";
    public static final String ZMS_PROP_AWS_RDS_MASTER_PORT        = "athenz.zms.aws_rds_master_port";
    public static final String ZMS_PROP_AWS_RDS_REPLICA_INSTANCE   = "athenz.zms.aws_rds_replica_instance";
    public static final String ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME = "athenz.zms.aws_rds_creds_refresh_time";
    public static final String ZMS_AUTO_UPDATE_TEMPLATE_FEATURE_FLAG = "athenz.zms.auto_update_template_feature_flag";

    public static final String DB_PROP_USER               = "user";
    public static final String DB_PROP_PASSWORD           = "password";
    public static final String DB_PROP_USE_SSL            = "useSSL";
    public static final String DB_PROP_VERIFY_SERVER_CERT = "verifyServerCertificate";
    public static final String DB_PROP_TLS_PROTOCOLS      = "enabledTLSProtocols";
    public static final String DB_PROP_CONN_TIME_ZONE     = "connectionTimeZone";

    public static final String ZMS_PROP_USER_AUTHORITY_CLASS      = "athenz.zms.user_authority_class";
    public static final String ZMS_PROP_PRINCIPAL_AUTHORITY_CLASS = "athenz.zms.principal_authority_class";

    public static final String ZMS_PROP_TIMEOUT                 = "athenz.zms.user_token_timeout";
    public static final String ZMS_PROP_SIGNED_POLICY_TIMEOUT   = "athenz.zms.signed_policy_timeout";
    public static final String ZMS_PROP_AUTHZ_SERVICE_FNAME     = "athenz.zms.authz_service_fname";
    public static final String ZMS_PROP_SOLUTION_TEMPLATE_FNAME = "athenz.zms.solution_templates_fname";
    public static final String ZMS_PROP_PROVIDER_ENDPOINTS      = "athenz.zms.provider_endpoints";
    public static final String ZMS_PROP_PRODUCT_ID_SUPPORT      = "athenz.zms.product_id_support";
    public static final String ZMS_PROP_SECURE_REQUESTS_ONLY    = "athenz.zms.secure_requests_only";
    public static final String ZMS_PROP_RESERVED_SERVICE_NAMES  = "athenz.zms.reserved_service_names";
    public static final String ZMS_PROP_SERVICE_NAME_MIN_LENGTH = "athenz.zms.service_name_min_length";
    public static final String ZMS_PROP_MAX_POLICY_VERSIONS     = "athenz.zms.max_policy_versions";

    public static final String ZMS_PROP_VALIDATE_USER_MEMBERS    = "athenz.zms.validate_user_members";
    public static final String ZMS_PROP_VALIDATE_SERVICE_MEMBERS = "athenz.zms.validate_service_members";
    public static final String ZMS_PROP_VALIDATE_ASSERTION_ROLES = "athenz.zms.validate_policy_assertion_roles";
    public static final String ZMS_PROP_VALIDATE_SERVICE_MEMBERS_SKIP_DOMAINS = "athenz.zms.validate_service_members_skip_domains";
    public static final String ZMS_PROP_MASTER_COPY_FOR_SIGNED_DOMAINS        = "athenz.zms.master_copy_for_signed_domains";

    // properties used to over-ride default Audit logger
 
    public static final String ZMS_PROP_METRIC_FACTORY_CLASS            = "athenz.zms.metric_factory_class";

    public static final String ZMS_PROP_AUDIT_LOGGER_FACTORY_CLASS      = "athenz.zms.audit_logger_factory_class";
    public static final String ZMS_AUDIT_LOGGER_FACTORY_CLASS           = "com.yahoo.athenz.common.server.log.impl.DefaultAuditLoggerFactory";

    public static final String ZMS_PROP_AUDIT_REF_VALIDATOR_FACTORY_CLASS = "athenz.zms.audit_ref_validator_factory_class";
    public static final String ZMS_PROP_AUDIT_REF_CHECK_OBJECTS           = "athenz.zms.audit_ref_check_objects";

    public static final String ZMS_AUDIT_TYPE_ROLE     = "role";
    public static final String ZMS_AUDIT_TYPE_GROUP    = "group";
    public static final String ZMS_AUDIT_TYPE_POLICY   = "policy";
    public static final String ZMS_AUDIT_TYPE_SERVICE  = "service";
    public static final String ZMS_AUDIT_TYPE_DOMAIN   = "domain";
    public static final String ZMS_AUDIT_TYPE_ENTITY   = "entity";
    public static final String ZMS_AUDIT_TYPE_TENANCY  = "tenancy";
    public static final String ZMS_AUDIT_TYPE_TEMPLATE = "template";

    public static final String ZMS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS = "athenz.zms.private_key_store_factory_class";
    public static final String ZMS_PRIVATE_KEY_STORE_FACTORY_CLASS      = "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";

    public static final String ZMS_PROP_OBJECT_STORE_FACTORY_CLASS      = "athenz.zms.object_store_factory_class";
    public static final String ZMS_OBJECT_STORE_FACTORY_CLASS           = "com.yahoo.athenz.zms.store.impl.JDBCObjectStoreFactory";

    public static final String ZMS_PROP_DOMAIN_META_STORE_FACTORY_CLASS = "athenz.zms.domain_meta_store_factory_class";
    public static final String ZMS_DOMAIN_META_STORE_FACTORY_CLASS      = "com.yahoo.athenz.common.server.metastore.impl.NoOpDomainMetaStoreFactory";

    // properties for our default quota limits

    public static final String ZMS_PROP_QUOTA_CHECK        = "athenz.zms.quota_check";
    public static final String ZMS_PROP_QUOTA_ROLE         = "athenz.zms.quota_role";
    public static final String ZMS_PROP_QUOTA_ROLE_MEMBER  = "athenz.zms.quota_role_member";
    public static final String ZMS_PROP_QUOTA_POLICY       = "athenz.zms.quota_policy";
    public static final String ZMS_PROP_QUOTA_ASSERTION    = "athenz.zms.quota_assertion";
    public static final String ZMS_PROP_QUOTA_SERVICE      = "athenz.zms.quota_service";
    public static final String ZMS_PROP_QUOTA_SERVICE_HOST = "athenz.zms.quota_service_host";
    public static final String ZMS_PROP_QUOTA_PUBLIC_KEY   = "athenz.zms.quota_public_key";
    public static final String ZMS_PROP_QUOTA_ENTITY       = "athenz.zms.quota_entity";
    public static final String ZMS_PROP_QUOTA_SUBDOMAIN    = "athenz.zms.quota_subdomain";
    public static final String ZMS_PROP_QUOTA_GROUP        = "athenz.zms.quota_group";
    public static final String ZMS_PROP_QUOTA_GROUP_MEMBER = "athenz.zms.quota_group_member";
    public static final String ZMS_PROP_QUOTA_ROLE_TAG     = "athenz.zms.quota_role_tag";
    public static final String ZMS_PROP_QUOTA_DOMAIN_TAG   = "athenz.zms.quota_domain_tag";
    public static final String ZMS_PROP_QUOTA_GROUP_TAG   = "athenz.zms.quota_group_tag";
    
    public static final String ZMS_PROP_MYSQL_SERVER_TIMEZONE = "athenz.zms.mysql_server_timezone";

    public static final String ZMS_PRINCIPAL_AUTHORITY_CLASS  = "com.yahoo.athenz.auth.impl.PrincipalAuthority";

    public static final String ZMS_UNKNOWN_DOMAIN     = "unknown_domain";
    public static final String ZMS_INVALID_DOMAIN     = "invalid_domain";
    public static final String ZMS_SERVICE            = "zms";

    public static final String ZMS_DOMAIN_NAME_MAX_SIZE_DEFAULT = "128";
    public static final int    ZMS_DEFAULT_TAG_LIMIT   = 25;

    public static final String USER_DOMAIN        = "user";

    public static final String RSA   = "RSA";
    public static final String EC    = "EC";

    public static final String HTTP_ORIGIN              = "Origin";
    public static final String HTTP_RFC1123_DATE_FORMAT = "EEE, d MMM yyyy HH:mm:ss zzz";
    public static final String HTTP_DATE_GMT_ZONE       = "GMT";

    public static final String HTTP_ACCESS_CONTROL_ALLOW_ORIGIN      = "Access-Control-Allow-Origin";
    public static final String HTTP_ACCESS_CONTROL_ALLOW_METHODS     = "Access-Control-Allow-Methods";
    public static final String HTTP_ACCESS_CONTROL_ALLOW_HEADERS     = "Access-Control-Allow-Headers";
    public static final String HTTP_ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
    public static final String HTTP_ACCESS_CONTROL_MAX_AGE           = "Access-Control-Max-Age";
    public static final String HTTP_ACCESS_CONTROL_REQUEST_HEADERS   = "Access-Control-Request-Headers";

    public static final String ZMS_RESERVED_SERVICE_NAMES_DEFAULT = "com,net,org,edu,biz,gov,mil,info,name,mobi,cloud";

    public static final String LOCALHOST    = "localhost";
    public static final String SCHEME_HTTP  = "http";
    public static final String SCHEME_HTTPS = "https";
    public static final String SCHEME_CLASS = "class";

    public static final int ZMS_HTTPS_PORT_DEFAULT = 4443;
    public static final int ZMS_HTTP_PORT_DEFAULT  = 4080;

    public static final String DB_COLUMN_DESCRIPTION        = "description";
    public static final String DB_COLUMN_ORG                = "org";
    public static final String DB_COLUMN_UUID               = "uuid";
    public static final String DB_COLUMN_ENABLED            = "enabled";
    public static final String DB_COLUMN_AUDIT_ENABLED      = "audit_enabled";
    public static final String DB_COLUMN_MODIFIED           = "modified";
    public static final String DB_COLUMN_NAME               = "name";
    public static final String DB_COLUMN_TRUST              = "trust";
    public static final String DB_COLUMN_MEMBER             = "member";
    public static final String DB_COLUMN_ENTITY             = "entity";
    public static final String DB_COLUMN_SUBDOMAIN          = "subdomain";
    public static final String DB_COLUMN_ROLE               = "role";
    public static final String DB_COLUMN_ROLE_MEMBER        = "role_member";
    public static final String DB_COLUMN_POLICY             = "policy";
    public static final String DB_COLUMN_SERVICE            = "service";
    public static final String DB_COLUMN_SERVICE_HOST       = "service_host";
    public static final String DB_COLUMN_PUBLIC_KEY         = "public_key";
    public static final String DB_COLUMN_ASSERTION          = "assertion";
    public static final String DB_COLUMN_RESOURCE           = "resource";
    public static final String DB_COLUMN_ACTION             = "action";
    public static final String DB_COLUMN_EFFECT             = "effect";
    public static final String DB_COLUMN_KEY_VALUE          = "key_value";
    public static final String DB_COLUMN_KEY_ID             = "key_id";
    public static final String DB_COLUMN_SVC_USER           = "svc_user";
    public static final String DB_COLUMN_SVC_GROUP          = "svc_group";
    public static final String DB_COLUMN_EXECUTABLE         = "executable";
    public static final String DB_COLUMN_PROVIDER_ENDPOINT  = "provider_endpoint";
    public static final String DB_COLUMN_VALUE              = "value";
    public static final String DB_COLUMN_DOMAIN_ID          = "domain_id";
    public static final String DB_COLUMN_ACCOUNT            = "account";
    public static final String DB_COLUMN_PRODUCT_ID         = "ypm_id";
    public static final String DB_COLUMN_ADMIN              = "admin";
    public static final String DB_COLUMN_CREATED            = "created";
    public static final String DB_COLUMN_AUDIT_REF          = "audit_ref";
    public static final String DB_COLUMN_ROLE_NAME          = "role_name";
    public static final String DB_COLUMN_ASSERT_DOMAIN_ID   = "assert_domain_id";
    public static final String DB_COLUMN_ASSERT_ID          = "assertion_id";
    public static final String DB_COLUMN_CERT_DNS_DOMAIN    = "cert_dns_domain";
    public static final String DB_COLUMN_SELF_SERVE         = "self_serve";
    public static final String DB_COLUMN_EXPIRATION         = "expiration";
    public static final String DB_COLUMN_REVIEW_REMINDER    = "review_reminder";
    public static final String DB_COLUMN_MEMBER_EXPIRY_DAYS = "member_expiry_days";
    public static final String DB_COLUMN_TOKEN_EXPIRY_MINS  = "token_expiry_mins";
    public static final String DB_COLUMN_CERT_EXPIRY_MINS   = "cert_expiry_mins";
    public static final String DB_COLUMN_DOMAIN_NAME        = "domain_name";
    public static final String DB_COLUMN_PRINCIPAL_NAME     = "principal_name";
    public static final String DB_COLUMN_APPLICATION_ID     = "application_id";
    public static final String DB_COLUMN_SIGN_ALGORITHM     = "sign_algorithm";
    public static final String DB_COLUMN_REVIEW_ENABLED     = "review_enabled";
    public static final String DB_COLUMN_NOTIFY_ROLES       = "notify_roles";
    public static final String DB_COLUMN_LAST_REVIEWED_TIME = "last_reviewed_time";
    public static final String DB_COLUMN_REQ_PRINCIPAL      = "req_principal";
    public static final String DB_COLUMN_MEMBER_REVIEW_DAYS = "member_review_days";
    public static final String DB_COLUMN_TEMPLATE_NAME      = "template";
    public static final String DB_COLUMN_TEMPLATE_VERSION   = "current_version";
    public static final String DB_COLUMN_AS_DOMAIN_NAME     = "domain_name";
    public static final String DB_COLUMN_AS_ROLE_NAME       = "role_name";
    public static final String DB_COLUMN_AS_GROUP_NAME      = "group_name";
    public static final String DB_COLUMN_SYSTEM_DISABLED    = "system_disabled";
    public static final String DB_COLUMN_AZURE_SUBSCRIPTION = "azure_subscription";
    public static final String DB_COLUMN_BUSINESS_SERVICE   = "business_service";
    public static final String DB_COLUMN_ACTIVE             = "active";
    public static final String DB_COLUMN_VERSION            = "version";
    public static final String DB_COLUMN_POLICY_ID          = "policy_id";

    public static final String DB_COLUMN_SERVICE_REVIEW_DAYS      = "service_review_days";
    public static final String DB_COLUMN_SERVICE_EXPIRY_DAYS      = "service_expiry_days";
    public static final String DB_COLUMN_GROUP_EXPIRY_DAYS        = "group_expiry_days";
    public static final String DB_COLUMN_GROUP_REVIEW_DAYS        = "group_review_days";
    public static final String DB_COLUMN_ROLE_CERT_EXPIRY_MINS    = "role_cert_expiry_mins";
    public static final String DB_COLUMN_SERVICE_CERT_EXPIRY_MINS = "service_cert_expiry_mins";
    public static final String DB_COLUMN_PRINCIPAL_GROUP          = "principal_group";
    public static final String DB_COLUMN_PRINCIPAL_GROUP_MEMBER   = "principal_group_member";

    public static final String DB_COLUMN_USER_AUTHORITY_FILTER           = "user_authority_filter";
    public static final String DB_COLUMN_USER_AUTHORITY_EXPIRATION       = "user_authority_expiration";
    public static final String DB_COLUMN_AS_DOMAIN_USER_AUTHORITY_FILTER = "domain_user_authority_filter";

    public static final String DB_COLUMN_KEY                       = "key";
    public static final String DB_COLUMN_OPERATOR                  = "operator";
    public static final String DB_COLUMN_CONDITION_ID              = "condition_id";

    public static final String ADMIN_POLICY_NAME = "admin";
    public static final String ADMIN_ROLE_NAME   = "admin";

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
    public static final String OBJECT_GROUP     = "group";
    public static final String OBJECT_ENTITY    = "entity";

    public static final String SYSTEM_META_PRODUCT_ID         = "productid";
    public static final String SYSTEM_META_ACCOUNT            = "account";
    public static final String SYSTEM_META_CERT_DNS_DOMAIN    = "certdnsdomain";
    public static final String SYSTEM_META_AUDIT_ENABLED      = "auditenabled";
    public static final String SYSTEM_META_USER_AUTH_FILTER   = "userauthorityfilter";
    public static final String SYSTEM_META_ENABLED            = "enabled";
    public static final String SYSTEM_META_ORG                = "org";
    public static final String SYSTEM_META_LAST_MOD_TIME      = "modified";
    public static final String SYSTEM_META_PROVIDER_ENDPOINT  = "providerendpoint";
    public static final String SYSTEM_META_AZURE_SUBSCRIPTION = "azuresubscription";
    public static final String SYSTEM_META_BUSINESS_SERVICE   = "businessservice";


    // HTTP operation types used in metrics
    public static final String HTTP_GET     = "GET";
    public static final String HTTP_PUT     = "PUT";
    public static final String HTTP_POST    = "POST";
    public static final String HTTP_DELETE  = "DELETE";
    public static final String HTTP_OPTIONS = "OPTIONS";
    public static final String HTTP_REQUEST = "REQUEST";

    public static final String STR_DEF_ROOT     = "/home/athenz";

    public static final int STRING_BLDR_SIZE_DEFAULT = 512;

    public static final String ZMS_JSON_PARSER_ERROR_RESPONSE = "{\"code\":400,\"message\":\"Invalid Object: checkout https://github.com/AthenZ/athenz/tree/master/core/zms/src/main/rdl for object definitions\"}";

    public static final String SYS_AUTH_AUDIT_BY_ORG    = "sys.auth.audit.org";
    public static final String SYS_AUTH_AUDIT_BY_DOMAIN = "sys.auth.audit.domain";

    public static final String ZMS_PROP_PENDING_ROLE_MEMBER_LIFESPAN = "athenz.zms.pending_role_member_lifespan";
    public static final String ZMS_PENDING_ROLE_MEMBER_LIFESPAN_DEFAULT = "30";
    public static final String SYS_AUTH_MONITOR = "sys.auth.monitor";
    public static final String ZMS_PROP_MONITOR_IDENTITY = "athenz.zms.monitor_identity";

    public static final int ZMS_DISABLED_AUTHORITY_FILTER = 0x01;

    public static final String ZMS_PROP_STATUS_CHECKER_FACTORY_CLASS = "athenz.zms.status_checker_factory_class";

    public static final String ZMS_PROP_ENABLE_PRINCIPAL_STATE_UPDATER        = "athenz.zms.enable_principal_state_updater";
    public static final String ZMS_PROP_PRINCIPAL_STATE_UPDATER_FREQUENCY = "athenz.zms.principal_state_updater_frequency";
    public static final String ZMS_PROP_PRINCIPAL_STATE_UPDATER_FREQUENCY_DEFAULT = "30"; // in minutes
    public static final String ZMS_PROP_PRINCIPAL_STATE_UPDATER_DISABLE_TIMER = "athenz.zms.disable_principal_state_updater_timer_task";

    public static final String ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS = "athenz.zms.service_provider_manager_frequency_seconds";
    public static final String ZMS_PROP_SERVICE_PROVIDER_MANAGER_FREQUENCY_SECONDS_DEFAULT = "300";
    public static final String ZMS_PROP_SERVICE_PROVIDER_MANAGER_DOMAIN = "athenz.zms.service_provider_manager_domain";
    public static final String ZMS_PROP_SERVICE_PROVIDER_MANAGER_DOMAIN_DEFAULT = "sys.auth";
    public static final String ZMS_PROP_SERVICE_PROVIDER_MANAGER_ROLE = "athenz.zms.service_provider_manager_role";
    public static final String ZMS_PROP_SERVICE_PROVIDER_MANAGER_ROLE_DEFAULT = "service_providers";

    public static final String ZMS_PROP_QUOTA_ASSERTION_CONDITIONS = "athenz.zms.quota_assertion_conditions";

    public static final String ZMS_PROP_MAX_POLICY_VERSIONS_DEFAULT = "3";
    
    public static final String ZMS_PROP_DOMAIN_CHANGE_TOPIC_NAMES = "athenz.zms.domain_changes_topic_names";
    public static final String ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_FACTORY_CLASS = "athenz.zms.domain_change_publisher_factory_class";
    public static final String ZMS_PROP_DOMAIN_CHANGE_PUBLISHER_DEFAULT = "com.yahoo.athenz.common.messaging.impl.NoOpDomainChangePublisherFactory";

    public static final String DISABLE_REMINDER_NOTIFICATIONS_TAG = "zms.DisableReminderNotifications";
    public static final String DISABLE_EXPIRATION_NOTIFICATIONS_TAG = "zms.DisableExpirationNotifications";
    public static final String ZMS_PROP_PROVIDER_READ_TIMEOUT       = "athenz.zms.provider.client.read_timeout";
    public static final String ZMS_PROP_PROVIDER_TRUST_STORE = "athenz.zms.provider.client.truststore";
    public static final String ZMS_PROP_PROVIDER_TRUST_STORE_PASSWORD = "athenz.zms.provider.client.truststore_password";
    public static final String ZMS_PROP_PROVIDER_APP_NAME = "athenz.zms.provider.client.app_name";
    public static final String ZMS_PROP_PROVIDER_CERT_PATH = "athenz.zms.provider.client.cert_path";
    public static final String ZMS_PROP_PROVIDER_KEY_PATH = "athenz.zms.provider.client.key_path";
    public static final String ZMS_PROP_PROVIDER_MAX_POOL_ROUTE = "athenz.zms.provider.client.max_pool_route";
    public static final String ZMS_PROP_PROVIDER_MAX_POOL_TOTAL = "athenz.zms.provider.client.max_pool_total";
    public static final String ZMS_PROP_PROVIDER_RETRY_INTERVAL_MS = "athenz.zms.provider.client.retry_interval_ms";
    public static final String ZMS_PROP_PROVIDER_MAX_RETRIES = "athenz.zms.provider.client.max_retries";
    public static final String ZMS_PROP_PROVIDER_CONNECT_TIMEOUT_MS = "athenz.zms.provider.client.connect_timeout_ms";
    public static final String ZMS_PROP_PROVIDER_READ_TIMEOUT_MS = "athenz.zms.provider.client.read_timeout_ms";

    public static final String PROVIDER_RESPONSE_ALLOW = "allow";
    public static final String PROVIDER_RESPONSE_DENY = "deny";
}
