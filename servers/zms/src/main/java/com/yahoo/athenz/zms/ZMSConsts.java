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
package com.yahoo.athenz.zms;

/**
 * Contains constants shared by classes throughout the service.
 **/
public final class ZMSConsts {

    // System property names with defaults(where applicable)

    public static final String ZMS_PROP_USER_DOMAIN          = "athenz.user_domain";
    public static final String ZMS_PROP_HOME_DOMAIN          = "athenz.home_domain";
    public static final String ZMS_PROP_HEADLESS_USER_DOMAIN = "athenz.headless_user_domain";
    public static final String ZMS_PROP_USER_DOMAIN_ALIAS    = "athenz.user_domain_alias";

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

    public static final String ZMS_PROP_AUTHORITY_CLASSES = "athenz.zms.authority_classes";
    public static final String ZMS_PROP_STORE_OP_TIMEOUT  = "athenz.zms.store_operation_timeout";
    public static final String ZMS_PROP_NOAUTH_URI_LIST   = "athenz.zms.no_auth_uri_list";
    public static final String ZMS_PROP_CORS_ORIGIN_LIST  = "athenz.zms.cors_origin_list";
    public static final String ZMS_PROP_CORS_HEADER_LIST  = "athenz.zms.cors_header_list";

    public static final String ZMS_AUTO_UPDATE_TEMPLATE_FEATURE_FLAG = "athenz.zms.auto_update_template_feature_flag";
    public static final String ZMS_PROP_RESOURCE_OWNER_IGNORE_VALUE  = "athenz.zms.resource_owner_ignore_value";
    public static final String ZMS_PROP_ENFORCE_RESOURCE_OWNERSHIP   = "athenz.zms.enforce_resource_ownership";

    public static final String ZMS_PROP_USER_AUTHORITY_CLASS      = "athenz.zms.user_authority_class";
    public static final String ZMS_PROP_PRINCIPAL_AUTHORITY_CLASS = "athenz.zms.principal_authority_class";

    public static final String ZMS_PROP_TIMEOUT                 = "athenz.zms.user_token_timeout";
    public static final String ZMS_PROP_SIGNED_POLICY_TIMEOUT   = "athenz.zms.signed_policy_timeout";
    public static final String ZMS_PROP_AUTHZ_SERVICE_FNAME     = "athenz.zms.authz_service_fname";
    public static final String ZMS_PROP_SOLUTION_TEMPLATE_FNAME = "athenz.zms.solution_templates_fname";
    public static final String ZMS_PROP_PROVIDER_ENDPOINTS      = "athenz.zms.provider_endpoints";
    public static final String ZMS_PROP_PRODUCT_ID_SUPPORT      = "athenz.zms.product_id_support";
    public static final String ZMS_PROP_SECURE_REQUESTS_ONLY    = "athenz.zms.secure_requests_only";
    public static final String ZMS_PROP_RESERVED_DOMAIN_NAMES   = "athenz.zms.reserved_domain_names";
    public static final String ZMS_PROP_RESERVED_SERVICE_NAMES  = "athenz.zms.reserved_service_names";
    public static final String ZMS_PROP_SERVICE_NAME_MIN_LENGTH = "athenz.zms.service_name_min_length";
    public static final String ZMS_PROP_MAX_POLICY_VERSIONS     = "athenz.zms.max_policy_versions";
    public static final String ZMS_PROP_DOMAIN_CONTACT_TYPES    = "athenz.zms.domain_contact_types";
    public static final String ZMS_PROP_DOMAIN_ENVIRONMENTS     = "athenz.zms.domain_environments";
    public static final String ZMS_DEFAULT_DOMAIN_ENVIRONMENTS  = "production,integration,staging,sandbox,qa,development";

    public static final String ZMS_PROP_DEFAULT_MAX_USER_EXPIRY  = "athenz.zms.default_max_user_expiry_days";
    public static final String ZMS_PROP_DEFAULT_MAX_SERVICE_EXPIRY  = "athenz.zms.default_max_service_expiry_days";
    public static final String ZMS_PROP_DEFAULT_MAX_GROUP_EXPIRY  = "athenz.zms.default_max_group_expiry_days";

    public static final String ZMS_PROP_VALIDATE_USER_MEMBERS    = "athenz.zms.validate_user_members";
    public static final String ZMS_PROP_VALIDATE_SERVICE_MEMBERS = "athenz.zms.validate_service_members";
    public static final String ZMS_PROP_VALIDATE_ASSERTION_ROLES = "athenz.zms.validate_policy_assertion_roles";

    public static final String ZMS_PROP_VALIDATE_SERVICE_MEMBERS_SKIP_DOMAINS = "athenz.zms.validate_service_members_skip_domains";
    public static final String ZMS_PROP_MASTER_COPY_FOR_SIGNED_DOMAINS        = "athenz.zms.master_copy_for_signed_domains";
    public static final String ZMS_PROP_ALLOW_UNDERSCORE_IN_SERVICE_NAMES     = "athenz.zms.allow_underscore_in_service_names";
    public static final String ZMS_PROP_DOMAIN_DELETE_META_ATTRIBUTES         = "athenz.zms.domain_delete_meta_attributes";
    public static final String ZMS_PROP_DISALLOW_GROUPS_IN_ADMIN_ROLE         = "athenz.zms.disallow_groups_in_admin_role";

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
    public static final String ZMS_OBJECT_STORE_FACTORY_CLASS           = "com.yahoo.athenz.common.server.store.impl.JDBCObjectStoreFactory";

    public static final String ZMS_PROP_DOMAIN_META_STORE_FACTORY_CLASS = "athenz.zms.domain_meta_store_factory_class";
    public static final String ZMS_DOMAIN_META_STORE_FACTORY_CLASS      = "com.yahoo.athenz.common.server.metastore.impl.NoOpDomainMetaStoreFactory";

    public static final String ZMS_PROP_AUTH_HISTORY_STORE_FACTORY_CLASS    = "athenz.zms.auth_history_store_factory_class";

    public static final String ZMS_PROP_AWS_ASSUME_ROLE_ACTION    = "athenz.zms.aws_assume_role_action";
    public static final String ZMS_PROP_GCP_ASSUME_ROLE_ACTION    = "athenz.zms.gcp_assume_role_action";
    public static final String ZMS_PROP_GCP_ASSUME_SERVICE_ACTION = "athenz.zms.gcp_assume_service_action";

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
    public static final String ZMS_PROP_QUOTA_GROUP_TAG    = "athenz.zms.quota_group_tag";
    public static final String ZMS_PROP_QUOTA_POLICY_TAG   = "athenz.zms.quota_policy_tag";
    public static final String ZMS_PROP_QUOTA_SERVICE_TAG  = "athenz.zms.quota_service_tag";

    public static final String ZMS_PROP_SVC_CREDS_KEY_GROUP = "athenz.zms.svc_creds_key_group";
    public static final String ZMS_PROP_SVC_CREDS_KEY_NAME  = "athenz.zms.svc_creds_key_name";
    public static final String ZMS_PROP_SVC_CREDS_ENCRYPTION_ALGORITHM = "athenz.zms.svc_creds_encryption_algorithm";

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

    public static final String ADMIN_POLICY_NAME = "admin";
    public static final String ADMIN_ROLE_NAME   = "admin";

    public static final String ACTION_ASSUME_ROLE        = "assume_role";
    public static final String ACTION_ASSUME_AWS_ROLE    = "assume_aws_role";
    public static final String ACTION_ASSUME_GCP_ROLE    = "assume_gcp_role";
    public static final String ACTION_ASSUME_GCP_SERVICE = "assume_gcp_service";
    public static final String ACTION_UPDATE             = "update";

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
    public static final String SYSTEM_META_GCP_PROJECT        = "gcpproject";
    public static final String SYSTEM_META_BUSINESS_SERVICE   = "businessservice";
    public static final String SYSTEM_META_YPM_ID             = "ypmid";
    public static final String SYSTEM_META_FEATURE_FLAGS      = "featureflags";
    public static final String SYSTEM_META_ATTR_ALL           = "all";

    public static final String SYSTEM_META_X509_CERT_SIGNER_KEYID = "x509certsignerkeyid";
    public static final String SYSTEM_META_SSH_CERT_SIGNER_KEYID  = "sshcertsignerkeyid";

    // HTTP operation types used in metrics
    public static final String HTTP_GET     = "GET";
    public static final String HTTP_PUT     = "PUT";
    public static final String HTTP_POST    = "POST";
    public static final String HTTP_DELETE  = "DELETE";

    public static final String STR_DEF_ROOT     = "/home/athenz";

    public static final int STRING_BLDR_SIZE_DEFAULT = 512;

    public static final String ZMS_JSON_PARSER_ERROR_RESPONSE = "{\"code\":400,\"message\":\"Invalid Object: checkout https://github.com/AthenZ/athenz/tree/master/core/zms/src/main/rdl for object definitions\"}";

    public static final String SYS_AUTH_AUDIT_BY_ORG    = "sys.auth.audit.org";
    public static final String SYS_AUTH_AUDIT_BY_DOMAIN = "sys.auth.audit.domain";

    public static final String ZMS_PROP_PENDING_ROLE_MEMBER_LIFESPAN = "athenz.zms.pending_role_member_lifespan";
    public static final String ZMS_PENDING_ROLE_MEMBER_LIFESPAN_DEFAULT = "30";
    public static final String SYS_AUTH_MONITOR = "sys.auth.monitor";
    public static final String ZMS_PROP_MONITOR_IDENTITY = "athenz.zms.monitor_identity";

    public static final String ZMS_PROP_STATUS_CHECKER_FACTORY_CLASS = "athenz.zms.status_checker_factory_class";

    public static final String ZMS_PROP_RESOURCE_VALIDATOR_FACTORY_CLASS = "athenz.zms.resource_validator_factory_class";
    public static final String ZMS_PROP_RESOURCE_VALIDATOR_FACTORY_CLASS_DEFAULT = "com.yahoo.athenz.common.server.store.impl.NoOpResourceValidatorFactory";

    public static final String ZMS_PROP_ENABLE_PRINCIPAL_STATE_UPDATER = "athenz.zms.enable_principal_state_updater";
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
    public static final String ZMS_PROP_PROVIDER_TRUST_STORE = "athenz.zms.provider.client.truststore";
    public static final String ZMS_PROP_PROVIDER_TRUST_STORE_PASSWORD = "athenz.zms.provider.client.truststore_password";
    public static final String ZMS_PROP_PROVIDER_APP_NAME = "athenz.zms.provider.client.app_name";
    public static final String ZMS_PROP_PROVIDER_KEYGROUP_NAME = "athenz.zms.provider.client.keygroup_name";
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

    // purge task
    public static final String ZMS_PROP_PURGE_TASK_MAX_DB_CALLS_PER_RUN = "athenz.zms.purge_task_max_db_calls_per_run";
    public static final Integer ZMS_PURGE_TASK_MAX_DB_CALLS_PER_RUN_DEF = 20;
    public static final String ZMS_PROP_PURGE_TASK_LIMIT_PER_CALL = "athenz.zms.purge_task_limit_per_call";
    public static final Integer ZMS_PURGE_TASK_LIMIT_PER_CALL_DEF = 500;
    public static final String ZMS_PROP_PURGE_MEMBER_EXPIRY_DAYS = "athenz.zms.purge_member_expiry_days";
    public static final Integer ZMS_PURGE_MEMBER_EXPIRY_DAYS_DEF = 180;

    public static final String ZMS_PROP_ENFORCE_UNIQUE_AWS_ACCOUNTS = "athenz.zms.enforce_unique_aws_accounts";
    public static final String ZMS_PROP_ENFORCE_UNIQUE_AZURE_SUBSCRIPTIONS = "athenz.zms.enforce_unique_azure_subscriptions";
    public static final String ZMS_PROP_ENFORCE_UNIQUE_GCP_PROJECTS = "athenz.zms.enforce_unique_gcp_projects";
    public static final String ZMS_PROP_ENFORCE_UNIQUE_PRODUCT_IDS = "athenz.zms.enforce_unique_product_ids";

    //pending member
    public static final String PENDING_REQUEST_ADD_STATE = "ADD";
    public static final String PENDING_REQUEST_DELETE_STATE = "DELETE";
    public static final String PENDING_REQUEST_APPROVE = "approve";
    public static final String PENDING_REQUEST_REJECT = "reject";

    public static final String ZMS_PROP_JSON_MAX_NESTING_DEPTH = "athenz.zms.json_max_nesting_depth";
    public static final String ZMS_PROP_JSON_MAX_NUMBER_LENGTH = "athenz.zms.json_max_number_length";
    public static final String ZMS_PROP_JSON_MAX_STRING_LENGTH = "athenz.zms.json_max_string_length";

    public static final String ZMS_PROP_REVIEW_DATE_OFFSET_DAYS_NEW_OBJECT = "athenz.zms.review_date_offset_days_new_objects";
    public static final String ZMS_PROP_REVIEW_DATE_OFFSET_DAYS_NEW_OBJECT_DEFAULT = "365";

    public static final String ZMS_PROP_REVIEW_DATE_OFFSET_DAYS_UPDATED_OBJECT = "athenz.zms.review_date_offset_days_updated_objects";
    public static final String ZMS_PROP_REVIEW_DATE_OFFSET_DAYS_UPDATED_OBJECT_DEFAULT = "7";

    public static final String ZMS_PROP_REVIEW_DAYS_PERCENTAGE  = "athenz.zms.review_days_percentage";
    public static final Integer ZMS_PROP_REVIEW_DAYS_PERCENTAGE_DEFAULT = 68;

    public static final String ZMS_PROP_SEARCH_SERVICE_LIMIT = "athenz.zms.search_service_limit";
    public static final Integer ZMS_PROP_SEARCH_SERVICE_LIMIT_DEFAULT = 100;

    public static final String ZMS_PROP_USER_AUTHORITY_FILTER_DOC_URL = "athenz.zms.user_authority_filter_documentation_url";

    // ZMS feature flag bits
    public static final int ZMS_FEATURE_ALLOW_SERVICE_UNDERSCORE = 0x01;

    // Validator object types
    public static final String TYPE_DOMAIN_NAME      = "DomainName";
    public static final String TYPE_RESOURCE_NAME    = "ResourceName";
    public static final String TYPE_ROLE             = "Role";
    public static final String TYPE_POLICY           = "Policy";
    public static final String TYPE_SERVICE_IDENTITY = "ServiceIdentity";
}
