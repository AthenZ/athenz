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
package com.yahoo.athenz.zts;

/**
 * Contains constants shared by classes throughout the service.
 **/
public final class ZTSConsts {
    // System property names with defaults(where applicable)

    public static final String ZTS_PROP_USER_DOMAIN_ALIAS = "athenz.user_domain_alias";
    public static final String ZTS_PROP_HTTP_PORT         = "athenz.port";
    public static final String ZTS_PROP_HTTPS_PORT        = "athenz.tls_port";
    public static final String ZTS_PROP_OIDC_PORT         = "athenz.oidc_port";
    public static final String ZTS_PROP_STATUS_PORT       = "athenz.status_port";

    public static final String ZTS_PROP_ROOT_DIR    = "athenz.zts.root_dir";
    public static final String ZTS_PROP_HOSTNAME    = "athenz.zts.hostname";

    public static final String ZTS_PROP_KEYSTORE_PASSWORD           = "athenz.zts.ssl_key_store_password";
    public static final String ZTS_PROP_KEYSTORE_PASSWORD_APPNAME   = "athenz.zts.ssl_key_store_password_appname";
    public static final String ZTS_PROP_KEYMANAGER_PASSWORD         = "athenz.zts.ssl_key_manager_password";
    public static final String ZTS_PROP_KEYMANAGER_PASSWORD_APPNAME = "athenz.zts.ssl_key_manager_password_appname";
    public static final String ZTS_PROP_TRUSTSTORE_PASSWORD         = "athenz.zts.ssl_trust_store_password";
    public static final String ZTS_PROP_TRUSTSTORE_PASSWORD_APPNAME = "athenz.zts.ssl_trust_store_password_appname";

    public static final String ZTS_PROP_KEYSTORE_PATH          = "athenz.zts.ssl_key_store";
    public static final String ZTS_PROP_KEYSTORE_TYPE          = "athenz.zts.ssl_key_store_type";
    public static final String ZTS_PROP_TRUSTSTORE_PATH        = "athenz.zts.ssl_trust_store";
    public static final String ZTS_PROP_TRUSTSTORE_TYPE        = "athenz.zts.ssl_trust_store_type";
    public static final String ZTS_PROP_EXCLUDED_CIPHER_SUITES = "athenz.zts.ssl_excluded_cipher_suites";
    public static final String ZTS_PROP_EXCLUDED_PROTOCOLS     = "athenz.zts.ssl_excluded_protocols";
    public static final String ZTS_PROP_WANT_CLIENT_CERT       = "athenz.zts.want_client_cert";
    public static final String ZTS_PROP_AUTHORITY_CLASSES      = "athenz.zts.authority_classes";
    public static final String ZTS_PROP_CHANGE_LOG_STORE_DIR   = "athenz.zts.change_log_store_dir";
    public static final String ZTS_PROP_NOAUTH_URI_LIST        = "athenz.zts.no_auth_uri_list";
    public static final String ZTS_PROP_ROLE_COMPLETE_FLAG     = "athenz.zts.role_complete_flag";
    public static final String ZTS_PROP_READ_ONLY_MODE         = "athenz.zts.read_only_mode";
    public static final String ZTS_PROP_HEALTH_CHECK_PATH      = "athenz.zts.health_check_path";
    public static final String ZTS_PROP_SERVER_REGION          = "athenz.zts.server_region";
    public static final String ZTS_PROP_SPIFFE_TRUST_DOMAIN    = "athenz.zts.spiffe_trust_domain";

    public static final String ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT             = "athenz.zts.aws_creds_cache_timeout";
    public static final String ZTS_PROP_AWS_CREDS_INVALID_CACHE_TIMEOUT     = "athenz.zts.aws_creds_invalid_cache_timeout";
    public static final String ZTS_PROP_AWS_ENABLED                         = "athenz.zts.aws_enabled";
    public static final String ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT            = "athenz.zts.aws_creds_update_timeout";
    public static final String ZTS_PROP_AWS_ROLE_SESSION_NAME               = "athenz.zts.aws_role_session_name";

    public static final String ZTS_PROP_CERT_REFRESH_IP_FNAME  = "athenz.zts.cert_refresh_ip_fname";
    public static final String ZTS_PROP_CERT_ALLOWED_O_VALUES  = "athenz.zts.cert_allowed_o_values";
    public static final String ZTS_PROP_CERT_ALLOWED_OU_VALUES = "athenz.zts.cert_allowed_ou_values";
    public static final String ZTS_PROP_INSTANCE_CERT_IP_FNAME = "athenz.zts.instance_cert_ip_fname";
    public static final String ZTS_PROP_CERT_BUNDLES_FNAME     = "athenz.zts.cert_authority_bundles_fname";

    public static final String ZTS_PROP_OAUTH_ISSUER           = "athenz.zts.oauth_issuer";
    public static final String ZTS_PROP_OAUTH_OPENID_SCOPE     = "athenz.zts.oauth_openid_scope";
    public static final String ZTS_PROP_OPENID_ISSUER          = "athenz.zts.openid_issuer";
    public static final String ZTS_PROP_OIDC_PORT_ISSUER       = "athenz.zts.oidc_port_issuer";
    public static final String ZTS_PROP_REDIRECT_URI_SUFFIX    = "athenz.zts.redirect_uri_suffix";

    public static final String ZTS_PROP_CERTSIGN_BASE_URI            = "athenz.zts.certsign_base_uri";
    public static final String ZTS_PROP_CERTSIGN_REQUEST_TIMEOUT     = "athenz.zts.certsign_request_timeout";
    public static final String ZTS_PROP_CERTSIGN_CONNECT_TIMEOUT     = "athenz.zts.certsign_connect_timeout";
    public static final String ZTS_PROP_CERTSIGN_RETRY_COUNT         = "athenz.zts.certsign_retry_count";
    public static final String ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME     = "athenz.zts.certsign_max_expiry_time";
    public static final String ZTS_PROP_CERTSIGN_PROVIDER_KEYS_FNAME = "athenz.zts.certsign_provider_keys_fname";
    public static final String ZTS_PROP_CERTSIGN_RETRY_CONN_ONLY     = "athenz.zts.certsign_retry_conn_failures_only";
    public static final String ZTS_PROP_CERTSIGN_CONN_MAX_PER_ROUTE  = "athenz.zts.certsign_conn_max_per_route";
    public static final String ZTS_PROP_CERTSIGN_CONN_MAX_TOTAL      = "athenz.zts.certsign_conn_max_total";

    public static final String ZTS_PROP_LEAST_PRIVILEGE_PRINCIPLE  = "athenz.zts.least_privilege_principle";
    public static final String ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT     = "athenz.zts.role_token_max_timeout";
    public static final String ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT = "athenz.zts.role_token_default_timeout";
    public static final String ZTS_PROP_ID_TOKEN_MAX_TIMEOUT       = "athenz.zts.id_token_max_timeout";
    public static final String ZTS_PROP_ID_TOKEN_DEFAULT_TIMEOUT   = "athenz.zts.id_token_default_timeout";
    public static final String ZTS_PROP_ID_TOKEN_MAX_DOMAINS       = "athenz.zts.id_token_max_domains";
    public static final String ZTS_PROP_SIGNED_POLICY_TIMEOUT      = "athenz.zts.signed_policy_timeout";
    public static final String ZTS_PROP_AUTHORIZED_PROXY_USERS     = "athenz.zts.authorized_proxy_users";
    public static final String ZTS_PROP_SECURE_REQUESTS_ONLY       = "athenz.zts.secure_requests_only";
    public static final String ZTS_PROP_STATUS_CERT_SIGNER         = "athenz.zts.status_cert_signer";

    public static final String ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME    = "athenz.zts.self_signer_private_key_fname";
    public static final String ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD = "athenz.zts.self_signer_private_key_password";
    public static final String ZTS_PROP_SELF_SIGNER_CERT_DN              = "athenz.zts.self_signer_cert_dn";
    public static final String ZTS_PROP_CERT_REFRESH_VERIFY_HOSTNAMES    = "athenz.zts.cert_refresh_verify_hostnames";
    public static final String ZTS_PROP_CERT_REFRESH_RESET_TIME          = "athenz.zts.cert_refresh_reset_time";
    public static final String ZTS_PROP_CERT_REQUEST_VERIFY_IP           = "athenz.zts.cert_request_verify_ip";
    public static final String ZTS_PROP_CERT_REQUEST_VERIFY_SUBJECT_OU   = "athenz.zts.cert_request_verify_subject_ou";

    public static final String ZTS_PROP_CERT_JDBC_STORE                         = "athenz.zts.cert_jdbc_store";
    public static final String ZTS_PROP_CERT_JDBC_USER                          = "athenz.zts.cert_jdbc_user";
    public static final String ZTS_PROP_CERT_JDBC_PASSWORD                      = "athenz.zts.cert_jdbc_password";
    public static final String ZTS_PROP_CERT_JDBC_APP_NAME                      = "athenz.zts.cert_jdbc_app_name";
    public static final String ZTS_PROP_CERT_JDBC_VERIFY_SERVER_CERT            = "athenz.zts.cert_jdbc_verify_server_certificate";
    public static final String ZTS_PROP_CERT_JDBC_USE_SSL                       = "athenz.zts.cert_jdbc_use_ssl";
    public static final String ZTS_PROP_CERT_OP_TIMEOUT                         = "athenz.zts.cert_op_timeout";
    public static final String ZTS_PROP_CERT_DNS_SUFFIX                         = "athenz.zts.cert_dns_suffix";
    public static final String ZTS_PROP_CERT_FILE_STORE_PATH                    = "athenz.zts.cert_file_store_path";
    public static final String ZTS_PROP_CERT_FILE_STORE_NAME                    = "athenz.zts.cert_file_store_name";
    public static final String ZTS_PROP_CERT_DYNAMODB_TABLE_NAME                = "athenz.zts.cert_dynamodb_table_name";
    public static final String ZTS_PROP_CERT_DYNAMODB_ITEM_TTL_HOURS            = "athenz.zts.cert_dynamodb_item_ttl_hours";
    public static final String ZTS_PROP_CERT_DYNAMODB_INDEX_CURRENT_TIME_NAME   = "athenz.zts.cert_dynamodb_index_current_time_name";
    public static final String ZTS_PROP_CERT_DYNAMODB_INDEX_HOST_NAME           = "athenz.zts.cert_dynamodb_index_host_name";
    public static final String ZTS_PROP_CERT_DYNAMODB_RETRIES                   = "athenz.zts.cert_dynamodb_retries";
    public static final String ZTS_PROP_CERT_DYNAMODB_RETRIES_SLEEP_MILLIS      = "athenz.zts.cert_dynamodb_retries_sleep_millis";

    public static final String ZTS_PROP_DYNAMODB_KEY_PATH            = "athenz.zts.dynamodb_key_path";
    public static final String ZTS_PROP_DYNAMODB_CERT_PATH           = "athenz.zts.dynamodb_cert_path";
    public static final String ZTS_PROP_DYNAMODB_DOMAIN              = "athenz.zts.dynamodb_aws_domain";
    public static final String ZTS_PROP_DYNAMODB_ROLE                = "athenz.zts.dynamodb_aws_role";
    public static final String ZTS_PROP_DYNAMODB_TRUSTSTORE          = "athenz.zts.dynamodb_trust_store_path";
    public static final String ZTS_PROP_DYNAMODB_TRUSTSTORE_PASSWORD = "athenz.zts.dynamodb_trust_store_password";
    public static final String ZTS_PROP_DYNAMODB_TRUSTSTORE_APPNAME  = "athenz.zts.dynamodb_trust_store_app_name";
    public static final String ZTS_PROP_DYNAMODB_REGION              = "athenz.zts.dynamodb_region";
    public static final String ZTS_PROP_DYNAMODB_ZTS_URL             = "athenz.zts.dynamodb_zts_url";
    public static final String ZTS_PROP_DYNAMODB_EXTERNAL_ID         = "athenz.zts.dynamodb_external_id";
    public static final String ZTS_PROP_DYNAMODB_MIN_EXPIRY_TIME     = "athenz.zts.dynamodb_min_expiry_time";
    public static final String ZTS_PROP_DYNAMODB_MAX_EXPIRY_TIME     = "athenz.zts.dynamodb_max_expiry_time";

    public static final String ZTS_PROP_SSH_JDBC_STORE               = "athenz.zts.ssh_jdbc_store";
    public static final String ZTS_PROP_SSH_JDBC_USER                = "athenz.zts.ssh_jdbc_user";
    public static final String ZTS_PROP_SSH_JDBC_PASSWORD            = "athenz.zts.ssh_jdbc_password";
    public static final String ZTS_PROP_SSH_JDBC_APP_NAME            = "athenz.zts.ssh_jdbc_app_name";
    public static final String ZTS_PROP_SSH_JDBC_USE_SSL             = "athenz.zts.ssh_jdbc_use_ssl";
    public static final String ZTS_PROP_SSH_JDBC_VERIFY_SERVER_CERT  = "athenz.zts.ssh_jdbc_verify_server_certificate";
    public static final String ZTS_PROP_SSH_FILE_STORE_PATH          = "athenz.zts.ssh_file_store_path";
    public static final String ZTS_PROP_SSH_FILE_STORE_NAME          = "athenz.zts.ssh_file_store_name";
    public static final String ZTS_PROP_SSH_DYNAMODB_TABLE_NAME      = "athenz.zts.ssh_dynamodb_table_name";
    public static final String ZTS_PROP_SSH_DYNAMODB_ITEM_TTL_HOURS  = "athenz.zts.ssh_dynamodb_item_ttl_hours";
    public static final String ZTS_PROP_SSH_OP_TIMEOUT               = "athenz.zts.ssh_op_timeout";
    public static final String ZTS_PROP_SSH_CERT_VALIDATE_IP         = "athenz.zts.ssh_cert_validate_ip";

    public static final String ZTS_PROP_WORKLOAD_JDBC_STORE               = "athenz.zts.workload_jdbc_store";
    public static final String ZTS_PROP_WORKLOAD_JDBC_USER                = "athenz.zts.workload_jdbc_user";
    public static final String ZTS_PROP_WORKLOAD_JDBC_PASSWORD            = "athenz.zts.workload_jdbc_password";
    public static final String ZTS_PROP_WORKLOAD_JDBC_APP_NAME            = "athenz.zts.workload_jdbc_app_name";
    public static final String ZTS_PROP_WORKLOAD_JDBC_USE_SSL             = "athenz.zts.workload_jdbc_use_ssl";
    public static final String ZTS_PROP_WORKLOAD_JDBC_VERIFY_SERVER_CERT  = "athenz.zts.workload_jdbc_verify_server_certificate";
    public static final String ZTS_PROP_WORKLOAD_FILE_STORE_PATH          = "athenz.zts.workload_file_store_path";
    public static final String ZTS_PROP_WORKLOAD_FILE_STORE_NAME          = "athenz.zts.workload_file_store_name";
    public static final String ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME      = "athenz.zts.workload_dynamodb_table_name";
    public static final String ZTS_PROP_WORKLOAD_DYNAMODB_ITEM_TTL_HOURS  = "athenz.zts.workload_dynamodb_item_ttl_hours";
    public static final String ZTS_PROP_WORKLOAD_OP_TIMEOUT               = "athenz.zts.workload_op_timeout";
    public static final String ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME   = "athenz.zts.workload_dynamodb_index_service_name";
    public static final String ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME   = "athenz.zts.workload_dynamodb_index_ip_name";
    public static final String ZTS_PROP_WORKLOAD_ENABLE_STORE_FEATURE     = "athenz.zts.workload_enable_store_feature";
    public static final String ZTS_PROP_SYSTEM_AUTHZ_DETAILS_PATH         = "athenz.zts.system_authz_details_path";

    public static final String ZTS_PROP_PROVIDER_ENDPOINTS      = "athenz.zts.provider_endpoints";
    public static final String ZTS_PROP_INSTANCE_NTOKEN_TIMEOUT = "athenz.zts.instance_token_timeout";
    public static final String ZTS_PROP_X509_CA_CERT_FNAME      = "athenz.zts.x509_ca_cert_fname";
    public static final String ZTS_PROP_SSH_HOST_CA_CERT_FNAME  = "athenz.zts.ssh_host_ca_cert_fname";
    public static final String ZTS_PROP_SSH_USER_CA_CERT_FNAME  = "athenz.zts.ssh_user_ca_cert_fname";
    public static final String ZTS_PROP_RESP_X509_SIGNER_CERTS  = "athenz.zts.resp_x509_signer_certs";
    public static final String ZTS_PROP_RESP_SSH_SIGNER_CERTS   = "athenz.zts.resp_ssh_signer_certs";

    public static final String DB_PROP_USER               = "user";
    public static final String DB_PROP_PASSWORD           = "password";
    public static final String DB_PROP_USE_SSL            = "useSSL";
    public static final String DB_PROP_VERIFY_SERVER_CERT = "verifyServerCertificate";

    public static final String ZTS_PROP_AWS_RDS_USER               = "athenz.zts.aws_rds_user";
    public static final String ZTS_PROP_AWS_RDS_IAM_ROLE           = "athenz.zts.aws_rds_iam_role";
    public static final String ZTS_PROP_AWS_RDS_ENGINE             = "athenz.zts.aws_rds_engine";
    public static final String ZTS_PROP_AWS_RDS_DATABASE           = "athenz.zts.aws_rds_database";
    public static final String ZTS_PROP_AWS_RDS_MASTER_INSTANCE    = "athenz.zts.aws_rds_master_instance";
    public static final String ZTS_PROP_AWS_RDS_MASTER_PORT        = "athenz.zts.aws_rds_master_port";
    public static final String ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME = "athenz.zts.aws_rds_creds_refresh_time";

    public static final String ZTS_SERVICE           = "zts";
    public static final String ZTS_UNKNOWN_DOMAIN    = "unknown_domain";

    public static final int ZTS_HTTPS_PORT_DEFAULT   = 4443;
    public static final int ZTS_HTTP_PORT_DEFAULT    = 4080;

    public static final String ATHENZ_USER_DOMAIN    = "user";
    public static final String ATHENZ_ROOT_DIR       = "/home/athenz";

    public static final String ZTS_SSH_HOST = "host";
    public static final String ZTS_SSH_USER = "user";
    public static final String ZTS_SSH_TYPE = "certtype";

    public static final String ZTS_CERT_DNS_SUFFIX   = ".athenz.cloud";
    public static final String ZTS_RESOURCE_DNS      = "sys.auth:dns.";

    public static final String ZTS_CERT_INSTANCE_ID_DNS  = ".instanceid.athenz.";
    public static final String ZTS_CERT_INSTANCE_ID_URI  = "athenz://instanceid/";
    public static final String ZTS_CERT_HOSTNAME_URI     = "athenz://hostname/";
    public static final String ZTS_CERT_PRINCIPAL_URI    = "athenz://principal/";
    public static final String ZTS_CERT_SPIFFE_URI       = "spiffe://";
    public static final String ZTS_CERT_PROXY_USER_URI   = "athenz://proxyuser/";

    public static final String RSA   = "RSA";
    public static final String EC    = "EC";
    public static final String ECDSA = "ECDSA";
    public static final String JSON  = "json";

    public static final String ZTS_PROP_METRIC_FACTORY_CLASS             = "athenz.zts.metric_factory_class";
    public static final String ZTS_PROP_CERT_SIGNER_FACTORY_CLASS        = "athenz.zts.cert_signer_factory_class";
    public static final String ZTS_PROP_SSH_SIGNER_FACTORY_CLASS         = "athenz.zts.ssh_signer_factory_class";
    public static final String ZTS_PROP_AUDIT_LOGGER_FACTORY_CLASS       = "athenz.zts.audit_logger_factory_class";
    public static final String ZTS_PROP_CHANGE_LOG_STORE_FACTORY_CLASS   = "athenz.zts.change_log_store_factory_class";
    public static final String ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS  = "athenz.zts.private_key_store_factory_class";
    public static final String ZTS_PROP_CERT_RECORD_STORE_FACTORY_CLASS  = "athenz.zts.cert_record_store_factory_class";
    public static final String ZTS_PROP_HOSTNAME_RESOLVER_FACTORY_CLASS  = "athenz.zts.hostname_resolver_factory_class";
    public static final String ZTS_PROP_SSH_RECORD_STORE_FACTORY_CLASS   = "athenz.zts.ssh_record_store_factory_class";
    public static final String ZTS_PROP_VALIDATE_SERVICE_SKIP_DOMAINS    = "athenz.zts.validate_service_skip_domains";
    public static final String ZTS_PROP_VALIDATE_SERVICE_IDENTITY        = "athenz.zts.validate_service_identity";
    public static final String ZTS_PROP_MAX_AUTHZ_DETAILS_LENGTH         = "athenz.zts.max_authz_details_length";
    public static final String ZTS_PROP_WORKLOAD_RECORD_STORE_FACTORY_CLASS   = "athenz.zts.workload_record_store_factory_class";

    public static final String ZTS_CHANGE_LOG_STORE_FACTORY_CLASS  = "com.yahoo.athenz.common.server.store.impl.ZMSFileChangeLogStoreFactory";
    public static final String ZTS_PKEY_STORE_FACTORY_CLASS        = "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";
    public static final String ZTS_CERT_SIGNER_FACTORY_CLASS       = "com.yahoo.athenz.zts.cert.impl.crypki.HttpCertSignerFactory";
    public static final String ZTS_AUDIT_LOGGER_FACTORY_CLASS      = "com.yahoo.athenz.common.server.log.impl.DefaultAuditLoggerFactory";
    public static final String ZTS_PRINCIPAL_AUTHORITY_CLASS       = "com.yahoo.athenz.auth.impl.PrincipalAuthority";
    public static final String ZTS_CERT_RECORD_STORE_FACTORY_CLASS = "com.yahoo.athenz.zts.cert.impl.FileCertRecordStoreFactory";

    public static final String ZTS_PROP_NOTIFICATION_CERT_FAIL_PROVIDER_LIST            = "athenz.zts.notification_cert_fail_provider_list";
    public static final String ZTS_PROP_NOTIFICATION_CERT_FAIL_IGNORED_SERVICES_LIST    = "athenz.zts.notification_cert_fail_ignored_services_list";
    public static final String ZTS_PROP_NOTIFICATION_GRACE_PERIOD_HOURS                 = "athenz.zts.notification_cert_fail_grace_hours";
    public static final String ZTS_PROP_ATHENZ_GUIDE                                    = "athenz.zts.notification_cert_fail_athenz_guide";

    public static final String ZTS_PROP_NOTIFICATION_AWS_HEALTH_DOMAIN                  = "athenz.zts.notification_aws_health_domain";
    public static final String ZTS_PROP_NOTIFICATION_API_HOSTNAME                       = "athenz.zts.notification_api_hostname";
    public static final String ZTS_PROP_JWK_UPDATE_INTERVAL_HOURS                       = "athenz.zts.jwk_update_interval_hours";
    public static final String ZTS_JSON_PARSER_ERROR_RESPONSE = "{\"code\":400,\"message\":\"Invalid Object: checkout https://github.com/AthenZ/athenz/tree/master/core/zts/src/main/rdl for object defintions\"}";

    public static final String ZTS_PROP_STATUS_CHECKER_FACTORY_CLASS = "athenz.zts.status_checker_factory_class";
    public static final String ZTS_PROP_USER_AUTHORITY_CLASS = "athenz.zts.user_authority_class";
    public static final String ZTS_ISSUE_ROLE_CERT_TAG = "zts.IssueRoleCerts";

    public static final String ZTS_PROP_CERT_PRIORITY_MIN_PERCENT_LOW_PRIORITY = "athenz.zts.cert_priority_min_percent_low_priority";
    public static final String ZTS_CERT_PRIORITY_MIN_PERCENT_LOW_PRIORITY_DEFAULT = "75";
    public static final String ZTS_PROP_CERT_PRIORITY_MAX_PERCENT_HIGH_PRIORITY = "athenz.zts.cert_priority_max_percent_high_priority";
    public static final String ZTS_CERT_PRIORITY_MAX_PERCENT_HIGH_PRIORITY_DEFAULT = "25";

    public static final String ZTS_OPENID_RESPONSE_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:";
    public static final String ZTS_OPENID_RESPONSE_AT_ONLY    = "token";
    public static final String ZTS_OPENID_RESPONSE_IT_ONLY    = "id_token";
    public static final String ZTS_OPENID_RESPONSE_BOTH_IT_AT = "id_token token";
    public static final String ZTS_OPENID_SUBJECT_TYPE_PUBLIC = "public";

    public static final String ZTS_PROP_JSON_MAX_NESTING_DEPTH = "athenz.zts.json_max_nesting_depth";
    public static final String ZTS_PROP_JSON_MAX_NUMBER_LENGTH = "athenz.zts.json_max_number_length";
    public static final String ZTS_PROP_JSON_MAX_STRING_LENGTH = "athenz.zts.json_max_string_length";

    public static final String ZTS_PROP_KEY_ALGO_JSON_WEB_OBJECTS    = "athenz.zts.key_algo_json_web_objects";
    public static final String ZTS_PROP_KEY_ALGO_PROPRIETARY_OBJECTS = "athenz.zts.key_algo_proprietary_objects";
    public static final String ZTS_PROP_KEY_ALGO_PLUGINS             = "athenz.zts.key_algo_plugins";

    public static final String ZTS_PROP_GCP_WORKLOAD_POOL_NAME     = "athenz.zts.gcp_workload_pool_name";
    public static final String ZTS_PROP_GCP_WORKLOAD_PROVIDER_NAME = "athenz.zts.gcp_workload_provider_name";

    public static final String ZTS_PROP_EXTERNAL_CREDS_PROVIDERS = "athenz.zts.external_creds_providers";
    public static final String ZTS_EXTERNAL_CREDS_PROVIDER_GCP   = "gcp";
    public static final String ZTS_EXTERNAL_CREDS_PROVIDER_AWS   = "aws";

    public static final String ZTS_EXTERNAL_ATTR_ROLE_NAME     = "athenzRoleName";
    public static final String ZTS_EXTERNAL_ATTR_SCOPE         = "athenzScope";
    public static final String ZTS_EXTERNAL_ATTR_FULL_ARN      = "athenzFullArn";
    public static final String ZTS_EXTERNAL_ATTR_ISSUER_OPTION = "athenzIssuerOption";

    public static final String ZTS_ISSUER_TYPE_OPENID    = "openid";
    public static final String ZTS_ISSUER_TYPE_OIDC_PORT = "oidc_port";
}
