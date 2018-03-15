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
    
    public static final String ZTS_PROP_USER_DOMAIN       = "athenz.user_domain";
    public static final String ZTS_PROP_USER_DOMAIN_ALIAS = "athenz.user_domain_alias";
    public static final String ZTS_PROP_ATHENZ_CONF       = "athenz.athenz_conf";
    public static final String ZTS_PROP_HTTP_PORT         = "athenz.port";
    public static final String ZTS_PROP_HTTPS_PORT        = "athenz.tls_port";
    public static final String ZTS_PROP_STATUS_PORT       = "athenz.status_port";
    
    public static final String ZTS_PROP_HOSTNAME    = "athenz.zts.hostname";
    public static final String ZTS_PROP_FILE_NAME   = "athenz.zts.prop_file";
    
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
    public static final String ZTS_PROP_ZMS_URL_OVERRIDE       = "athenz.zts.zms_url";
    public static final String ZTS_PROP_CHANGE_LOG_STORE_DIR   = "athenz.zts.change_log_store_dir";
    public static final String ZTS_PROP_NOAUTH_URI_LIST        = "athenz.zts.no_auth_uri_list";
    public static final String ZTS_PROP_ROLE_COMPLETE_FLAG     = "athenz.zts.role_complete_flag";
    
    public static final String ZTS_PROP_CERT_REFRESH_IP_FNAME  = "athenz.zts.cert_refresh_ip_fname";
    public static final String ZTS_PROP_INSTANCE_CERT_IP_FNAME = "athenz.zts.instance_cert_ip_fname";
    
    public static final String ZTS_PROP_CERTSIGN_BASE_URI        = "athenz.zts.certsign_base_uri";
    public static final String ZTS_PROP_CERTSIGN_REQUEST_TIMEOUT = "athenz.zts.certsign_request_timeout";
    public static final String ZTS_PROP_CERTSIGN_CONNECT_TIMEOUT = "athenz.zts.certsign_connect_timeout";
    public static final String ZTS_PROP_CERTSIGN_RETRY_COUNT     = "athenz.zts.certsign_retry_count";
    public static final String ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME = "athenz.zts.certsign_max_expiry_time";
    
    public static final String ZTS_PROP_LEAST_PRIVILEGE_PRINCIPLE  = "athenz.zts.least_privilege_principle";
    public static final String ZTS_PROP_ROLE_TOKEN_MAX_TIMEOUT     = "athenz.zts.role_token_max_timeout";
    public static final String ZTS_PROP_ROLE_TOKEN_DEFAULT_TIMEOUT = "athenz.zts.role_token_default_timeout";
    public static final String ZTS_PROP_SIGNED_POLICY_TIMEOUT      = "athenz.zts.signed_policy_timeout";
    public static final String ZTS_PROP_AUTHORIZED_PROXY_USERS     = "athenz.zts.authorized_proxy_users";
    public static final String ZTS_PROP_SECURE_REQUESTS_ONLY       = "athenz.zts.secure_requests_only";
    public static final String ZTS_PROP_STATUS_CERT_SIGNER         = "athenz.zts.status_cert_signer";

    public static final String ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_FNAME    = "athenz.zts.self_signer_private_key_fname";
    public static final String ZTS_PROP_SELF_SIGNER_PRIVATE_KEY_PASSWORD = "athenz.zts.self_signer_private_key_password";
    public static final String ZTS_PROP_SELF_SIGNER_CERT_DN              = "athenz.zts.self_signer_cert_dn";
    public static final String ZTS_PROP_OSTK_HOST_SIGNER_SERVICE         = "athenz.zts.ostk_host_signer_service";
    
    public static final String ZTS_PROP_CERT_JDBC_STORE         = "athenz.zts.cert_jdbc_store";
    public static final String ZTS_PROP_CERT_JDBC_USER          = "athenz.zts.cert_jdbc_user";
    public static final String ZTS_PROP_CERT_JDBC_PASSWORD      = "athenz.zts.cert_jdbc_password";
    public static final String ZTS_PROP_CERT_OP_TIMEOUT         = "athenz.zts.cert_op_timeout";
    public static final String ZTS_PROP_CERT_DNS_SUFFIX         = "athenz.zts.cert_dns_suffix";
    public static final String ZTS_PROP_PROVIDER_ENDPOINTS      = "athenz.zts.provider_endpoints";
    public static final String ZTS_PROP_CERT_FILE_STORE_PATH    = "athenz.zts.cert_file_store_path";
    public static final String ZTS_PROP_CERT_FILE_STORE_NAME    = "athenz.zts.cert_file_store_name";
    public static final String ZTS_PROP_INSTANCE_NTOKEN_TIMEOUT = "athenz.zts.instance_token_timeout";
    
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
    
    public static final String ATHENZ_SYS_DOMAIN     = "sys.auth";
    public static final String ATHENZ_USER_DOMAIN    = "user";
    public static final String ATHENZ_ROOT_DIR       = "/home/athenz";
    public static final String ATHENZ_ENV_ROOT_DIR   = "ROOT";
    
    public static final String ZTS_SSH_HOST = "host";
    public static final String ZTS_SSH_USER = "user";
    public static final String ZTS_SSH_TYPE = "certtype";
    
    public static final String ZTS_CERT_USAGE        = "certUsage";
    public static final String ZTS_CERT_EXPIRY_TIME  = "certExpiryTime";
    public static final String ZTS_CERT_REFRESH      = "certRefresh";
    
    public static final String ZTS_CERT_USAGE_CLIENT = "client";
    public static final String ZTS_CERT_USAGE_SERVER = "server";
    
    public static final String ZTS_CERT_INSTANCE_ID  = ".instanceid.athenz.";
    public static final String ZTS_CERT_DNS_SUFFIX   = ".athenz.cloud";
    public static final String ZTS_ACTION_LAUNCH     = "launch";
    public static final String ZTS_RESOURCE_INSTANCE = "sys.auth:instance";
    public static final String ZTS_RESOURCE_DNS      = "sys.auth:dns.";
    
    public static final String ZTS_INSTANCE_SAN_DNS       = "sanDNS";
    public static final String ZTS_INSTANCE_SAN_IP        = "sanIP";
    public static final String ZTS_INSTANCE_CLIENT_IP     = "clientIP";
    public static final String ZTS_INSTANCE_CLOUD_ACCOUNT = "cloudAccount";
    
    public static final String ZTS_PROP_AWS_ENABLED              = "athenz.zts.aws_enabled";
    public static final String ZTS_PROP_AWS_BUCKET_NAME          = "athenz.zts.aws_bucket_name";
    public static final String ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT = "athenz.zts.aws_creds_update_timeout";
    public static final String ZTS_PROP_AWS_REGION_NAME          = "athenz.zts.aws_region_name";
    public static final String ZTS_PROP_AWS_PUBLIC_CERT          = "athenz.zts.aws_public_cert";
    public static final String ZTS_PROP_AWS_BOOT_TIME_OFFSET     = "athenz.zts.aws_boot_time_offset";

    public static final String ZTS_PROP_METRIC_FACTORY_CLASS             = "athenz.zts.metric_factory_class";
    public static final String ZTS_PROP_CERT_SIGNER_FACTORY_CLASS        = "athenz.zts.cert_signer_factory_class";
    public static final String ZTS_PROP_AUDIT_LOGGER_FACTORY_CLASS       = "athenz.zts.audit_logger_factory_class";
    public static final String ZTS_PROP_CHANGE_LOG_STORE_FACTORY_CLASS   = "athenz.zts.change_log_store_factory_class";
    public static final String ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS  = "athenz.zts.private_key_store_factory_class";
    public static final String ZTS_PROP_CERT_RECORD_STORE_FACTORY_CLASS  = "athenz.zts.cert_record_store_factory_class";
    
    public static final String ZTS_METRIC_FACTORY_CLASS            = "com.yahoo.athenz.common.metrics.impl.NoOpMetricFactory";
    public static final String ZTS_CHANGE_LOG_STORE_FACTORY_CLASS  = "com.yahoo.athenz.zts.store.impl.ZMSFileChangeLogStoreFactory";
    public static final String ZTS_PKEY_STORE_FACTORY_CLASS        = "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";
    public static final String ZTS_CERT_SIGNER_FACTORY_CLASS       = "com.yahoo.athenz.zts.cert.impl.HttpCertSignerFactory";
    public static final String ZTS_AUDIT_LOGGER_FACTORY_CLASS      = "com.yahoo.athenz.common.server.log.impl.DefaultAuditLoggerFactory";
    public static final String ZTS_PRINCIPAL_AUTHORITY_CLASS       = "com.yahoo.athenz.auth.impl.PrincipalAuthority";
    public static final String ZTS_CERT_RECORD_STORE_FACTORY_CLASS = "com.yahoo.athenz.zts.cert.impl.FileCertRecordStoreFactory";
    
    
}
