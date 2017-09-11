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
    public static final String ZMS_PROP_USER_DOMAIN       = "athenz.user_domain";
    public static final String ZMS_PROP_HOME_DOMAIN       = "athenz.home_domain";
    public static final String ZMS_PROP_USER_DOMAIN_ALIAS = "athenz.user_domain_alias";

    public static final String ZMS_PROP_HOSTNAME      = "athenz.zms.hostname";
    public static final String ZMS_PROP_DOMAIN_ADMIN  = "athenz.zms.domain_admin";
    public static final String ZMS_PROP_FILE_NAME     = "athenz.zms.prop_file";
    
    public static final String ZMS_PROP_VIRTUAL_DOMAIN       = "athenz.zms.virtual_domain_support";
    public static final String ZMS_PROP_VIRTUAL_DOMAIN_LIMIT = "athenz.zms.virtual_domain_limit";
    public static final String ZMS_PROP_READ_ONLY_MODE       = "athenz.zms.read_only_mode";
    public static final String ZMS_PROP_DOMAIN_NAME_MAX_SIZE = "athenz.zms.domain_name_max_len";
    
    public static final String ZMS_PROP_CONFLICT_RETRY_COUNT      = "athenz.zms.request_conflict_retry_count";
    public static final String ZMS_PROP_CONFLICT_RETRY_SLEEP_TIME = "athenz.zms.request_conflict_retry_sleep_time";

    public static final String ZMS_PROP_JDBC_RW_STORE     = "athenz.zms.jdbc_store";
    public static final String ZMS_PROP_JDBC_RW_USER      = "athenz.zms.jdbc_user";
    public static final String ZMS_PROP_JDBC_RW_PASSWORD  = "athenz.zms.jdbc_password";
    public static final String ZMS_PROP_JDBC_RO_STORE     = "athenz.zms.jdbc_ro_store";
    public static final String ZMS_PROP_JDBC_RO_USER      = "athenz.zms.jdbc_ro_user";
    public static final String ZMS_PROP_JDBC_RO_PASSWORD  = "athenz.zms.jdbc_ro_password";
    public static final String ZMS_PROP_FILE_STORE_NAME   = "athenz.zms.file_store_name";
    public static final String ZMS_PROP_FILE_STORE_QUOTA  = "athenz.zms.file_store_quota";
    public static final String ZMS_PROP_FILE_STORE_PATH   = "athenz.zms.file_store_path";
    public static final String ZMS_PROP_MAX_THREADS       = "athenz.zms.http_max_threads";
    public static final String ZMS_PROP_AUTHORITY_CLASSES = "athenz.zms.authority_classes";
    public static final String ZMS_PROP_STORE_OP_TIMEOUT  = "athenz.zms.store_operation_timeout";
    
    public static final String ZMS_PROP_AWS_RDS_USER               = "athenz.zms.aws_rds_user";
    public static final String ZMS_PROP_AWS_RDS_IAM_ROLE           = "athenz.zms.aws_rds_iam_role";
    public static final String ZMS_PROP_AWS_RDS_ENGINE             = "athenz.zms.aws_rds_engine";
    public static final String ZMS_PROP_AWS_RDS_DATABASE           = "athenz.zms.aws_rds_database";
    public static final String ZMS_PROP_AWS_RDS_MASTER_INSTANCE    = "athenz.zms.aws_rds_master_instance";
    public static final String ZMS_PROP_AWS_RDS_MASTER_PORT        = "athenz.zms.aws_rds_master_port";
    public static final String ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME = "athenz.zms.aws_rds_creds_refresh_time";

    public static final String ZMS_PROP_USER_AUTHORITY_CLASS      = "athenz.zms.user_authority_class";
    public static final String ZMS_PROP_PRINCIPAL_AUTHORITY_CLASS = "athenz.zms.principal_authority_class";

    public static final String ZMS_PROP_TIMEOUT                 = "athenz.zms.user_token_timeout";
    public static final String ZMS_PROP_SIGNED_POLICY_TIMEOUT   = "athenz.zms.signed_policy_timeout";
    public static final String ZMS_PROP_AUTHZ_SERVICE_FNAME     = "athenz.zms.authz_service_fname";
    public static final String ZMS_PROP_SOLUTION_TEMPLATE_FNAME = "athenz.zms.solution_templates_fname";
    public static final String ZMS_PROP_PROVIDER_ENDPOINTS      = "athenz.zms.provider_endpoints";
    public static final String ZMS_PROP_PRODUCT_ID_SUPPORT      = "athenz.zms.product_id_support";
    public static final String ZMS_PROP_SECURE_REQUESTS_ONLY    = "athenz.zms.secure_requests_only";
    
    // properties used to over-ride default Audit logger
 
    public static final String ZMS_PROP_METRIC_FACTORY_CLASS            = "athenz.zms.metric_factory_class";
    public static final String ZMS_METRIC_FACTORY_CLASS                 = "com.yahoo.athenz.common.metrics.impl.NoOpMetricFactory";

    public static final String ZMS_PROP_AUDIT_LOGGER_FACTORY_CLASS      = "athenz.zms.audit_logger_factory_class";
    public static final String ZMS_AUDIT_LOGGER_FACTORY_CLASS           = "com.yahoo.athenz.common.server.log.impl.DefaultAuditLoggerFactory";

    public static final String ZMS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS = "athenz.zms.private_key_store_factory_class";
    public static final String ZMS_PRIVATE_KEY_STORE_FACTORY_CLASS      = "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";

    public static final String ZMS_PROP_OBJECT_STORE_FACTORY_CLASS      = "athenz.zms.object_store_factory_class";
    public static final String ZMS_OBJECT_STORE_FACTORY_CLASS           = "com.yahoo.athenz.zms.store.impl.FileObjectStoreFactory";

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
    
    public static final String ZMS_PRINCIPAL_AUTHORITY_CLASS  = "com.yahoo.athenz.auth.impl.PrincipalAuthority";

    public static final String ZMS_UNKNOWN_DOMAIN     = "unknown_domain";
    public static final String ZMS_INVALID_DOMAIN     = "invalid_domain";
    public static final String ZMS_SERVICE            = "zms";
    
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
    public static final String SCHEME_HTTP  = "http";
    public static final String SCHEME_HTTPS = "https";
    public static final String SCHEME_CLASS = "class";
    
    public static final String DB_COLUMN_DESCRIPTION       = "description";
    public static final String DB_COLUMN_ORG               = "org";
    public static final String DB_COLUMN_UUID              = "uuid";
    public static final String DB_COLUMN_ENABLED           = "enabled";
    public static final String DB_COLUMN_AUDIT_ENABLED     = "audit_enabled";
    public static final String DB_COLUMN_MODIFIED          = "modified";
    public static final String DB_COLUMN_NAME              = "name";
    public static final String DB_COLUMN_TRUST             = "trust";
    public static final String DB_COLUMN_MEMBER            = "member";
    public static final String DB_COLUMN_ENTITY            = "entity";
    public static final String DB_COLUMN_SUBDOMAIN         = "subdomain";
    public static final String DB_COLUMN_ROLE              = "role";
    public static final String DB_COLUMN_ROLE_MEMBER       = "role_member";
    public static final String DB_COLUMN_POLICY            = "policy";
    public static final String DB_COLUMN_SERVICE           = "service";
    public static final String DB_COLUMN_SERVICE_HOST      = "service_host";
    public static final String DB_COLUMN_PUBLIC_KEY        = "public_key";
    public static final String DB_COLUMN_ASSERTION         = "assertion";
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

