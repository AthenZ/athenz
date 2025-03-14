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
package com.yahoo.athenz.common.server.store.impl;

/**
 * Contains constants shared by classes throughout the service.
 **/
public final class JDBCConsts {

    public static final String ZMS_PROP_JDBC_RW_STORE           = "athenz.zms.jdbc_store";
    public static final String ZMS_PROP_JDBC_RW_USER            = "athenz.zms.jdbc_user";
    public static final String ZMS_PROP_JDBC_RW_PASSWORD        = "athenz.zms.jdbc_password";
    public static final String ZMS_PROP_JDBC_RO_STORE           = "athenz.zms.jdbc_ro_store";
    public static final String ZMS_PROP_JDBC_RO_USER            = "athenz.zms.jdbc_ro_user";
    public static final String ZMS_PROP_JDBC_RO_PASSWORD        = "athenz.zms.jdbc_ro_password";
    public static final String ZMS_PROP_JDBC_APP_NAME           = "athenz.zms.jdbc_app_name";
    public static final String ZMS_PROP_JDBC_KEYGROUP_NAME      = "athenz.zms.jdbc_keygroup_name";
    public static final String ZMS_PROP_JDBC_VERIFY_SERVER_CERT = "athenz.zms.jdbc_verify_server_certificate";
    public static final String ZMS_PROP_JDBC_USE_SSL            = "athenz.zms.jdbc_use_ssl";
    public static final String ZMS_PROP_JDBC_TLS_VERSIONS       = "athenz.zms.jdbc_tls_versions";
    public static final String ZMS_PROP_JDBC_DRIVER_CLASS       = "athenz.db.driver.class";

    public static final String ZMS_PROP_MYSQL_SERVER_TIMEZONE = "athenz.zms.mysql_server_timezone";
    public static final String ZMS_PROP_MYSQL_SERVER_TRUST_ROLES_UPDATE_TIMEOUT = "athenz.zms.mysql_server_trust_roles_update_timeout";

    public static final int ZMS_DEFAULT_TAG_LIMIT   = 25;

    public static final String DB_COLUMN_DESCRIPTION        = "description";
    public static final String DB_COLUMN_ORG                = "org";
    public static final String DB_COLUMN_UUID               = "uuid";
    public static final String DB_COLUMN_ENABLED            = "enabled";
    public static final String DB_COLUMN_AUDIT_ENABLED      = "audit_enabled";
    public static final String DB_COLUMN_MODIFIED           = "modified";
    public static final String DB_COLUMN_NAME               = "name";
    public static final String DB_COLUMN_TYPE               = "type";
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
    public static final String DB_COLUMN_YPM_ID             = "ypm_id";
    public static final String DB_COLUMN_PRODUCT_ID         = "product_id";
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
    public static final String DB_COLUMN_DELETE_PROTECTION  = "delete_protection";
    public static final String DB_COLUMN_NOTIFY_ROLES       = "notify_roles";
    public static final String DB_COLUMN_LAST_REVIEWED_TIME = "last_reviewed_time";
    public static final String DB_COLUMN_REQ_PRINCIPAL      = "req_principal";
    public static final String DB_COLUMN_PENDING_STATE      = "pending_state";
    public static final String DB_COLUMN_MEMBER_REVIEW_DAYS = "member_review_days";
    public static final String DB_COLUMN_TEMPLATE_NAME      = "template";
    public static final String DB_COLUMN_TEMPLATE_VERSION   = "current_version";
    public static final String DB_COLUMN_AS_DOMAIN_NAME     = "domain_name";
    public static final String DB_COLUMN_AS_SERVICE_NAME    = "service_name";
    public static final String DB_COLUMN_AS_ROLE_NAME       = "role_name";
    public static final String DB_COLUMN_AS_GROUP_NAME      = "group_name";
    public static final String DB_COLUMN_AS_PRINCIPAL_NAME  = "principal_name";
    public static final String DB_COLUMN_SYSTEM_DISABLED    = "system_disabled";
    public static final String DB_COLUMN_AZURE_SUBSCRIPTION = "azure_subscription";
    public static final String DB_COLUMN_AZURE_TENANT       = "azure_tenant";
    public static final String DB_COLUMN_AZURE_CLIENT       = "azure_client";
    public static final String DB_COLUMN_GCP_PROJECT_ID     = "gcp_project";
    public static final String DB_COLUMN_GCP_PROJECT_NUMBER = "gcp_project_number";
    public static final String DB_COLUMN_BUSINESS_SERVICE   = "business_service";
    public static final String DB_COLUMN_ACTIVE             = "active";
    public static final String DB_COLUMN_VERSION            = "version";
    public static final String DB_COLUMN_POLICY_ID          = "policy_id";
    public static final String DB_COLUMN_FEATURE_FLAGS      = "feature_flags";
    public static final String DB_COLUMN_MAX_MEMBERS        = "max_members";
    public static final String DB_COLUMN_SELF_RENEW         = "self_renew";
    public static final String DB_COLUMN_SELF_RENEW_MINS    = "self_renew_mins";
    public static final String DB_COLUMN_ENVIRONMENT        = "environment";
    public static final String DB_COLUMN_RESOURCE_OWNER     = "resource_owner";
    public static final String DB_COLUMN_SYSTEM_SUSPENDED   = "system_suspended";
    public static final String DB_COLUMN_NOTIFY_DETAILS     = "notify_details";
    public static final String DB_COLUMN_CREDS              = "creds";

    public static final String DB_COLUMN_PRINCIPAL_DOMAIN_FILTER  = "principal_domain_filter";
    public static final String DB_COLUMN_SERVICE_REVIEW_DAYS      = "service_review_days";
    public static final String DB_COLUMN_SERVICE_EXPIRY_DAYS      = "service_expiry_days";
    public static final String DB_COLUMN_GROUP_EXPIRY_DAYS        = "group_expiry_days";
    public static final String DB_COLUMN_GROUP_REVIEW_DAYS        = "group_review_days";
    public static final String DB_COLUMN_ROLE_CERT_EXPIRY_MINS    = "role_cert_expiry_mins";
    public static final String DB_COLUMN_SERVICE_CERT_EXPIRY_MINS = "service_cert_expiry_mins";
    public static final String DB_COLUMN_PRINCIPAL_GROUP          = "principal_group";
    public static final String DB_COLUMN_PRINCIPAL_GROUP_MEMBER   = "principal_group_member";
    public static final String DB_COLUMN_MEMBER_PURGE_EXPIRY_DAYS = "member_purge_expiry_days";
    public static final String DB_COLUMN_X509_CERT_SIGNER_KEYID   = "x509_cert_signer_keyid";
    public static final String DB_COLUMN_SSH_CERT_SIGNER_KEYID    = "ssh_cert_signer_keyid";
    public static final String DB_COLUMN_SLACK_CHANNEL            = "slack_channel";

    public static final String DB_COLUMN_USER_AUTHORITY_FILTER           = "user_authority_filter";
    public static final String DB_COLUMN_USER_AUTHORITY_EXPIRATION       = "user_authority_expiration";
    public static final String DB_COLUMN_AS_DOMAIN_USER_AUTHORITY_FILTER = "domain_user_authority_filter";

    public static final String DB_COLUMN_KEY                       = "key";
    public static final String DB_COLUMN_OPERATOR                  = "operator";
    public static final String DB_COLUMN_CONDITION_ID              = "condition_id";

    public static final String ADMIN_POLICY_NAME = "admin";
    public static final String ADMIN_ROLE_NAME   = "admin";

    public static final String ASSERTION_EFFECT_ALLOW    = "ALLOW";

    public static final String OBJECT_DOMAIN    = "domain";
    public static final String OBJECT_ROLE      = "role";
    public static final String OBJECT_POLICY    = "policy";
    public static final String OBJECT_SERVICE   = "service";
    public static final String OBJECT_PRINCIPAL = "principal";
    public static final String OBJECT_HOST      = "host";
    public static final String OBJECT_GROUP     = "group";

    public static final String ZMS_PROP_JDBC_NOTIFY_DETAILS_SELF_SERVE_ROLE  = "athenz.zms.jdbc.notify_details_self_serve_role";
    public static final String ZMS_PROP_JDBC_NOTIFY_DETAILS_SELF_SERVE_GROUP = "athenz.zms.jdbc.notify_details_self_serve_group";

    public static final String NOTIFY_DETAILS_SELF_SERVE_ROLE = "self-serve role";
    public static final String NOTIFY_DETAILS_SELF_SERVE_GROUP = "self-serve group";

    //pending member
    public static final String PENDING_REQUEST_ADD_STATE = "ADD";
    public static final String PENDING_REQUEST_DELETE_STATE = "DELETE";
}
