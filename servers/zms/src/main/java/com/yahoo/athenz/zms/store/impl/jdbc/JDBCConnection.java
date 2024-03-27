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
package com.yahoo.athenz.zms.store.impl.jdbc;

import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import com.yahoo.athenz.zms.utils.ResourceOwnership;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.UUID;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static com.yahoo.athenz.zms.ZMSConsts.*;

public class JDBCConnection implements ObjectStoreConnection {

    private static final Logger LOG = LoggerFactory.getLogger(JDBCConnection.class);

    private static final int MYSQL_ER_OPTION_PREVENTS_STATEMENT = 1290;
    private static final int MYSQL_ER_OPTION_DUPLICATE_ENTRY = 1062;

    private static final String MYSQL_EXC_STATE_DEADLOCK   = "40001";
    private static final String MYSQL_EXC_STATE_COMM_ERROR = "08S01";

    private static final String SQL_TABLE_DOMAIN = "domain";
    private static final String SQL_TABLE_ROLE = "role";
    private static final String SQL_TABLE_ROLE_MEMBER = "role_member";
    private static final String SQL_TABLE_POLICY = "policy";
    private static final String SQL_TABLE_ASSERTION = "assertion";
    private static final String SQL_TABLE_PRINCIPAL_GROUP = "principal_group";
    private static final String SQL_TABLE_PRINCIPAL_GROUP_MEMBER = "principal_group_member";
    private static final String SQL_TABLE_SERVICE = "service";
    private static final String SQL_TABLE_PUBLIC_KEY = "public_key";
    private static final String SQL_TABLE_SERVICE_HOST = "service_host";
    private static final String SQL_TABLE_ENTITY = "entity";

    private static final String SQL_DELETE_DOMAIN = "DELETE FROM domain WHERE name=?;";
    private static final String SQL_GET_DOMAIN = "SELECT * FROM domain WHERE name=?;";
    private static final String SQL_GET_DOMAIN_ID = "SELECT domain_id FROM domain WHERE name=?;";
    private static final String SQL_GET_ACTIVE_DOMAIN_ID = "SELECT domain_id FROM domain WHERE name=? AND enabled=true;";
    private static final String SQL_GET_DOMAINS_WITH_NAME = "SELECT name FROM domain WHERE name LIKE ?;";
    private static final String SQL_GET_DOMAIN_WITH_AWS_ACCOUNT = "SELECT name FROM domain WHERE account=?;";
    private static final String SQL_GET_DOMAIN_WITH_AZURE_SUBSCRIPTION = "SELECT name FROM domain WHERE azure_subscription=?;";
    private static final String SQL_GET_DOMAIN_WITH_GCP_PROJECT = "SELECT name FROM domain WHERE gcp_project=?;";
    private static final String SQL_LIST_DOMAINS_WITH_AWS_ACCOUNT = "SELECT name, account FROM domain WHERE account!='';";
    private static final String SQL_LIST_DOMAINS_WITH_AZURE_SUBSCRIPTION = "SELECT name, azure_subscription FROM domain WHERE azure_subscription!='';";
    private static final String SQL_LIST_DOMAINS_WITH_GCP_PROJECT = "SELECT name, gcp_project FROM domain WHERE gcp_project!='';";
    private static final String SQL_GET_DOMAIN_WITH_YPM_ID = "SELECT name FROM domain WHERE ypm_id=?;";
    private static final String SQL_GET_DOMAIN_WITH_PRODUCT_ID = "SELECT name FROM domain WHERE product_id=?;";
    private static final String SQL_LIST_DOMAIN_WITH_BUSINESS_SERVICE = "SELECT name FROM domain WHERE business_service=?;";
    private static final String SQL_INSERT_DOMAIN = "INSERT INTO domain "
            + "(name, description, org, uuid, enabled, audit_enabled, account, ypm_id, application_id, cert_dns_domain,"
            + " member_expiry_days, token_expiry_mins, service_cert_expiry_mins, role_cert_expiry_mins, sign_algorithm,"
            + " service_expiry_days, user_authority_filter, group_expiry_days, azure_subscription, business_service,"
            + " member_purge_expiry_days, gcp_project, gcp_project_number, product_id, feature_flags, environment)"
            + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_DOMAIN = "UPDATE domain "
            + "SET description=?, org=?, uuid=?, enabled=?, audit_enabled=?, account=?, ypm_id=?, application_id=?,"
            + " cert_dns_domain=?, member_expiry_days=?, token_expiry_mins=?, service_cert_expiry_mins=?,"
            + " role_cert_expiry_mins=?, sign_algorithm=?, service_expiry_days=?, user_authority_filter=?,"
            + " group_expiry_days=?, azure_subscription=?, business_service=?, member_purge_expiry_days=?,"
            + " gcp_project=?, gcp_project_number=?, product_id=?, feature_flags=?, environment=? WHERE name=?;";
    private static final String SQL_UPDATE_DOMAIN_MOD_TIMESTAMP = "UPDATE domain "
            + "SET modified=CURRENT_TIMESTAMP(3) WHERE name=?;";
    private static final String SQL_GET_DOMAIN_MOD_TIMESTAMP = "SELECT modified FROM domain WHERE name=?;";
    private static final String SQL_LIST_DOMAIN = "SELECT * FROM domain;";
    private static final String SQL_LIST_DOMAIN_PREFIX = "SELECT name, modified, enabled FROM domain WHERE name>=? AND name<?;";
    private static final String SQL_LIST_DOMAIN_MODIFIED = "SELECT * FROM domain WHERE modified>?;";
    private static final String SQL_LIST_DOMAIN_PREFIX_MODIFIED = "SELECT name, modified, enabled FROM domain "
            + "WHERE name>=? AND name<? AND modified>?;";
    private static final String SQL_LIST_DOMAIN_ROLE_NAME_MEMBER = "SELECT domain.name FROM domain "
            + "JOIN role ON role.domain_id=domain.domain_id "
            + "JOIN role_member ON role_member.role_id=role.role_id "
            + "JOIN principal ON principal.principal_id=role_member.principal_id "
            + "WHERE principal.name=? AND role.name=?;";
    private static final String SQL_LIST_DOMAIN_ROLE_MEMBER = "SELECT domain.name FROM domain "
            + "JOIN role ON role.domain_id=domain.domain_id "
            + "JOIN role_member ON role_member.role_id=role.role_id "
            + "JOIN principal ON principal.principal_id=role_member.principal_id "
            + "WHERE principal.name=?;";
    private static final String SQL_LIST_DOMAIN_ROLE_NAME = "SELECT domain.name FROM domain "
            + "JOIN role ON role.domain_id=domain.domain_id WHERE role.name=?;";
    private static final String SQL_GET_ROLE = "SELECT * FROM role "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "WHERE domain.name=? AND role.name=?;";
    private static final String SQL_GET_ROLE_ID = "SELECT role_id FROM role WHERE domain_id=? AND name=?;";
    private static final String SQL_INSERT_ROLE = "INSERT INTO role (name, domain_id, trust, audit_enabled, self_serve,"
            + " member_expiry_days, token_expiry_mins, cert_expiry_mins, sign_algorithm, service_expiry_days,"
            + " member_review_days, service_review_days, group_review_days, review_enabled, notify_roles, user_authority_filter,"
            + " user_authority_expiration, description, group_expiry_days, delete_protection, last_reviewed_time,"
            + " max_members, self_renew, self_renew_mins) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_ROLE = "UPDATE role SET trust=?, audit_enabled=?, self_serve=?, "
            + "member_expiry_days=?, token_expiry_mins=?, cert_expiry_mins=?, sign_algorithm=?, "
            + "service_expiry_days=?, member_review_days=?, service_review_days=?, group_review_days=?, review_enabled=?, notify_roles=?, "
            + "user_authority_filter=?, user_authority_expiration=?, description=?, group_expiry_days=?, "
            + "delete_protection=?, last_reviewed_time=?, max_members=?, self_renew=?, self_renew_mins=? WHERE role_id=?;";
    private static final String SQL_DELETE_ROLE = "DELETE FROM role WHERE domain_id=? AND name=?;";
    private static final String SQL_UPDATE_ROLE_MOD_TIMESTAMP = "UPDATE role "
            + "SET modified=CURRENT_TIMESTAMP(3) WHERE role_id=?;";
    private static final String SQL_LIST_ROLE = "SELECT name FROM role WHERE domain_id=?;";
    private static final String SQL_COUNT_ROLE = "SELECT COUNT(*) FROM role WHERE domain_id=?;";
    private static final String SQL_GET_ROLE_MEMBER = "SELECT principal.principal_id, role_member.expiration, "
            + "role_member.review_reminder, role_member.req_principal, role_member.system_disabled FROM principal "
            + "JOIN role_member ON role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role.role_id=? AND principal.name=?;";
    private static final String SQL_GET_TEMP_ROLE_MEMBER = "SELECT principal.principal_id, role_member.expiration, "
            + "role_member.review_reminder, role_member.req_principal, role_member.system_disabled FROM principal "
            + "JOIN role_member ON role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role.role_id=? AND principal.name=? AND role_member.expiration=?;";
    private static final String SQL_GET_PENDING_ROLE_MEMBER = "SELECT principal.principal_id, pending_role_member.expiration, pending_role_member.review_reminder, pending_role_member.req_principal, pending_role_member.pending_state FROM principal "
            + "JOIN pending_role_member ON pending_role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=pending_role_member.role_id "
            + "WHERE role.role_id=? AND principal.name=?;";
    private static final String SQL_GET_TEMP_PENDING_ROLE_MEMBER = "SELECT principal.principal_id, pending_role_member.expiration, pending_role_member.review_reminder, pending_role_member.req_principal, pending_role_member.pending_state FROM principal "
            + "JOIN pending_role_member ON pending_role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=pending_role_member.role_id "
            + "WHERE role.role_id=? AND principal.name=? AND pending_role_member.expiration=?;";
    private static final String SQL_GET_PENDING_ROLE_MEMBER_STATE = "SELECT pending_role_member.pending_state FROM principal "
            + "JOIN pending_role_member ON pending_role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=pending_role_member.role_id "
            + "WHERE role.role_id=? AND principal.name=?;";
    private static final String SQL_STD_ROLE_MEMBER_EXISTS = "SELECT principal_id FROM role_member WHERE role_id=? AND principal_id=?;";
    private static final String SQL_PENDING_ROLE_MEMBER_EXISTS = "SELECT pending_state FROM pending_role_member WHERE role_id=? AND principal_id=?;";
    private static final String SQL_LIST_ROLE_MEMBERS = "SELECT principal.name, role_member.expiration, "
            + "role_member.review_reminder, role_member.active, role_member.audit_ref, role_member.system_disabled FROM principal "
            + "JOIN role_member ON role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=role_member.role_id WHERE role.role_id=?;";
    private static final String SQL_LIST_PENDING_ROLE_MEMBERS = "SELECT principal.name, pending_role_member.expiration, pending_role_member.review_reminder, pending_role_member.req_time, pending_role_member.audit_ref, pending_role_member.pending_state FROM principal "
            + "JOIN pending_role_member ON pending_role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=pending_role_member.role_id WHERE role.role_id=?;";
    private static final String SQL_COUNT_ROLE_MEMBERS = "SELECT COUNT(*) FROM role_member WHERE role_id=?;";
    private static final String SQL_GET_PRINCIPAL_ID = "SELECT principal_id FROM principal WHERE name=?;";
    private static final String SQL_INSERT_PRINCIPAL = "INSERT INTO principal (name) VALUES (?);";
    private static final String SQL_DELETE_PRINCIPAL = "DELETE FROM principal WHERE name=?;";
    private static final String SQL_DELETE_SUB_PRINCIPALS = "DELETE FROM principal WHERE name LIKE ?;";
    private static final String SQL_LIST_PRINCIPAL = "SELECT * FROM principal;";
    private static final String SQL_LIST_PRINCIPAL_DOMAIN = "SELECT * FROM principal WHERE name LIKE ? OR name LIKE ?;";
    private static final String SQL_LAST_INSERT_ID = "SELECT LAST_INSERT_ID();";
    private static final String SQL_INSERT_ROLE_MEMBER = "INSERT INTO role_member "
            + "(role_id, principal_id, expiration, review_reminder, active, audit_ref, req_principal) VALUES (?,?,?,?,?,?,?);";
    private static final String SQL_INSERT_PENDING_ROLE_MEMBER = "INSERT INTO pending_role_member "
            + "(role_id, principal_id, expiration, review_reminder, audit_ref, req_principal, pending_state) VALUES (?,?,?,?,?,?,?);";
    private static final String SQL_DELETE_ROLE_MEMBER = "DELETE FROM role_member WHERE role_id=? AND principal_id=?;";
    private static final String SQL_DELETE_EXPIRED_ROLE_MEMBER = "DELETE FROM role_member WHERE role_id=? AND principal_id=? AND expiration=?;";
    private static final String SQL_DELETE_PENDING_ROLE_MEMBER = "DELETE FROM pending_role_member WHERE role_id=? AND principal_id=?;";
    private static final String SQL_UPDATE_ROLE_MEMBER = "UPDATE role_member "
            + "SET expiration=?, review_reminder=?, active=?, audit_ref=?, req_principal=? WHERE role_id=? AND principal_id=?;";
    private static final String SQL_UPDATE_ROLE_MEMBER_DISABLED_STATE = "UPDATE role_member "
            + "SET system_disabled=?, audit_ref=?, req_principal=? WHERE role_id=? AND principal_id=?;";
    private static final String SQL_UPDATE_PENDING_ROLE_MEMBER = "UPDATE pending_role_member "
            + "SET expiration=?, review_reminder=?, audit_ref=?, req_time=CURRENT_TIMESTAMP(3), req_principal=? WHERE role_id=? AND principal_id=?;";
    private static final String SQL_INSERT_ROLE_AUDIT_LOG = "INSERT INTO role_audit_log "
            + "(role_id, admin, member, action, audit_ref) VALUES (?,?,?,?,?);";
    private static final String SQL_LIST_ROLE_AUDIT_LOGS = "SELECT * FROM role_audit_log WHERE role_id=?;";
    private static final String SQL_GET_POLICY = "SELECT * FROM policy "
            + "JOIN domain ON domain.domain_id=policy.domain_id WHERE domain.name=? AND policy.name=? AND policy.active=true;";
    private static final String SQL_GET_POLICY_VERSION = "SELECT * FROM policy "
            + "JOIN domain ON domain.domain_id=policy.domain_id WHERE domain.name=? AND policy.name=? AND policy.version=?;";
    private static final String SQL_INSERT_POLICY = "INSERT INTO policy (name, domain_id) VALUES (?,?);";
    private static final String SQL_INSERT_POLICY_VERSION = "INSERT INTO policy (name, domain_id, version, active) VALUES (?,?,?,?);";
    private static final String SQL_UPDATE_POLICY = "UPDATE policy SET name=? WHERE policy_id=?;";
    private static final String SQL_UPDATE_POLICY_MOD_TIMESTAMP = "UPDATE policy "
            + "SET modified=CURRENT_TIMESTAMP(3) WHERE policy_id=?;";
    private static final String SQL_SET_ACTIVE_POLICY_VERSION = "UPDATE policy SET active = CASE WHEN version=? then true ELSE false END WHERE domain_id=? AND name=?;";
    private static final String SQL_GET_ACTIVE_POLICY_ID = "SELECT policy_id FROM policy WHERE domain_id=? AND name=? AND active=true;";
    private static final String SQL_GET_POLICY_VERSION_ID = "SELECT policy_id FROM policy WHERE domain_id=? AND name=? AND version=?;";
    private static final String SQL_DELETE_POLICY = "DELETE FROM policy WHERE domain_id=? AND name=?;";
    private static final String SQL_DELETE_POLICY_VERSION = "DELETE FROM policy WHERE domain_id=? AND name=? AND version=? and active=false;";
    private static final String SQL_LIST_POLICY = "SELECT name FROM policy WHERE domain_id=? AND active=true";
    private static final String SQL_LIST_POLICY_VERSION = "SELECT version FROM policy WHERE domain_id=? AND name=?";
    private static final String SQL_COUNT_POLICY = "SELECT COUNT(*) FROM policy WHERE domain_id=?";
    private static final String SQL_LIST_ASSERTION = "SELECT * FROM assertion WHERE policy_id=?";
    private static final String SQL_COUNT_ASSERTION = "SELECT COUNT(*) FROM assertion WHERE policy_id=?";
    private static final String SQL_GET_ASSERTION = "SELECT * FROM assertion "
            + "JOIN policy ON assertion.policy_id=policy.policy_id "
            + "JOIN domain ON policy.domain_id=domain.domain_id "
            + "WHERE assertion.assertion_id=? AND domain.name=? AND policy.name=?;";
    private static final String SQL_CHECK_ASSERTION = "SELECT assertion_id FROM assertion "
            + "WHERE policy_id=? AND role=? AND resource=? AND action=? AND effect=?;";
    private static final String SQL_INSERT_ASSERTION = "INSERT INTO assertion "
            + "(policy_id, role, resource, action, effect) VALUES (?,?,?,?,?);";
    private static final String SQL_DELETE_ASSERTION = "DELETE FROM assertion "
            + "WHERE policy_id=? AND assertion_id=?;";
    private static final String SQL_GET_SERVICE = "SELECT * FROM service "
            + "JOIN domain ON domain.domain_id=service.domain_id WHERE domain.name=? AND service.name=?;";
    private static final String SQL_INSERT_SERVICE = "INSERT INTO service "
            + "(name, description, provider_endpoint, executable, svc_user, svc_group, domain_id) VALUES (?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_SERVICE = "UPDATE service SET "
            + "description=?, provider_endpoint=?, executable=?, svc_user=?, svc_group=?  WHERE service_id=?;";
    private static final String SQL_UPDATE_SERVICE_MOD_TIMESTAMP = "UPDATE service "
            + "SET modified=CURRENT_TIMESTAMP(3) WHERE service_id=?;";
    private static final String SQL_DELETE_SERVICE = "DELETE FROM service WHERE domain_id=? AND name=?;";
    private static final String SQL_GET_SERVICE_ID = "SELECT service_id FROM service WHERE domain_id=? AND name=?;";
    private static final String SQL_LIST_SERVICE = "SELECT name FROM service WHERE domain_id=?;";
    private static final String SQL_COUNT_SERVICE = "SELECT COUNT(*) FROM service WHERE domain_id=?;";
    private static final String SQL_LIST_PUBLIC_KEY = "SELECT * FROM public_key WHERE service_id=?;";
    private static final String SQL_COUNT_PUBLIC_KEY = "SELECT COUNT(*) FROM public_key WHERE service_id=?;";
    private static final String SQL_GET_PUBLIC_KEY = "SELECT key_value FROM public_key WHERE service_id=? AND key_id=?;";
    private static final String SQL_INSERT_PUBLIC_KEY = "INSERT INTO public_key "
            + "(service_id, key_id, key_value) VALUES (?,?,?);";
    private static final String SQL_UPDATE_PUBLIC_KEY = "UPDATE public_key SET key_value=? WHERE service_id=? AND key_id=?;";
    private static final String SQL_DELETE_PUBLIC_KEY = "DELETE FROM public_key WHERE service_id=? AND key_id=?;";
    private static final String SQL_LIST_SERVICE_HOST = "SELECT host.name FROM host "
            + "JOIN service_host ON service_host.host_id=host.host_id "
            + "WHERE service_host.service_id=?;";
    private static final String SQL_INSERT_SERVICE_HOST = "INSERT INTO service_host (service_id, host_id) VALUES (?,?);";
    private static final String SQL_DELETE_SERVICE_HOST = "DELETE FROM service_host WHERE service_id=? AND host_id=?;";
    private static final String SQL_GET_HOST_ID = "SELECT host_id FROM host WHERE name=?;";
    private static final String SQL_INSERT_HOST = "INSERT INTO host (name) VALUES (?);";
    private static final String SQL_INSERT_ENTITY = "INSERT INTO entity (domain_id, name, value) VALUES (?,?,?);";
    private static final String SQL_UPDATE_ENTITY = "UPDATE entity SET value=? WHERE domain_id=? AND name=?;";
    private static final String SQL_DELETE_ENTITY = "DELETE FROM entity WHERE domain_id=? AND name=?;";
    private static final String SQL_GET_ENTITY = "SELECT value FROM entity WHERE domain_id=? AND name=?;";
    private static final String SQL_LIST_ENTITY = "SELECT name FROM entity WHERE domain_id=?;";
    private static final String SQL_COUNT_ENTITY = "SELECT COUNT(*) FROM entity WHERE domain_id=?;";
    private static final String SQL_INSERT_DOMAIN_TEMPLATE = "INSERT INTO domain_template (domain_id, template) VALUES (?,?);";
    private static final String SQL_UPDATE_DOMAIN_TEMPLATE = "UPDATE domain_template SET current_version=? WHERE domain_id=? and template=?;";
    private static final String SQL_DELETE_DOMAIN_TEMPLATE = "DELETE FROM domain_template WHERE domain_id=? AND template=?;";
    private static final String SQL_LIST_DOMAIN_TEMPLATES = "SELECT * FROM domain_template WHERE domain_id=?;";
    private static final String SQL_LIST_DOMAIN_TEMPLATE = "SELECT template FROM domain_template "
            + "JOIN domain ON domain_template.domain_id=domain.domain_id "
            + "WHERE domain.name=?;";
    private static final String SQL_GET_DOMAIN_ENTITIES = "SELECT * FROM entity WHERE domain_id=?;";
    private static final String SQL_GET_DOMAIN_ROLES = "SELECT * FROM role WHERE domain_id=?;";
    private static final String SQL_GET_DOMAIN_ROLE_MEMBERS = "SELECT role.name, principal.name, role_member.expiration, "
            + "role_member.review_reminder, role_member.system_disabled FROM principal "
            + "JOIN role_member ON role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role.domain_id=?;";
    private static final String SQL_GET_PRINCIPAL_ROLES = "SELECT role.name, domain.name, role_member.expiration, "
            + "role_member.review_reminder, role_member.system_disabled FROM role_member "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "WHERE role_member.principal_id=?;";
    private static final String SQL_GET_PRINCIPAL_ROLES_DOMAIN = "SELECT role.name, domain.name, role_member.expiration, "
            + "role_member.review_reminder, role_member.system_disabled FROM role_member "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "WHERE role_member.principal_id=? AND domain.domain_id=?;";
    private static final String SQL_GET_REVIEW_OVERDUE_DOMAIN_ROLE_MEMBERS = "SELECT role.name, principal.name, role_member.expiration, "
            + "role_member.review_reminder, role_member.system_disabled FROM principal "
            + "JOIN role_member ON role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role.domain_id=? AND role_member.review_reminder < CURRENT_TIME;";
    private static final String SQL_GET_DOMAIN_POLICIES = "SELECT * FROM policy WHERE domain_id=?;";
    private static final String SQL_GET_DOMAIN_POLICY_ASSERTIONS = "SELECT policy.policy_id, "
            + "assertion.effect, assertion.action, assertion.role, assertion.resource, "
            + "assertion.assertion_id FROM assertion "
            + "JOIN policy ON policy.policy_id=assertion.policy_id "
            + "WHERE policy.domain_id=?;";
    private static final String SQL_GET_DOMAIN_SERVICES = "SELECT * FROM service WHERE domain_id=?;";
    private static final String SQL_GET_DOMAIN_SERVICES_HOSTS = "SELECT service.name, host.name FROM host "
            + "JOIN service_host ON host.host_id=service_host.host_id "
            + "JOIN service ON service.service_id=service_host.service_id "
            + "WHERE service.domain_id=?;";
    private static final String SQL_GET_DOMAIN_SERVICES_PUBLIC_KEYS = "SELECT service.name, "
            + "public_key.key_id, public_key.key_value FROM public_key "
            + "JOIN service ON service.service_id=public_key.service_id "
            + "WHERE service.domain_id=?;";
    private static final String SQL_LIST_POLICY_REFERENCING_ROLE = "SELECT name FROM policy "
            + "JOIN assertion ON policy.policy_id=assertion.policy_id "
            + "WHERE policy.domain_id=? AND assertion.role=?;";
    private static final String SQL_LIST_ROLE_ASSERTIONS = "SELECT assertion.role, assertion.resource, "
            + "assertion.action, assertion.effect, assertion.assertion_id, policy.domain_id, domain.name FROM assertion "
            + "JOIN policy ON assertion.policy_id=policy.policy_id "
            + "JOIN domain ON policy.domain_id=domain.domain_id";
    private static final String SQL_LIST_ROLE_ASSERTION_QUERY_ACTION = " WHERE assertion.action=?;";
    private static final String SQL_LIST_ROLE_ASSERTION_NO_ACTION = " WHERE assertion.action!='assume_role';";
    private static final String SQL_LIST_ROLE_PRINCIPALS = "SELECT role.domain_id, role.name AS role_name FROM principal "
            + "JOIN role_member ON principal.principal_id=role_member.principal_id "
            + "JOIN role ON role_member.role_id=role.role_id WHERE principal.name=? "
            + "AND principal.system_suspended=0 AND role_member.system_disabled=0 "
            + "AND (role_member.expiration IS NULL OR role_member.expiration > CURRENT_TIME);";
    private static final String SQL_LIST_ROLE_GROUP_PRINCIPALS = "SELECT principal.name, role.domain_id, "
            + "role.name AS role_name FROM principal "
            + "JOIN role_member ON principal.principal_id=role_member.principal_id "
            + "JOIN role ON role_member.role_id=role.role_id WHERE principal.name LIKE '%:group.%' "
            + "AND principal.system_suspended=0 AND role_member.system_disabled=0 "
            + "AND (role_member.expiration IS NULL OR role_member.expiration > CURRENT_TIME);";
    private static final String SQL_LIST_GROUP_FOR_PRINCIPAL = "SELECT principal_group.name, domain.name AS domain_name "
            + "FROM principal_group_member  JOIN principal_group ON principal_group.group_id=principal_group_member.group_id "
            + "JOIN domain ON domain.domain_id=principal_group.domain_id JOIN principal ON principal.principal_id=principal_group_member.principal_id "
            + "WHERE principal.name=? AND principal.system_suspended=0 AND principal_group_member.system_disabled=0 "
            + "AND (principal_group_member.expiration IS NULL OR principal_group_member.expiration > CURRENT_TIME);";
    private static final String SQL_LIST_TRUSTED_STANDARD_ROLES = "SELECT role.domain_id, role.name, "
            + "policy.domain_id AS assert_domain_id, assertion.role FROM role "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "JOIN assertion ON assertion.resource=CONCAT(domain.name, \":role.\", role.name) "
            + "JOIN policy ON policy.policy_id=assertion.policy_id "
            + "WHERE assertion.action='assume_role';";
    private static final String SQL_LIST_TRUSTED_WILDCARD_ROLES = "SELECT role.domain_id, role.name, "
            + "policy.domain_id AS assert_domain_id, assertion.role FROM role "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "JOIN assertion ON assertion.resource=CONCAT(\"*:role.\", role.name) "
            + "JOIN policy ON policy.policy_id=assertion.policy_id "
            + "WHERE assertion.action='assume_role';";
    private static final String SQL_LIST_TRUSTED_ROLES_WITH_WILDCARD = "SELECT domain.name, role.name FROM role "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "WHERE domain.name LIKE ? AND role.name LIKE ? AND role.trust=?;";
    private static final String SQL_GET_QUOTA = "SELECT * FROM quota WHERE domain_id=?;";
    private static final String SQL_INSERT_QUOTA = "INSERT INTO quota (domain_id, role, role_member, "
            + "policy, assertion, service, service_host, public_key, entity, subdomain, principal_group, principal_group_member) "
            + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_QUOTA = "UPDATE quota SET role=?, role_member=?, "
            + "policy=?, assertion=?, service=?, service_host=?, public_key=?, entity=?, "
            + "subdomain=?, principal_group=?, principal_group_member=?  WHERE domain_id=?;";
    private static final String SQL_DELETE_QUOTA = "DELETE FROM quota WHERE domain_id=?;";
    private static final String SQL_PENDING_ORG_AUDIT_ROLE_MEMBER_LIST = "SELECT do.name AS domain, ro.name AS role, "
            + "principal.name AS member, rmo.expiration, rmo.review_reminder, rmo.audit_ref, rmo.req_time, rmo.req_principal, rmo.pending_state "
            + "FROM principal JOIN pending_role_member rmo "
            + "ON rmo.principal_id=principal.principal_id JOIN role ro ON ro.role_id=rmo.role_id JOIN domain do ON ro.domain_id=do.domain_id "
            + "WHERE ro.audit_enabled=true AND ro.domain_id IN ( select domain_id FROM domain WHERE org IN ( "
            + "SELECT DISTINCT role.name AS org FROM role_member JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role_member.principal_id=? AND role.domain_id=?) ) order by do.name, ro.name, principal.name;";
    private static final String SQL_PENDING_DOMAIN_AUDIT_ROLE_MEMBER_LIST = "SELECT do.name AS domain, ro.name AS role, "
            + "principal.name AS member, rmo.expiration, rmo.review_reminder, rmo.audit_ref, rmo.req_time, rmo.req_principal, rmo.pending_state "
            + "FROM principal JOIN pending_role_member rmo "
            + "ON rmo.principal_id=principal.principal_id JOIN role ro ON ro.role_id=rmo.role_id JOIN domain do ON ro.domain_id=do.domain_id "
            + "WHERE ro.audit_enabled=true AND ro.domain_id IN ( select domain_id FROM domain WHERE name IN ( "
            + "SELECT DISTINCT role.name AS domain_name FROM role_member JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role_member.principal_id=? AND role.domain_id=?) ) order by do.name, ro.name, principal.name;";
    private static final String SQL_PENDING_DOMAIN_ADMIN_ROLE_MEMBER_LIST = "SELECT do.name AS domain, ro.name AS role, "
            + "principal.name AS member, rmo.expiration, rmo.review_reminder, rmo.audit_ref, rmo.req_time, rmo.req_principal, rmo.pending_state "
            + "FROM principal JOIN pending_role_member rmo "
            + "ON rmo.principal_id=principal.principal_id JOIN role ro ON ro.role_id=rmo.role_id JOIN domain do ON ro.domain_id=do.domain_id "
            + "WHERE (ro.self_serve=true OR ro.review_enabled=true) AND ro.domain_id IN ( SELECT domain.domain_id FROM domain JOIN role "
            + "ON role.domain_id=domain.domain_id JOIN role_member ON role.role_id=role_member.role_id "
            + "WHERE role_member.principal_id=? AND role_member.active=true AND role.name='admin' ) "
            + "order by do.name, ro.name, principal.name;";
    private static final String SQL_PENDING_DOMAIN_ROLE_MEMBER_LIST = "SELECT do.name AS domain, ro.name AS role, "
            + "principal.name AS member, rmo.expiration, rmo.review_reminder, rmo.audit_ref, rmo.req_time, rmo.req_principal, rmo.pending_state "
            + "FROM principal JOIN pending_role_member rmo "
            + "ON rmo.principal_id=principal.principal_id JOIN role ro ON ro.role_id=rmo.role_id JOIN domain do ON ro.domain_id=do.domain_id "
            + "WHERE ro.domain_id=? AND (ro.self_serve=true OR ro.review_enabled=true OR ro.audit_enabled=true) "
            + "order by do.name, ro.name, principal.name;";
    private static final String SQL_PENDING_ALL_DOMAIN_ROLE_MEMBER_LIST = "SELECT do.name AS domain, ro.name AS role, "
            + "principal.name AS member, rmo.expiration, rmo.review_reminder, rmo.audit_ref, rmo.req_time, rmo.req_principal, rmo.pending_state "
            + "FROM principal JOIN pending_role_member rmo "
            + "ON rmo.principal_id=principal.principal_id JOIN role ro ON ro.role_id=rmo.role_id JOIN domain do ON ro.domain_id=do.domain_id "
            + "WHERE (ro.self_serve=true OR ro.review_enabled=true OR ro.audit_enabled=true)"
            + "order by do.name, ro.name, principal.name;";
    private static final String SQL_AUDIT_ENABLED_PENDING_MEMBERSHIP_REMINDER_ENTRIES =
              "SELECT distinct d.org, d.name FROM pending_role_member rm "
            + "JOIN role r ON r.role_id=rm.role_id JOIN domain d ON r.domain_id=d.domain_id "
            + "WHERE r.audit_enabled=true AND rm.last_notified_time=? AND rm.server=?;";
    private static final String SQL_ADMIN_PENDING_MEMBERSHIP_REMINDER_DOMAINS =
              "SELECT distinct d.name FROM pending_role_member rm "
            + "JOIN role r ON r.role_id=rm.role_id "
            + "JOIN domain d ON r.domain_id=d.domain_id WHERE (r.self_serve=true OR r.review_enabled=true) AND rm.last_notified_time=? AND rm.server=?;";
    private static final String SQL_GET_EXPIRED_PENDING_ROLE_MEMBERS = "SELECT d.name, r.name, p.name, prm.expiration, prm.review_reminder, prm.audit_ref, prm.req_time, prm.req_principal, prm.pending_state "
            + "FROM principal p JOIN pending_role_member prm "
            + "ON prm.principal_id=p.principal_id JOIN role r ON prm.role_id=r.role_id JOIN domain d ON d.domain_id=r.domain_id "
            + "WHERE prm.req_time < (CURRENT_TIME - INTERVAL ? DAY);";
    private static final String SQL_UPDATE_PENDING_ROLE_MEMBERS_NOTIFICATION_TIMESTAMP = "UPDATE pending_role_member SET last_notified_time=?, server=? "
            + "WHERE DAYOFWEEK(req_time)=DAYOFWEEK(?) AND (last_notified_time IS NULL || last_notified_time < (CURRENT_TIME - INTERVAL ? DAY));";
    private static final String SQL_UPDATE_ROLE_MEMBERS_EXPIRY_NOTIFICATION_TIMESTAMP =
              "UPDATE role_member SET last_notified_time=?, server=? "
            + "WHERE expiration > CURRENT_TIME AND DATEDIFF(expiration, CURRENT_TIME) IN (0,1,7,14,21,28);";
    private static final String SQL_LIST_NOTIFY_TEMPORARY_ROLE_MEMBERS = "SELECT domain.name AS domain_name, role.name AS role_name, "
            + "principal.name AS principal_name, role_member.expiration, role_member.review_reminder FROM role_member "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "JOIN principal ON principal.principal_id=role_member.principal_id "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "WHERE role_member.last_notified_time=? AND role_member.server=?;";
    private static final String SQL_UPDATE_ROLE_MEMBERS_REVIEW_NOTIFICATION_TIMESTAMP =
              "UPDATE role_member SET review_last_notified_time=?, review_server=? "
            + "WHERE review_reminder > CURRENT_TIME AND expiration IS NULL AND DATEDIFF(review_reminder, CURRENT_TIME) IN (0,1,7,14,21,28);";
    private static final String SQL_LIST_NOTIFY_REVIEW_ROLE_MEMBERS = "SELECT domain.name AS domain_name, role.name AS role_name, "
            + "principal.name AS principal_name, role_member.expiration, role_member.review_reminder FROM role_member "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "JOIN principal ON principal.principal_id=role_member.principal_id "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "WHERE role_member.review_last_notified_time=? AND role_member.review_server=?;";
    private static final String SQL_UPDATE_ROLE_REVIEW_TIMESTAMP = "UPDATE role SET last_reviewed_time=CURRENT_TIMESTAMP(3) WHERE role_id=?;";
    private static final String SQL_LIST_ROLES_WITH_RESTRICTIONS = "SELECT domain.name as domain_name, "
            + "role.name as role_name, domain.user_authority_filter as domain_user_authority_filter FROM role "
            + "JOIN domain ON role.domain_id=domain.domain_id WHERE role.user_authority_filter!='' "
            + "OR role.user_authority_expiration!='' OR domain.user_authority_filter!='';";
    private static final String SQL_GET_GROUP = "SELECT * FROM principal_group "
            + "JOIN domain ON domain.domain_id=principal_group.domain_id "
            + "WHERE domain.name=? AND principal_group.name=?;";
    private static final String SQL_INSERT_GROUP = "INSERT INTO principal_group (name, domain_id, audit_enabled, self_serve, "
            + "review_enabled, notify_roles, user_authority_filter, user_authority_expiration, member_expiry_days, "
            + "service_expiry_days, delete_protection, last_reviewed_time, max_members, self_renew, self_renew_mins) "
            + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_GROUP = "UPDATE principal_group SET audit_enabled=?, self_serve=?, "
            + "review_enabled=?, notify_roles=?, user_authority_filter=?, user_authority_expiration=?, "
            + "member_expiry_days=?, service_expiry_days=?, delete_protection=?, last_reviewed_time=?, "
            + "max_members=?, self_renew=?, self_renew_mins=? WHERE group_id=?;";
    private static final String SQL_GET_GROUP_ID = "SELECT group_id FROM principal_group WHERE domain_id=? AND name=?;";
    private static final String SQL_DELETE_GROUP = "DELETE FROM principal_group WHERE domain_id=? AND name=?;";
    private static final String SQL_UPDATE_GROUP_MOD_TIMESTAMP = "UPDATE principal_group "
            + "SET modified=CURRENT_TIMESTAMP(3) WHERE group_id=?;";
    private static final String SQL_COUNT_GROUP = "SELECT COUNT(*) FROM principal_group WHERE domain_id=?;";
    private static final String SQL_GET_GROUP_MEMBER = "SELECT principal.principal_id, principal_group_member.expiration, "
            + "principal_group_member.req_principal, principal_group_member.system_disabled FROM principal "
            + "JOIN principal_group_member ON principal_group_member.principal_id=principal.principal_id "
            + "JOIN principal_group ON principal_group.group_id=principal_group_member.group_id "
            + "WHERE principal_group.group_id=? AND principal.name=?;";
    private static final String SQL_GET_TEMP_GROUP_MEMBER = "SELECT principal.principal_id, principal_group_member.expiration, "
            + "principal_group_member.req_principal, principal_group_member.system_disabled FROM principal "
            + "JOIN principal_group_member ON principal_group_member.principal_id=principal.principal_id "
            + "JOIN principal_group ON principal_group.group_id=principal_group_member.group_id "
            + "WHERE principal_group.group_id=? AND principal.name=? AND principal_group_member.expiration=?;";
    private static final String SQL_GET_PENDING_GROUP_MEMBER = "SELECT principal.principal_id, "
            + "pending_principal_group_member.expiration, pending_principal_group_member.req_principal, pending_principal_group_member.pending_state FROM principal "
            + "JOIN pending_principal_group_member ON pending_principal_group_member.principal_id=principal.principal_id "
            + "JOIN principal_group ON principal_group.group_id=pending_principal_group_member.group_id "
            + "WHERE principal_group.group_id=? AND principal.name=?;";
    private static final String SQL_GET_TEMP_PENDING_GROUP_MEMBER = "SELECT principal.principal_id, "
            + "pending_principal_group_member.expiration, pending_principal_group_member.req_principal, pending_principal_group_member.pending_state FROM principal "
            + "JOIN pending_principal_group_member ON pending_principal_group_member.principal_id=principal.principal_id "
            + "JOIN principal_group ON principal_group.group_id=pending_principal_group_member.group_id "
            + "WHERE principal_group.group_id=? AND principal.name=? AND pending_principal_group_member.expiration=?;";
    private static final String SQL_GET_PENDING_GROUP_MEMBER_STATE = "SELECT pending_principal_group_member.pending_state FROM principal "
            + "JOIN pending_principal_group_member ON pending_principal_group_member.principal_id=principal.principal_id "
            + "JOIN principal_group ON principal_group.group_id=pending_principal_group_member.group_id "
            + "WHERE principal_group.group_id=? AND principal.name=?;";
    private static final String SQL_LIST_GROUP_AUDIT_LOGS = "SELECT * FROM principal_group_audit_log WHERE group_id=?;";
    private static final String SQL_UPDATE_GROUP_REVIEW_TIMESTAMP = "UPDATE principal_group SET last_reviewed_time=CURRENT_TIMESTAMP(3) WHERE group_id=?;";
    private static final String SQL_LIST_GROUPS_WITH_RESTRICTIONS = "SELECT domain.name as domain_name, "
            + "principal_group.name as group_name, domain.user_authority_filter as domain_user_authority_filter FROM principal_group "
            + "JOIN domain ON principal_group.domain_id=domain.domain_id WHERE principal_group.user_authority_filter!='' "
            + "OR principal_group.user_authority_expiration!='' OR domain.user_authority_filter!='';";
    private static final String SQL_LIST_GROUP_MEMBERS = "SELECT principal.name, principal_group_member.expiration, "
            + "principal_group_member.active, principal_group_member.audit_ref, principal_group_member.system_disabled FROM principal "
            + "JOIN principal_group_member ON principal_group_member.principal_id=principal.principal_id "
            + "JOIN principal_group ON principal_group.group_id=principal_group_member.group_id WHERE principal_group.group_id=?;";
    private static final String SQL_LIST_PENDING_GROUP_MEMBERS = "SELECT principal.name, pending_principal_group_member.expiration, "
            + "pending_principal_group_member.req_time, pending_principal_group_member.audit_ref, pending_principal_group_member.pending_state FROM principal "
            + "JOIN pending_principal_group_member ON pending_principal_group_member.principal_id=principal.principal_id "
            + "JOIN principal_group ON principal_group.group_id=pending_principal_group_member.group_id WHERE principal_group.group_id=?;";
    private static final String SQL_COUNT_GROUP_MEMBERS = "SELECT COUNT(*) FROM principal_group_member WHERE group_id=?;";
    private static final String SQL_STD_GROUP_MEMBER_EXISTS = "SELECT principal_id FROM principal_group_member WHERE group_id=? AND principal_id=?;";
    private static final String SQL_PENDING_GROUP_MEMBER_EXISTS = "SELECT pending_state FROM pending_principal_group_member WHERE group_id=? AND principal_id=?;";
    private static final String SQL_UPDATE_GROUP_MEMBER = "UPDATE principal_group_member "
            + "SET expiration=?, active=?, audit_ref=?, req_principal=? WHERE group_id=? AND principal_id=?;";
    private static final String SQL_UPDATE_GROUP_MEMBER_DISABLED_STATE = "UPDATE principal_group_member "
            + "SET system_disabled=?, audit_ref=?, req_principal=? WHERE group_id=? AND principal_id=?;";
    private static final String SQL_UPDATE_PENDING_GROUP_MEMBER = "UPDATE pending_principal_group_member "
            + "SET expiration=?, audit_ref=?, req_time=CURRENT_TIMESTAMP(3), req_principal=? WHERE group_id=? AND principal_id=?;";
    private static final String SQL_INSERT_GROUP_MEMBER = "INSERT INTO principal_group_member "
            + "(group_id, principal_id, expiration, active, audit_ref, req_principal) VALUES (?,?,?,?,?,?);";
    private static final String SQL_INSERT_PENDING_GROUP_MEMBER = "INSERT INTO pending_principal_group_member "
            + "(group_id, principal_id, expiration, audit_ref, req_principal, pending_state) VALUES (?,?,?,?,?,?);";
    private static final String SQL_DELETE_GROUP_MEMBER = "DELETE FROM principal_group_member WHERE group_id=? AND principal_id=?;";
    private static final String SQL_DELETE_EXPIRED_GROUP_MEMBER = "DELETE FROM principal_group_member WHERE group_id=? AND principal_id=? AND expiration=?;";
    private static final String SQL_DELETE_PENDING_GROUP_MEMBER = "DELETE FROM pending_principal_group_member WHERE group_id=? AND principal_id=?;";
    private static final String SQL_INSERT_GROUP_AUDIT_LOG = "INSERT INTO principal_group_audit_log "
            + "(group_id, admin, member, action, audit_ref) VALUES (?,?,?,?,?);";
    private static final String SQL_GET_PRINCIPAL_GROUPS = "SELECT principal_group.name, domain.name, principal_group_member.expiration, "
            + "principal_group_member.system_disabled FROM principal_group_member "
            + "JOIN principal_group ON principal_group.group_id=principal_group_member.group_id "
            + "JOIN domain ON domain.domain_id=principal_group.domain_id "
            + "WHERE principal_group_member.principal_id=?;";
    private static final String SQL_GET_PRINCIPAL_GROUPS_DOMAIN = "SELECT principal_group.name, domain.name, principal_group_member.expiration, "
            + "principal_group_member.system_disabled FROM principal_group_member "
            + "JOIN principal_group ON principal_group.group_id=principal_group_member.group_id "
            + "JOIN domain ON domain.domain_id=principal_group.domain_id "
            + "WHERE principal_group_member.principal_id=? AND domain.domain_id=?;";
    private static final String SQL_GET_DOMAIN_GROUPS = "SELECT * FROM principal_group WHERE domain_id=?;";
    private static final String SQL_GET_DOMAIN_GROUP_MEMBERS = "SELECT principal_group.name, principal.name, "
            + "principal_group_member.expiration, principal_group_member.system_disabled FROM principal "
            + "JOIN principal_group_member ON principal_group_member.principal_id=principal.principal_id "
            + "JOIN principal_group ON principal_group.group_id=principal_group_member.group_id "
            + "WHERE principal_group.domain_id=?;";
    private static final String SQL_PENDING_ORG_AUDIT_GROUP_MEMBER_LIST = "SELECT do.name AS domain, grp.name AS group_name, "
            + "principal.name AS member, pgm.expiration, pgm.audit_ref, pgm.req_time, pgm.req_principal, pgm.pending_state "
            + "FROM principal JOIN pending_principal_group_member pgm "
            + "ON pgm.principal_id=principal.principal_id JOIN principal_group grp ON grp.group_id=pgm.group_id JOIN domain do ON grp.domain_id=do.domain_id "
            + "WHERE grp.audit_enabled=true AND grp.domain_id IN ( select domain_id FROM domain WHERE org IN ( "
            + "SELECT DISTINCT role.name AS org FROM role_member JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role_member.principal_id=? AND role.domain_id=?) ) order by do.name, grp.name, principal.name;";
    private static final String SQL_PENDING_DOMAIN_AUDIT_GROUP_MEMBER_LIST = "SELECT do.name AS domain, grp.name AS group_name, "
            + "principal.name AS member, pgm.expiration, pgm.audit_ref, pgm.req_time, pgm.req_principal, pgm.pending_state "
            + "FROM principal JOIN pending_principal_group_member pgm "
            + "ON pgm.principal_id=principal.principal_id JOIN principal_group grp ON grp.group_id=pgm.group_id JOIN domain do ON grp.domain_id=do.domain_id "
            + "WHERE grp.audit_enabled=true AND grp.domain_id IN ( select domain_id FROM domain WHERE name IN ( "
            + "SELECT DISTINCT role.name AS domain_name FROM role_member JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role_member.principal_id=? AND role.domain_id=?) ) order by do.name, grp.name, principal.name;";
    private static final String SQL_PENDING_DOMAIN_ADMIN_GROUP_MEMBER_LIST = "SELECT do.name AS domain, grp.name AS group_name, "
            + "principal.name AS member, pgm.expiration, pgm.audit_ref, pgm.req_time, pgm.req_principal, pgm.pending_state "
            + "FROM principal JOIN pending_principal_group_member pgm "
            + "ON pgm.principal_id=principal.principal_id JOIN principal_group grp ON grp.group_id=pgm.group_id JOIN domain do ON grp.domain_id=do.domain_id "
            + "WHERE (grp.self_serve=true OR grp.review_enabled=true) AND grp.domain_id IN ( SELECT domain.domain_id FROM domain JOIN role "
            + "ON role.domain_id=domain.domain_id JOIN role_member ON role.role_id=role_member.role_id "
            + "WHERE role_member.principal_id=? AND role_member.active=true AND role.name='admin' ) "
            + "order by do.name, grp.name, principal.name;";
    private static final String SQL_PENDING_DOMAIN_GROUP_MEMBER_LIST = "SELECT do.name AS domain, grp.name AS group_name, "
            + "principal.name AS member, pgm.expiration, pgm.audit_ref, pgm.req_time, pgm.req_principal, pgm.pending_state "
            + "FROM principal JOIN pending_principal_group_member pgm "
            + "ON pgm.principal_id=principal.principal_id JOIN principal_group grp ON grp.group_id=pgm.group_id JOIN domain do ON grp.domain_id=do.domain_id "
            + "WHERE grp.domain_id=? AND (grp.self_serve=true OR grp.review_enabled=true OR grp.audit_enabled=true) "
            + "order by do.name, grp.name, principal.name;";
    private static final String SQL_PENDING_ALL_DOMAIN_GROUP_MEMBER_LIST = "SELECT do.name AS domain, grp.name AS group_name, "
            + "principal.name AS member, pgm.expiration, pgm.audit_ref, pgm.req_time, pgm.req_principal, pgm.pending_state "
            + "FROM principal JOIN pending_principal_group_member pgm "
            + "ON pgm.principal_id=principal.principal_id JOIN principal_group grp ON grp.group_id=pgm.group_id JOIN domain do ON grp.domain_id=do.domain_id "
            + "WHERE (grp.self_serve=true OR grp.review_enabled=true OR grp.audit_enabled=true) "
            + "order by do.name, grp.name, principal.name;";
    private static final String SQL_GET_EXPIRED_PENDING_GROUP_MEMBERS = "SELECT d.name, grp.name, p.name, pgm.expiration, pgm.audit_ref, pgm.req_time, pgm.req_principal, pgm.pending_state "
            + "FROM principal p JOIN pending_principal_group_member pgm "
            + "ON pgm.principal_id=p.principal_id JOIN principal_group grp ON pgm.group_id=grp.group_id JOIN domain d ON d.domain_id=grp.domain_id "
            + "WHERE pgm.req_time < (CURRENT_TIME - INTERVAL ? DAY);";
    private static final String SQL_AUDIT_ENABLED_PENDING_GROUP_MEMBERSHIP_REMINDER_ENTRIES = "SELECT distinct d.org, d.name FROM pending_principal_group_member pgm "
            + "JOIN principal_group grp ON grp.group_id=pgm.group_id JOIN domain d ON grp.domain_id=d.domain_id "
            + "WHERE grp.audit_enabled=true AND pgm.last_notified_time=? AND pgm.server=?;";
    private static final String SQL_UPDATE_PENDING_GROUP_MEMBERS_NOTIFICATION_TIMESTAMP = "UPDATE pending_principal_group_member SET last_notified_time=?, server=? "
            + "WHERE DAYOFWEEK(req_time)=DAYOFWEEK(?) AND (last_notified_time IS NULL || last_notified_time < (CURRENT_TIME - INTERVAL ? DAY));";
    private static final String SQL_ADMIN_PENDING_GROUP_MEMBERSHIP_REMINDER_DOMAINS = "SELECT distinct d.name FROM pending_principal_group_member pgm "
            + "JOIN principal_group grp ON grp.group_id=pgm.group_id JOIN domain d ON grp.domain_id=d.domain_id "
            + "WHERE grp.self_serve=true AND pgm.last_notified_time=? AND pgm.server=?;";
    private static final String SQL_UPDATE_GROUP_MEMBERS_EXPIRY_NOTIFICATION_TIMESTAMP =
              "UPDATE principal_group_member SET last_notified_time=?, server=? "
            + "WHERE expiration > CURRENT_TIME AND DATEDIFF(expiration, CURRENT_TIME) IN (0,1,7,14,21,28);";
    private static final String SQL_LIST_NOTIFY_TEMPORARY_GROUP_MEMBERS = "SELECT domain.name AS domain_name, principal_group.name AS group_name, "
            + "principal.name AS principal_name, principal_group_member.expiration FROM principal_group_member "
            + "JOIN principal_group ON principal_group.group_id=principal_group_member.group_id "
            + "JOIN principal ON principal.principal_id=principal_group_member.principal_id "
            + "JOIN domain ON domain.domain_id=principal_group.domain_id "
            + "WHERE principal_group_member.last_notified_time=? AND principal_group_member.server=?;";
    private static final String SQL_UPDATE_PRINCIPAL = "UPDATE principal SET system_suspended=? WHERE name=?;";
    private static final String SQL_GET_PRINCIPAL = "SELECT name FROM principal WHERE system_suspended=?;";
    private static final String SQL_INSERT_ROLE_TAG = "INSERT INTO role_tags"
            + "(role_id, role_tags.key, role_tags.value) VALUES (?,?,?);";
    private static final String SQL_ROLE_TAG_COUNT = "SELECT COUNT(*) FROM role_tags WHERE role_id=?";
    private static final String SQL_DELETE_ROLE_TAG = "DELETE FROM role_tags WHERE role_id=? AND role_tags.key=?;";
    private static final String SQL_GET_ROLE_TAGS = "SELECT rt.key, rt.value FROM role_tags rt "
            + "JOIN role r ON rt.role_id = r.role_id JOIN domain ON domain.domain_id=r.domain_id "
            + "WHERE domain.name=? AND r.name=?";
    private static final String SQL_GET_DOMAIN_ROLE_TAGS = "SELECT r.name, rt.key, rt.value FROM role_tags rt "
            + "JOIN role r ON rt.role_id = r.role_id JOIN domain ON domain.domain_id=r.domain_id "
            + "WHERE domain.name=?";
    private static final String SQL_INSERT_DOMAIN_TAG = "INSERT INTO domain_tags"
            + "(domain_id, domain_tags.key, domain_tags.value) VALUES (?,?,?);";
    private static final String SQL_DOMAIN_TAG_COUNT = "SELECT COUNT(*) FROM domain_tags WHERE domain_id=?";
    private static final String SQL_DELETE_DOMAIN_TAG = "DELETE FROM domain_tags WHERE domain_id=? AND domain_tags.key=?;";
    private static final String SQL_GET_DOMAIN_TAGS = "SELECT dt.key, dt.value FROM domain_tags dt WHERE dt.domain_id=?";
    private static final String SQL_LOOKUP_DOMAIN_BY_TAG_KEY = "SELECT d.name FROM domain d "
            + "JOIN domain_tags dt ON dt.domain_id = d.domain_id WHERE dt.key=?";
    private static final String SQL_LOOKUP_DOMAIN_BY_TAG_KEY_VAL = "SELECT d.name FROM domain d "
            + "JOIN domain_tags dt ON dt.domain_id = d.domain_id WHERE dt.key=? AND dt.value=?";
    private static final String SQL_INSERT_GROUP_TAG = "INSERT INTO group_tags"
            + "(group_id, group_tags.key, group_tags.value) VALUES (?,?,?);";
    private static final String SQL_GROUP_TAG_COUNT = "SELECT COUNT(*) FROM group_tags WHERE group_id=?";
    private static final String SQL_DELETE_GROUP_TAG = "DELETE FROM group_tags WHERE group_id=? AND group_tags.key=?;";
    private static final String SQL_GET_GROUP_TAGS = "SELECT gt.key, gt.value FROM group_tags gt "
            + "JOIN principal_group g ON gt.group_id = g.group_id JOIN domain ON domain.domain_id=g.domain_id "
            + "WHERE domain.name=? AND g.name=?";
    private static final String SQL_GET_DOMAIN_GROUP_TAGS = "SELECT g.name, gt.key, gt.value FROM group_tags gt "
            + "JOIN principal_group g ON gt.group_id = g.group_id JOIN domain ON domain.domain_id=g.domain_id "
            + "WHERE domain.name=?";
    private static final String SQL_INSERT_SERVICE_TAG = "INSERT INTO service_tags"
            + "(service_id, service_tags.key, service_tags.value) VALUES (?,?,?);";
    private static final String SQL_SERVICE_TAG_COUNT = "SELECT COUNT(*) FROM service_tags WHERE service_id=?";
    private static final String SQL_DELETE_SERVICE_TAG = "DELETE FROM service_tags WHERE service_id=? AND service_tags.key=?;";
    private static final String SQL_GET_SERVICE_TAGS = "SELECT st.key, st.value FROM service_tags st "
            + "JOIN service s ON st.service_id = s.service_id JOIN domain ON domain.domain_id=s.domain_id "
            + "WHERE domain.name=? AND s.name=?";
    private static final String SQL_GET_DOMAIN_SERVICE_TAGS = "SELECT s.name, st.key, st.value FROM service_tags st "
            + "JOIN service s ON st.service_id = s.service_id JOIN domain ON domain.domain_id=s.domain_id "
            + "WHERE domain.name=?";
    private static final String SQL_GET_ASSERTION_CONDITIONS = "SELECT assertion_condition.condition_id, "
            + "assertion_condition.key, assertion_condition.operator, assertion_condition.value "
            + "FROM assertion_condition WHERE assertion_condition.assertion_id=? ORDER BY assertion_condition.condition_id;";
    private static final String SQL_GET_ASSERTION_CONDITION = "SELECT assertion_condition.key, assertion_condition.operator, assertion_condition.value, condition_id "
            + "FROM assertion_condition WHERE assertion_id=? AND condition_id=? ORDER BY condition_id;";
    private static final String SQL_COUNT_ASSERTION_CONDITIONS = "SELECT count(1) FROM assertion_condition WHERE assertion_id=?;";
    private static final String SQL_INSERT_ASSERTION_CONDITION = "INSERT INTO assertion_condition (assertion_id,condition_id,`key`,operator,`value`) VALUES (?,?,?,?,?);";
    private static final String SQL_DELETE_ASSERTION_CONDITION = "DELETE FROM assertion_condition WHERE assertion_id=? AND condition_id=?;";
    private static final String SQL_DELETE_ASSERTION_CONDITIONS = "DELETE FROM assertion_condition WHERE assertion_id=?;";
    private static final String SQL_GET_NEXT_CONDITION_ID = "SELECT IFNULL(MAX(condition_id)+1, 1) FROM assertion_condition WHERE assertion_id=?;";
    private static final String SQL_GET_DOMAIN_POLICY_ASSERTIONS_CONDITIONS = "SELECT assertion.assertion_id, "
            + "assertion_condition.condition_id, assertion_condition.key, assertion_condition.operator, assertion_condition.value "
            + "FROM assertion_condition JOIN assertion ON assertion_condition.assertion_id=assertion.assertion_id "
            + "JOIN policy ON policy.policy_id=assertion.policy_id "
            + "WHERE policy.domain_id=? ORDER BY assertion.assertion_id, assertion_condition.condition_id;";

    private static final String SQL_GET_POLICY_ASSERTIONS_CONDITIONS = "SELECT assertion.assertion_id, "
            + "assertion_condition.condition_id, assertion_condition.key, assertion_condition.operator, assertion_condition.value "
            + "FROM assertion_condition JOIN assertion ON assertion_condition.assertion_id=assertion.assertion_id "
            + "JOIN policy ON policy.policy_id=assertion.policy_id "
            + "WHERE policy.policy_id=? ORDER BY assertion.assertion_id, assertion_condition.condition_id;";

    private static final String SQL_GET_OBJECT_SYSTEM_COUNT = "SELECT COUNT(*) FROM ";
    private static final String SQL_GET_OBJECT_DOMAIN_COUNT = "SELECT COUNT(*) FROM ";
    private static final String SQL_GET_OBJECT_DOMAIN_COUNT_QUERY = " WHERE domain_id=?";
    private static final String SQL_GET_DOMAIN_ASSERTION_COUNT = "SELECT COUNT(*) from assertion JOIN policy on policy.policy_id=assertion.policy_id WHERE policy.domain_id=?;";
    private static final String SQL_GET_DOMAIN_ROLE_MEMBER_COUNT = "SELECT COUNT(*) from role_member JOIN role on role.role_id=role_member.role_id WHERE role.domain_id=?;";
    private static final String SQL_GET_DOMAIN_GROUP_MEMBER_COUNT = "SELECT COUNT(*) from principal_group_member JOIN principal_group on principal_group.group_id=principal_group_member.group_id WHERE principal_group.domain_id=?;";
    private static final String SQL_GET_DOMAIN_SERVICE_HOST_COUNT = "SELECT COUNT(*) from service_host JOIN service on service_host.service_id=service.service_id WHERE service.domain_id=?;";
    private static final String SQL_GET_DOMAIN_SERVICE_PUBLIC_KEY_COUNT = "SELECT COUNT(*) from public_key JOIN service on public_key.service_id=service.service_id WHERE service.domain_id=?;";
    private static final String SQL_GET_DOMAIN_PREFIX_COUNT = "SELECT COUNT(*) FROM domain WHERE name>=? AND name<?;";
    private static final String SQL_INSERT_DOMAIN_DEPENDENCY = "INSERT INTO service_domain_dependency (domain, service) VALUES (?,?);";
    private static final String SQL_DELETE_DOMAIN_DEPENDENCY = "DELETE FROM service_domain_dependency WHERE domain=? AND service=?;";
    private static final String SQL_LIST_SERVICE_DEPENDENCIES = "SELECT service FROM service_domain_dependency WHERE domain=?;";
    private static final String SQL_LIST_DOMAIN_DEPENDENCIES = "SELECT domain FROM service_domain_dependency WHERE service=?;";
    private static final String GET_ALL_EXPIRED_ROLE_MEMBERS = "SELECT D.name as domain_name, R.name as role_name, M.expiration, P.name as principal_name"
            + " FROM domain D JOIN role R ON D.domain_id = R.domain_id JOIN"
            + " role_member M ON R.role_id = M.role_id JOIN principal P ON M.principal_id = P.principal_id"
            + " WHERE D.member_purge_expiry_days > -1 AND M.expiration is not null"
            + " AND (D.member_purge_expiry_days = 0 AND CURRENT_DATE() >= DATE_ADD(DATE(M.expiration), INTERVAL ? DAY)"
            + " OR D.member_purge_expiry_days != 0 AND CURRENT_DATE() >= DATE_ADD(DATE(M.expiration), INTERVAL D.member_purge_expiry_days DAY))"
            + " limit ? offset ?";
    private static final String GET_ALL_EXPIRED_GROUP_MEMBERS = "SELECT D.name as domain_name, G.name as group_name, M.expiration, P.name as principal_name"
            + " FROM domain D JOIN principal_group G ON D.domain_id = G.domain_id JOIN"
            + " principal_group_member M ON G.group_id = M.group_id JOIN principal P ON M.principal_id = P.principal_id"
            + " WHERE D.member_purge_expiry_days > -1 AND M.expiration is not null"
            + " AND (D.member_purge_expiry_days = 0 AND CURRENT_DATE() >= DATE_ADD(DATE(M.expiration), INTERVAL ? DAY)"
            + " OR D.member_purge_expiry_days != 0 AND CURRENT_DATE() >= DATE_ADD(DATE(M.expiration), INTERVAL D.member_purge_expiry_days DAY))"
            + " limit ? offset ?";
    private static final String SQL_INSERT_POLICY_TAG = "INSERT INTO policy_tags"
            + "(policy_id, policy_tags.key, policy_tags.value) VALUES (?,?,?);";
    private static final String SQL_POLICY_TAG_COUNT = "SELECT COUNT(*) FROM policy_tags WHERE policy_id=?";
    private static final String SQL_DELETE_POLICY_TAG = "DELETE FROM policy_tags WHERE policy_id=? AND policy_tags.key=?;";
    private static final String SQL_GET_POLICY_TAGS = "SELECT pt.key, pt.value FROM policy_tags pt WHERE pt.policy_id=?;";
    private static final String SQL_GET_DOMAIN_POLICY_TAGS = "SELECT p.name, pt.key, pt.value, p.version FROM policy_tags pt "
            + "JOIN policy p ON pt.policy_id = p.policy_id JOIN domain ON domain.domain_id=p.domain_id "
            + "WHERE domain.name=?";
    private static final String SQL_ROLE_EXPIRY_LAST_NOTIFIED_TIME = "SELECT last_notified_time FROM role_member"
            + " WHERE last_notified_time IS NOT NULL ORDER BY last_notified_time DESC LIMIT 1;";
    private static final String SQL_ROLE_REVIEW_LAST_NOTIFIED_TIME = "SELECT review_last_notified_time FROM role_member"
            + " WHERE review_last_notified_time IS NOT NULL ORDER BY review_last_notified_time DESC LIMIT 1;";
    private static final String SQL_GROUP_EXPIRY_LAST_NOTIFIED_TIME = "SELECT last_notified_time FROM principal_group_member"
            + " WHERE last_notified_time IS NOT NULL ORDER BY last_notified_time DESC LIMIT 1;";
    private static final String SQL_GET_ROLE_REVIEW_LIST  = "SELECT domain.name AS domain_name, role.name AS role_name,"
            + " role.member_expiry_days, role.service_expiry_days, role.group_expiry_days, role.member_review_days,"
            + " role.service_review_days, role.group_review_days, role.last_reviewed_time, role.created FROM role"
            + " JOIN domain ON role.domain_id=domain.domain_id WHERE role.trust='' AND"
            + " (role.member_expiry_days!=0 OR role.service_expiry_days!=0 OR role.group_expiry_days!=0 OR"
            + " role.member_review_days!=0 OR role.service_review_days!=0 OR role.group_review_days!=0) AND"
            + " role.domain_id IN (SELECT domain.domain_id FROM domain JOIN role ON role.domain_id=domain.domain_id"
            + " JOIN role_member ON role.role_id=role_member.role_id WHERE role_member.principal_id=? AND"
            + " role_member.active=true AND role.name='admin') ORDER BY domain.name, role.name;";
    private static final String SQL_GET_GROUP_REVIEW_LIST = "SELECT domain.name AS domain_name, principal_group.name AS group_name,"
            + " principal_group.member_expiry_days, principal_group.service_expiry_days, principal_group.last_reviewed_time,"
            + " principal_group.created FROM principal_group JOIN domain ON principal_group.domain_id=domain.domain_id WHERE"
            + " (principal_group.member_expiry_days!=0 OR principal_group.service_expiry_days!=0) AND"
            + " principal_group.domain_id IN (SELECT domain.domain_id FROM domain JOIN role ON"
            + " role.domain_id=domain.domain_id JOIN role_member ON role.role_id=role_member.role_id"
            + " WHERE role_member.principal_id=? AND role_member.active=true AND role.name='admin')"
            + " ORDER BY domain.name, principal_group.name;";
    private static final String SQL_INSERT_DOMAIN_CONTACT = "INSERT INTO domain_contacts (domain_id, type, name) VALUES (?,?,?);";
    private static final String SQL_UPDATE_DOMAIN_CONTACT = "UPDATE domain_contacts SET name=? WHERE domain_id=? and type=?;";
    private static final String SQL_DELETE_DOMAIN_CONTACT = "DELETE FROM domain_contacts WHERE domain_id=? AND type=?;";
    private static final String SQL_LIST_CONTACT_DOMAINS = "SELECT domain.name, domain_contacts.type FROM domain_contacts "
            + "JOIN domain ON domain_contacts.domain_id=domain.domain_id "
            + "WHERE domain_contacts.name=?;";
    private static final String SQL_LIST_DOMAIN_CONTACTS = "SELECT type, name FROM domain_contacts WHERE domain_id=?;";
    private static final String SQL_GET_LAST_ASSUME_ROLE_ASSERTION = "SELECT policy.modified FROM policy "
            + " JOIN assertion ON policy.policy_id=assertion.policy_id WHERE assertion.action='assume_role' "
            + " ORDER BY policy.modified DESC LIMIT 1";
    private static final String SQL_SET_DOMAIN_RESOURCE_OWNERSHIP = "UPDATE domain SET resource_owner=? WHERE name=?;";
    private static final String SQL_SET_ROLE_RESOURCE_OWNERSHIP = "UPDATE role SET resource_owner=? WHERE domain_id=? AND name=?;";
    private static final String SQL_SET_GROUP_RESOURCE_OWNERSHIP = "UPDATE principal_group SET resource_owner=? WHERE domain_id=? AND name=?;";
    private static final String SQL_SET_POLICY_RESOURCE_OWNERSHIP = "UPDATE policy SET resource_owner=? WHERE domain_id=? AND name=?;";
    private static final String SQL_SET_SERVICE_RESOURCE_OWNERSHIP = "UPDATE service SET resource_owner=? WHERE domain_id=? AND name=?;";

    private static final String CACHE_DOMAIN    = "d:";
    private static final String CACHE_ROLE      = "r:";
    private static final String CACHE_GROUP     = "g:";
    private static final String CACHE_POLICY    = "p:";
    private static final String CACHE_SERVICE   = "s:";
    private static final String CACHE_PRINCIPAL = "u:";
    private static final String CACHE_HOST      = "h:";
    private static final String ALL_PRINCIPALS  = "*";

    private static final String MYSQL_SERVER_TIMEZONE = System.getProperty(ZMSConsts.ZMS_PROP_MYSQL_SERVER_TIMEZONE, "GMT");

    private int roleTagsLimit = ZMSConsts.ZMS_DEFAULT_TAG_LIMIT;
    private int groupTagsLimit = ZMSConsts.ZMS_DEFAULT_TAG_LIMIT;
    private int domainTagsLimit = ZMSConsts.ZMS_DEFAULT_TAG_LIMIT;
    private int policyTagsLimit = ZMSConsts.ZMS_DEFAULT_TAG_LIMIT;
    private int serviceTagsLimit = ZMSConsts.ZMS_DEFAULT_TAG_LIMIT;

    Connection con;
    int queryTimeout = 60;
    Map<String, Integer> objectMap;
    boolean transactionCompleted;
    DomainOptions domainOptions;
    private Object synchronizer = new Object();
    private volatile static Map<String, List<String>> SERVER_TRUST_ROLES_MAP;
    private volatile static long SERVER_TRUST_ROLES_TIMESTAMP;
    private static final long SERVER_TRUST_ROLES_UPDATE_TIMEOUT = Long.parseLong(
            System.getProperty(ZMSConsts.ZMS_PROP_MYSQL_SERVER_TRUST_ROLES_UPDATE_TIMEOUT, "600000"));

    public JDBCConnection(Connection con, boolean autoCommit) throws SQLException {
        this.con = con;
        con.setAutoCommit(autoCommit);
        transactionCompleted = autoCommit;
        objectMap = new HashMap<>();
    }

    public void setObjectSynchronizer(Object synchronizer) {
        this.synchronizer = synchronizer;
    }

    /**
     * Used only by the test classes to reset the server trust roles map
     */
    void resetTrustRolesMap() {
        SERVER_TRUST_ROLES_MAP = null;
        SERVER_TRUST_ROLES_TIMESTAMP = 0;
    }

    @Override
    public void setDomainOptions(DomainOptions domainOptions) {
        this.domainOptions = domainOptions;
    }

    @Override
    public void setOperationTimeout(int queryTimeout) {
        this.queryTimeout = queryTimeout;
    }

    @Override
    public void setTagLimit(int domainLimit, int roleLimit, int groupLimit, int policyLimit, int serviceTagsLimit) {
        this.domainTagsLimit = domainLimit;
        this.roleTagsLimit = roleLimit;
        this.groupTagsLimit = groupLimit;
        this.policyTagsLimit = policyLimit;
        this.serviceTagsLimit = serviceTagsLimit;
    }

    @Override
    public void close() {

        if (con == null) {
            return;
        }

        // the client is always responsible for properly committing
        // all changes before closing the connection, but in case
        // we missed it, we're going to be safe and commit all
        // changes before closing the connection

        try {
            commitChanges();
        } catch (Exception ex) {
            // error is already logged but we have to continue
            // processing so we can close our connection
        }

        try {
            con.close();
            con = null;
        } catch (SQLException ex) {
            LOG.error("close: state - {}, code - {}, message - {}", ex.getSQLState(),
                    ex.getErrorCode(), ex.getMessage());
        }
    }

    @Override
    public void rollbackChanges() {

        if (LOG.isDebugEnabled()) {
            LOG.debug("rollback transaction changes...");
        }

        if (transactionCompleted) {
            return;
        }

        try {
            con.rollback();
        } catch (SQLException ex) {
            LOG.error("rollbackChanges: state - {}, code - {}, message - {}", ex.getSQLState(),
                    ex.getErrorCode(), ex.getMessage());
        }

        transactionCompleted = true;
        try {
            con.setAutoCommit(true);
        } catch (SQLException ex) {
            LOG.error("rollback auto-commit after failure: state - {}, code - {}, message - {}",
                    ex.getSQLState(), ex.getErrorCode(), ex.getMessage());
        }
    }

    @Override
    public void commitChanges() {

        final String caller = "commitChanges";
        if (transactionCompleted) {
            return;
        }

        try {
            con.commit();
            transactionCompleted = true;
            con.setAutoCommit(true);
        } catch (SQLException ex) {
            LOG.error("commitChanges: state - {}, code - {}, message - {}", ex.getSQLState(),
                    ex.getErrorCode(), ex.getMessage());
            transactionCompleted = true;
            throw sqlError(ex, caller);
        }
    }

    int executeUpdate(PreparedStatement ps, String caller) throws SQLException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("{}: {}", caller, ps.toString());
        }
        ps.setQueryTimeout(queryTimeout);
        return ps.executeUpdate();
    }

    ResultSet executeQuery(PreparedStatement ps, String caller) throws SQLException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("{}: {}", caller, ps.toString());
        }
        ps.setQueryTimeout(queryTimeout);
        return ps.executeQuery();
    }

    int[] executeBatch(PreparedStatement ps, String caller) throws SQLException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("{}: {}", caller, ps.toString());
        }
        ps.setQueryTimeout(queryTimeout);
        return ps.executeBatch();
    }

    Domain saveDomainSettings(String domainName, ResultSet rs, boolean fetchAddlDetails) throws SQLException {
        Domain domain = new Domain().setName(domainName)
                .setAuditEnabled(rs.getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED))
                .setEnabled(rs.getBoolean(ZMSConsts.DB_COLUMN_ENABLED))
                .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                .setDescription(saveValue(rs.getString(ZMSConsts.DB_COLUMN_DESCRIPTION)))
                .setOrg(saveValue(rs.getString(ZMSConsts.DB_COLUMN_ORG)))
                .setId(saveUuidValue(rs.getString(ZMSConsts.DB_COLUMN_UUID)))
                .setAccount(saveValue(rs.getString(ZMSConsts.DB_COLUMN_ACCOUNT)))
                .setAzureSubscription(saveValue(rs.getString(ZMSConsts.DB_COLUMN_AZURE_SUBSCRIPTION)))
                .setGcpProject(saveValue(rs.getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_ID)))
                .setGcpProjectNumber(saveValue(rs.getString(ZMSConsts.DB_COLUMN_GCP_PROJECT_NUMBER)))
                .setYpmId(rs.getInt(ZMSConsts.DB_COLUMN_YPM_ID))
                .setProductId(saveValue(rs.getString(ZMSConsts.DB_COLUMN_PRODUCT_ID)))
                .setCertDnsDomain(saveValue(rs.getString(ZMSConsts.DB_COLUMN_CERT_DNS_DOMAIN)))
                .setMemberExpiryDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_MEMBER_EXPIRY_DAYS), 0))
                .setTokenExpiryMins(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_TOKEN_EXPIRY_MINS), 0))
                .setRoleCertExpiryMins(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_ROLE_CERT_EXPIRY_MINS), 0))
                .setServiceCertExpiryMins(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_SERVICE_CERT_EXPIRY_MINS), 0))
                .setApplicationId(saveValue(rs.getString(ZMSConsts.DB_COLUMN_APPLICATION_ID)))
                .setSignAlgorithm(saveValue(rs.getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM)))
                .setServiceExpiryDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_SERVICE_EXPIRY_DAYS), 0))
                .setGroupExpiryDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_GROUP_EXPIRY_DAYS), 0))
                .setUserAuthorityFilter(saveValue(rs.getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER)))
                .setBusinessService(saveValue(rs.getString(ZMSConsts.DB_COLUMN_BUSINESS_SERVICE)))
                .setMemberPurgeExpiryDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_MEMBER_PURGE_EXPIRY_DAYS), 0))
                .setFeatureFlags(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_FEATURE_FLAGS), 0))
                .setEnvironment(saveValue(rs.getString(ZMSConsts.DB_COLUMN_ENVIRONMENT)))
                .setResourceOwnership(ResourceOwnership.getResourceDomainOwnership(rs.getString(ZMSConsts.DB_COLUMN_RESOURCE_OWNER)));
        if (fetchAddlDetails) {
            int domainId = rs.getInt(ZMSConsts.DB_COLUMN_DOMAIN_ID);
            domain.setTags(getDomainTags(domainId));
            domain.setContacts(getDomainContacts(domainId));
        }
        return domain;
    }

    @Override
    public Domain getDomain(String domainName) {

        final String caller = "getDomain";
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN)) {
            ps.setString(1, domainName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    return saveDomainSettings(domainName, rs, true);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return null;
    }

    @Override
    public boolean insertDomain(Domain domain) {

        int affectedRows;
        final String caller = "insertDomain";

        // we need to verify that our account and product ids are unique
        // in the store. we can't rely on db uniqueness check since
        // some of the domains will not have these attributes set

        verifyDomainAwsAccountUniqueness(domain.getName(), domain.getAccount(), caller);
        verifyDomainAzureSubscriptionUniqueness(domain.getName(), domain.getAzureSubscription(), caller);
        verifyDomainGcpProjectUniqueness(domain.getName(), domain.getGcpProject(), caller);
        verifyDomainProductIdUniqueness(domain.getName(), domain.getYpmId(), caller);
        verifyDomainProductIdUniqueness(domain.getName(), domain.getProductId(), caller);
        verifyDomainNameDashUniqueness(domain.getName(), caller);

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_DOMAIN)) {
            ps.setString(1, domain.getName());
            ps.setString(2, processInsertValue(domain.getDescription()));
            ps.setString(3, processInsertValue(domain.getOrg()));
            ps.setString(4, processInsertUuidValue(domain.getId()));
            ps.setBoolean(5, processInsertValue(domain.getEnabled(), true));
            ps.setBoolean(6, processInsertValue(domain.getAuditEnabled(), false));
            ps.setString(7, processInsertValue(domain.getAccount()));
            ps.setInt(8, processInsertValue(domain.getYpmId()));
            ps.setString(9, processInsertValue(domain.getApplicationId()));
            ps.setString(10, processInsertValue(domain.getCertDnsDomain()));
            ps.setInt(11, processInsertValue(domain.getMemberExpiryDays()));
            ps.setInt(12, processInsertValue(domain.getTokenExpiryMins()));
            ps.setInt(13, processInsertValue(domain.getServiceCertExpiryMins()));
            ps.setInt(14, processInsertValue(domain.getRoleCertExpiryMins()));
            ps.setString(15, processInsertValue(domain.getSignAlgorithm()));
            ps.setInt(16, processInsertValue(domain.getServiceExpiryDays()));
            ps.setString(17, processInsertValue(domain.getUserAuthorityFilter()));
            ps.setInt(18, processInsertValue(domain.getGroupExpiryDays()));
            ps.setString(19, processInsertValue(domain.getAzureSubscription()));
            ps.setString(20, processInsertValue(domain.getBusinessService()));
            ps.setInt(21, processInsertValue(domain.getMemberPurgeExpiryDays()));
            ps.setString(22, processInsertValue(domain.getGcpProject()));
            ps.setString(23, processInsertValue(domain.getGcpProjectNumber()));
            ps.setString(24, processInsertValue(domain.getProductId()));
            ps.setInt(25, processInsertValue(domain.getFeatureFlags()));
            ps.setString(26, processInsertValue(domain.getEnvironment()));
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    void verifyDomainNameDashUniqueness(final String name, String caller) {

        // with our certificates we replace .'s with -'s
        // so we need to make sure we don't allow creation
        // of domains such as sports.api and sports-api since
        // they'll have the same component value

        final String domainMatch = name.replace('.', '-');
        final String domainQuery = name.replace('.', '_').replace('-', '_');

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAINS_WITH_NAME)) {
            ps.setString(1, domainQuery);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    final String domainName = rs.getString(1);
                    if (domainMatch.equals(domainName.replace('.', '-'))) {
                        throw requestError(caller, "Domain name conflict: " + domainName);
                    }
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    void verifyDomainProductIdUniqueness(final String name, Integer productNumber, final String caller) {

        if (productNumber == null || productNumber == 0) {
            return;
        }
        if (domainOptions != null && !domainOptions.getEnforceUniqueProductIds()) {
            return;
        }
        final String domainName = lookupDomainByProductId(productNumber);
        if (domainName != null && !domainName.equals(name)) {
            throw requestError(caller, "Product Id: " + productNumber + " is already assigned to domain: " + domainName);
        }
    }

    void verifyDomainProductIdUniqueness(final String name, String productId, final String caller) {

        if (StringUtil.isEmpty(productId)) {
            return;
        }
        if (domainOptions != null && !domainOptions.getEnforceUniqueProductIds()) {
            return;
        }
        final String domainName = lookupDomainByProductId(productId);
        if (domainName != null && !domainName.equals(name)) {
            throw requestError(caller, "Product Id: " + productId + " is already assigned to domain: " + domainName);
        }
    }

    void verifyDomainAwsAccountUniqueness(final String name, final String account, final String caller) {

        if (StringUtil.isEmpty(account)) {
            return;
        }
        if (domainOptions != null && !domainOptions.getEnforceUniqueAWSAccounts()) {
            return;
        }
        final String domainName = lookupDomainByCloudProvider(ObjectStoreConnection.PROVIDER_AWS, account);
        if (domainName != null && !domainName.equals(name)) {
            throw requestError(caller, "Account Id: " + account + " is already assigned to domain: " + domainName);
        }
    }

    void verifyDomainAzureSubscriptionUniqueness(final String name, final String subscription, final String caller) {

        if (StringUtil.isEmpty(subscription)) {
            return;
        }
        if (domainOptions != null && !domainOptions.getEnforceUniqueAzureSubscriptions()) {
            return;
        }
        final String domainName = lookupDomainByCloudProvider(ObjectStoreConnection.PROVIDER_AZURE, subscription);
        if (domainName != null && !domainName.equals(name)) {
            throw requestError(caller, "Subscription Id: " + subscription + " is already assigned to domain: " + domainName);
        }
    }

    void verifyDomainGcpProjectUniqueness(final String name, final String project, final String caller) {

        if (StringUtil.isEmpty(project)) {
            return;
        }
        if (domainOptions != null && !domainOptions.getEnforceUniqueGCPProjects()) {
            return;
        }
        final String domainName = lookupDomainByCloudProvider(ObjectStoreConnection.PROVIDER_GCP, project);
        if (domainName != null && !domainName.equals(name)) {
            throw requestError(caller, "Project: " + project + " is already assigned to domain: " + domainName);
        }
    }

    @Override
    public boolean updateDomain(Domain domain) {

        int affectedRows;
        final String caller = "updateDomain";

        // we need to verify that our account and product ids are unique
        // in the store. we can't rely on db uniqueness check since
        // some of the domains will not have these attributes set

        verifyDomainAwsAccountUniqueness(domain.getName(), domain.getAccount(), caller);
        verifyDomainAzureSubscriptionUniqueness(domain.getName(), domain.getAzureSubscription(), caller);
        verifyDomainGcpProjectUniqueness(domain.getName(), domain.getGcpProject(), caller);
        verifyDomainProductIdUniqueness(domain.getName(), domain.getYpmId(), caller);
        verifyDomainProductIdUniqueness(domain.getName(), domain.getProductId(), caller);

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_DOMAIN)) {
            ps.setString(1, processInsertValue(domain.getDescription()));
            ps.setString(2, processInsertValue(domain.getOrg()));
            ps.setString(3, processInsertUuidValue(domain.getId()));
            ps.setBoolean(4, processInsertValue(domain.getEnabled(), true));
            ps.setBoolean(5, processInsertValue(domain.getAuditEnabled(), false));
            ps.setString(6, processInsertValue(domain.getAccount()));
            ps.setInt(7, processInsertValue(domain.getYpmId()));
            ps.setString(8, processInsertValue(domain.getApplicationId()));
            ps.setString(9, processInsertValue(domain.getCertDnsDomain()));
            ps.setInt(10, processInsertValue(domain.getMemberExpiryDays()));
            ps.setInt(11, processInsertValue(domain.getTokenExpiryMins()));
            ps.setInt(12, processInsertValue(domain.getServiceCertExpiryMins()));
            ps.setInt(13, processInsertValue(domain.getRoleCertExpiryMins()));
            ps.setString(14, processInsertValue(domain.getSignAlgorithm()));
            ps.setInt(15, processInsertValue(domain.getServiceExpiryDays()));
            ps.setString(16, processInsertValue(domain.getUserAuthorityFilter()));
            ps.setInt(17, processInsertValue(domain.getGroupExpiryDays()));
            ps.setString(18, processInsertValue(domain.getAzureSubscription()));
            ps.setString(19, processInsertValue(domain.getBusinessService()));
            ps.setInt(20, processInsertValue(domain.getMemberPurgeExpiryDays()));
            ps.setString(21, processInsertValue(domain.getGcpProject()));
            ps.setString(22, processInsertValue(domain.getGcpProjectNumber()));
            ps.setString(23, processInsertValue(domain.getProductId()));
            ps.setInt(24, processInsertValue(domain.getFeatureFlags()));
            ps.setString(25, processInsertValue(domain.getEnvironment()));
            ps.setString(26, domain.getName());
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        // invalidate the cache domain entry

        objectMap.remove(CACHE_DOMAIN + domain.getName());
        return (affectedRows > 0);
    }

    @Override
    public boolean updateDomainModTimestamp(String domainName) {

        int affectedRows;
        final String caller = "updateDomainModTimestamp";

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_DOMAIN_MOD_TIMESTAMP)) {
            ps.setString(1, domainName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public long getDomainModTimestamp(String domainName) {

        long modTime = 0;
        final String caller = "getDomainModTimestamp";

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_MOD_TIMESTAMP)) {
            ps.setString(1, domainName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    modTime = rs.getTimestamp(1).getTime();
                }
            }
        } catch (SQLException ex) {
            // ignore any failures and return default value 0
        }
        return modTime;
    }

    @Override
    public boolean deleteDomain(String domainName) {

        int affectedRows;
        final String caller = "deleteDomain";

        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_DOMAIN)) {
            ps.setString(1, domainName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    PreparedStatement prepareDomainScanStatement(String prefix, long modifiedSince)
            throws SQLException {

        PreparedStatement ps;
        if (!StringUtil.isEmpty(prefix)) {
            int len = prefix.length();
            char c = (char) (prefix.charAt(len - 1) + 1);
            String stop = prefix.substring(0, len - 1) + c;
            if (modifiedSince != 0) {
                ps = con.prepareStatement(SQL_LIST_DOMAIN_PREFIX_MODIFIED);
                ps.setString(1, prefix);
                ps.setString(2, stop);
                Calendar cal = Calendar.getInstance(TimeZone.getTimeZone(MYSQL_SERVER_TIMEZONE));
                ps.setTimestamp(3, new java.sql.Timestamp(modifiedSince), cal);
            } else {
                ps = con.prepareStatement(SQL_LIST_DOMAIN_PREFIX);
                ps.setString(1, prefix);
                ps.setString(2, stop);
            }
        } else if (modifiedSince != 0) {
            ps = con.prepareStatement(SQL_LIST_DOMAIN_MODIFIED);
            Calendar cal = Calendar.getInstance(TimeZone.getTimeZone(MYSQL_SERVER_TIMEZONE));
            ps.setTimestamp(1, new java.sql.Timestamp(modifiedSince), cal);
        } else {
            ps = con.prepareStatement(SQL_LIST_DOMAIN);
        }
        return ps;
    }

    PreparedStatement prepareScanByRoleStatement(String roleMember, String roleName)
            throws SQLException {

        PreparedStatement ps;
        boolean memberPresent = (roleMember != null && !roleMember.isEmpty());
        boolean rolePresent = (roleName != null && !roleName.isEmpty());
        if (memberPresent && rolePresent) {
            ps = con.prepareStatement(SQL_LIST_DOMAIN_ROLE_NAME_MEMBER);
            ps.setString(1, roleMember);
            ps.setString(2, roleName);
        } else if (memberPresent) {
            ps = con.prepareStatement(SQL_LIST_DOMAIN_ROLE_MEMBER);
            ps.setString(1, roleMember);
        } else if (rolePresent) {
            ps = con.prepareStatement(SQL_LIST_DOMAIN_ROLE_NAME);
            ps.setString(1, roleName);
        } else {
            ps = con.prepareStatement(SQL_LIST_DOMAIN);
        }
        return ps;
    }

    @Override
    public List<String> lookupDomainByRole(String roleMember, String roleName) {

        final String caller = "lookupDomainByRole";

        // it's possible that we'll get duplicate domain names returned
        // from this result - e.g. when no role name is filtered on so
        // we're going to automatically skip those by using a set

        Set<String> uniqueDomains = new HashSet<>();
        try (PreparedStatement ps = prepareScanByRoleStatement(roleMember, roleName)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    uniqueDomains.add(rs.getString(ZMSConsts.DB_COLUMN_NAME));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        List<String> domains = new ArrayList<>(uniqueDomains);
        Collections.sort(domains);
        return domains;
    }

    @Override
    public List<String> lookupDomainByBusinessService(String businessService) {

        final String caller = "lookupDomainByBusinessService";

        List<String> domains = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_DOMAIN_WITH_BUSINESS_SERVICE)) {
            ps.setString(1, businessService.trim());
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    domains.add(rs.getString(ZMSConsts.DB_COLUMN_NAME));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return domains;
    }

    @Override
    public String lookupDomainByProductId(int productId) {

        final String caller = "lookupDomainByProductId";
        String domainName = null;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_WITH_YPM_ID)) {
            ps.setInt(1, productId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    domainName = rs.getString(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return domainName;
    }

    @Override
    public String lookupDomainByProductId(String productId) {

        final String caller = "lookupDomainByProductId";
        String domainName = null;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_WITH_PRODUCT_ID)) {
            ps.setString(1, productId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    domainName = rs.getString(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return domainName;
    }

    String getCloudProviderLookupDomainSQLCommand(final String provider) {
        if (provider == null) {
            return null;
        }
        switch (provider.toLowerCase()) {
            case ObjectStoreConnection.PROVIDER_AWS:
                return SQL_GET_DOMAIN_WITH_AWS_ACCOUNT;
            case ObjectStoreConnection.PROVIDER_AZURE:
                return SQL_GET_DOMAIN_WITH_AZURE_SUBSCRIPTION;
            case ObjectStoreConnection.PROVIDER_GCP:
                return SQL_GET_DOMAIN_WITH_GCP_PROJECT;
        }
        return null;
    }

    String getCloudProviderListDomainsSQLCommand(final String provider) {
        if (provider == null) {
            return null;
        }
        switch (provider.toLowerCase()) {
            case ObjectStoreConnection.PROVIDER_AWS:
                return SQL_LIST_DOMAINS_WITH_AWS_ACCOUNT;
            case ObjectStoreConnection.PROVIDER_AZURE:
                return SQL_LIST_DOMAINS_WITH_AZURE_SUBSCRIPTION;
            case ObjectStoreConnection.PROVIDER_GCP:
                return SQL_LIST_DOMAINS_WITH_GCP_PROJECT;
        }
        return null;
    }

    String getCloudProviderColumnName(final String provider) {
        if (provider == null) {
            return null;
        }
        switch (provider.toLowerCase()) {
            case ObjectStoreConnection.PROVIDER_AWS:
                return DB_COLUMN_ACCOUNT;
            case ObjectStoreConnection.PROVIDER_AZURE:
                return DB_COLUMN_AZURE_SUBSCRIPTION;
            case ObjectStoreConnection.PROVIDER_GCP:
                return DB_COLUMN_GCP_PROJECT_ID;
        }
        return null;
    }

    @Override
    public String lookupDomainByCloudProvider(String provider, String value) {

        final String caller = "lookupDomainByCloudProvider";
        final String sqlCmd = getCloudProviderLookupDomainSQLCommand(provider);
        if (sqlCmd == null || value == null) {
            return null;
        }
        String domainName = null;
        try (PreparedStatement ps = con.prepareStatement(sqlCmd)) {
            ps.setString(1, value.trim());
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    domainName = rs.getString(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return domainName;
    }

    @Override
    public Map<String, String> listDomainsByCloudProvider(String provider) {

        final String caller = "listDomainByCloudProvider";
        final String sqlCmd = getCloudProviderListDomainsSQLCommand(provider);
        if (sqlCmd == null) {
            return null;
        }
        final String columnName = getCloudProviderColumnName(provider);
        Map<String, String> domains = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(sqlCmd)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    domains.put(rs.getString(ZMSConsts.DB_COLUMN_NAME), rs.getString(columnName));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return domains;
    }

    @Override
    public List<String> listDomains(String prefix, long modifiedSince) {

        final String caller = "listDomains";

        List<String> domains = new ArrayList<>();
        try (PreparedStatement ps = prepareDomainScanStatement(prefix, modifiedSince)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    domains.add(rs.getString(ZMSConsts.DB_COLUMN_NAME));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        Collections.sort(domains);
        return domains;
    }

    public boolean deleteDomainTags(String domainName, Set<String> tagsToRemove) {
        final String caller = "deleteDomainTags";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        boolean res = true;
        for (String tagKey : tagsToRemove) {
            try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_DOMAIN_TAG)) {
                ps.setInt(1, domainId);
                ps.setString(2, processInsertValue(tagKey));
                res &= (executeUpdate(ps, caller) > 0);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }
        return res;
    }

    public boolean insertDomainTags(String domainName, Map<String, TagValueList> tags) {
        final String caller = "updateDomainTags";
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int curTagCount = getDomainTagsCount(domainId);
        int newTagCount = calculateTagCount(tags);
        if (curTagCount + newTagCount > domainTagsLimit) {
            throw requestError(caller, "domain tag quota exceeded - limit: "
                + domainTagsLimit + ", current tags count: " + curTagCount + ", new tags count: " + newTagCount);
        }

        boolean res = true;
        for (Map.Entry<String, TagValueList> e : tags.entrySet()) {
            for (String tagValue : e.getValue().getList()) {
                try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_DOMAIN_TAG)) {
                    ps.setInt(1, domainId);
                    ps.setString(2, processInsertValue(e.getKey()));
                    ps.setString(3, processInsertValue(tagValue));
                    res &= (executeUpdate(ps, caller) > 0);
                } catch (SQLException ex) {
                    throw sqlError(ex, caller);
                }
            }
        }

        return res;
    }

    private int calculateTagCount(Map<String, TagValueList> tags) {
        int count = 0;
        for (Map.Entry<String, TagValueList> e : tags.entrySet()) {
            count += e.getValue().getList().size();
        }
        return count;
    }

    int getDomainTagsCount(int domainId) {
        final String caller = "getDomainTagsCount";
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_DOMAIN_TAG_COUNT)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    public Map<String, TagValueList> getDomainTags(int domainId) {
        final String caller = "getDomainTags";
        Map<String, TagValueList> domainTag = null;

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_TAGS)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String tagKey = rs.getString(1);
                    String tagValue = rs.getString(2);
                    if (domainTag == null) {
                        domainTag = new HashMap<>();
                    }
                    TagValueList tagValues = domainTag.computeIfAbsent(tagKey, k -> new TagValueList().setList(new ArrayList<>()));
                    tagValues.getList().add(tagValue);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return domainTag;
    }

    public List<String> lookupDomainByTags(String tagKey, String tagValue) {
        final String caller = "lookupDomainByTags";

        // since domain tag might include multiple values - duplicates
        // are possible. use Set to avoid duplicates

        Set<String> uniqueDomains = new HashSet<>();

        try (PreparedStatement ps = prepareScanByTags(tagKey, tagValue)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    uniqueDomains.add(rs.getString(ZMSConsts.DB_COLUMN_NAME));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        List<String> domains = new ArrayList<>(uniqueDomains);
        Collections.sort(domains);
        return domains;
    }

    PreparedStatement prepareScanByTags(String tagKey, String tagValue) throws SQLException {
        PreparedStatement ps;
        if (!StringUtil.isEmpty(tagValue)) {
            ps = con.prepareStatement(SQL_LOOKUP_DOMAIN_BY_TAG_KEY_VAL);
            ps.setString(1, tagKey);
            ps.setString(2, tagValue);
        } else {
            ps = con.prepareStatement(SQL_LOOKUP_DOMAIN_BY_TAG_KEY);
            ps.setString(1, tagKey);
        }
        return ps;
    }

    @Override
    public boolean insertDomainTemplate(String domainName, String templateName, String params) {

        final String caller = "insertDomainTemplate";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_DOMAIN_TEMPLATE)) {
            ps.setInt(1, domainId);
            ps.setString(2, templateName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateDomainTemplate(String domainName, String templateName, TemplateMetaData templateMetaData) {

        final String caller = "updateDomainTemplate";
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_DOMAIN_TEMPLATE)) {
            ps.setInt(1, templateMetaData.getLatestVersion());
            ps.setInt(2, domainId);
            ps.setString(3, templateName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }


    @Override
    public boolean deleteDomainTemplate(String domainName, String templateName, String params) {

        final String caller = "deleteDomainTemplate";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_DOMAIN_TEMPLATE)) {
            ps.setInt(1, domainId);
            ps.setString(2, templateName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public List<String> listDomainTemplates(String domainName) {

        final String caller = "listDomainTemplates";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        List<String> templates = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_DOMAIN_TEMPLATE)) {
            ps.setString(1, domainName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    templates.add(rs.getString(1));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        Collections.sort(templates);
        return templates;
    }

    @Override
    public Map<String, List<String>> getDomainFromTemplateName(Map<String, Integer> templateNameAndLatestVersion) {
        final String caller = "getDomainsFromTemplate";
        Map<String, List<String>> domainNameTemplateListMap = new HashMap<>();

        try (PreparedStatement ps = con.prepareStatement(generateDomainTemplateVersionQuery(templateNameAndLatestVersion))) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String domainName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    String templateName = rs.getString(ZMSConsts.DB_COLUMN_TEMPLATE_NAME);
                    if (domainNameTemplateListMap.get(domainName) != null) {
                        List<String> tempTemplateList = domainNameTemplateListMap.get(domainName);
                        tempTemplateList.add(templateName);
                    } else {
                        List<String> templateList = new ArrayList<>();
                        templateList.add(templateName);
                        domainNameTemplateListMap.put(domainName, templateList);
                    }
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return domainNameTemplateListMap;
    }

    int getDomainId(String domainName) {
        return getDomainId(domainName, false);
    }

    int getDomainId(String domainName, boolean domainStateCheck) {

        final String caller = "getDomainId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server

        final String cacheKey = CACHE_DOMAIN + domainName;
        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }

        int domainId = 0;
        final String sqlCommand = domainStateCheck ? SQL_GET_ACTIVE_DOMAIN_ID : SQL_GET_DOMAIN_ID;
        try (PreparedStatement ps = con.prepareStatement(sqlCommand)) {
            ps.setString(1, domainName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    domainId = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            LOG.error("unable to get domain id for name: {} error code: {} msg: {}",
                    domainName, ex.getErrorCode(), ex.getMessage());
        }

        // before returning the value update our cache

        if (domainId != 0) {
            objectMap.put(cacheKey, domainId);
        }

        return domainId;
    }

    int getPolicyId(int domainId, String policyName, String version) {

        final String caller = "getPolicyId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server

        final String cacheKey = StringUtil.isEmpty(version) ? null : CACHE_POLICY + domainId + '.' + policyName + '.' + version;

        if (cacheKey != null) {
            Integer value = objectMap.get(cacheKey);
            if (value != null) {
                return value;
            }
        }

        int policyId = 0;
        try (PreparedStatement ps = con.prepareStatement(StringUtil.isEmpty(version) ? SQL_GET_ACTIVE_POLICY_ID : SQL_GET_POLICY_VERSION_ID)) {
            ps.setInt(1, domainId);
            ps.setString(2, policyName);
            if (!StringUtil.isEmpty(version)) {
                ps.setString(3, version);
            }
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    policyId = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            LOG.error("unable to get policy id for name: {} error code: {} msg: {}",
                    policyName, ex.getErrorCode(), ex.getMessage());
        }

        // before returning the value update our cache

        if (policyId != 0 && cacheKey != null) {
            objectMap.put(cacheKey, policyId);
        }

        return policyId;
    }

    int getRoleId(int domainId, String roleName) {

        final String caller = "getRoleId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server

        final String cacheKey = CACHE_ROLE + domainId + '.' + roleName;

        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }

        int roleId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ROLE_ID)) {
            ps.setInt(1, domainId);
            ps.setString(2, roleName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    roleId = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            LOG.error("unable to get role id for name: {} error code: {} msg: {}",
                    roleName, ex.getErrorCode(), ex.getMessage());
        }

        // before returning the value update our cache

        if (roleId != 0) {
            objectMap.put(cacheKey, roleId);
        }

        return roleId;
    }

    int getGroupId(int domainId, final String groupName) {

        final String caller = "getGroupId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server

        final String cacheKey = CACHE_GROUP + domainId + '.' + groupName;

        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }

        int groupId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_GROUP_ID)) {
            ps.setInt(1, domainId);
            ps.setString(2, groupName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    groupId = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            LOG.error("unable to get group id for name: {} error code: {} msg: {}",
                    groupName, ex.getErrorCode(), ex.getMessage());
        }

        // before returning the value update our cache

        if (groupId != 0) {
            objectMap.put(cacheKey, groupId);
        }

        return groupId;
    }

    int getServiceId(int domainId, String serviceName) {

        final String caller = "getServiceId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server

        final String cacheKey = CACHE_SERVICE + domainId + '.' + serviceName;

        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }

        int serviceId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_SERVICE_ID)) {
            ps.setInt(1, domainId);
            ps.setString(2, serviceName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    serviceId = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            LOG.error("unable to get service id for name: {} error code: {} msg: {}",
                    serviceName, ex.getErrorCode(), ex.getMessage());
        }

        // before returning the value update our cache

        if (serviceId != 0) {
            objectMap.put(cacheKey, serviceId);
        }

        return serviceId;
    }

    int getPrincipalId(String principal) {

        final String caller = "getPrincipalId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server

        final String cacheKey = CACHE_PRINCIPAL + principal;
        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }

        int principalId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_PRINCIPAL_ID)) {
            ps.setString(1, principal);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    principalId = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            LOG.error("unable to get principal id for name: {} error code: {} msg: {}",
                    principal, ex.getErrorCode(), ex.getMessage());
        }

        // before returning the value update our cache

        if (principalId != 0) {
            objectMap.put(cacheKey, principalId);
        }

        return principalId;
    }

    int getHostId(String hostName) {

        final String caller = "getHostId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server

        final String cacheKey = CACHE_HOST + hostName;
        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }

        int hostId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_HOST_ID)) {
            ps.setString(1, hostName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    hostId = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            LOG.error("unable to get host id for name: {} error code: {} msg: {}",
                    hostName, ex.getErrorCode(), ex.getMessage());
        }

        // before returning the value update our cache

        if (hostId != 0) {
            objectMap.put(cacheKey, hostId);
        }

        return hostId;
    }

    int getLastInsertId() {

        int lastInsertId = 0;
        final String caller = "getLastInsertId";

        try (PreparedStatement ps = con.prepareStatement(SQL_LAST_INSERT_ID)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    lastInsertId = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            LOG.error("unable to get last insert id - error code: {} msg: {}",
                    ex.getErrorCode(), ex.getMessage());
        }
        return lastInsertId;
    }

    PreparedStatement preparePrincipalScanStatement(String domainName)
            throws SQLException {

        PreparedStatement ps;
        if (!StringUtils.isEmpty(domainName)) {
            ps = con.prepareStatement(SQL_LIST_PRINCIPAL_DOMAIN);
            ps.setString(1, domainName + ".%");
            ps.setString(2, domainName + ":group.%");
        } else {
            ps = con.prepareStatement(SQL_LIST_PRINCIPAL);
        }
        return ps;
    }

    @Override
    public List<String> listPrincipals(String domainName) {

        final String caller = "listPrincipals";

        List<String> principals = new ArrayList<>();
        try (PreparedStatement ps = preparePrincipalScanStatement(domainName)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    principals.add(rs.getString(ZMSConsts.DB_COLUMN_NAME));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return principals;
    }

    @Override
    public boolean deletePrincipal(String principalName, boolean subDomains) {

        final String caller = "deletePrincipal";

        // first we're going to delete the principal from the principal table

        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_PRINCIPAL)) {
            ps.setString(1, principalName);
            executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        // next delete any principal that was created in the principal's
        // sub-domains. These will be in the format "principal.%"

        if (subDomains) {
            final String domainPattern = principalName + ".%";
            try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_SUB_PRINCIPALS)) {
                ps.setString(1, domainPattern);
                executeUpdate(ps, caller);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }

        return true;
    }

    @Override
    public Role getRole(String domainName, String roleName) {

        final String caller = "getRole";

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ROLE)) {
            ps.setString(1, domainName);
            ps.setString(2, roleName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    return retrieveRole(rs, domainName, roleName);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return null;
    }

    @Override
    public boolean insertRole(String domainName, Role role) {

        int affectedRows;
        final String caller = "insertRole";

        String roleName = ZMSUtils.extractRoleName(domainName, role.getName());
        if (roleName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " insert role name: " + role.getName());
        }

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        java.sql.Timestamp lastReviewedTime = role.getLastReviewedDate() == null ? null :
                new java.sql.Timestamp(role.getLastReviewedDate().millis());

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ROLE)) {
            ps.setString(1, roleName);
            ps.setInt(2, domainId);
            ps.setString(3, processInsertValue(role.getTrust()));
            ps.setBoolean(4, processInsertValue(role.getAuditEnabled(), false));
            ps.setBoolean(5, processInsertValue(role.getSelfServe(), false));
            ps.setInt(6, processInsertValue(role.getMemberExpiryDays()));
            ps.setInt(7, processInsertValue(role.getTokenExpiryMins()));
            ps.setInt(8, processInsertValue(role.getCertExpiryMins()));
            ps.setString(9, processInsertValue(role.getSignAlgorithm()));
            ps.setInt(10, processInsertValue(role.getServiceExpiryDays()));
            ps.setInt(11, processInsertValue(role.getMemberReviewDays()));
            ps.setInt(12, processInsertValue(role.getServiceReviewDays()));
            ps.setInt(13, processInsertValue(role.getGroupReviewDays()));
            ps.setBoolean(14, processInsertValue(role.getReviewEnabled(), false));
            ps.setString(15, processInsertValue(role.getNotifyRoles()));
            ps.setString(16, processInsertValue(role.getUserAuthorityFilter()));
            ps.setString(17, processInsertValue(role.getUserAuthorityExpiration()));
            ps.setString(18, processInsertValue(role.getDescription()));
            ps.setInt(19, processInsertValue(role.getGroupExpiryDays()));
            ps.setBoolean(20, processInsertValue(role.getDeleteProtection(), false));
            ps.setTimestamp(21, lastReviewedTime);
            ps.setInt(22, processInsertValue(role.getMaxMembers()));
            ps.setBoolean(23, processInsertValue(role.getSelfRenew(), false));
            ps.setInt(24, processInsertValue(role.getSelfRenewMins()));
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateRole(String domainName, Role role) {

        int affectedRows;
        final String caller = "updateRole";

        String roleName = ZMSUtils.extractRoleName(domainName, role.getName());
        if (roleName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " update role name: " + role.getName());
        }

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }

        java.sql.Timestamp lastReviewedTime = role.getLastReviewedDate() == null ? null :
                new java.sql.Timestamp(role.getLastReviewedDate().millis());

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ROLE)) {
            ps.setString(1, processInsertValue(role.getTrust()));
            ps.setBoolean(2, processInsertValue(role.getAuditEnabled(), false));
            ps.setBoolean(3, processInsertValue(role.getSelfServe(), false));
            ps.setInt(4, processInsertValue(role.getMemberExpiryDays()));
            ps.setInt(5, processInsertValue(role.getTokenExpiryMins()));
            ps.setInt(6, processInsertValue(role.getCertExpiryMins()));
            ps.setString(7, processInsertValue(role.getSignAlgorithm()));
            ps.setInt(8, processInsertValue(role.getServiceExpiryDays()));
            ps.setInt(9, processInsertValue(role.getMemberReviewDays()));
            ps.setInt(10, processInsertValue(role.getServiceReviewDays()));
            ps.setInt(11, processInsertValue(role.getGroupReviewDays()));
            ps.setBoolean(12, processInsertValue(role.getReviewEnabled(), false));
            ps.setString(13, processInsertValue(role.getNotifyRoles()));
            ps.setString(14, processInsertValue(role.getUserAuthorityFilter()));
            ps.setString(15, processInsertValue(role.getUserAuthorityExpiration()));
            ps.setString(16, processInsertValue(role.getDescription()));
            ps.setInt(17, processInsertValue(role.getGroupExpiryDays()));
            ps.setBoolean(18, processInsertValue(role.getDeleteProtection(), false));
            ps.setTimestamp(19, lastReviewedTime);
            ps.setInt(20, processInsertValue(role.getMaxMembers()));
            ps.setBoolean(21, processInsertValue(role.getSelfRenew(), false));
            ps.setInt(22, processInsertValue(role.getSelfRenewMins()));
            ps.setInt(23, roleId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return (affectedRows > 0);
    }

    @Override
    public boolean updateRoleModTimestamp(String domainName, String roleName) {

        int affectedRows;
        final String caller = "updateRoleModTimestamp";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ROLE_MOD_TIMESTAMP)) {
            ps.setInt(1, roleId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateRoleReviewTimestamp(String domainName, String roleName) {

        int affectedRows;
        final String caller = "updateRoleReviewTimestamp";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ROLE_REVIEW_TIMESTAMP)) {
            ps.setInt(1, roleId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateServiceIdentityModTimestamp(String domainName, String serviceName) {

        int affectedRows;
        final String caller = "updateServiceIdentityModTimestamp";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_SERVICE_MOD_TIMESTAMP)) {
            ps.setInt(1, serviceId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deleteRole(String domainName, String roleName) {

        final String caller = "deleteRole";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_ROLE)) {
            ps.setInt(1, domainId);
            ps.setString(2, roleName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public List<String> listRoles(String domainName) {

        final String caller = "listRoles";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        List<String> roles = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ROLE)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    roles.add(rs.getString(1));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        Collections.sort(roles);
        return roles;
    }

    @Override
    public List<String> listTrustedRolesWithWildcards(String domainName, String roleName, String trustDomainName) {

        final String caller = "listTrustedRolesWithWildcards";

        List<String> roles = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_TRUSTED_ROLES_WITH_WILDCARD)) {
            ps.setString(1, domainName.replace('*', '%'));
            ps.setString(2, roleName.replace('*', '%'));
            ps.setString(3, trustDomainName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    roles.add(ResourceUtils.roleResourceName(rs.getString(1), rs.getString(2)));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return roles;
    }

    @Override
    public int countRoles(String domainName) {

        final String caller = "countRoles";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_COUNT_ROLE)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    public static Comparator<RoleMember> RoleMemberComparator = (roleMember1, roleMember2) -> {
        String roleMember1Name = roleMember1.getMemberName().toLowerCase();
        String roleMember2Name = roleMember2.getMemberName().toLowerCase();
        return roleMember1Name.compareTo(roleMember2Name);
    };

    public static Comparator<GroupMember> GroupMemberComparator = (groupMember1, groupMember2) -> {
        String groupMember1Name = groupMember1.getMemberName().toLowerCase();
        String groupMember2Name = groupMember2.getMemberName().toLowerCase();
        return groupMember1Name.compareTo(groupMember2Name);
    };

    void getStdRoleMembers(int roleId, List<RoleMember> members, final String caller) {

        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ROLE_MEMBERS)) {
            ps.setInt(1, roleId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    RoleMember roleMember = new RoleMember();
                    roleMember.setMemberName(rs.getString(1));
                    java.sql.Timestamp expiration = rs.getTimestamp(2);
                    if (expiration != null) {
                        roleMember.setExpiration(Timestamp.fromMillis(expiration.getTime()));
                    }
                    java.sql.Timestamp reviewReminder = rs.getTimestamp(3);
                    if (reviewReminder != null) {
                        roleMember.setReviewReminder(Timestamp.fromMillis(reviewReminder.getTime()));
                    }
                    roleMember.setActive(nullIfDefaultValue(rs.getBoolean(4), true));
                    roleMember.setAuditRef(rs.getString(5));
                    roleMember.setSystemDisabled(nullIfDefaultValue(rs.getInt(6), 0));
                    roleMember.setApproved(true);
                    members.add(roleMember);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    void getPendingRoleMembers(int roleId, List<RoleMember> members, final String caller) {

        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_PENDING_ROLE_MEMBERS)) {
            ps.setInt(1, roleId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    RoleMember roleMember = new RoleMember();
                    roleMember.setMemberName(rs.getString(1));
                    java.sql.Timestamp timestamp = rs.getTimestamp(2);
                    if (timestamp != null) {
                        roleMember.setExpiration(Timestamp.fromMillis(timestamp.getTime()));
                    }
                    timestamp = rs.getTimestamp(3);
                    if (timestamp != null) {
                        roleMember.setReviewReminder(Timestamp.fromMillis(timestamp.getTime()));
                    }
                    timestamp = rs.getTimestamp(4);
                    if (timestamp != null) {
                        roleMember.setRequestTime(Timestamp.fromMillis(timestamp.getTime()));
                    }
                    roleMember.setAuditRef(rs.getString(5));
                    roleMember.setPendingState(rs.getString(6));
                    roleMember.setActive(false);
                    roleMember.setApproved(false);
                    members.add(roleMember);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    @Override
    public List<RoleMember> listRoleMembers(String domainName, String roleName, Boolean pending) {

        final String caller = "listRoleMembers";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }

        // first get our standard role members

        List<RoleMember> members = new ArrayList<>();
        getStdRoleMembers(roleId, members, caller);

        // if requested, include pending members as well

        if (pending == Boolean.TRUE) {
            getPendingRoleMembers(roleId, members, caller);
        }

        members.sort(RoleMemberComparator);
        return members;
    }

    @Override
    public int countRoleMembers(String domainName, String roleName) {

        final String caller = "countRoleMembers";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_COUNT_ROLE_MEMBERS)) {
            ps.setInt(1, roleId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    @Override
    public List<RoleAuditLog> listRoleAuditLogs(String domainName, String roleName) {

        final String caller = "listRoleAuditLogs";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }
        List<RoleAuditLog> logs = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ROLE_AUDIT_LOGS)) {
            ps.setInt(1, roleId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    RoleAuditLog log = new RoleAuditLog();
                    log.setAction(rs.getString(ZMSConsts.DB_COLUMN_ACTION));
                    log.setMember(rs.getString(ZMSConsts.DB_COLUMN_MEMBER));
                    log.setAdmin(rs.getString(ZMSConsts.DB_COLUMN_ADMIN));
                    log.setAuditRef(saveValue(rs.getString(ZMSConsts.DB_COLUMN_AUDIT_REF)));
                    log.setCreated(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_CREATED).getTime()));
                    logs.add(log);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return logs;
    }

    boolean parsePrincipal(String principal, StringBuilder domain, StringBuilder name) {
        int idx = principal.lastIndexOf('.');
        if (idx == -1 || idx == 0 || idx == principal.length() - 1) {
            return false;
        }
        domain.append(principal, 0, idx);
        name.append(principal.substring(idx + 1));
        return true;
    }

    boolean getRoleMembership(final String query, int roleId, final String member, long expiration,
            Membership membership, boolean disabledFlagCheck, final String caller) {

        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setInt(1, roleId);
            ps.setString(2, member);
            if (expiration != 0) {
                ps.setTimestamp(3, new java.sql.Timestamp(expiration));
            }
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    membership.setIsMember(true);
                    java.sql.Timestamp expiry = rs.getTimestamp(ZMSConsts.DB_COLUMN_EXPIRATION);
                    if (expiry != null) {
                        membership.setExpiration(Timestamp.fromMillis(expiry.getTime()));
                    }
                    java.sql.Timestamp reviewReminder = rs.getTimestamp(ZMSConsts.DB_COLUMN_REVIEW_REMINDER);
                    if (reviewReminder != null) {
                        membership.setReviewReminder(Timestamp.fromMillis(reviewReminder.getTime()));
                    }
                    membership.setRequestPrincipal(rs.getString(ZMSConsts.DB_COLUMN_REQ_PRINCIPAL));
                    if (disabledFlagCheck) {
                        membership.setSystemDisabled(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_SYSTEM_DISABLED), 0));
                    } else {
                        membership.setPendingState(rs.getString(DB_COLUMN_PENDING_STATE));
                    }
                    return true;
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return false;
    }

    @Override
    public Membership getRoleMember(String domainName, String roleName, String member,
            long expiration, boolean pending) {

        final String caller = "getRoleMember";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }

        Membership membership = new Membership()
                .setMemberName(member)
                .setRoleName(ResourceUtils.roleResourceName(domainName, roleName))
                .setIsMember(false);

        // first we're going to check if we have a standard user with the given
        // details before checking for pending unless we're specifically asking
        // for pending member only in which case we'll skip the first check

        if (!pending) {
            String query = expiration == 0 ? SQL_GET_ROLE_MEMBER : SQL_GET_TEMP_ROLE_MEMBER;
            if (getRoleMembership(query, roleId, member, expiration, membership, true, caller)) {
                membership.setApproved(true);
            }
        }

        if (!membership.getIsMember()) {
            String query = expiration == 0 ? SQL_GET_PENDING_ROLE_MEMBER : SQL_GET_TEMP_PENDING_ROLE_MEMBER;
            if (getRoleMembership(query, roleId, member, expiration, membership, false, caller)) {
                membership.setApproved(false);
            }
        }

        return membership;
    }

    int insertPrincipal(String principal) {

        int affectedRows;
        final String caller = "insertPrincipal";

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_PRINCIPAL)) {
            ps.setString(1, principal);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {

            // it's possible that 2 threads try to add the same principal
            // into different roles. so we're going to have a special
            // handling here - if we get back entry already exists exception
            // we're just going to look up the principal id and return
            // that instead of returning an exception. However, if we still
            // get no response for the principal id, then it indicates that
            // the other thread hasn't completed its transaction yet, so
            // we need to return a conflict exception so the server can
            // retry its operation after a short while

            if (ex.getErrorCode() == MYSQL_ER_OPTION_DUPLICATE_ENTRY) {
                int principalId = getPrincipalId(principal);
                if (principalId == 0) {
                    throw sqlError(new SQLException("insert principal lock conflict", MYSQL_EXC_STATE_DEADLOCK), caller);
                }
                return principalId;
            }

            throw sqlError(ex, caller);
        }

        // if we got an expected response of 1 row updated, then we'll
        // pick up the last insert id.

        if (affectedRows == 1) {
            return getLastInsertId();
        }

        // However, if we got back 0 rows updated without the duplicate
        // entry exception, we'll assume that entry exists, and we'll try
        // to fetch it one more time. And if we still get no response,
        // that indicates that the previous transaction hasn't completed
        // yet, so we'll return a conflict exception so the server can
        // retry the operation

        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw sqlError(new SQLException("insert principal lock conflict", MYSQL_EXC_STATE_DEADLOCK), caller);
        }
        return principalId;
    }

    int insertHost(String hostName) {

        int affectedRows;
        final String caller = "insertHost";

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_HOST)) {
            ps.setString(1, hostName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        int hostId = 0;
        if (affectedRows == 1) {
            hostId = getLastInsertId();
        }
        return hostId;
    }

    boolean roleMemberExists(int roleId, int principalId, String principal, String pendingState, final String caller) {
        boolean pending = pendingState != null;
        String statement =  pending ? SQL_PENDING_ROLE_MEMBER_EXISTS : SQL_STD_ROLE_MEMBER_EXISTS;
        try (PreparedStatement ps = con.prepareStatement(statement)) {
            ps.setInt(1, roleId);
            ps.setInt(2, principalId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    if (pending) {
                        String currentState = rs.getString(1);
                        // check current request doesn't contradict the existing one
                        if (currentState != null && !currentState.equals(pendingState)) {
                            throw ZMSUtils.requestError("The user " + principal + " already has a pending request in a different state", caller);
                        }
                    }
                    return true;
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return false;
    }

    @Override
    public boolean insertRoleMember(String domainName, String roleName, RoleMember roleMember,
            String admin, String auditRef) {

        final String caller = "insertRoleMember";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }
        String principal = roleMember.getMemberName();
        if (!validatePrincipalDomain(principal)) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, principal);
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            principalId = insertPrincipal(principal);
            if (principalId == 0) {
                throw internalServerError(caller, "Unable to insert principal: " + principal);
            }
        }

        // need to check if entry already exists

        boolean pendingRequest = (roleMember.getApproved() == Boolean.FALSE);
        boolean roleMemberExists = roleMemberExists(roleId, principalId, principal, roleMember.getPendingState(), caller);

        // process the request based on the type of the request
        // either pending request or standard insert

        boolean result;
        if (pendingRequest) {
            result = insertPendingRoleMember(roleId, principalId, roleMember, admin,
                    auditRef, roleMemberExists, caller);
        } else {
            result = insertStandardRoleMember(roleId, principalId, roleMember, admin,
                    principal, auditRef, roleMemberExists, false, caller);
        }
        return result;
    }

    boolean insertPendingRoleMember(int roleId, int principalId, RoleMember roleMember,
            final String admin, final String auditRef, boolean roleMemberExists, final String caller) {

        java.sql.Timestamp expiration = roleMember.getExpiration() == null ? null :
                new java.sql.Timestamp(roleMember.getExpiration().millis());

        java.sql.Timestamp reviewReminder = roleMember.getReviewReminder() == null ? null :
                new java.sql.Timestamp(roleMember.getReviewReminder().millis());

        int affectedRows;
        if (roleMemberExists) {
            try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_PENDING_ROLE_MEMBER)) {
                ps.setTimestamp(1, expiration);
                ps.setTimestamp(2, reviewReminder);
                ps.setString(3, processInsertValue(auditRef));
                ps.setString(4, processInsertValue(admin));
                ps.setInt(5, roleId);
                ps.setInt(6, principalId);
                affectedRows = executeUpdate(ps, caller);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }

        } else {

            try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_PENDING_ROLE_MEMBER)) {
                ps.setInt(1, roleId);
                ps.setInt(2, principalId);
                ps.setTimestamp(3, expiration);
                ps.setTimestamp(4, reviewReminder);
                ps.setString(5, processInsertValue(auditRef));
                ps.setString(6, processInsertValue(admin));
                ps.setString(7, roleMember.getPendingState());
                affectedRows = executeUpdate(ps, caller);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }

        return (affectedRows > 0);
    }

    boolean insertStandardRoleMember(int roleId, int principalId, RoleMember roleMember,
            final String admin, final String principal, final String auditRef,
            boolean roleMemberExists, boolean approveRequest, final String caller) {

        java.sql.Timestamp expiration = roleMember.getExpiration() == null ? null :
                new java.sql.Timestamp(roleMember.getExpiration().millis());

        java.sql.Timestamp reviewReminder = roleMember.getReviewReminder() == null ? null :
                new java.sql.Timestamp(roleMember.getReviewReminder().millis());

        boolean result;
        String auditOperation;

        if (roleMemberExists) {

            try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ROLE_MEMBER)) {
                ps.setTimestamp(1, expiration);
                ps.setTimestamp(2, reviewReminder);
                ps.setBoolean(3, processInsertValue(roleMember.getActive(), true));
                ps.setString(4, processInsertValue(auditRef));
                ps.setString(5, processInsertValue(admin));
                ps.setInt(6, roleId);
                ps.setInt(7, principalId);
                executeUpdate(ps, caller);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
            auditOperation = approveRequest ? "APPROVE" : "UPDATE";
            result = true;

        } else {

            int affectedRows;
            try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ROLE_MEMBER)) {
                ps.setInt(1, roleId);
                ps.setInt(2, principalId);
                ps.setTimestamp(3, expiration);
                ps.setTimestamp(4, reviewReminder);
                ps.setBoolean(5, processInsertValue(roleMember.getActive(), true));
                ps.setString(6, processInsertValue(auditRef));
                ps.setString(7, processInsertValue(admin));
                affectedRows = executeUpdate(ps, caller);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }

            auditOperation = approveRequest ? "APPROVE" : "ADD";
            result = (affectedRows > 0);
        }

        // add audit log entry for this change if the operation was successful
        // add return the result of the audit log insert operation

        if (result) {
            result = insertRoleAuditLog(roleId, admin, principal, auditOperation, auditRef);
        }
        return result;
    }

    @Override
    public boolean updateRoleMemberDisabledState(String domainName, String roleName, String principal,
            String admin, int disabledState, String auditRef) {

        final String caller = "updateRoleMemberDisabledState";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ROLE_MEMBER_DISABLED_STATE)) {
            ps.setInt(1, disabledState);
            ps.setString(2, processInsertValue(auditRef));
            ps.setString(3, processInsertValue(admin));
            ps.setInt(4, roleId);
            ps.setInt(5, principalId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        boolean result = (affectedRows > 0);

        // add audit log entry for this change if the disable was successful
        // add return the result of the audit log insert operation

        if (result) {
            final String operation = disabledState == 0 ? "ENABLE" : "DISABLE";
            result = insertRoleAuditLog(roleId, admin, principal, operation, auditRef);
        }

        return result;
    }

    @Override
    public boolean deleteRoleMember(String domainName, String roleName, String principal,
            String admin, String auditRef) {

        final String caller = "deleteRoleMember";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_ROLE_MEMBER)) {
            ps.setInt(1, roleId);
            ps.setInt(2, principalId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        boolean result = (affectedRows > 0);

        // add audit log entry for this change if the delete was successful
        // add return the result of the audit log insert operation

        if (result) {
            result = insertRoleAuditLog(roleId, admin, principal, "DELETE", auditRef);
        }

        return result;
    }

    @Override
    public boolean deleteExpiredRoleMember(String domainName, String roleName, String principal,
                                           String admin, Timestamp expiration, String auditRef) {
        final String caller = "deleteRoleMember";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        java.sql.Timestamp ts = new java.sql.Timestamp(expiration.millis());

        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_EXPIRED_ROLE_MEMBER)) {
            ps.setInt(1, roleId);
            ps.setInt(2, principalId);
            ps.setTimestamp(3, ts);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        boolean result = (affectedRows > 0);

        // add audit log entry for this change if the delete was successful
        // add return the result of the audit log insert operation

        if (result) {
            result = insertRoleAuditLog(roleId, admin, principal, "DELETE", auditRef);
        }

        return result;
    }

    boolean insertRoleAuditLog(int roleId, String admin, String member,
            String action, String auditRef) {

        int affectedRows;
        final String caller = "insertRoleAuditEntry";

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ROLE_AUDIT_LOG)) {
            ps.setInt(1, roleId);
            ps.setString(2, processInsertValue(admin));
            ps.setString(3, member);
            ps.setString(4, action);
            ps.setString(5, processInsertValue(auditRef));
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public Assertion getAssertion(String domainName, String policyName, Long assertionId) {

        final String caller = "getAssertion";

        Assertion assertion = null;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ASSERTION)) {
            ps.setInt(1, assertionId.intValue());
            ps.setString(2, domainName);
            ps.setString(3, policyName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    assertion = new Assertion();
                    assertion.setRole(ResourceUtils.roleResourceName(domainName, rs.getString(ZMSConsts.DB_COLUMN_ROLE)));
                    assertion.setResource(rs.getString(ZMSConsts.DB_COLUMN_RESOURCE));
                    assertion.setAction(rs.getString(ZMSConsts.DB_COLUMN_ACTION));
                    assertion.setEffect(AssertionEffect.valueOf(rs.getString(ZMSConsts.DB_COLUMN_EFFECT)));
                    assertion.setId((long) rs.getInt(ZMSConsts.DB_COLUMN_ASSERT_ID));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return assertion;
    }

    @Override
    public Policy getPolicy(String domainName, String policyName, String version) {

        final String caller = "getPolicy";

        try (PreparedStatement ps = con.prepareStatement((StringUtil.isEmpty(version)) ? SQL_GET_POLICY : SQL_GET_POLICY_VERSION)) {
            ps.setString(1, domainName);
            ps.setString(2, policyName);
            if (!StringUtil.isEmpty(version)) {
                ps.setString(3, version);
            }
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    return savePolicySettings(domainName, policyName, rs);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return null;
    }

    @Override
    public boolean insertPolicy(String domainName, Policy policy) {

        int affectedRows;
        final String caller = "insertPolicy";

        String policyName = ZMSUtils.extractPolicyName(domainName, policy.getName());
        if (policyName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " insert policy name: " + policy.getName());
        }

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        try (PreparedStatement ps = con.prepareStatement(!StringUtil.isEmpty(policy.getVersion()) ? SQL_INSERT_POLICY_VERSION : SQL_INSERT_POLICY)) {
            ps.setString(1, policyName);
            ps.setInt(2, domainId);
            if (!StringUtil.isEmpty(policy.getVersion())) {
                ps.setString(3, policy.getVersion());
                ps.setBoolean(4, policy.getActive());
            }
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updatePolicy(String domainName, Policy policy) {

        int affectedRows;
        final String caller = "updatePolicy";

        String policyName = ZMSUtils.extractPolicyName(domainName, policy.getName());
        if (policyName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " update policy name: " + policy.getName());
        }

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName, policy.getVersion());
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ResourceUtils.policyResourceName(domainName, policyName));
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_POLICY)) {
            ps.setString(1, policyName);
            ps.setInt(2, policyId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updatePolicyModTimestamp(String domainName, String policyName, String version) {

        int affectedRows;
        final String caller = "updatePolicyModTimestamp";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName, version);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ResourceUtils.policyResourceName(domainName, policyName));
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_POLICY_MOD_TIMESTAMP)) {
            ps.setInt(1, policyId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean setActivePolicyVersion(String domainName, String policyName, String version) {

        int affectedRows;
        final String caller = "setActivePolicyVersion";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_SET_ACTIVE_POLICY_VERSION)) {
            ps.setString(1, version);
            ps.setInt(2, domainId);
            ps.setString(3, policyName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }


    @Override
    public boolean deletePolicy(String domainName, String policyName) {

        final String caller = "deletePolicy";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_POLICY)) {
            ps.setInt(1, domainId);
            ps.setString(2, policyName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deletePolicyVersion(String domainName, String policyName, String version) {

        final String caller = "deletePolicyVersion";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_POLICY_VERSION)) {
            ps.setInt(1, domainId);
            ps.setString(2, policyName);
            ps.setString(3, version);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public List<String> listPolicies(String domainName, String assertionRoleName) {

        final String caller = "listPolicies";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        List<String> policies = new ArrayList<>();
        final String sqlStatement = (assertionRoleName == null) ? SQL_LIST_POLICY : SQL_LIST_POLICY_REFERENCING_ROLE;
        try (PreparedStatement ps = con.prepareStatement(sqlStatement)) {
            ps.setInt(1, domainId);
            if (assertionRoleName != null) {
                ps.setString(2, assertionRoleName);
            }
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    policies.add(rs.getString(1));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        Collections.sort(policies);
        return policies;
    }

    @Override
    public List<String> listPolicyVersions(String domainName, String policyName) {
        final String caller = "listPolicyVersions";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName, null);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ResourceUtils.policyResourceName(domainName, policyName));
        }
        List<String> policies = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_POLICY_VERSION)) {
            ps.setInt(1, domainId);
            ps.setString(2, policyName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    policies.add(rs.getString(1));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        Collections.sort(policies);
        return policies;
    }

    @Override
    public int countPolicies(String domainName) {

        final String caller = "countPolicies";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_COUNT_POLICY)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    @Override
    public boolean insertAssertion(String domainName, String policyName, String version, Assertion assertion) {

        final String caller = "insertAssertion";

        String roleName = ZMSUtils.extractRoleName(domainName, assertion.getRole());
        if (roleName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " assertion role name: " + assertion.getRole());
        }

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName, version);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ResourceUtils.policyResourceName(domainName, policyName));
        }

        // special handling for assertions since we don't want to have duplicates
        // and we don't want to setup a unique key across all values in the row

        try (PreparedStatement ps = con.prepareStatement(SQL_CHECK_ASSERTION)) {
            ps.setInt(1, policyId);
            ps.setString(2, roleName);
            ps.setString(3, assertion.getResource());
            ps.setString(4, assertion.getAction());
            ps.setString(5, processInsertValue(assertion.getEffect()));
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    return true;
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        // at this point we know we don't have another assertion with the same
        // values so we'll go ahead and add one

        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ASSERTION)) {
            ps.setInt(1, policyId);
            ps.setString(2, roleName);
            ps.setString(3, assertion.getResource());
            ps.setString(4, assertion.getAction());
            ps.setString(5, processInsertValue(assertion.getEffect()));
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        boolean result = (affectedRows > 0);

        if (result) {
            assertion.setId((long) getLastInsertId());
        }
        return result;
    }

    @Override
    public boolean deleteAssertion(String domainName, String policyName, String version, Long assertionId) {

        final String caller = "deleteAssertion";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName, version);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ResourceUtils.policyResourceName(domainName, policyName));
        }

        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_ASSERTION)) {
            ps.setInt(1, policyId);
            ps.setInt(2, assertionId.intValue());
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public List<Assertion> listAssertions(String domainName, String policyName, String version) {

        final String caller = "listAssertions";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName, version);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ResourceUtils.policyResourceName(domainName, policyName));
        }

        // assertion fetch
        List<Assertion> assertions = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ASSERTION)) {
            ps.setInt(1, policyId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    Assertion assertion = new Assertion();
                    assertion.setRole(ResourceUtils.roleResourceName(domainName, rs.getString(ZMSConsts.DB_COLUMN_ROLE)));
                    assertion.setResource(rs.getString(ZMSConsts.DB_COLUMN_RESOURCE));
                    assertion.setAction(rs.getString(ZMSConsts.DB_COLUMN_ACTION));
                    assertion.setEffect(AssertionEffect.valueOf(rs.getString(ZMSConsts.DB_COLUMN_EFFECT)));
                    assertion.setId((long) rs.getInt(ZMSConsts.DB_COLUMN_ASSERT_ID));
                    assertions.add(assertion);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        // assertion conditions fetch
        Map<Long, Assertion> assertionsMap = assertions.stream().collect(Collectors.toMap(Assertion::getId, assertion -> assertion));
        Map<String, AssertionCondition> assertionConditionMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_POLICY_ASSERTIONS_CONDITIONS)) {
            ps.setInt(1, policyId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    long assertionId = rs.getLong(ZMSConsts.DB_COLUMN_ASSERT_ID);
                    Assertion assertion = assertionsMap.get(assertionId);
                    if (assertion == null) {
                        continue;
                    }
                    AssertionConditions assertionConditions = assertion.getConditions();
                    if (assertionConditions == null) {
                        assertionConditions = new AssertionConditions();
                        List<AssertionCondition> assertionConditionList = new ArrayList<>();
                        assertionConditions.setConditionsList(assertionConditionList);
                        assertion.setConditions(assertionConditions);
                    }
                    int conditionId = rs.getInt(ZMSConsts.DB_COLUMN_CONDITION_ID);
                    AssertionCondition assertionCondition = assertionConditionMap.get(assertionId + ":" + conditionId);
                    if (assertionCondition == null) {
                        assertionCondition = new AssertionCondition();
                        Map<String, AssertionConditionData> assertionConditionDataMap = new HashMap<>();
                        assertionCondition.setConditionsMap(assertionConditionDataMap);
                        assertionCondition.setId(conditionId);
                        assertionConditionMap.put(assertionId + ":" + conditionId, assertionCondition);
                        assertionConditions.getConditionsList().add(assertionCondition);
                    }
                    AssertionConditionData assertionConditionData = new AssertionConditionData();
                    if (rs.getString(ZMSConsts.DB_COLUMN_OPERATOR) != null) {
                        assertionConditionData.setOperator(AssertionConditionOperator.fromString(rs.getString(ZMSConsts.DB_COLUMN_OPERATOR)));
                    }
                    assertionConditionData.setValue(rs.getString(ZMSConsts.DB_COLUMN_VALUE));
                    assertionCondition.getConditionsMap().put(rs.getString(ZMSConsts.DB_COLUMN_KEY), assertionConditionData);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return assertions;
    }

    @Override
    public int countAssertions(String domainName, String policyName, String version) {

        final String caller = "countAssertions";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName, version);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ResourceUtils.policyResourceName(domainName, policyName));
        }
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_COUNT_ASSERTION)) {
            ps.setInt(1, policyId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    String saveValue(String value) {
        return (value.isEmpty()) ? null : value;
    }

    UUID saveUuidValue(String value) {
        return (value.isEmpty()) ? null : UUID.fromString(value);
    }

    @Override
    public ServiceIdentity getServiceIdentity(String domainName, String serviceName) {

        final String caller = "getServiceIdentity";

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_SERVICE)) {
            ps.setString(1, domainName);
            ps.setString(2, serviceName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {

                    return new ServiceIdentity()
                            .setName(ResourceUtils.serviceResourceName(domainName, serviceName))
                            .setDescription(saveValue(rs.getString(ZMSConsts.DB_COLUMN_DESCRIPTION)))
                            .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                            .setProviderEndpoint(saveValue(rs.getString(ZMSConsts.DB_COLUMN_PROVIDER_ENDPOINT)))
                            .setExecutable(saveValue(rs.getString(ZMSConsts.DB_COLUMN_EXECUTABLE)))
                            .setUser(saveValue(rs.getString(ZMSConsts.DB_COLUMN_SVC_USER)))
                            .setGroup(saveValue(rs.getString(ZMSConsts.DB_COLUMN_SVC_GROUP)))
                            .setResourceOwnership(ResourceOwnership.getResourceServiceOwnership(rs.getString(ZMSConsts.DB_COLUMN_RESOURCE_OWNER)));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return null;
    }

    int processInsertValue(Integer value) {
        return (value == null) ? 0 : value;
    }

    String processInsertValue(String value) {
        return (value == null) ? "" : value.trim();
    }

    boolean processInsertValue(Boolean value, boolean defaultValue) {
        return (value == null) ? defaultValue : value;
    }

    String processInsertValue(AssertionEffect value) {
        return (value == null) ? ZMSConsts.ASSERTION_EFFECT_ALLOW : value.toString();
    }

    String processInsertUuidValue(UUID value) {
        return (value == null) ? "" : value.toString();
    }

    @Override
    public boolean insertServiceIdentity(String domainName, ServiceIdentity service) {

        int affectedRows;
        final String caller = "insertServiceIdentity";

        String serviceName = ZMSUtils.extractServiceName(domainName, service.getName());
        if (serviceName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " insert service name: " + service.getName());
        }

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_SERVICE)) {
            ps.setString(1, serviceName);
            ps.setString(2, processInsertValue(service.getDescription()));
            ps.setString(3, processInsertValue(service.getProviderEndpoint()));
            ps.setString(4, processInsertValue(service.getExecutable()));
            ps.setString(5, processInsertValue(service.getUser()));
            ps.setString(6, processInsertValue(service.getGroup()));
            ps.setInt(7, domainId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateServiceIdentity(String domainName, ServiceIdentity service) {

        int affectedRows;
        final String caller = "updateServiceIdentity";

        String serviceName = ZMSUtils.extractServiceName(domainName, service.getName());
        if (serviceName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " update service name: " + service.getName());
        }

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_SERVICE)) {
            ps.setString(1, processInsertValue(service.getDescription()));
            ps.setString(2, processInsertValue(service.getProviderEndpoint()));
            ps.setString(3, processInsertValue(service.getExecutable()));
            ps.setString(4, processInsertValue(service.getUser()));
            ps.setString(5, processInsertValue(service.getGroup()));
            ps.setInt(6, serviceId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deleteServiceIdentity(String domainName, String serviceName) {

        final String caller = "deleteServiceIdentity";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_SERVICE)) {
            ps.setInt(1, domainId);
            ps.setString(2, serviceName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public List<String> listServiceIdentities(String domainName) {

        final String caller = "listServiceIdentities";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        List<String> services = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_SERVICE)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    services.add(rs.getString(1));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        Collections.sort(services);
        return services;
    }

    @Override
    public int countServiceIdentities(String domainName) {

        final String caller = "countServiceIdentities";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_COUNT_SERVICE)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    @Override
    public List<PublicKeyEntry> listPublicKeys(String domainName, String serviceName) {

        final String caller = "listPublicKeys";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        List<PublicKeyEntry> publicKeys = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_PUBLIC_KEY)) {
            ps.setInt(1, serviceId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    PublicKeyEntry publicKey = new PublicKeyEntry()
                            .setId(rs.getString(ZMSConsts.DB_COLUMN_KEY_ID))
                            .setKey(rs.getString(ZMSConsts.DB_COLUMN_KEY_VALUE));
                    publicKeys.add(publicKey);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return publicKeys;
    }

    @Override
    public int countPublicKeys(String domainName, String serviceName) {

        final String caller = "countPublicKeys";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_COUNT_PUBLIC_KEY)) {
            ps.setInt(1, serviceId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    @Override
    public PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName,
            String keyId, boolean domainStateCheck) {

        final String caller = "getPublicKeyEntry";

        int domainId = getDomainId(domainName, domainStateCheck);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_PUBLIC_KEY)) {
            ps.setInt(1, serviceId);
            ps.setString(2, keyId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    return new PublicKeyEntry().setId(keyId)
                            .setKey(rs.getString(ZMSConsts.DB_COLUMN_KEY_VALUE));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return null;
    }

    @Override
    public boolean insertPublicKeyEntry(String domainName, String serviceName, PublicKeyEntry publicKey) {

        final String caller = "insertPublicKeyEntry";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_PUBLIC_KEY)) {
            ps.setInt(1, serviceId);
            ps.setString(2, publicKey.getId());
            ps.setString(3, publicKey.getKey());
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updatePublicKeyEntry(String domainName, String serviceName, PublicKeyEntry publicKey) {

        final String caller = "updatePublicKeyEntry";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_PUBLIC_KEY)) {
            ps.setString(1, publicKey.getKey());
            ps.setInt(2, serviceId);
            ps.setString(3, publicKey.getId());
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deletePublicKeyEntry(String domainName, String serviceName, String keyId) {

        final String caller = "deletePublicKeyEntry";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_PUBLIC_KEY)) {
            ps.setInt(1, serviceId);
            ps.setString(2, keyId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public List<String> listServiceHosts(String domainName, String serviceName) {

        final String caller = "listServiceHosts";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        List<String> hosts = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_SERVICE_HOST)) {
            ps.setInt(1, serviceId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    hosts.add(rs.getString(ZMSConsts.DB_COLUMN_NAME));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return hosts;
    }

    @Override
    public boolean insertServiceHost(String domainName, String serviceName, String hostName) {

        final String caller = "insertServiceHost";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        int hostId = getHostId(hostName);
        if (hostId == 0) {
            hostId = insertHost(hostName);
            if (hostId == 0) {
                throw internalServerError(caller, "Unable to insert host: " + hostName);
            }
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_SERVICE_HOST)) {
            ps.setInt(1, serviceId);
            ps.setInt(2, hostId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deleteServiceHost(String domainName, String serviceName, String hostName) {

        final String caller = "deleteServiceHost";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        int hostId = getHostId(hostName);
        if (hostId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_HOST, hostName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_SERVICE_HOST)) {
            ps.setInt(1, serviceId);
            ps.setInt(2, hostId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean insertEntity(String domainName, Entity entity) {

        final String caller = "insertEntity";

        String entityName = ZMSUtils.extractEntityName(domainName, entity.getName());
        if (entityName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " insert entity name: " + entity.getName());
        }

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ENTITY)) {
            ps.setInt(1, domainId);
            ps.setString(2, entityName);
            ps.setString(3, JSON.string(entity.getValue()));
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateEntity(String domainName, Entity entity) {

        final String caller = "updateEntity";

        String entityName = ZMSUtils.extractEntityName(domainName, entity.getName());
        if (entityName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " insert entity name: " + entity.getName());
        }

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ENTITY)) {
            ps.setString(1, JSON.string(entity.getValue()));
            ps.setInt(2, domainId);
            ps.setString(3, entityName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deleteEntity(String domainName, String entityName) {

        final String caller = "deleteEntity";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_ENTITY)) {
            ps.setInt(1, domainId);
            ps.setString(2, entityName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public Entity getEntity(String domainName, String entityName) {

        final String caller = "getEntity";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ENTITY)) {
            ps.setInt(1, domainId);
            ps.setString(2, entityName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    return new Entity().setName(ResourceUtils.entityResourceName(domainName, entityName))
                            .setValue(JSON.fromString(rs.getString(ZMSConsts.DB_COLUMN_VALUE), Struct.class));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return null;
    }

    @Override
    public List<String> listEntities(String domainName) {

        final String caller = "listEntities";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        List<String> entities = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ENTITY)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    entities.add(rs.getString(1));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        Collections.sort(entities);
        return entities;
    }

    @Override
    public int countEntities(String domainName) {

        final String caller = "countEntities";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_COUNT_ENTITY)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    Role retrieveRole(ResultSet rs, final String domainName, final String roleName) throws SQLException {
        Role role = new Role().setName(ResourceUtils.roleResourceName(domainName, roleName))
                .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                .setTrust(saveValue(rs.getString(ZMSConsts.DB_COLUMN_TRUST)))
                .setAuditEnabled(nullIfDefaultValue(rs.getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED), false))
                .setSelfServe(nullIfDefaultValue(rs.getBoolean(ZMSConsts.DB_COLUMN_SELF_SERVE), false))
                .setMemberExpiryDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_MEMBER_EXPIRY_DAYS), 0))
                .setTokenExpiryMins(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_TOKEN_EXPIRY_MINS), 0))
                .setCertExpiryMins(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_CERT_EXPIRY_MINS), 0))
                .setSignAlgorithm(saveValue(rs.getString(ZMSConsts.DB_COLUMN_SIGN_ALGORITHM)))
                .setServiceExpiryDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_SERVICE_EXPIRY_DAYS), 0))
                .setGroupExpiryDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_GROUP_EXPIRY_DAYS), 0))
                .setReviewEnabled(nullIfDefaultValue(rs.getBoolean(ZMSConsts.DB_COLUMN_REVIEW_ENABLED), false))
                .setDeleteProtection(nullIfDefaultValue(rs.getBoolean(ZMSConsts.DB_COLUMN_DELETE_PROTECTION), false))
                .setMemberReviewDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_MEMBER_REVIEW_DAYS), 0))
                .setServiceReviewDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_SERVICE_REVIEW_DAYS), 0))
                .setGroupReviewDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_GROUP_REVIEW_DAYS), 0))
                .setNotifyRoles(saveValue(rs.getString(ZMSConsts.DB_COLUMN_NOTIFY_ROLES)))
                .setUserAuthorityFilter(saveValue(rs.getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER)))
                .setUserAuthorityExpiration(saveValue(rs.getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_EXPIRATION)))
                .setDescription(saveValue(rs.getString(ZMSConsts.DB_COLUMN_DESCRIPTION)))
                .setMaxMembers(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_MAX_MEMBERS), 0))
                .setSelfRenew(nullIfDefaultValue(rs.getBoolean(ZMSConsts.DB_COLUMN_SELF_RENEW), false))
                .setSelfRenewMins(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_SELF_RENEW_MINS), 0))
                .setResourceOwnership(ResourceOwnership.getResourceRoleOwnership(rs.getString(ZMSConsts.DB_COLUMN_RESOURCE_OWNER)));
        java.sql.Timestamp lastReviewedTime = rs.getTimestamp(ZMSConsts.DB_COLUMN_LAST_REVIEWED_TIME);
        if (lastReviewedTime != null) {
            role.setLastReviewedDate(Timestamp.fromMillis(lastReviewedTime.getTime()));
        }
        return role;
    }

    void getAthenzDomainRoles(String domainName, int domainId, AthenzDomain athenzDomain) {

        final String caller = "getAthenzDomain";
        Map<String, Role> roleMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_ROLES)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    final String roleName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    Role role = retrieveRole(rs, domainName, roleName);
                    roleMap.put(roleName, role);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_ROLE_MEMBERS)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String roleName = rs.getString(1);
                    Role role = roleMap.get(roleName);
                    if (role == null) {
                        continue;
                    }
                    List<RoleMember> members = role.getRoleMembers();
                    if (members == null) {
                        members = new ArrayList<>();
                        role.setRoleMembers(members);
                    }
                    RoleMember roleMember = new RoleMember();
                    roleMember.setMemberName(rs.getString(2));
                    java.sql.Timestamp expiration = rs.getTimestamp(3);
                    if (expiration != null) {
                        roleMember.setExpiration(Timestamp.fromMillis(expiration.getTime()));
                    }
                    java.sql.Timestamp reviewReminder = rs.getTimestamp(4);
                    if (reviewReminder != null) {
                        roleMember.setReviewReminder(Timestamp.fromMillis(reviewReminder.getTime()));
                    }
                    roleMember.setSystemDisabled(nullIfDefaultValue(rs.getInt(5), 0));
                    members.add(roleMember);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        // add role tags
        addTagsToRoles(roleMap, athenzDomain.getName());

        athenzDomain.getRoles().addAll(roleMap.values());
    }

    void getAthenzDomainGroups(String domainName, int domainId, AthenzDomain athenzDomain) {

        final String caller = "getAthenzDomain";
        Map<String, Group> groupMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_GROUPS)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    final String groupName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    Group group = retrieveGroup(rs, domainName, groupName);
                    groupMap.put(groupName, group);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_GROUP_MEMBERS)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    final String groupName = rs.getString(1);
                    Group group = groupMap.get(groupName);
                    if (group == null) {
                        continue;
                    }
                    List<GroupMember> members = group.getGroupMembers();
                    if (members == null) {
                        members = new ArrayList<>();
                        group.setGroupMembers(members);
                    }
                    GroupMember groupMember = new GroupMember();
                    groupMember.setMemberName(rs.getString(2));
                    groupMember.setGroupName(group.getName());
                    java.sql.Timestamp expiration = rs.getTimestamp(3);
                    if (expiration != null) {
                        groupMember.setExpiration(Timestamp.fromMillis(expiration.getTime()));
                    }
                    groupMember.setSystemDisabled(nullIfDefaultValue(rs.getInt(4), 0));
                    members.add(groupMember);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        // add group tags
        addTagsToGroups(groupMap, athenzDomain.getName());

        athenzDomain.getGroups().addAll(groupMap.values());
    }

    void getAthenzDomainPolicies(String domainName, int domainId, AthenzDomain athenzDomain) {

        final String caller = "getAthenzDomain";
        Map<Integer, Policy> policyMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_POLICIES)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    int policyId = rs.getInt(ZMSConsts.DB_COLUMN_POLICY_ID);
                    final String policyName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    policyMap.put(policyId, savePolicySettings(domainName, policyName, rs));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        Map<Long, Assertion> assertionsMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_POLICY_ASSERTIONS)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    int policyId = rs.getInt(ZMSConsts.DB_COLUMN_POLICY_ID);
                    Policy policy = policyMap.get(policyId);
                    if (policy == null) {
                        continue;
                    }
                    List<Assertion> assertions = policy.getAssertions();
                    if (assertions == null) {
                        assertions = new ArrayList<>();
                        policy.setAssertions(assertions);
                    }
                    Assertion assertion = new Assertion();
                    assertion.setRole(ResourceUtils.roleResourceName(domainName, rs.getString(ZMSConsts.DB_COLUMN_ROLE)));
                    assertion.setResource(rs.getString(ZMSConsts.DB_COLUMN_RESOURCE));
                    assertion.setAction(rs.getString(ZMSConsts.DB_COLUMN_ACTION));
                    assertion.setEffect(AssertionEffect.valueOf(rs.getString(ZMSConsts.DB_COLUMN_EFFECT)));
                    assertion.setId(rs.getLong(ZMSConsts.DB_COLUMN_ASSERT_ID));

                    assertions.add(assertion);
                    assertionsMap.put(assertion.getId(), assertion);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        // assertion conditions fetch

        Map<String, AssertionCondition> assertionConditionMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_POLICY_ASSERTIONS_CONDITIONS)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    long assertionId = rs.getLong(ZMSConsts.DB_COLUMN_ASSERT_ID);
                    Assertion assertion = assertionsMap.get(assertionId);
                    if (assertion == null) {
                        continue;
                    }
                    AssertionConditions assertionConditions = assertion.getConditions();
                    if (assertionConditions == null) {
                        assertionConditions = new AssertionConditions();
                        List<AssertionCondition> assertionConditionList = new ArrayList<>();
                        assertionConditions.setConditionsList(assertionConditionList);
                        assertion.setConditions(assertionConditions);
                    }
                    int conditionId = rs.getInt(ZMSConsts.DB_COLUMN_CONDITION_ID);
                    AssertionCondition assertionCondition = assertionConditionMap.get(assertionId + ":" + conditionId);
                    if (assertionCondition == null) {
                        assertionCondition = new AssertionCondition();
                        Map<String, AssertionConditionData> assertionConditionDataMap = new HashMap<>();
                        assertionCondition.setConditionsMap(assertionConditionDataMap);
                        assertionCondition.setId(conditionId);
                        assertionConditionMap.put(assertionId + ":" + conditionId, assertionCondition);
                        assertionConditions.getConditionsList().add(assertionCondition);
                    }
                    AssertionConditionData assertionConditionData = new AssertionConditionData();
                    if (rs.getString(ZMSConsts.DB_COLUMN_OPERATOR) != null) {
                        assertionConditionData.setOperator(AssertionConditionOperator.fromString(rs.getString(ZMSConsts.DB_COLUMN_OPERATOR)));
                    }
                    assertionConditionData.setValue(rs.getString(ZMSConsts.DB_COLUMN_VALUE));
                    assertionCondition.getConditionsMap().put(rs.getString(ZMSConsts.DB_COLUMN_KEY), assertionConditionData);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        // add policies tags
        addTagsToPolicies(policyMap, athenzDomain.getName());

        athenzDomain.getPolicies().addAll(policyMap.values());
    }

    void addTagsToPolicies(Map<Integer, Policy> policyMap, String domainName) {

        Map<String, Map<String, TagValueList>> domainPolicyTags = getDomainPolicyTags(domainName);
        if (domainPolicyTags != null) {
            for (Map.Entry<Integer, Policy> policyEntry : policyMap.entrySet()) {
                Map<String, TagValueList> policyTag = domainPolicyTags.get(ZMSUtils.extractPolicyName(domainName, policyEntry.getValue().name) + ":" + policyEntry.getValue().getVersion());
                if (policyTag != null) {
                    policyEntry.getValue().setTags(policyTag);
                }
            }
        }
    }

    Map<String, Map<String, TagValueList>> getDomainPolicyTags(String domainName) {
        final String funcCaller = "getDomainPolicyTags";
        Map<String, Map<String, TagValueList>> domainResourceTags = null;

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_POLICY_TAGS)) {
            ps.setString(1, domainName);
            try (ResultSet rs = executeQuery(ps, funcCaller)) {
                while (rs.next()) {
                    String resourceName = rs.getString(1);
                    String tagKey = rs.getString(2);
                    String tagValue = rs.getString(3);
                    String version = rs.getString(4);
                    if (domainResourceTags == null) {
                        domainResourceTags = new HashMap<>();
                    }
                    Map<String, TagValueList> resourceTag = domainResourceTags.computeIfAbsent(resourceName + ":" + version, tags -> new HashMap<>());
                    TagValueList tagValues = resourceTag.computeIfAbsent(tagKey, k -> new TagValueList().setList(new ArrayList<>()));
                    tagValues.getList().add(tagValue);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, funcCaller);
        }
        return domainResourceTags;
    }

    @Override
    public boolean insertPolicyTags(String policyName, String domainName, Map<String, TagValueList> policyTags, String version) {
        final String caller = "insertPolicyTags";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName, version);
        if (policyId == 0) {
            throw notFoundError(caller, OBJECT_POLICY, ResourceUtils.policyResourceName(domainName, policyName));
        }
        int curTagCount = getPolicyTagsCount(policyId);
        int newTagCount = calculateTagCount(policyTags);
        if (curTagCount + newTagCount > policyTagsLimit) {
            throw requestError(caller, "policy tag quota exceeded - limit: "
                    + policyTagsLimit + ", current tags count: " + curTagCount + ", new tags count: " + newTagCount);
        }

        boolean res = true;
        for (Map.Entry<String, TagValueList> e : policyTags.entrySet()) {
            for (String tagValue : e.getValue().getList()) {
                try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_POLICY_TAG)) {
                    ps.setInt(1, policyId);
                    ps.setString(2, processInsertValue(e.getKey()));
                    ps.setString(3, processInsertValue(tagValue));
                    res &= (executeUpdate(ps, caller) > 0);
                } catch (SQLException ex) {
                    throw sqlError(ex, caller);
                }
            }
        }
        return res;
    }

    int getPolicyTagsCount(int policyId) {
        final String caller = "getPolicyTagsCount";
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_POLICY_TAG_COUNT)) {
            ps.setInt(1, policyId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    @Override
    public boolean deletePolicyTags(String policyName, String domainName, Set<String> tagKeys, String version) {
        final String caller = "deletePolicyTags";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName, version);
        if (policyId == 0) {
            throw notFoundError(caller, OBJECT_POLICY, ResourceUtils.policyResourceName(domainName, policyName));
        }
        boolean res = true;
        for (String tagKey : tagKeys) {
            try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_POLICY_TAG)) {
                ps.setInt(1, policyId);
                ps.setString(2, processInsertValue(tagKey));
                res &= (executeUpdate(ps, caller) > 0);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }
        return res;
    }

    @Override
    public Map<String, TagValueList> getPolicyTags(String domainName, String policyName, String version) {

        final String caller = "getPolicyTags";
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName, version);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ResourceUtils.policyResourceName(domainName, policyName));
        }
        Map<String, TagValueList> policyTag = null;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_POLICY_TAGS)) {
            ps.setInt(1, policyId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String tagKey = rs.getString(1);
                    String tagValue = rs.getString(2);
                    if (policyTag == null) {
                        policyTag = new HashMap<>();
                    }
                    TagValueList tagValues = policyTag.computeIfAbsent(tagKey, k -> new TagValueList().setList(new ArrayList<>()));
                    tagValues.getList().add(tagValue);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return policyTag;
    }

    void getAthenzDomainServices(String domainName, int domainId, AthenzDomain athenzDomain) {

        final String caller = "getAthenzDomain";
        Map<String, ServiceIdentity> serviceMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_SERVICES)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String serviceName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    ServiceIdentity service = new ServiceIdentity()
                            .setName(ResourceUtils.serviceResourceName(domainName, serviceName))
                            .setProviderEndpoint(saveValue(rs.getString(ZMSConsts.DB_COLUMN_PROVIDER_ENDPOINT)))
                            .setDescription(saveValue(rs.getString(ZMSConsts.DB_COLUMN_DESCRIPTION)))
                            .setExecutable(saveValue(rs.getString(ZMSConsts.DB_COLUMN_EXECUTABLE)))
                            .setUser(saveValue(rs.getString(ZMSConsts.DB_COLUMN_SVC_USER)))
                            .setGroup(saveValue(rs.getString(ZMSConsts.DB_COLUMN_SVC_GROUP)))
                            .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()));
                    List<PublicKeyEntry> publicKeys = new ArrayList<>();
                    service.setPublicKeys(publicKeys);
                    serviceMap.put(serviceName, service);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_SERVICES_HOSTS)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String serviceName = rs.getString(1);
                    ServiceIdentity service = serviceMap.get(serviceName);
                    if (service == null) {
                        continue;
                    }
                    List<String> hosts = service.getHosts();
                    if (hosts == null) {
                        hosts = new ArrayList<>();
                        service.setHosts(hosts);
                    }
                    hosts.add(rs.getString(2));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_SERVICES_PUBLIC_KEYS)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String serviceName = rs.getString(1);
                    ServiceIdentity service = serviceMap.get(serviceName);
                    if (service == null) {
                        continue;
                    }
                    PublicKeyEntry publicKey = new PublicKeyEntry()
                            .setId(rs.getString(ZMSConsts.DB_COLUMN_KEY_ID))
                            .setKey(rs.getString(ZMSConsts.DB_COLUMN_KEY_VALUE));
                    service.getPublicKeys().add(publicKey);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        // add services tags
        addTagsToServices(serviceMap, athenzDomain.getName());

        athenzDomain.getServices().addAll(serviceMap.values());
    }

    void getAthenzDomainEntities(String domainName, int domainId, AthenzDomain athenzDomain) {

        final String caller = "getAthenzDomain";
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_ENTITIES)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    athenzDomain.getEntities().add(new Entity()
                            .setName(ResourceUtils.entityResourceName(domainName, rs.getString(ZMSConsts.DB_COLUMN_NAME)))
                            .setValue(JSON.fromString(rs.getString(ZMSConsts.DB_COLUMN_VALUE), Struct.class)));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    @Override
    public AthenzDomain getAthenzDomain(String domainName) {

        final String caller = "getAthenzDomain";

        int domainId = 0;
        AthenzDomain athenzDomain = new AthenzDomain(domainName);

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN)) {
            ps.setString(1, domainName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    athenzDomain.setDomain(saveDomainSettings(domainName, rs, true));
                    domainId = rs.getInt(ZMSConsts.DB_COLUMN_DOMAIN_ID);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }

        getAthenzDomainRoles(domainName, domainId, athenzDomain);
        getAthenzDomainGroups(domainName, domainId, athenzDomain);
        getAthenzDomainPolicies(domainName, domainId, athenzDomain);
        getAthenzDomainServices(domainName, domainId, athenzDomain);
        getAthenzDomainEntities(domainName, domainId, athenzDomain);

        return athenzDomain;
    }

    @Override
    public DomainMetaList listModifiedDomains(long modifiedSince) {

        final String caller = "listModifiedDomains";

        DomainMetaList domainModifiedList = new DomainMetaList();
        List<Domain> nameMods = new ArrayList<>();

        try (PreparedStatement ps = prepareDomainScanStatement(null, modifiedSince)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    final String domainName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    nameMods.add(saveDomainSettings(domainName, rs, false));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        domainModifiedList.setDomains(nameMods);
        return domainModifiedList;
    }

    boolean validatePrincipalDomain(String principal) {
        // special case for all principals
        if (ALL_PRINCIPALS.equals(principal)) {
            return true;
        }
        int idx = principal.indexOf(AuthorityConsts.GROUP_SEP);
        if (idx == -1) {
            idx = principal.lastIndexOf('.');
            if (idx == -1 || idx == 0 || idx == principal.length() - 1) {
                return false;
            }
        }
        return getDomainId(principal.substring(0, idx)) != 0;
    }

    String roleIndex(String domainId, String roleName) {
        return domainId + ':' + roleName;
    }

    PreparedStatement prepareRoleAssertionsStatement(String action)
            throws SQLException {

        PreparedStatement ps;
        if (!StringUtils.isEmpty(action)) {
            ps = con.prepareStatement(SQL_LIST_ROLE_ASSERTIONS + SQL_LIST_ROLE_ASSERTION_QUERY_ACTION);
            ps.setString(1, action);
        } else {
            ps = con.prepareStatement(SQL_LIST_ROLE_ASSERTIONS + SQL_LIST_ROLE_ASSERTION_NO_ACTION);
        }
        return ps;
    }

    Map<String, List<Assertion>> getRoleAssertions(String action, String caller) {

        Map<String, List<Assertion>> roleAssertions = new HashMap<>();
        try (PreparedStatement ps = prepareRoleAssertionsStatement(action)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    Assertion assertion = new Assertion();
                    String domainName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    String roleName = rs.getString(ZMSConsts.DB_COLUMN_ROLE);
                    assertion.setRole(ResourceUtils.roleResourceName(domainName, roleName));
                    assertion.setResource(rs.getString(ZMSConsts.DB_COLUMN_RESOURCE));
                    assertion.setAction(rs.getString(ZMSConsts.DB_COLUMN_ACTION));
                    assertion.setEffect(AssertionEffect.valueOf(rs.getString(ZMSConsts.DB_COLUMN_EFFECT)));
                    assertion.setId((long) rs.getInt(ZMSConsts.DB_COLUMN_ASSERT_ID));

                    String index = roleIndex(rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID), roleName);
                    List<Assertion> assertions = roleAssertions.computeIfAbsent(index, k -> new ArrayList<>());

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("{}: adding assertion {} for {}", caller, assertion, index);
                    }

                    assertions.add(assertion);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return roleAssertions;
    }

    Set<String> getRolePrincipals(final String principalName, final String caller) {

        // first let's find out all the roles that given principal is member of

        Set<String> rolePrincipals = getRolesForPrincipal(principalName, caller);

        // next let's extract all groups that the given principal is member of
        // if the group list is not empty then we need to extract all the roles
        // where groups are member of and include those roles that match our
        // extracted groups in the role principals map

        Set<String> groups = getGroupsForPrincipal(principalName, caller);
        if (!groups.isEmpty()) {
            updatePrincipalRoleGroupMembership(rolePrincipals, groups, principalName, caller);
        }
        return rolePrincipals;
    }

    void updatePrincipalRoleGroupMembership(Set<String> rolePrincipals, final Set<String> groups,
            final String principalName, final String caller) {

        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ROLE_GROUP_PRINCIPALS)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {

                    final String groupName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    if (!groups.contains(groupName)) {
                        continue;
                    }

                    final String roleName = rs.getString(ZMSConsts.DB_COLUMN_ROLE_NAME);
                    final String index = roleIndex(rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID), roleName);

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("{}: adding principal {} for {}", caller, principalName, index);
                    }

                    rolePrincipals.add(index);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    Set<String> getGroupsForPrincipal(final String principalName, final String caller) {

        Set<String> groups = new HashSet<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_GROUP_FOR_PRINCIPAL)) {
            ps.setString(1, principalName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    final String groupName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    final String domainName = rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_NAME);
                    groups.add(ResourceUtils.groupResourceName(domainName, groupName));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return groups;
    }

    Set<String> getRolesForPrincipal(final String principalName, final String caller) {

        Set<String> rolePrincipals = new HashSet<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ROLE_PRINCIPALS)) {
            ps.setString(1, principalName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {

                    final String roleName = rs.getString(ZMSConsts.DB_COLUMN_ROLE_NAME);
                    final String index = roleIndex(rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID), roleName);

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("{}: adding principal {} for {}", caller, principalName, index);
                    }

                    rolePrincipals.add(index);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return rolePrincipals;
    }

    void getTrustedSubTypeRoles(String sqlCommand, Map<String, List<String>> trustedRoles,
            String caller) {

        try (PreparedStatement ps = con.prepareStatement(sqlCommand)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String trustDomainId = rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID);
                    String trustRoleName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    String assertDomainId = rs.getString(ZMSConsts.DB_COLUMN_ASSERT_DOMAIN_ID);
                    String assertRoleName = rs.getString(ZMSConsts.DB_COLUMN_ROLE);

                    String index = roleIndex(assertDomainId, assertRoleName);
                    List<String> roles = trustedRoles.computeIfAbsent(index, k -> new ArrayList<>());
                    String tRoleName = roleIndex(trustDomainId, trustRoleName);
                    roles.add(tRoleName);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    long lastTrustRoleUpdatesTimestamp() {

        final String caller = "lastTrustRoleUpdatesTimestamp";

        long timeStamp = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_LAST_ASSUME_ROLE_ASSERTION)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    timeStamp = rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime();
                }
            }
        } catch (SQLException ignored) {
        }

        return timeStamp;
    }

    Map<String, List<String>> getTrustedRoles(String caller) {

        // if our last timestamp has passed our timeout or our map has not been
        // initialized, then we need to update our trust map so need for any
        // extra timestamp checks

        long now = System.currentTimeMillis();
        if (SERVER_TRUST_ROLES_MAP == null || now - SERVER_TRUST_ROLES_TIMESTAMP > SERVER_TRUST_ROLES_UPDATE_TIMEOUT) {
            updateTrustRolesMap(now, true, caller);
        } else {

            // we want to make sure to capture any additions right away, so we'll get
            // the last modification timestamp of the latest policy that has an assume_role
            // assertion

            long lastTimeStamp = lastTrustRoleUpdatesTimestamp();
            if (lastTimeStamp > SERVER_TRUST_ROLES_TIMESTAMP) {
                updateTrustRolesMap(lastTimeStamp, false, caller);
            }
        }

        return SERVER_TRUST_ROLES_MAP;
    }

    void updateTrustRolesMap(long lastTimeStamp, boolean timeoutUpdate, final String caller) {

        synchronized (synchronizer) {

            // a couple of simple checks in case we already have a valid
            // map to see if we can skip updating the map

            if (SERVER_TRUST_ROLES_MAP != null) {

                // if our last timestamp is older than the one we have
                // then we're going to skip the update

                if (SERVER_TRUST_ROLES_TIMESTAMP >= lastTimeStamp) {
                    return;
                }

                // if this is a timeout update we're going to check if the map
                // has already been updated by another thread while we were waiting

                if (timeoutUpdate && lastTimeStamp - SERVER_TRUST_ROLES_TIMESTAMP < SERVER_TRUST_ROLES_UPDATE_TIMEOUT) {
                    return;
                }
            }

            Map<String, List<String>> trustedRoles = new HashMap<>();
            getTrustedSubTypeRoles(SQL_LIST_TRUSTED_STANDARD_ROLES, trustedRoles, caller);
            getTrustedSubTypeRoles(SQL_LIST_TRUSTED_WILDCARD_ROLES, trustedRoles, caller);
            SERVER_TRUST_ROLES_TIMESTAMP = lastTimeStamp;
            SERVER_TRUST_ROLES_MAP = trustedRoles;
        }
    }

    void addRoleAssertions(List<Assertion> principalAssertions, List<Assertion> roleAssertions) {
        if (roleAssertions != null && !roleAssertions.isEmpty()) {
            principalAssertions.addAll(roleAssertions);
        }
    }

    ResourceAccess getResourceAccessObject(String principal, List<Assertion> assertions) {
        ResourceAccess rsrcAccess = new ResourceAccess();
        rsrcAccess.setPrincipal(principal);
        rsrcAccess.setAssertions(assertions != null ? assertions : new ArrayList<>());
        return rsrcAccess;
    }

    @Override
    public ResourceAccessList listResourceAccess(String principal, String action, String userDomain) {

        final String caller = "listResourceAccess";

        ResourceAccessList rsrcAccessList = new ResourceAccessList();
        List<ResourceAccess> resources = new ArrayList<>();
        rsrcAccessList.setResources(resources);

        // first let's get the principal list that we're asked to check for
        // since if we have no matches then we have nothing to do

        Set<String> rolePrincipals = getRolePrincipals(principal, caller);
        if (rolePrincipals.isEmpty()) {

            // so the given principal is not available as a role member
            // so before returning an empty response let's make sure
            // that it has been registered in Athenz otherwise we'll
            // just return 404 - not found exception

            if (getPrincipalId(principal) == 0) {
                throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
            }

            resources.add(getResourceAccessObject(principal, null));
            return rsrcAccessList;
        }

        // now let's get the list of role assertions. if we have
        // no matches, then we have nothing to do

        Map<String, List<Assertion>> roleAssertions = getRoleAssertions(action, caller);
        if (roleAssertions.isEmpty()) {
            resources.add(getResourceAccessObject(principal, null));
            return rsrcAccessList;
        }

        // finally we need to get all the trusted role maps

        Map<String, List<String>> trustedRoles = getTrustedRoles(caller);

        // now let's go ahead and combine all of our data together
        // we're going to go through each principal, lookup
        // the assertions for the role and add them to the return object
        // if the role has no corresponding assertions, then we're going
        // to look at the trust role map in case it's a trusted role

        Map<String, List<Assertion>> principalAssertions = new HashMap<>();
        for (String roleIndex : rolePrincipals) {

            if (LOG.isDebugEnabled()) {
                LOG.debug("{}: processing role: {}", caller, roleIndex);
            }

            List<Assertion> assertions = principalAssertions.computeIfAbsent(principal, k -> new ArrayList<>());

            // retrieve the assertions for this role

            addRoleAssertions(assertions, roleAssertions.get(roleIndex));

            // check to see if this is a trusted role. There might be multiple
            // roles all being mapped as trusted, so we need to process them all

            List<String> mappedTrustedRoles = trustedRoles.get(roleIndex);
            if (mappedTrustedRoles != null) {
                for (String mappedTrustedRole : mappedTrustedRoles) {

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("{}: processing trusted role: {}", caller, mappedTrustedRole);
                    }

                    addRoleAssertions(assertions, roleAssertions.get(mappedTrustedRole));
                }
            }
        }

        // finally we need to create resource access list objects and return

        for (Map.Entry<String, List<Assertion>> entry : principalAssertions.entrySet()) {
            resources.add(getResourceAccessObject(entry.getKey(), entry.getValue()));
        }

        return rsrcAccessList;
    }

    @Override
    public Stats getStats(String domainName) {

        final String caller = "getStats";

        if (!StringUtil.isEmpty(domainName)) {
            int domainId = getDomainId(domainName);
            if (domainId == 0) {
                throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
            }
            return getDomainStats(domainName, domainId);
        } else {
            return getSystemStats();
        }
    }

    Stats getSystemStats() {
        Stats stats = new Stats();
        stats.setAssertion(getObjectSystemCount(SQL_TABLE_ASSERTION));
        stats.setRole(getObjectSystemCount(SQL_TABLE_ROLE));
        stats.setRoleMember(getObjectSystemCount(SQL_TABLE_ROLE_MEMBER));
        stats.setPolicy(getObjectSystemCount(SQL_TABLE_POLICY));
        stats.setService(getObjectSystemCount(SQL_TABLE_SERVICE));
        stats.setServiceHost(getObjectSystemCount(SQL_TABLE_SERVICE_HOST));
        stats.setPublicKey(getObjectSystemCount(SQL_TABLE_PUBLIC_KEY));
        stats.setEntity(getObjectSystemCount(SQL_TABLE_ENTITY));
        stats.setSubdomain(getObjectSystemCount(SQL_TABLE_DOMAIN));
        stats.setGroup(getObjectSystemCount(SQL_TABLE_PRINCIPAL_GROUP));
        stats.setGroupMember(getObjectSystemCount(SQL_TABLE_PRINCIPAL_GROUP_MEMBER));
        return stats;
    }

    Stats getDomainStats(final String domainName, int domainId) {

        Stats stats = new Stats().setName(domainName);
        stats.setRole(getObjectDomainCount(SQL_TABLE_ROLE, domainId));
        stats.setPolicy(getObjectDomainCount(SQL_TABLE_POLICY, domainId));
        stats.setEntity(getObjectDomainCount(SQL_TABLE_ENTITY, domainId));
        stats.setService(getObjectDomainCount(SQL_TABLE_SERVICE, domainId));
        stats.setGroup(getObjectDomainCount(SQL_TABLE_PRINCIPAL_GROUP, domainId));

        stats.setAssertion(getObjectDomainComponentCount(SQL_GET_DOMAIN_ASSERTION_COUNT, domainId));
        stats.setRoleMember(getObjectDomainComponentCount(SQL_GET_DOMAIN_ROLE_MEMBER_COUNT, domainId));
        stats.setGroupMember(getObjectDomainComponentCount(SQL_GET_DOMAIN_GROUP_MEMBER_COUNT, domainId));
        stats.setServiceHost(getObjectDomainComponentCount(SQL_GET_DOMAIN_SERVICE_HOST_COUNT, domainId));
        stats.setPublicKey(getObjectDomainComponentCount(SQL_GET_DOMAIN_SERVICE_PUBLIC_KEY_COUNT, domainId));

        stats.setSubdomain(getSubdomainPrefixCount(domainName));
        return stats;
    }

    int getObjectSystemCount(final String tableName) {

        final String caller = "getObjectSystemCount";

        int count = 0;
        final String sqlCommand = SQL_GET_OBJECT_SYSTEM_COUNT + tableName;
        try (PreparedStatement ps = con.prepareStatement(sqlCommand)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    int getObjectDomainCount(final String tableName, int domainId) {

        final String caller = "getObjectDomainCount";

        int count = 0;
        final String sqlCommand = SQL_GET_OBJECT_DOMAIN_COUNT + tableName + SQL_GET_OBJECT_DOMAIN_COUNT_QUERY;
        try (PreparedStatement ps = con.prepareStatement(sqlCommand)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    int getObjectDomainComponentCount(final String sqlCommand, int domainId) {

        final String caller = "getObjectDomainComponentCount";

        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(sqlCommand)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    int getSubdomainPrefixCount(final String domainName) {

        final String caller = "getSubdomainPrefixCount";

        final String domainPrefix = domainName + ".";
        int len = domainPrefix.length();
        char c = (char) (domainPrefix.charAt(len - 1) + 1);
        final String stop = domainPrefix.substring(0, len - 1) + c;

        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_PREFIX_COUNT)) {
            ps.setString(1, domainPrefix);
            ps.setString(2, stop);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    @Override
    public Quota getQuota(String domainName) {

        final String caller = "getQuota";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        Quota quota = null;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_QUOTA)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    quota = new Quota().setName(domainName);
                    quota.setAssertion(rs.getInt(ZMSConsts.DB_COLUMN_ASSERTION));
                    quota.setRole(rs.getInt(ZMSConsts.DB_COLUMN_ROLE));
                    quota.setRoleMember(rs.getInt(ZMSConsts.DB_COLUMN_ROLE_MEMBER));
                    quota.setPolicy(rs.getInt(ZMSConsts.DB_COLUMN_POLICY));
                    quota.setService(rs.getInt(ZMSConsts.DB_COLUMN_SERVICE));
                    quota.setServiceHost(rs.getInt(ZMSConsts.DB_COLUMN_SERVICE_HOST));
                    quota.setPublicKey(rs.getInt(ZMSConsts.DB_COLUMN_PUBLIC_KEY));
                    quota.setEntity(rs.getInt(ZMSConsts.DB_COLUMN_ENTITY));
                    quota.setSubdomain(rs.getInt(ZMSConsts.DB_COLUMN_SUBDOMAIN));
                    quota.setGroup(rs.getInt(ZMSConsts.DB_COLUMN_PRINCIPAL_GROUP));
                    quota.setGroupMember(rs.getInt(ZMSConsts.DB_COLUMN_PRINCIPAL_GROUP_MEMBER));
                    quota.setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return quota;
    }

    @Override
    public boolean insertQuota(String domainName, Quota quota) {

        final String caller = "insertQuota";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_QUOTA)) {
            ps.setInt(1, domainId);
            ps.setInt(2, quota.getRole());
            ps.setInt(3, quota.getRoleMember());
            ps.setInt(4, quota.getPolicy());
            ps.setInt(5, quota.getAssertion());
            ps.setInt(6, quota.getService());
            ps.setInt(7, quota.getServiceHost());
            ps.setInt(8, quota.getPublicKey());
            ps.setInt(9, quota.getEntity());
            ps.setInt(10, quota.getSubdomain());
            ps.setInt(11, quota.getGroup());
            ps.setInt(12, quota.getGroupMember());
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateQuota(String domainName, Quota quota) {

        final String caller = "updateQuota";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_QUOTA)) {
            ps.setInt(1, quota.getRole());
            ps.setInt(2, quota.getRoleMember());
            ps.setInt(3, quota.getPolicy());
            ps.setInt(4, quota.getAssertion());
            ps.setInt(5, quota.getService());
            ps.setInt(6, quota.getServiceHost());
            ps.setInt(7, quota.getPublicKey());
            ps.setInt(8, quota.getEntity());
            ps.setInt(9, quota.getSubdomain());
            ps.setInt(10, quota.getGroup());
            ps.setInt(11, quota.getGroupMember());
            ps.setInt(12, domainId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deleteQuota(String domainName) {

        final String caller = "deleteQuota";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_QUOTA)) {
            ps.setInt(1, domainId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public DomainRoleMembers listDomainRoleMembers(String domainName) {
        return listDomainRoleMembersWithQuery(domainName, SQL_GET_DOMAIN_ROLE_MEMBERS, "listDomainRoleMembers");
    }

    @Override
    public DomainRoleMember getPrincipalRoles(String principal, String domainName) {

        final String caller = "getPrincipalRoles";

        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        DomainRoleMember roleMember = new DomainRoleMember();
        roleMember.setMemberRoles(new ArrayList<>());
        roleMember.setMemberName(principal);
        if (StringUtil.isEmpty(domainName)) {
            try (PreparedStatement ps = con.prepareStatement(SQL_GET_PRINCIPAL_ROLES)) {
                ps.setInt(1, principalId);
                return getRolesForPrincipal(caller, roleMember, ps);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        } else {
            int domainId = getDomainId(domainName);
            if (domainId == 0) {
                throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
            }

            try (PreparedStatement ps = con.prepareStatement(SQL_GET_PRINCIPAL_ROLES_DOMAIN)) {
                ps.setInt(1, principalId);
                ps.setInt(2, domainId);
                return getRolesForPrincipal(caller, roleMember, ps);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }
    }

    private DomainRoleMember getRolesForPrincipal(String caller, DomainRoleMember roleMember, PreparedStatement ps) throws SQLException {
        try (ResultSet rs = executeQuery(ps, caller)) {
            while (rs.next()) {
                final String roleName = rs.getString(1);
                final String domain = rs.getString(2);

                MemberRole memberRole = new MemberRole();
                memberRole.setRoleName(roleName);
                memberRole.setDomainName(domain);

                java.sql.Timestamp expiration = rs.getTimestamp(3);
                if (expiration != null) {
                    memberRole.setExpiration(Timestamp.fromMillis(expiration.getTime()));
                }
                java.sql.Timestamp reviewReminder = rs.getTimestamp(4);
                if (reviewReminder != null) {
                    memberRole.setReviewReminder(Timestamp.fromMillis(reviewReminder.getTime()));
                }
                memberRole.setSystemDisabled(nullIfDefaultValue(rs.getInt(5), 0));

                roleMember.getMemberRoles().add(memberRole);
            }

            return roleMember;
        }
    }

    @Override
    public DomainRoleMembers listOverdueReviewRoleMembers(String domainName) {
        return listDomainRoleMembersWithQuery(domainName, SQL_GET_REVIEW_OVERDUE_DOMAIN_ROLE_MEMBERS, "listDomainRoleMembersWithQuery");
    }

    @Override
    public Map<String, List<DomainGroupMember>> getPendingDomainGroupMembersByPrincipal(String principal) {

        final String caller = "getPendingDomainGroupMembersList";
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        Map<String, List<DomainGroupMember>> domainGroupMembersMap = new LinkedHashMap<>();

        // first we're going to retrieve all the members that are waiting
        // for approval based on their domain org values

        processPendingGroupMembers(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG, SQL_PENDING_ORG_AUDIT_GROUP_MEMBER_LIST,
                principalId, domainGroupMembersMap, caller);

        // then we're going to retrieve all the members that are waiting
        // for approval based on their domain name values

        processPendingGroupMembers(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN, SQL_PENDING_DOMAIN_AUDIT_GROUP_MEMBER_LIST,
                principalId, domainGroupMembersMap, caller);

        // finally retrieve the self serve groups

        try (PreparedStatement ps = con.prepareStatement(SQL_PENDING_DOMAIN_ADMIN_GROUP_MEMBER_LIST)) {
            ps.setInt(1, principalId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    populateDomainGroupMembersMapFromResultSet(domainGroupMembersMap, rs);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return domainGroupMembersMap;
    }

    @Override
    public Map<String, List<DomainGroupMember>> getPendingDomainGroupMembersByDomain(String domainName) {

        final String caller = "getPendingDomainGroupMembersList";
        final boolean allDomains = "*".equals(domainName);
        int domainId = 0;

        if (!allDomains) {
            domainId = getDomainId(domainName);
            if (domainId == 0) {
                throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
            }
        }

        Map<String, List<DomainGroupMember>> domainGroupMembersMap = new LinkedHashMap<>();
        if (allDomains) {
            // retrieve all members pending approval in principal group across all domains

            try (PreparedStatement ps = con.prepareStatement(SQL_PENDING_ALL_DOMAIN_GROUP_MEMBER_LIST)) {
                try (ResultSet rs = executeQuery(ps, caller)) {
                    while (rs.next()) {
                        populateDomainGroupMembersMapFromResultSet(domainGroupMembersMap, rs);
                    }
                }
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        } else {
            // retrieve all the members that are waiting for approval
            // in review enabled, self serve and audit enabled groups for given domain

            try (PreparedStatement ps = con.prepareStatement(SQL_PENDING_DOMAIN_GROUP_MEMBER_LIST)) {
                ps.setInt(1, domainId);
                try (ResultSet rs = executeQuery(ps, caller)) {
                    while (rs.next()) {
                        populateDomainGroupMembersMapFromResultSet(domainGroupMembersMap, rs);
                    }
                }
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }

        return domainGroupMembersMap;
    }

    @Override
    public Map<String, List<DomainGroupMember>> getExpiredPendingDomainGroupMembers(int pendingGroupMemberLifespan) {

        final String caller = "getExpiredPendingDomainGroupMembers";

        //update audit log with details before deleting

        Map<String, List<DomainGroupMember>> domainGroupMembersMap = new LinkedHashMap<>();

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_EXPIRED_PENDING_GROUP_MEMBERS)) {
            ps.setInt(1, pendingGroupMemberLifespan);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    populateDomainGroupMembersMapFromResultSet(domainGroupMembersMap, rs);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return domainGroupMembersMap;
    }

    @Override
    public Set<String> getPendingGroupMembershipApproverRoles(String server, long timestamp) {

        final String caller = "getPendingGroupMembershipApproverGroups";

        Set<String> targetRoles = new HashSet<>();
        int orgDomainId = getDomainId(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG);
        int domDomainId = getDomainId(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN);

        java.sql.Timestamp ts = new java.sql.Timestamp(timestamp);

        //Get orgs and domains for audit enabled groups with pending membership

        try (PreparedStatement ps = con.prepareStatement(SQL_AUDIT_ENABLED_PENDING_GROUP_MEMBERSHIP_REMINDER_ENTRIES)) {
            ps.setTimestamp(1, ts);
            ps.setString(2, server);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {

                    // first process the org value

                    final String org = rs.getString(1);
                    if (org != null && !org.isEmpty()) {
                        int roleId = getRoleId(orgDomainId, org);
                        if (roleId != 0) {
                            targetRoles.add(ResourceUtils.roleResourceName(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG, org));
                        }
                    }

                    // then process the domain value

                    final String domain = rs.getString(2);
                    int roleId = getRoleId(domDomainId, domain);
                    if (roleId != 0) {
                        targetRoles.add(ResourceUtils.roleResourceName(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN, domain));
                    }
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        // get admin groups of pending self-serve and review-enabled requests

        getRecipientRoleForAdminGroupMembershipApproval(caller, targetRoles, ts, server);

        return targetRoles;
    }

    @Override
    public boolean updatePendingGroupMembersNotificationTimestamp(String server, long timestamp, int delayDays) {

        final String caller = "updatePendingGroupMembersNotificationTimestamp";
        int affectedRows;
        java.sql.Timestamp ts = new java.sql.Timestamp(timestamp);
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_PENDING_GROUP_MEMBERS_NOTIFICATION_TIMESTAMP)) {
            ps.setTimestamp(1, ts);
            ps.setString(2, server);
            ps.setTimestamp(3, ts);
            ps.setInt(4, delayDays);

            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    private DomainRoleMembers listDomainRoleMembersWithQuery(String domainName, String query, String caller) {
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        DomainRoleMembers domainRoleMembers = new DomainRoleMembers();
        domainRoleMembers.setDomainName(domainName);

        Map<String, DomainRoleMember> memberMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    final String roleName = rs.getString(1);
                    final String memberName = rs.getString(2);

                    DomainRoleMember domainRoleMember = memberMap.get(memberName);
                    if (domainRoleMember == null) {
                        domainRoleMember = new DomainRoleMember();
                        domainRoleMember.setMemberName(memberName);
                        memberMap.put(memberName, domainRoleMember);
                    }
                    List<MemberRole> memberRoles = domainRoleMember.getMemberRoles();
                    if (memberRoles == null) {
                        memberRoles = new ArrayList<>();
                        domainRoleMember.setMemberRoles(memberRoles);
                    }
                    MemberRole memberRole = new MemberRole();
                    memberRole.setRoleName(roleName);

                    java.sql.Timestamp expiration = rs.getTimestamp(3);
                    if (expiration != null) {
                        memberRole.setExpiration(Timestamp.fromMillis(expiration.getTime()));
                    }
                    java.sql.Timestamp reviewReminder = rs.getTimestamp(4);
                    if (reviewReminder != null) {
                        memberRole.setReviewReminder(Timestamp.fromMillis(reviewReminder.getTime()));
                    }
                    memberRole.setSystemDisabled(nullIfDefaultValue(rs.getInt(5), 0));
                    memberRoles.add(memberRole);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        if (!memberMap.isEmpty()) {
            domainRoleMembers.setMembers(new ArrayList<>(memberMap.values()));
        }
        return domainRoleMembers;
    }

    @Override
    public boolean deletePendingRoleMember(String domainName, String roleName, String principal,
            String admin, String auditRef) {

        final String caller = "deletePendingRoleMember";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }
        return executeDeletePendingRoleMember(roleId, principalId, admin, principal, auditRef, true, caller);
    }

    public boolean executeDeletePendingRoleMember(int roleId, int principalId, final String admin,
            final String principal, final String auditRef, boolean auditLog, final String caller) {

        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_PENDING_ROLE_MEMBER)) {
            ps.setInt(1, roleId);
            ps.setInt(2, principalId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        boolean result = (affectedRows > 0);
        if (result && auditLog) {
            result = insertRoleAuditLog(roleId, admin, principal, "REJECT", auditRef);
        }
        return result;
    }

    @Override
    public boolean confirmRoleMember(String domainName, String roleName, RoleMember roleMember,
            String admin, String auditRef) {

        final String caller = "confirmRoleMember";

        String principal = roleMember.getMemberName();
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        // need to check if the pending entry already exists
        // before doing any work

        String state = getPendingRoleMemberState(roleId, principal);
        if (state == null) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        boolean result = false;
        if (roleMember.getApproved() == Boolean.TRUE) {
            if (ZMSConsts.PENDING_REQUEST_ADD_STATE.equals(state)) {
                boolean roleMemberExists = roleMemberExists(roleId, principalId, principal, null, caller);
                result = insertStandardRoleMember(roleId, principalId, roleMember, admin,
                        principal, auditRef, roleMemberExists, true, caller);
            } else if (ZMSConsts.PENDING_REQUEST_DELETE_STATE.equals(state)) {
                result = deleteRoleMember(domainName, roleName, principal, admin, auditRef);
            }
            if (result) {
                executeDeletePendingRoleMember(roleId, principalId, admin, principal,
                        auditRef, false, caller);
            }
        } else {
            result = executeDeletePendingRoleMember(roleId, principalId, admin,
                principal, auditRef, true, caller);
        }

        return result;
    }

    public String getPendingRoleMemberState(Integer roleId, String member) {

        final String caller = "getPendingRoleMemberState";
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_PENDING_ROLE_MEMBER_STATE)) {
            ps.setInt(1, roleId);
            ps.setString(2, member);
                try (ResultSet rs = executeQuery(ps, caller)) {
                    if (rs.next()) {
                        return rs.getString(1);
                    } else {
                        return null;
                    }
                }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

    }

    public String getPendingGroupMemberState(Integer groupId, String member) {

        final String caller = "getPendingGroupMemberState";
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_PENDING_GROUP_MEMBER_STATE)) {
            ps.setInt(1, groupId);
            ps.setString(2, member);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    return rs.getString(1);
                } else {
                    return null;
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

    }

    void processPendingMembers(final String domainName, final String query, int principalId,
            Map<String, List<DomainRoleMember>> domainRoleMembersMap, final String caller) {

        int auditDomId = getDomainId(domainName);
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setInt(1, principalId);
            ps.setInt(2, auditDomId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    populateDomainRoleMembersMapFromResultSet(domainRoleMembersMap, rs);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    void processPendingGroupMembers(final String domainName, final String query, int principalId,
                                    Map<String, List<DomainGroupMember>> domainGroupMembersMap, final String caller) {

        int auditDomId = getDomainId(domainName);
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setInt(1, principalId);
            ps.setInt(2, auditDomId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    populateDomainGroupMembersMapFromResultSet(domainGroupMembersMap, rs);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    @Override
    public Map<String, List<DomainRoleMember>> getPendingDomainRoleMembersByPrincipal(String principal) {

        final String caller = "getPendingDomainRoleMembersList";
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        Map<String, List<DomainRoleMember>> domainRoleMembersMap = new LinkedHashMap<>();

        // first we're going to retrieve all the members that are waiting
        // for approval based on their domain org values

        processPendingMembers(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG, SQL_PENDING_ORG_AUDIT_ROLE_MEMBER_LIST,
            principalId, domainRoleMembersMap, caller);

        // then we're going to retrieve all the members that are waiting
        // for approval based on their domain name values
        processPendingMembers(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN, SQL_PENDING_DOMAIN_AUDIT_ROLE_MEMBER_LIST,
            principalId, domainRoleMembersMap, caller);

        // finally retrieve the self serve roles
        try (PreparedStatement ps = con.prepareStatement(SQL_PENDING_DOMAIN_ADMIN_ROLE_MEMBER_LIST)) {
            ps.setInt(1, principalId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    populateDomainRoleMembersMapFromResultSet(domainRoleMembersMap, rs);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return domainRoleMembersMap;
    }

    @Override
    public Map<String, List<DomainRoleMember>> getPendingDomainRoleMembersByDomain(String domainName) {

        final String caller = "getPendingDomainRoleMembersList";
        final boolean allDomains = "*".equals(domainName);

        int domainId = 0;
        if (!allDomains) {
            domainId = getDomainId(domainName);
            if (domainId == 0) {
                throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
            }
        }

        Map<String, List<DomainRoleMember>> domainRoleMembersMap = new LinkedHashMap<>();

        if (allDomains) {
            // retrieve all the members waiting approval across all domains

            try (PreparedStatement ps = con.prepareStatement(SQL_PENDING_ALL_DOMAIN_ROLE_MEMBER_LIST)) {
                try (ResultSet rs = executeQuery(ps, caller)) {
                    while (rs.next()) {
                        populateDomainRoleMembersMapFromResultSet(domainRoleMembersMap, rs);
                    }
                }
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        } else {
            // retrieve all the members that are waiting for approval
            // in audit_enabled,review_enabled and self serve roles in given domain

            try (PreparedStatement ps = con.prepareStatement(SQL_PENDING_DOMAIN_ROLE_MEMBER_LIST)) {
                ps.setInt(1, domainId);
                try (ResultSet rs = executeQuery(ps, caller)) {
                    while (rs.next()) {
                        populateDomainRoleMembersMapFromResultSet(domainRoleMembersMap, rs);
                    }
                }
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }

        return domainRoleMembersMap;
    }

    private void populateDomainRoleMembersMapFromResultSet(Map<String, List<DomainRoleMember>> domainRoleMembersMap, ResultSet rs) throws SQLException {

        List<DomainRoleMember> domainRoleMembers;
        final String domain = rs.getString(1);
        if (!domainRoleMembersMap.containsKey(domain)) {
            domainRoleMembers = new ArrayList<>();
            domainRoleMembersMap.put(domain, domainRoleMembers);
        }
        domainRoleMembers = domainRoleMembersMap.get(domain);

        DomainRoleMember domainRoleMember = new DomainRoleMember();
        domainRoleMember.setMemberName(rs.getString(3));
        List<MemberRole> memberRoles = new ArrayList<>();

        MemberRole memberRole = new MemberRole();
        memberRole.setRoleName(rs.getString(2));
        java.sql.Timestamp expiration = rs.getTimestamp(4);
        if (expiration != null) {
            memberRole.setExpiration(Timestamp.fromMillis(expiration.getTime()));
        }
        java.sql.Timestamp reviewReminder = rs.getTimestamp(5);
        if (reviewReminder != null) {
            memberRole.setReviewReminder(Timestamp.fromMillis(reviewReminder.getTime()));
        }
        memberRole.setActive(false);
        memberRole.setAuditRef(rs.getString(6));

        expiration = rs.getTimestamp(7);
        if (expiration != null) {
            memberRole.setRequestTime(Timestamp.fromMillis(expiration.getTime()));
        }
        memberRole.setRequestPrincipal(rs.getString(8));
        memberRole.setPendingState(rs.getString(9));
        memberRoles.add(memberRole);
        domainRoleMember.setMemberRoles(memberRoles);
        if (!domainRoleMembers.contains(domainRoleMember)) {
            domainRoleMembers.add(domainRoleMember);
        }
    }

    private void populateDomainGroupMembersMapFromResultSet(Map<String, List<DomainGroupMember>> domainGroupMembersMap, ResultSet rs) throws SQLException {

        List<DomainGroupMember> domainGroupMembers;
        final String domain = rs.getString(1);
        if (!domainGroupMembersMap.containsKey(domain)) {
            domainGroupMembers = new ArrayList<>();
            domainGroupMembersMap.put(domain, domainGroupMembers);
        }
        domainGroupMembers = domainGroupMembersMap.get(domain);

        DomainGroupMember domainGroupMember = new DomainGroupMember();
        domainGroupMember.setMemberName(rs.getString(3));
        List<GroupMember> memberGroups = new ArrayList<>();

        GroupMember memberGroup = new GroupMember();
        memberGroup.setGroupName(rs.getString(2));
        java.sql.Timestamp expiration = rs.getTimestamp(4);
        if (expiration != null) {
            memberGroup.setExpiration(Timestamp.fromMillis(expiration.getTime()));
        }
        memberGroup.setActive(false);
        memberGroup.setAuditRef(rs.getString(5));

        expiration = rs.getTimestamp(6);
        if (expiration != null) {
            memberGroup.setRequestTime(Timestamp.fromMillis(expiration.getTime()));
        }
        memberGroup.setRequestPrincipal(rs.getString(7));
        memberGroup.setPendingState(rs.getString(8));
        memberGroups.add(memberGroup);

        domainGroupMember.setMemberGroups(memberGroups);
        if (!domainGroupMembers.contains(domainGroupMember)) {
            domainGroupMembers.add(domainGroupMember);
        }
    }

    @Override
    public Set<String> getPendingMembershipApproverRoles(String server, long timestamp) {

        final String caller = "getPendingMembershipApproverRoles";

        Set<String> targetRoles = new HashSet<>();
        int orgDomainId = getDomainId(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG);
        int domDomainId = getDomainId(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN);

        java.sql.Timestamp ts = new java.sql.Timestamp(timestamp);

        //Get orgs and domains for audit enabled roles with pending membership

        try (PreparedStatement ps = con.prepareStatement(SQL_AUDIT_ENABLED_PENDING_MEMBERSHIP_REMINDER_ENTRIES)) {
            ps.setTimestamp(1, ts);
            ps.setString(2, server);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {

                    // first process the org value

                    final String org = rs.getString(1);
                    if (org != null && !org.isEmpty()) {
                        int roleId = getRoleId(orgDomainId, org);
                        if (roleId != 0) {
                            targetRoles.add(ResourceUtils.roleResourceName(ZMSConsts.SYS_AUTH_AUDIT_BY_ORG, org));
                        }
                    }

                    // then process the domain value

                    final String domain = rs.getString(2);
                    int roleId = getRoleId(domDomainId, domain);
                    if (roleId != 0) {
                        targetRoles.add(ResourceUtils.roleResourceName(ZMSConsts.SYS_AUTH_AUDIT_BY_DOMAIN, domain));
                    }
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        // get admin roles of pending self-serve and review-enabled requests

        getRecipientRoleForAdminMembershipApproval(caller, targetRoles, ts, server);

        return targetRoles;
    }

    @Override
    public Map<String, List<DomainRoleMember>> getExpiredPendingDomainRoleMembers(int pendingRoleMemberLifespan) {

        final String caller = "getExpiredPendingMembers";
        //update audit log with details before deleting

        Map<String, List<DomainRoleMember>> domainRoleMembersMap = new LinkedHashMap<>();

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_EXPIRED_PENDING_ROLE_MEMBERS)) {
            ps.setInt(1, pendingRoleMemberLifespan);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    populateDomainRoleMembersMapFromResultSet(domainRoleMembersMap, rs);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return domainRoleMembersMap;
    }

    @Override
    public boolean updatePendingRoleMembersNotificationTimestamp(String server, long timestamp, int delayDays) {
        final String caller = "updatePendingRoleMembersNotificationTimestamp";
        int affectedRows;
        java.sql.Timestamp ts = new java.sql.Timestamp(timestamp);
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_PENDING_ROLE_MEMBERS_NOTIFICATION_TIMESTAMP)) {
            ps.setTimestamp(1, ts);
            ps.setString(2, server);
            ps.setTimestamp(3, ts);
            ps.setInt(4, delayDays);

            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    private void getRecipientRoleForAdminMembershipApproval(String caller, Set<String> targetRoles,
                java.sql.Timestamp timestamp, String server) {

        try (PreparedStatement ps = con.prepareStatement(SQL_ADMIN_PENDING_MEMBERSHIP_REMINDER_DOMAINS)) {
            ps.setTimestamp(1, timestamp);
            ps.setString(2, server);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    targetRoles.add(ResourceUtils.roleResourceName(rs.getString(1), ZMSConsts.ADMIN_ROLE_NAME));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    private void getRecipientRoleForAdminGroupMembershipApproval(String caller, Set<String> targetRoles,
                                                            java.sql.Timestamp timestamp, String server) {

        try (PreparedStatement ps = con.prepareStatement(SQL_ADMIN_PENDING_GROUP_MEMBERSHIP_REMINDER_DOMAINS)) {
            ps.setTimestamp(1, timestamp);
            ps.setString(2, server);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    targetRoles.add(ResourceUtils.roleResourceName(rs.getString(1), ZMSConsts.ADMIN_ROLE_NAME));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    @Override
    public Map<String, DomainRoleMember> getNotifyTemporaryRoleMembers(String server, long timestamp) {
        return getNotifyRoleMembers(server, timestamp, SQL_LIST_NOTIFY_TEMPORARY_ROLE_MEMBERS, "listNotifyTemporaryRoleMembers");
    }

    @Override
    public boolean updateRoleMemberExpirationNotificationTimestamp(String server, long timestamp, int delayDays) {

        // first verify that we haven't had any updates in the last configured
        // number of delayed days. We don't want multiple instances running
        // and generating multiple emails depending on the time. We want to
        // make sure, for example, to generate only a single email per day

        if (isLastNotifyTimeWithinSpecifiedDays(SQL_ROLE_EXPIRY_LAST_NOTIFIED_TIME, delayDays)) {
            return false;
        }

        // process our request

        return updateMemberNotificationTimestamp(server, timestamp,
                SQL_UPDATE_ROLE_MEMBERS_EXPIRY_NOTIFICATION_TIMESTAMP, "updateRoleMemberExpirationNotificationTimestamp");
    }

    @Override
    public Map<String, DomainGroupMember> getNotifyTemporaryGroupMembers(String server, long timestamp) {

        final String caller = "getNotifyTemporaryGroupMembers";
        Map<String, DomainGroupMember> memberMap = new HashMap<>();

        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_NOTIFY_TEMPORARY_GROUP_MEMBERS)) {
            ps.setTimestamp(1, new java.sql.Timestamp(timestamp));
            ps.setString(2, server);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    final String memberName = rs.getString(DB_COLUMN_PRINCIPAL_NAME);
                    java.sql.Timestamp expiration = rs.getTimestamp(ZMSConsts.DB_COLUMN_EXPIRATION);

                    DomainGroupMember domainGroupMember = memberMap.get(memberName);
                    if (domainGroupMember == null) {
                        domainGroupMember = new DomainGroupMember();
                        domainGroupMember.setMemberName(memberName);
                        memberMap.put(memberName, domainGroupMember);
                    }
                    List<GroupMember> memberGroups = domainGroupMember.getMemberGroups();
                    if (memberGroups == null) {
                        memberGroups = new ArrayList<>();
                        domainGroupMember.setMemberGroups(memberGroups);
                    }
                    GroupMember memberGroup = new GroupMember();
                    memberGroup.setMemberName(memberName);
                    memberGroup.setGroupName(rs.getString(ZMSConsts.DB_COLUMN_AS_GROUP_NAME));
                    memberGroup.setDomainName(rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_NAME));
                    if (expiration != null) {
                        memberGroup.setExpiration(Timestamp.fromMillis(expiration.getTime()));
                    }
                    memberGroups.add(memberGroup);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return memberMap;
    }

    @Override
    public boolean updateGroupMemberExpirationNotificationTimestamp(String server, long timestamp, int delayDays) {

        // first verify that we haven't had any updates in the last configured
        // number of delayed days. We don't want multiple instances running
        // and generating multiple emails depending on the time. We want to
        // make sure, for example, to generate only a single email per day

        if (isLastNotifyTimeWithinSpecifiedDays(SQL_GROUP_EXPIRY_LAST_NOTIFIED_TIME, delayDays)) {
            return false;
        }

        return updateMemberNotificationTimestamp(server, timestamp,
                SQL_UPDATE_GROUP_MEMBERS_EXPIRY_NOTIFICATION_TIMESTAMP, "updateGroupMemberExpirationNotificationTimestamp");
    }

    @Override
    public Map<String, DomainRoleMember> getNotifyReviewRoleMembers(String server, long timestamp) {
        return getNotifyRoleMembers(server, timestamp, SQL_LIST_NOTIFY_REVIEW_ROLE_MEMBERS, "listNotifyReviewRoleMembers");
    }

    @Override
    public boolean updateRoleMemberReviewNotificationTimestamp(String server, long timestamp, int delayDays) {

        // first verify that we haven't had any updates in the last configured
        // number of delayed days. We don't want multiple instances running
        // and generating multiple emails depending on the time. We want to
        // make sure, for example, to generate only a single email per day

        if (isLastNotifyTimeWithinSpecifiedDays(SQL_ROLE_REVIEW_LAST_NOTIFIED_TIME, delayDays)) {
            return false;
        }

        return updateMemberNotificationTimestamp(server, timestamp,
                SQL_UPDATE_ROLE_MEMBERS_REVIEW_NOTIFICATION_TIMESTAMP, "updateRoleMemberReviewNotificationTimestamp");
    }

    private boolean updateMemberNotificationTimestamp(final String server, long timestamp, final String query, final String caller) {
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setTimestamp(1, new java.sql.Timestamp(timestamp));
            ps.setString(2, server);

            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    private Map<String, DomainRoleMember> getNotifyRoleMembers(final String server, long timestamp, final String query,
                                                               final String caller) {

        Map<String, DomainRoleMember> memberMap = new HashMap<>();

        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setTimestamp(1, new java.sql.Timestamp(timestamp));
            ps.setString(2, server);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    final String memberName = rs.getString(DB_COLUMN_PRINCIPAL_NAME);
                    java.sql.Timestamp expiration = rs.getTimestamp(ZMSConsts.DB_COLUMN_EXPIRATION);
                    java.sql.Timestamp reviewReminder = rs.getTimestamp(ZMSConsts.DB_COLUMN_REVIEW_REMINDER);

                    DomainRoleMember domainRoleMember = memberMap.get(memberName);
                    if (domainRoleMember == null) {
                        domainRoleMember = new DomainRoleMember();
                        domainRoleMember.setMemberName(memberName);
                        memberMap.put(memberName, domainRoleMember);
                    }
                    List<MemberRole> memberRoles = domainRoleMember.getMemberRoles();
                    if (memberRoles == null) {
                        memberRoles = new ArrayList<>();
                        domainRoleMember.setMemberRoles(memberRoles);
                    }
                    MemberRole memberRole = new MemberRole();
                    memberRole.setMemberName(memberName);
                    memberRole.setRoleName(rs.getString(ZMSConsts.DB_COLUMN_ROLE_NAME));
                    memberRole.setDomainName(rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_NAME));
                    if (expiration != null) {
                        memberRole.setExpiration(Timestamp.fromMillis(expiration.getTime()));
                    }
                    if (reviewReminder != null) {
                        memberRole.setReviewReminder(Timestamp.fromMillis(reviewReminder.getTime()));
                    }
                    memberRoles.add(memberRole);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return memberMap;
    }

    @Override
    public List<TemplateMetaData> getDomainTemplates(String domainName) {
        TemplateMetaData templateDomainMapping;
        List<TemplateMetaData> templateDomainMappingList = new ArrayList<>();
        final String caller = "getDomainTemplates";
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_DOMAIN_TEMPLATES)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    templateDomainMapping = new TemplateMetaData();
                    templateDomainMapping.setTemplateName(rs.getString(ZMSConsts.DB_COLUMN_TEMPLATE_NAME));
                    templateDomainMapping.setCurrentVersion(rs.getInt(ZMSConsts.DB_COLUMN_TEMPLATE_VERSION));
                    templateDomainMappingList.add(templateDomainMapping);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return templateDomainMappingList;
    }

    @Override
    public List<PrincipalRole> listRolesWithUserAuthorityRestrictions() {

        final String caller = "listRolesWithUserAuthorityRestrictions";
        List<PrincipalRole> roles = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ROLES_WITH_RESTRICTIONS)) {

            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    PrincipalRole prRole = new PrincipalRole();
                    prRole.setDomainName(rs.getString(ZMSConsts.DB_COLUMN_AS_DOMAIN_NAME));
                    prRole.setRoleName(rs.getString(ZMSConsts.DB_COLUMN_AS_ROLE_NAME));
                    prRole.setDomainUserAuthorityFilter(rs.getString(ZMSConsts.DB_COLUMN_AS_DOMAIN_USER_AUTHORITY_FILTER));
                    roles.add(prRole);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return roles;
    }

    Group retrieveGroup(ResultSet rs, final String domainName, final String groupName) throws SQLException {
        Group group = new Group().setName(ResourceUtils.groupResourceName(domainName, groupName))
                .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                .setAuditEnabled(nullIfDefaultValue(rs.getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED), false))
                .setSelfServe(nullIfDefaultValue(rs.getBoolean(ZMSConsts.DB_COLUMN_SELF_SERVE), false))
                .setReviewEnabled(nullIfDefaultValue(rs.getBoolean(ZMSConsts.DB_COLUMN_REVIEW_ENABLED), false))
                .setNotifyRoles(saveValue(rs.getString(ZMSConsts.DB_COLUMN_NOTIFY_ROLES)))
                .setUserAuthorityFilter(saveValue(rs.getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_FILTER)))
                .setUserAuthorityExpiration(saveValue(rs.getString(ZMSConsts.DB_COLUMN_USER_AUTHORITY_EXPIRATION)))
                .setMemberExpiryDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_MEMBER_EXPIRY_DAYS), 0))
                .setServiceExpiryDays(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_SERVICE_EXPIRY_DAYS), 0))
                .setDeleteProtection(nullIfDefaultValue(rs.getBoolean(DB_COLUMN_DELETE_PROTECTION), false))
                .setMaxMembers(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_MAX_MEMBERS), 0))
                .setSelfRenew(nullIfDefaultValue(rs.getBoolean(ZMSConsts.DB_COLUMN_SELF_RENEW), false))
                .setSelfRenewMins(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_SELF_RENEW_MINS), 0))
                .setResourceOwnership(ResourceOwnership.getResourceGroupOwnership(rs.getString(ZMSConsts.DB_COLUMN_RESOURCE_OWNER)));
        java.sql.Timestamp lastReviewedTime = rs.getTimestamp(ZMSConsts.DB_COLUMN_LAST_REVIEWED_TIME);
        if (lastReviewedTime != null) {
            group.setLastReviewedDate(Timestamp.fromMillis(lastReviewedTime.getTime()));
        }
        return group;
    }

    @Override
    public Group getGroup(String domainName, String groupName) {
        final String caller = "getGroup";

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_GROUP)) {
            ps.setString(1, domainName);
            ps.setString(2, groupName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    return retrieveGroup(rs, domainName, groupName);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return null;
    }

    @Override
    public boolean insertGroup(String domainName, Group group) {
        int affectedRows;
        final String caller = "insertGroup";

        String groupName = ZMSUtils.extractGroupName(domainName, group.getName());
        if (groupName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " insert group name: " + group.getName());
        }

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }

        java.sql.Timestamp lastReviewedTime = group.getLastReviewedDate() == null ? null :
                new java.sql.Timestamp(group.getLastReviewedDate().millis());

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_GROUP)) {
            ps.setString(1, groupName);
            ps.setInt(2, domainId);
            ps.setBoolean(3, processInsertValue(group.getAuditEnabled(), false));
            ps.setBoolean(4, processInsertValue(group.getSelfServe(), false));
            ps.setBoolean(5, processInsertValue(group.getReviewEnabled(), false));
            ps.setString(6, processInsertValue(group.getNotifyRoles()));
            ps.setString(7, processInsertValue(group.getUserAuthorityFilter()));
            ps.setString(8, processInsertValue(group.getUserAuthorityExpiration()));
            ps.setInt(9, processInsertValue(group.getMemberExpiryDays()));
            ps.setInt(10, processInsertValue(group.getServiceExpiryDays()));
            ps.setBoolean(11, processInsertValue(group.getDeleteProtection(), false));
            ps.setTimestamp(12, lastReviewedTime);
            ps.setInt(13, processInsertValue(group.getMaxMembers()));
            ps.setBoolean(14, processInsertValue(group.getSelfRenew(), false));
            ps.setInt(15, processInsertValue(group.getSelfRenewMins()));
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateGroup(String domainName, Group group) {
        int affectedRows;
        final String caller = "updateGroup";

        String groupName = ZMSUtils.extractGroupName(domainName, group.getName());
        if (groupName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " update group name: " + group.getName());
        }

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }

        java.sql.Timestamp lastReviewedTime = group.getLastReviewedDate() == null ? null :
                new java.sql.Timestamp(group.getLastReviewedDate().millis());

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_GROUP)) {
            ps.setBoolean(1, processInsertValue(group.getAuditEnabled(), false));
            ps.setBoolean(2, processInsertValue(group.getSelfServe(), false));
            ps.setBoolean(3, processInsertValue(group.getReviewEnabled(), false));
            ps.setString(4, processInsertValue(group.getNotifyRoles()));
            ps.setString(5, processInsertValue(group.getUserAuthorityFilter()));
            ps.setString(6, processInsertValue(group.getUserAuthorityExpiration()));
            ps.setInt(7, processInsertValue(group.getMemberExpiryDays()));
            ps.setInt(8, processInsertValue(group.getServiceExpiryDays()));
            ps.setBoolean(9, processInsertValue(group.getDeleteProtection(), false));
            ps.setTimestamp(10, lastReviewedTime);
            ps.setInt(11, processInsertValue(group.getMaxMembers()));
            ps.setBoolean(12, processInsertValue(group.getSelfRenew(), false));
            ps.setInt(13, processInsertValue(group.getSelfRenewMins()));
            ps.setInt(14, groupId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return (affectedRows > 0);
    }

    @Override
    public boolean deleteGroup(String domainName, String groupName) {

        final String caller = "deleteGroup";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_GROUP)) {
            ps.setInt(1, domainId);
            ps.setString(2, groupName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateGroupModTimestamp(String domainName, String groupName) {
        int affectedRows;
        final String caller = "updateGroupModTimestamp";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_GROUP_MOD_TIMESTAMP)) {
            ps.setInt(1, groupId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public int countGroups(String domainName) {
        final String caller = "countGroups";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_COUNT_GROUP)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    @Override
    public List<GroupAuditLog> listGroupAuditLogs(String domainName, String groupName) {

        final String caller = "listGroupAuditLogs";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }
        List<GroupAuditLog> logs = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_GROUP_AUDIT_LOGS)) {
            ps.setInt(1, groupId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    GroupAuditLog log = new GroupAuditLog();
                    log.setAction(rs.getString(ZMSConsts.DB_COLUMN_ACTION));
                    log.setMember(rs.getString(ZMSConsts.DB_COLUMN_MEMBER));
                    log.setAdmin(rs.getString(ZMSConsts.DB_COLUMN_ADMIN));
                    log.setAuditRef(saveValue(rs.getString(ZMSConsts.DB_COLUMN_AUDIT_REF)));
                    log.setCreated(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_CREATED).getTime()));
                    logs.add(log);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return logs;
    }

    @Override
    public boolean updateGroupReviewTimestamp(String domainName, String groupName) {
        int affectedRows;
        final String caller = "updateGroupReviewTimestamp";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_GROUP_REVIEW_TIMESTAMP)) {
            ps.setInt(1, groupId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    void getStdGroupMembers(int groupId, List<GroupMember> members, final String caller) {

        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_GROUP_MEMBERS)) {
            ps.setInt(1, groupId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    GroupMember groupMember = new GroupMember();
                    groupMember.setMemberName(rs.getString(1));
                    java.sql.Timestamp expiration = rs.getTimestamp(2);
                    if (expiration != null) {
                        groupMember.setExpiration(Timestamp.fromMillis(expiration.getTime()));
                    }
                    groupMember.setActive(nullIfDefaultValue(rs.getBoolean(3), true));
                    groupMember.setAuditRef(rs.getString(4));
                    groupMember.setSystemDisabled(nullIfDefaultValue(rs.getInt(5), 0));
                    groupMember.setApproved(true);
                    members.add(groupMember);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    void getPendingGroupMembers(int groupId, List<GroupMember> members, final String caller) {

        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_PENDING_GROUP_MEMBERS)) {
            ps.setInt(1, groupId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    GroupMember groupMember = new GroupMember();
                    groupMember.setMemberName(rs.getString(1));
                    java.sql.Timestamp timestamp = rs.getTimestamp(2);
                    if (timestamp != null) {
                        groupMember.setExpiration(Timestamp.fromMillis(timestamp.getTime()));
                    }
                    timestamp = rs.getTimestamp(3);
                    if (timestamp != null) {
                        groupMember.setRequestTime(Timestamp.fromMillis(timestamp.getTime()));
                    }
                    groupMember.setAuditRef(rs.getString(4));
                    groupMember.setPendingState(rs.getString(5));
                    groupMember.setActive(false);
                    groupMember.setApproved(false);
                    members.add(groupMember);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }

    @Override
    public List<GroupMember> listGroupMembers(String domainName, String groupName, Boolean pending) {
        final String caller = "listGroupMembers";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }

        // first get our standard group members

        List<GroupMember> members = new ArrayList<>();
        getStdGroupMembers(groupId, members, caller);

        // if requested, include pending members as well

        if (pending == Boolean.TRUE) {
            getPendingGroupMembers(groupId, members, caller);
        }

        members.sort(GroupMemberComparator);
        return members;
    }

    @Override
    public int countGroupMembers(String domainName, String groupName) {
        final String caller = "countGroupMembers";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_COUNT_GROUP_MEMBERS)) {
            ps.setInt(1, groupId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    boolean getGroupMembership(final String query, int groupId, final String member, long expiration,
                               GroupMembership membership, boolean disabledFlagCheck, final String caller) {

        try (PreparedStatement ps = con.prepareStatement(query)) {
            ps.setInt(1, groupId);
            ps.setString(2, member);
            if (expiration != 0) {
                ps.setTimestamp(3, new java.sql.Timestamp(expiration));
            }
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    membership.setIsMember(true);
                    java.sql.Timestamp expiry = rs.getTimestamp(ZMSConsts.DB_COLUMN_EXPIRATION);
                    if (expiry != null) {
                        membership.setExpiration(Timestamp.fromMillis(expiry.getTime()));
                    }
                    membership.setRequestPrincipal(rs.getString(ZMSConsts.DB_COLUMN_REQ_PRINCIPAL));
                    if (disabledFlagCheck) {
                        membership.setSystemDisabled(nullIfDefaultValue(rs.getInt(ZMSConsts.DB_COLUMN_SYSTEM_DISABLED), 0));
                    } else {
                        membership.setPendingState(rs.getString(DB_COLUMN_PENDING_STATE));
                    }
                    return true;
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return false;
    }

    @Override
    public GroupMembership getGroupMember(String domainName, String groupName, String member, long expiration, boolean pending) {

        final String caller = "getGroupMember";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }

        GroupMembership membership = new GroupMembership()
                .setMemberName(member)
                .setGroupName(ResourceUtils.groupResourceName(domainName, groupName))
                .setIsMember(false);

        // first we're going to check if we have a standard user with the given
        // details before checking for pending unless we're specifically asking
        // for pending member only in which case we'll skip the first check

        if (!pending) {
            String query = expiration == 0 ? SQL_GET_GROUP_MEMBER : SQL_GET_TEMP_GROUP_MEMBER;
            if (getGroupMembership(query, groupId, member, expiration, membership, true, caller)) {
                membership.setApproved(true);
            }
        }

        if (!membership.getIsMember()) {
            String query = expiration == 0 ? SQL_GET_PENDING_GROUP_MEMBER : SQL_GET_TEMP_PENDING_GROUP_MEMBER;
            if (getGroupMembership(query, groupId, member, expiration, membership, false, caller)) {
                membership.setApproved(false);
            }
        }

        return membership;
    }

    boolean groupMemberExists(int groupId, int principalId, String principal, String pendingState, final String caller) {

        boolean pending = pendingState != null;
        String statement = pending ? SQL_PENDING_GROUP_MEMBER_EXISTS : SQL_STD_GROUP_MEMBER_EXISTS;
        try (PreparedStatement ps = con.prepareStatement(statement)) {
            ps.setInt(1, groupId);
            ps.setInt(2, principalId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    if (pending) {
                        String currentState = rs.getString(1);
                        // check current request doesn't contradict the existing one
                        if (currentState != null && !currentState.equals(pendingState)) {
                            throw ZMSUtils.requestError("The user " + principal + " already has a pending request in a different state", caller);
                        }
                    }
                    return true;
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return false;
    }

    boolean insertGroupAuditLog(int groupId, String admin, String member,
                               String action, String auditRef) {

        int affectedRows;
        final String caller = "insertGroupAuditEntry";

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_GROUP_AUDIT_LOG)) {
            ps.setInt(1, groupId);
            ps.setString(2, processInsertValue(admin));
            ps.setString(3, member);
            ps.setString(4, action);
            ps.setString(5, processInsertValue(auditRef));
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    boolean insertPendingGroupMember(int groupId, int principalId, GroupMember groupMember,
                                    final String admin, final String auditRef, boolean groupMemberExists, final String caller) {

        java.sql.Timestamp expiration = groupMember.getExpiration() == null ? null
                : new java.sql.Timestamp(groupMember.getExpiration().millis());

        int affectedRows;
        if (groupMemberExists) {

            try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_PENDING_GROUP_MEMBER)) {
                ps.setTimestamp(1, expiration);
                ps.setString(2, processInsertValue(auditRef));
                ps.setString(3, processInsertValue(admin));
                ps.setInt(4, groupId);
                ps.setInt(5, principalId);
                affectedRows = executeUpdate(ps, caller);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }

        } else {

            try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_PENDING_GROUP_MEMBER)) {
                ps.setInt(1, groupId);
                ps.setInt(2, principalId);
                ps.setTimestamp(3, expiration);
                ps.setString(4, processInsertValue(auditRef));
                ps.setString(5, processInsertValue(admin));
                ps.setString(6, processInsertValue(groupMember.getPendingState()));
                affectedRows = executeUpdate(ps, caller);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }

        return (affectedRows > 0);
    }

    boolean insertStandardGroupMember(int groupId, int principalId, GroupMember groupMember,
                                     final String admin, final String principal, final String auditRef,
                                     boolean groupMemberExists, boolean approveRequest, final String caller) {

        java.sql.Timestamp expiration = groupMember.getExpiration() == null ? null
                : new java.sql.Timestamp(groupMember.getExpiration().millis());

        boolean result;
        String auditOperation;

        if (groupMemberExists) {

            try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_GROUP_MEMBER)) {
                ps.setTimestamp(1, expiration);
                ps.setBoolean(2, processInsertValue(groupMember.getActive(), true));
                ps.setString(3, processInsertValue(auditRef));
                ps.setString(4, processInsertValue(admin));
                ps.setInt(5, groupId);
                ps.setInt(6, principalId);
                executeUpdate(ps, caller);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
            auditOperation = approveRequest ? "APPROVE" : "UPDATE";
            result = true;

        } else {

            int affectedRows;
            try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_GROUP_MEMBER)) {
                ps.setInt(1, groupId);
                ps.setInt(2, principalId);
                ps.setTimestamp(3, expiration);
                ps.setBoolean(4, processInsertValue(groupMember.getActive(), true));
                ps.setString(5, processInsertValue(auditRef));
                ps.setString(6, processInsertValue(admin));
                affectedRows = executeUpdate(ps, caller);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }

            auditOperation = approveRequest ? "APPROVE" : "ADD";
            result = (affectedRows > 0);
        }

        // add audit log entry for this change if the operation was successful
        // add return the result of the audit log insert operation

        if (result) {
            result = insertGroupAuditLog(groupId, admin, principal, auditOperation, auditRef);
        }
        return result;
    }

    @Override
    public boolean insertGroupMember(String domainName, String groupName, GroupMember groupMember,
                                     String admin, String auditRef) {

        final String caller = "insertGroupMember";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }
        String principal = groupMember.getMemberName();
        if (!validatePrincipalDomain(principal)) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, principal);
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            principalId = insertPrincipal(principal);
            if (principalId == 0) {
                throw internalServerError(caller, "Unable to insert principal: " + principal);
            }
        }

        // need to check if entry already exists

        boolean pendingRequest = (groupMember.getApproved() == Boolean.FALSE);
        boolean groupMemberExists = groupMemberExists(groupId, principalId, principal, groupMember.getPendingState(), caller);

        // process the request based on the type of the request
        // either pending request or standard insert

        boolean result;
        if (pendingRequest) {
            result = insertPendingGroupMember(groupId, principalId, groupMember, admin,
                    auditRef, groupMemberExists, caller);
        } else {
            result = insertStandardGroupMember(groupId, principalId, groupMember, admin,
                    principal, auditRef, groupMemberExists, false, caller);
        }
        return result;
    }

    @Override
    public boolean deleteGroupMember(String domainName, String groupName, String principal, String admin, String auditRef) {

        final String caller = "deleteGroupMember";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_GROUP_MEMBER)) {
            ps.setInt(1, groupId);
            ps.setInt(2, principalId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        boolean result = (affectedRows > 0);

        // add audit log entry for this change if the delete was successful
        // add return the result of the audit log insert operation

        if (result) {
            result = insertGroupAuditLog(groupId, admin, principal, "DELETE", auditRef);
        }

        return result;
    }

    @Override
    public boolean deleteExpiredGroupMember(String domainName, String groupName, String principal, String admin, Timestamp expiration, String auditRef) {

        final String caller = "deleteGroupMember";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }
        java.sql.Timestamp ts = new java.sql.Timestamp(expiration.millis());
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_EXPIRED_GROUP_MEMBER)) {
            ps.setInt(1, groupId);
            ps.setInt(2, principalId);
            ps.setTimestamp(3, ts);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        boolean result = (affectedRows > 0);

        // add audit log entry for this change if the delete was successful
        // add return the result of the audit log insert operation

        if (result) {
            result = insertGroupAuditLog(groupId, admin, principal, "DELETE", auditRef);
        }

        return result;    }

    @Override
    public boolean updateGroupMemberDisabledState(String domainName, String groupName, String principal, String admin,
                                                  int disabledState, String auditRef) {

        final String caller = "updateGroupMemberDisabledState";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_GROUP_MEMBER_DISABLED_STATE)) {
            ps.setInt(1, disabledState);
            ps.setString(2, processInsertValue(auditRef));
            ps.setString(3, processInsertValue(admin));
            ps.setInt(4, groupId);
            ps.setInt(5, principalId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        boolean result = (affectedRows > 0);

        // add audit log entry for this change if the disable was successful
        // add return the result of the audit log insert operation

        if (result) {
            final String operation = disabledState == 0 ? "ENABLE" : "DISABLE";
            result = insertGroupAuditLog(groupId, admin, principal, operation, auditRef);
        }

        return result;
    }

    @Override
    public boolean deletePendingGroupMember(String domainName, String groupName, String principal,
                                           String admin, String auditRef) {

        final String caller = "deletePendingGroupMember";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }
        return executeDeletePendingGroupMember(groupId, principalId, admin, principal, auditRef, true, caller);
    }

    public boolean executeDeletePendingGroupMember(int groupId, int principalId, final String admin,
                                                  final String principal, final String auditRef, boolean auditLog, final String caller) {

        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_PENDING_GROUP_MEMBER)) {
            ps.setInt(1, groupId);
            ps.setInt(2, principalId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        boolean result = (affectedRows > 0);
        if (result && auditLog) {
            result = insertGroupAuditLog(groupId, admin, principal, "REJECT", auditRef);
        }
        return result;
    }

    @Override
    public boolean confirmGroupMember(String domainName, String groupName, GroupMember groupMember,
                                      String admin, String auditRef) {

        final String caller = "confirmGroupMember";

        String principal = groupMember.getMemberName();
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }
        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        // need to check if the pending entry already exists
        // before doing any work

        String state = getPendingGroupMemberState(groupId, principal);
        if (state == null) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        boolean result = false;
        if (groupMember.getApproved() == Boolean.TRUE) {
            if (ZMSConsts.PENDING_REQUEST_ADD_STATE.equals(state)) {
                boolean groupMemberExists = groupMemberExists(groupId, principalId, principal, groupMember.getPendingState(), caller);
                result = insertStandardGroupMember(groupId, principalId, groupMember, admin,
                        principal, auditRef, groupMemberExists, true, caller);
            } else if (ZMSConsts.PENDING_REQUEST_DELETE_STATE.equals(state)) {
                result = deleteGroupMember(domainName, groupName, principal, admin, auditRef);
            }
            if (result) {
                executeDeletePendingGroupMember(groupId, principalId, admin, principal,
                        auditRef, false, caller);
            }
        } else {
            result = executeDeletePendingGroupMember(groupId, principalId, admin,
                    principal, auditRef, true, caller);
        }

        return result;
    }

    private DomainGroupMember getGroupsForPrincipal(String caller, DomainGroupMember domainGroupMember, PreparedStatement ps) throws SQLException {

        try (ResultSet rs = executeQuery(ps, caller)) {
            while (rs.next()) {
                final String groupName = rs.getString(1);
                final String domain = rs.getString(2);

                GroupMember groupMember = new GroupMember();
                groupMember.setGroupName(groupName);
                groupMember.setDomainName(domain);

                java.sql.Timestamp expiration = rs.getTimestamp(3);
                if (expiration != null) {
                    groupMember.setExpiration(Timestamp.fromMillis(expiration.getTime()));
                }
                groupMember.setSystemDisabled(nullIfDefaultValue(rs.getInt(4), 0));

                domainGroupMember.getMemberGroups().add(groupMember);
            }

            return domainGroupMember;
        }
    }

    @Override
    public DomainGroupMember getPrincipalGroups(String principal, String domainName) {

        final String caller = "getPrincipalGroups";

        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        DomainGroupMember domainGroupMember = new DomainGroupMember();
        domainGroupMember.setMemberGroups(new ArrayList<>());
        domainGroupMember.setMemberName(principal);
        if (StringUtil.isEmpty(domainName)) {
            try (PreparedStatement ps = con.prepareStatement(SQL_GET_PRINCIPAL_GROUPS)) {
                ps.setInt(1, principalId);
                return getGroupsForPrincipal(caller, domainGroupMember, ps);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        } else {
            int domainId = getDomainId(domainName);
            if (domainId == 0) {
                throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
            }
            try (PreparedStatement ps = con.prepareStatement(SQL_GET_PRINCIPAL_GROUPS_DOMAIN)) {
                ps.setInt(1, principalId);
                ps.setInt(2, domainId);
                return getGroupsForPrincipal(caller, domainGroupMember, ps);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }
    }

    @Override
    public List<PrincipalGroup> listGroupsWithUserAuthorityRestrictions() {

        final String caller = "listGroupsWithUserAuthorityRestrictions";
        List<PrincipalGroup> groups = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_GROUPS_WITH_RESTRICTIONS)) {

            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    PrincipalGroup group = new PrincipalGroup();
                    group.setDomainName(rs.getString(ZMSConsts.DB_COLUMN_AS_DOMAIN_NAME));
                    group.setGroupName(rs.getString(ZMSConsts.DB_COLUMN_AS_GROUP_NAME));
                    group.setDomainUserAuthorityFilter(rs.getString(ZMSConsts.DB_COLUMN_AS_DOMAIN_USER_AUTHORITY_FILTER));
                    groups.add(group);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }

        return groups;
    }


    @Override
    public boolean updatePrincipal(String principal, int newState) {
        final String caller = "updatePrincipal";

        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_PRINCIPAL)) {
            ps.setInt(1, newState);
            ps.setString(2, principal);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public List<String> getPrincipals(int queriedState) {
        final String caller = "getPrincipals";
        List<String> principals = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_PRINCIPAL)) {
            ps.setInt(1, queriedState);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    principals.add(rs.getString(ZMSConsts.DB_COLUMN_NAME));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return principals;
    }

    // To avoid firing multiple queries against DB, this function will generate 1 consolidated query for all domains->templates combination
    public String generateDomainTemplateVersionQuery(Map<String, Integer> templateNameAndLatestVersion) {
        StringBuilder query = new StringBuilder();
        query.append("SELECT domain.name, domain_template.template FROM domain_template " +
                "JOIN domain ON domain_template.domain_id=domain.domain_id WHERE ");
        for (String templateName : templateNameAndLatestVersion.keySet()) {
            query.append("(domain_template.template = '").append(templateName).append("' and current_version < ")
                    .append(templateNameAndLatestVersion.get(templateName)).append(") OR ");
        }
        //To remove the last occurrence of "OR" from the generated query
        query.delete(query.lastIndexOf(") OR"), query.lastIndexOf("OR") + 3).append(");");
        return query.toString();
    }

    RuntimeException notFoundError(String caller, String objectType, String objectName) {
        rollbackChanges();
        String message = "unknown " + objectType + " - " + objectName;
        return ZMSUtils.notFoundError(message, caller);
    }

    RuntimeException requestError(String caller, String message) {
        rollbackChanges();
        return ZMSUtils.requestError(message, caller);
    }

    RuntimeException internalServerError(String caller, String message) {
        rollbackChanges();
        return ZMSUtils.internalServerError(message, caller);
    }

    RuntimeException sqlError(SQLException ex, String caller) {

        // check to see if this is a conflict error in which case
        // we're going to let the server to retry the caller
        // The two SQL states that are 'retry-able' are 08S01
        // for a communications error, and 40001 for deadlock.
        // also check for the error code where the mysql server is
        // in read-mode which could happen if we had a failover
        // and the connections are still going to the old master

        final String sqlState = ex.getSQLState();
        int code = ResourceException.INTERNAL_SERVER_ERROR;
        String msg;
        if (MYSQL_EXC_STATE_COMM_ERROR.equals(sqlState) || MYSQL_EXC_STATE_DEADLOCK.equals(sqlState)) {
            code = ResourceException.CONFLICT;
            msg = "Concurrent update conflict, please retry your operation later.";
        } else if (ex.getErrorCode() == MYSQL_ER_OPTION_PREVENTS_STATEMENT) {
            code = ResourceException.GONE;
            msg = "MySQL Database running in read-only mode";
        } else if (ex.getErrorCode() == MYSQL_ER_OPTION_DUPLICATE_ENTRY) {
            code = ResourceException.BAD_REQUEST;
            msg = "Entry already exists";
        } else if (ex instanceof SQLTimeoutException) {
            code = ResourceException.SERVICE_UNAVAILABLE;
            msg = "Statement cancelled due to timeout";
        } else {
            msg = ex.getMessage() + ", state: " + sqlState + ", code: " + ex.getErrorCode();
        }
        rollbackChanges();
        return ZMSUtils.error(code, msg, caller);
    }

    Boolean nullIfDefaultValue(boolean flag, boolean defaultValue) {
        return flag == defaultValue ? null : flag;
    }

    Integer nullIfDefaultValue(int value, int defaultValue) {
        return value == defaultValue ? null : value;
    }

    private void addTagsToRoles(Map<String, Role> roleMap, String domainName) {

        Map<String, Map<String, TagValueList>> domainRoleTags = getDomainRoleTags(domainName);
        if (domainRoleTags != null) {
            for (Map.Entry<String, Role> roleEntry : roleMap.entrySet()) {
                Map<String, TagValueList> roleTag = domainRoleTags.get(roleEntry.getKey());
                if (roleTag != null) {
                    roleEntry.getValue().setTags(roleTag);
                }
            }
        }
    }

    private void addTagsToServices(Map<String, ServiceIdentity> serviceMap, String domainName) {

        Map<String, Map<String, TagValueList>> domainServiceTags = getServiceResourceTags(domainName);
        if (domainServiceTags != null) {
            for (Map.Entry<String, ServiceIdentity> serviceEntry : serviceMap.entrySet()) {
                Map<String, TagValueList> serviceTag = domainServiceTags.get(serviceEntry.getKey());
                if (serviceTag != null) {
                    serviceEntry.getValue().setTags(serviceTag);
                }
            }
        }
    }

    Map<String, Map<String, TagValueList>> getDomainRoleTags(String domainName) {
        final String caller = "getDomainRoleTags";
        Map<String, Map<String, TagValueList>> domainRoleTags = null;

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_ROLE_TAGS)) {
            ps.setString(1, domainName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String roleName = rs.getString(1);
                    String tagKey = rs.getString(2);
                    String tagValue = rs.getString(3);
                    if (domainRoleTags == null) {
                        domainRoleTags = new HashMap<>();
                    }
                    Map<String, TagValueList> roleTag = domainRoleTags.computeIfAbsent(roleName, tags -> new HashMap<>());
                    TagValueList tagValues = roleTag.computeIfAbsent(tagKey, k -> new TagValueList().setList(new ArrayList<>()));
                    tagValues.getList().add(tagValue);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return domainRoleTags;
    }

    @Override
    public Map<String, TagValueList> getRoleTags(String domainName, String roleName) {
        final String caller = "getRoleTags";
        Map<String, TagValueList> roleTag = null;

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ROLE_TAGS)) {
            ps.setString(1, domainName);
            ps.setString(2, roleName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String tagKey = rs.getString(1);
                    String tagValue = rs.getString(2);
                    if (roleTag == null) {
                        roleTag = new HashMap<>();
                    }
                    TagValueList tagValues = roleTag.computeIfAbsent(tagKey, k -> new TagValueList().setList(new ArrayList<>()));
                    tagValues.getList().add(tagValue);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return roleTag;
    }

    @Override
    public boolean insertRoleTags(String roleName, String domainName, Map<String, TagValueList> roleTags) {
        final String caller = "insertRoleTags";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }
        int curTagCount = getRoleTagsCount(roleId);
        int newTagCount = calculateTagCount(roleTags);
        if (curTagCount + newTagCount > roleTagsLimit) {
            throw requestError(caller, "role tag quota exceeded - limit: "
                + roleTagsLimit + ", current tags count: " + curTagCount + ", new tags count: " + newTagCount);
        }

        boolean res = true;
        for (Map.Entry<String, TagValueList> e : roleTags.entrySet()) {
            for (String tagValue : e.getValue().getList()) {
                try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ROLE_TAG)) {
                    ps.setInt(1, roleId);
                    ps.setString(2, processInsertValue(e.getKey()));
                    ps.setString(3, processInsertValue(tagValue));
                    res &= (executeUpdate(ps, caller) > 0);
                } catch (SQLException ex) {
                    throw sqlError(ex, caller);
                }
            }
        }
        return res;
    }

    int getRoleTagsCount(int roleId) {
        final String caller = "getRoleTagsCount";
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_ROLE_TAG_COUNT)) {
            ps.setInt(1, roleId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    @Override
    public boolean deleteRoleTags(String roleName, String domainName, Set<String> tagKeys) {
        final String caller = "deleteRoleTags";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ResourceUtils.roleResourceName(domainName, roleName));
        }
        boolean res = true;
        for (String tagKey : tagKeys) {
            try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_ROLE_TAG)) {
                ps.setInt(1, roleId);
                ps.setString(2, processInsertValue(tagKey));
                res &= (executeUpdate(ps, caller) > 0);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }
        return res;
    }

    @Override
    public boolean insertServiceTags(String serviceName, String domainName, Map<String, TagValueList> serviceTags) {
        final String caller = "insertServiceTags";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        int curTagCount = getServiceTagsCount(serviceId);
        int newTagCount = calculateTagCount(serviceTags);
        if (curTagCount + newTagCount > serviceTagsLimit) {
            throw requestError(caller, "service tag quota exceeded - limit: "
                    + serviceTagsLimit + ", current tags count: " + curTagCount + ", new tags count: " + newTagCount);
        }

        boolean res = true;
        for (Map.Entry<String, TagValueList> e : serviceTags.entrySet()) {
            for (String tagValue : e.getValue().getList()) {
                try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_SERVICE_TAG)) {
                    ps.setInt(1, serviceId);
                    ps.setString(2, processInsertValue(e.getKey()));
                    ps.setString(3, processInsertValue(tagValue));
                    res &= (executeUpdate(ps, caller) > 0);
                } catch (SQLException ex) {
                    throw sqlError(ex, caller);
                }
            }
        }
        return res;
    }

    int getServiceTagsCount(int serviceId) {
        final String caller = "getServiceTagsCount";
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_SERVICE_TAG_COUNT)) {
            ps.setInt(1, serviceId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    @Override
    public boolean deleteServiceTags(String serviceName, String domainName, Set<String> tagKeys) {
        final String caller = "deleteServiceTags";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, OBJECT_SERVICE, ResourceUtils.serviceResourceName(domainName, serviceName));
        }
        boolean res = true;
        for (String tagKey : tagKeys) {
            try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_SERVICE_TAG)) {
                ps.setInt(1, serviceId);
                ps.setString(2, processInsertValue(tagKey));
                res &= (executeUpdate(ps, caller) > 0);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }
        return res;
    }

    @Override
    public Map<String, TagValueList> getServiceTags(String domainName, String serviceName) {
        final String caller = "getServiceTags";
        Map<String, TagValueList> serviceTag = null;

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_SERVICE_TAGS)) {
            ps.setString(1, domainName);
            ps.setString(2, serviceName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String tagKey = rs.getString(1);
                    String tagValue = rs.getString(2);
                    if (serviceTag == null) {
                        serviceTag = new HashMap<>();
                    }
                    TagValueList tagValues = serviceTag.computeIfAbsent(tagKey, k -> new TagValueList().setList(new ArrayList<>()));
                    tagValues.getList().add(tagValue);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return serviceTag;
    }



    private void addTagsToGroups(Map<String, Group> groupMap, String domainName) {

        Map<String, Map<String, TagValueList>> domainGroupTags = getDomainGroupTags(domainName);
        if (domainGroupTags != null) {
            for (Map.Entry<String, Group> groupEntry : groupMap.entrySet()) {
                Map<String, TagValueList> groupTag = domainGroupTags.get(groupEntry.getKey());
                if (groupTag != null) {
                    groupEntry.getValue().setTags(groupTag);
                }
            }
        }
    }

    Map<String, Map<String, TagValueList>> getServiceResourceTags(String domainName) {
        final String funcCaller = "getDomainServiceTags";
        Map<String, Map<String, TagValueList>> domainResourceTags = null;

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_SERVICE_TAGS)) {
            ps.setString(1, domainName);
            try (ResultSet rs = executeQuery(ps, funcCaller)) {
                while (rs.next()) {
                    String resourceName = rs.getString(1);
                    String tagKey = rs.getString(2);
                    String tagValue = rs.getString(3);
                    if (domainResourceTags == null) {
                        domainResourceTags = new HashMap<>();
                    }
                    Map<String, TagValueList> resourceTag = domainResourceTags.computeIfAbsent(resourceName, tags -> new HashMap<>());
                    TagValueList tagValues = resourceTag.computeIfAbsent(tagKey, k -> new TagValueList().setList(new ArrayList<>()));
                    tagValues.getList().add(tagValue);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, funcCaller);
        }
        return domainResourceTags;
    }

    Map<String, Map<String, TagValueList>> getDomainGroupTags(String domainName) {
        final String caller = "getDomainGroupTags";
        Map<String, Map<String, TagValueList>> domainGroupTags = null;

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_GROUP_TAGS)) {
            ps.setString(1, domainName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String groupName = rs.getString(1);
                    String tagKey = rs.getString(2);
                    String tagValue = rs.getString(3);
                    if (domainGroupTags == null) {
                        domainGroupTags = new HashMap<>();
                    }
                    Map<String, TagValueList> groupTag = domainGroupTags.computeIfAbsent(groupName, tags -> new HashMap<>());
                    TagValueList tagValues = groupTag.computeIfAbsent(tagKey, k -> new TagValueList().setList(new ArrayList<>()));
                    tagValues.getList().add(tagValue);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return domainGroupTags;
    }

    @Override
    public Map<String, TagValueList> getGroupTags(String domainName, String groupName) {
        final String caller = "getGroupTags";
        Map<String, TagValueList> groupTag = null;

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_GROUP_TAGS)) {
            ps.setString(1, domainName);
            ps.setString(2, groupName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String tagKey = rs.getString(1);
                    String tagValue = rs.getString(2);
                    if (groupTag == null) {
                        groupTag = new HashMap<>();
                    }
                    TagValueList tagValues = groupTag.computeIfAbsent(tagKey, k -> new TagValueList().setList(new ArrayList<>()));
                    tagValues.getList().add(tagValue);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return groupTag;
    }

    @Override
    public boolean insertGroupTags(String groupName, String domainName, Map<String, TagValueList> groupTags) {

        final String caller = "insertGroupTags";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }
        int curTagCount = getGroupTagsCount(groupId);
        int newTagCount = calculateTagCount(groupTags);
        if (curTagCount + newTagCount > groupTagsLimit) {
            throw requestError(caller, "group tag quota exceeded - limit: "
                    + groupTagsLimit + ", current tags count: " + curTagCount + ", new tags count: " + newTagCount);
        }

        boolean res = true;
        for (Map.Entry<String, TagValueList> e : groupTags.entrySet()) {
            for (String tagValue : e.getValue().getList()) {
                try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_GROUP_TAG)) {
                    ps.setInt(1, groupId);
                    ps.setString(2, processInsertValue(e.getKey()));
                    ps.setString(3, processInsertValue(tagValue));
                    res &= (executeUpdate(ps, caller) > 0);
                } catch (SQLException ex) {
                    throw sqlError(ex, caller);
                }
            }
        }
        return res;

    }

    int getGroupTagsCount(int groupId) {
        final String caller = "getGroupTagsCount";
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GROUP_TAG_COUNT)) {
            ps.setInt(1, groupId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    @Override
    public boolean deleteGroupTags(String groupName, String domainName, Set<String> tagKeys) {
        final String caller = "deleteGroupTags";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int groupId = getGroupId(domainId, groupName);
        if (groupId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_GROUP, ResourceUtils.groupResourceName(domainName, groupName));
        }
        boolean res = true;
        for (String tagKey : tagKeys) {
            try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_GROUP_TAG)) {
                ps.setInt(1, groupId);
                ps.setString(2, processInsertValue(tagKey));
                res &= (executeUpdate(ps, caller) > 0);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }
        }
        return res;
    }

    @Override
    public int countAssertionConditions(long assertionId) {

        final String caller = "countAssertionConditions";
        int count = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_COUNT_ASSERTION_CONDITIONS)) {
            ps.setLong(1, assertionId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return count;
    }

    @Override
    public List<AssertionCondition> getAssertionConditions(long assertionId) {
        final String caller = "getAssertionConditions";
        List<AssertionCondition> assertionConditions = new ArrayList<>();
        Map<Integer, AssertionCondition> assertionConditionMap = new HashMap<>();
        int conditionId;
        AssertionCondition assertionCondition;
        Map<String, AssertionConditionData> assertionConditionDataMap;
        AssertionConditionData assertionConditionData;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ASSERTION_CONDITIONS)) {
            ps.setLong(1, assertionId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    conditionId = rs.getInt(ZMSConsts.DB_COLUMN_CONDITION_ID);
                    assertionCondition = assertionConditionMap.get(conditionId);
                    if (assertionCondition == null) {
                        assertionCondition = new AssertionCondition();
                        assertionConditionDataMap = new HashMap<>();
                        assertionCondition.setConditionsMap(assertionConditionDataMap);
                        assertionCondition.setId(conditionId);
                        assertionConditionMap.put(conditionId, assertionCondition);
                        assertionConditions.add(assertionCondition);
                    }
                    assertionConditionData = new AssertionConditionData();
                    if (rs.getString(ZMSConsts.DB_COLUMN_OPERATOR) != null) {
                        assertionConditionData.setOperator(AssertionConditionOperator.fromString(rs.getString(ZMSConsts.DB_COLUMN_OPERATOR)));
                    }
                    assertionConditionData.setValue(rs.getString(ZMSConsts.DB_COLUMN_VALUE));
                    assertionCondition.getConditionsMap().put(rs.getString(ZMSConsts.DB_COLUMN_KEY), assertionConditionData);

                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return assertionConditions;
    }

    @Override
    public AssertionCondition getAssertionCondition(long assertionId, int conditionId) {
        final String caller = "getAssertionCondition";
        AssertionCondition assertionCondition = null;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ASSERTION_CONDITION)) {
            ps.setLong(1, assertionId);
            ps.setInt(2, conditionId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    if (assertionCondition == null) {
                        assertionCondition = new AssertionCondition();
                        assertionCondition.setId(rs.getInt(ZMSConsts.DB_COLUMN_CONDITION_ID));
                        Map<String, AssertionConditionData> conditionDataMap = new HashMap<>();
                        assertionCondition.setConditionsMap(conditionDataMap);
                    }
                    AssertionConditionData conditionData = new AssertionConditionData();
                    if (rs.getString(ZMSConsts.DB_COLUMN_OPERATOR) != null) {
                        conditionData.setOperator(AssertionConditionOperator.fromString(rs.getString(ZMSConsts.DB_COLUMN_OPERATOR)));
                    }
                    conditionData.setValue(rs.getString(ZMSConsts.DB_COLUMN_VALUE));
                    assertionCondition.getConditionsMap().put(rs.getString(ZMSConsts.DB_COLUMN_KEY), conditionData);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return assertionCondition;
    }

    @Override
    public boolean insertAssertionConditions(long assertionId, AssertionConditions assertionConditions) {
        final String caller = "insertAssertionConditions";
        boolean result = true;
        for (AssertionCondition assertionCondition : assertionConditions.getConditionsList()) {
            // get condition id for each AssertionCondition object in the list
            // all keys in the conditionMap of AssertionCondition object share same condition id
            assertionCondition.setId(getNextConditionId(assertionId, caller));
            result = result && insertSingleAssertionCondition(assertionId, assertionCondition, caller);
        }
        return result;
    }

    @Override
    public boolean deleteAssertionConditions(long assertionId) {
        final String caller = "deleteAssertionConditions";
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_ASSERTION_CONDITIONS)) {
            ps.setLong(1, assertionId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return affectedRows > 0;
    }

    @Override
    public boolean insertAssertionCondition(long assertionId, AssertionCondition assertionCondition) {
        final String caller = "insertAssertionCondition";
        return insertSingleAssertionCondition(assertionId, assertionCondition, caller);
    }

    @Override
    public int getNextConditionId(long assertionId, String caller) {
        int nextConditionId = 1;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_NEXT_CONDITION_ID)) {
            ps.setLong(1, assertionId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    nextConditionId = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return nextConditionId;
    }

    private boolean insertSingleAssertionCondition(long assertionId, AssertionCondition assertionCondition, String caller) {
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ASSERTION_CONDITION)) {
            // loop over all the keys in the given condition map
            for (String key : assertionCondition.getConditionsMap().keySet()) {
                ps.setLong(1, assertionId);
                ps.setInt(2, assertionCondition.getId());
                ps.setString(3, key);
                ps.setString(4, assertionCondition.getConditionsMap().get(key).getOperator().name());
                ps.setString(5, assertionCondition.getConditionsMap().get(key).getValue());

                ps.addBatch();
            }
            affectedRows = Arrays.stream(executeBatch(ps, caller)).sum();

        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return affectedRows > 0;
    }

    @Override
    public boolean deleteAssertionCondition(long assertionId, int conditionId) {
        final String caller = "deleteAssertionCondition";
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_ASSERTION_CONDITION)) {
            ps.setLong(1, assertionId);
            ps.setInt(2, conditionId);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return affectedRows > 0;
    }

    @Override
    public List<String> listServiceDependencies(String domainName) {

        final String caller = "listServiceDependencies";

        List<String> services = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_SERVICE_DEPENDENCIES)) {
            ps.setString(1, domainName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    services.add(rs.getString(1));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        Collections.sort(services);
        return services;
    }

    @Override
    public List<String> listDomainDependencies(String service) {

        final String caller = "listServiceDependencies";

        List<String> domains = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_DOMAIN_DEPENDENCIES)) {
            ps.setString(1, service);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    domains.add(rs.getString(1));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        Collections.sort(domains);
        return domains;
    }


    @Override
    public List<ExpiryMember> getAllExpiredRoleMembers(int limit, int offset, int serverPurgeExpiryDays) {
        final String caller = "getAllExpiredRoleMembers";
        List<ExpiryMember> members = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(GET_ALL_EXPIRED_ROLE_MEMBERS)) {
            ps.setInt(1, serverPurgeExpiryDays);
            ps.setInt(2, limit);
            ps.setInt(3, offset);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    ExpiryMember expiryMember = new ExpiryMember()
                            .setDomainName(rs.getString(DB_COLUMN_AS_DOMAIN_NAME))
                            .setCollectionName(rs.getString(DB_COLUMN_AS_ROLE_NAME))
                            .setPrincipalName(rs.getString(DB_COLUMN_AS_PRINCIPAL_NAME))
                            .setExpiration(Timestamp.fromMillis(rs.getTimestamp(DB_COLUMN_EXPIRATION).getTime()));
                    members.add(expiryMember);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return members;
    }

    @Override
    public List<ExpiryMember> getAllExpiredGroupMembers(int limit, int offset, int serverPurgeExpiryDays) {
        final String caller = "getAllExpiredGroupMembers";
        List<ExpiryMember> members = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(GET_ALL_EXPIRED_GROUP_MEMBERS)) {
            ps.setInt(1, serverPurgeExpiryDays);
            ps.setInt(2, limit);
            ps.setInt(3, offset);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String domainName = rs.getString(DB_COLUMN_AS_DOMAIN_NAME);
                    ExpiryMember member = new ExpiryMember()
                            .setDomainName(domainName)
                            .setCollectionName(rs.getString(DB_COLUMN_AS_GROUP_NAME))
                            .setPrincipalName(rs.getString(DB_COLUMN_AS_PRINCIPAL_NAME))
                            .setExpiration(Timestamp.fromMillis(rs.getTimestamp(DB_COLUMN_EXPIRATION).getTime()));
                    members.add(member);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return members;
    }

    @Override
    public boolean insertDomainDependency(String dependencyDomainName, String service) {
        int affectedRows;
        final String caller = "insertDomainDependency";

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_DOMAIN_DEPENDENCY)) {
            ps.setString(1, dependencyDomainName);
            ps.setString(2, service);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deleteDomainDependency(String dependencyDomainName, String service) {
        int affectedRows;
        final String caller = "deleteDomainDependency";

        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_DOMAIN_DEPENDENCY)) {
            ps.setString(1, dependencyDomainName);
            ps.setString(2, service);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    Policy savePolicySettings(final String domainName, final String policyName,  ResultSet rs) throws SQLException {
        return new Policy()
                .setName(ResourceUtils.policyResourceName(domainName, policyName))
                .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                .setActive(rs.getBoolean(ZMSConsts.DB_COLUMN_ACTIVE))
                .setVersion(rs.getString(ZMSConsts.DB_COLUMN_VERSION))
                .setResourceOwnership(ResourceOwnership.getResourcePolicyOwnership(rs.getString(ZMSConsts.DB_COLUMN_RESOURCE_OWNER)));
    }

    boolean isLastNotifyTimeWithinSpecifiedDays(final String sqlCmd, int delayDays) {

        final String caller = "isLastNotifyTimeWithinSpecifiedDays";

        long lastRunTime = 0;
        try (PreparedStatement ps = con.prepareStatement(sqlCmd)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    lastRunTime = rs.getTimestamp(1).getTime();
                }
            }
        } catch (SQLException ex) {
            LOG.error("unable to retrieve last notification run time: {}", ex.getMessage());
            return false;
        }
        return System.currentTimeMillis() - lastRunTime < TimeUnit.DAYS.toMillis(delayDays);
    }

    @Override
    public ReviewObjects getRolesForReview(String principal) {

        final String caller = "getRolesForReview";

        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        List<ReviewObject> reviewRoles = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ROLE_REVIEW_LIST)) {
            ps.setInt(1, principalId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    ReviewObject reviewObject = new ReviewObject()
                            .setDomainName(rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_NAME))
                            .setName(rs.getString(DB_COLUMN_AS_ROLE_NAME))
                            .setMemberExpiryDays(rs.getInt(ZMSConsts.DB_COLUMN_MEMBER_EXPIRY_DAYS))
                            .setServiceExpiryDays(rs.getInt(ZMSConsts.DB_COLUMN_SERVICE_EXPIRY_DAYS))
                            .setGroupExpiryDays(rs.getInt(ZMSConsts.DB_COLUMN_GROUP_EXPIRY_DAYS))
                            .setMemberReviewDays(rs.getInt(ZMSConsts.DB_COLUMN_MEMBER_REVIEW_DAYS))
                            .setServiceReviewDays(rs.getInt(ZMSConsts.DB_COLUMN_SERVICE_REVIEW_DAYS))
                            .setGroupReviewDays(rs.getInt(ZMSConsts.DB_COLUMN_GROUP_REVIEW_DAYS))
                            .setCreated(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_CREATED).getTime()));
                    java.sql.Timestamp lastReviewedTime = rs.getTimestamp(ZMSConsts.DB_COLUMN_LAST_REVIEWED_TIME);
                    if (lastReviewedTime != null) {
                        reviewObject.setLastReviewedDate(Timestamp.fromMillis(lastReviewedTime.getTime()));
                    }
                    reviewRoles.add(reviewObject);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return new ReviewObjects().setList(reviewRoles);
    }

    @Override
    public ReviewObjects getGroupsForReview(String principal) {

        final String caller = "getGroupsForReview";

        int principalId = getPrincipalId(principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }

        List<ReviewObject> reviewRoles = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_GROUP_REVIEW_LIST)) {
            ps.setInt(1, principalId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    ReviewObject reviewObject = new ReviewObject()
                            .setDomainName(rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_NAME))
                            .setName(rs.getString(DB_COLUMN_AS_GROUP_NAME))
                            .setMemberExpiryDays(rs.getInt(ZMSConsts.DB_COLUMN_MEMBER_EXPIRY_DAYS))
                            .setServiceExpiryDays(rs.getInt(ZMSConsts.DB_COLUMN_SERVICE_EXPIRY_DAYS))
                            .setCreated(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_CREATED).getTime()));
                    java.sql.Timestamp lastReviewedTime = rs.getTimestamp(ZMSConsts.DB_COLUMN_LAST_REVIEWED_TIME);
                    if (lastReviewedTime != null) {
                        reviewObject.setLastReviewedDate(Timestamp.fromMillis(lastReviewedTime.getTime()));
                    }
                    reviewRoles.add(reviewObject);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return new ReviewObjects().setList(reviewRoles);
    }

    @Override
    public boolean insertDomainContact(String domainName, String contactType, String username) {

        final String caller = "insertDomainContact";
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_DOMAIN_CONTACT)) {
            ps.setInt(1, domainId);
            ps.setString(2, contactType);
            ps.setString(3, username);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateDomainContact(String domainName, String contactType, String username) {

        final String caller = "updateDomainContact";
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_DOMAIN_CONTACT)) {
            ps.setString(1, username);
            ps.setInt(2, domainId);
            ps.setString(3, contactType);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deleteDomainContact(String domainName, String contactType) {

        final String caller = "deleteDomainContact";
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_DOMAIN_CONTACT)) {
            ps.setInt(1, domainId);
            ps.setString(2, contactType);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public Map<String, List<String>> listContactDomains(String username) {

        final String caller = "listContactDomains";

        Map<String, List<String>> contactDomains = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_CONTACT_DOMAINS)) {
            ps.setString(1, username);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    List<String> contactTypes = contactDomains.computeIfAbsent(rs.getString(1), k -> new ArrayList<>());
                    contactTypes.add(rs.getString(2));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return contactDomains;
    }

    public Map<String, String> getDomainContacts(int domainId) {

        final String caller = "getDomainContacts";
        Map<String, String> domainContacts = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_DOMAIN_CONTACTS)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    domainContacts.put(rs.getString(ZMSConsts.DB_COLUMN_TYPE), rs.getString(ZMSConsts.DB_COLUMN_NAME));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return domainContacts;
    }

    @Override
    public boolean setResourceDomainOwnership(String domainName, ResourceDomainOwnership resourceOwner) {
        final String caller = "setResourceDomainOwnership";
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_SET_DOMAIN_RESOURCE_OWNERSHIP)) {
            ps.setString(1, ResourceOwnership.generateResourceOwnerString(resourceOwner));
            ps.setString(2, domainName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean setResourceRoleOwnership(String domainName, String roleName, ResourceRoleOwnership resourceOwner) {
        final String caller = "setResourceRoleOwnership";
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_SET_ROLE_RESOURCE_OWNERSHIP)) {
            ps.setString(1, ResourceOwnership.generateResourceOwnerString(resourceOwner));
            ps.setInt(2, domainId);
            ps.setString(3, roleName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean setResourceGroupOwnership(String domainName, String groupName, ResourceGroupOwnership resourceOwner) {
        final String caller = "setResourceGroupOwnership";
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_SET_GROUP_RESOURCE_OWNERSHIP)) {
            ps.setString(1, ResourceOwnership.generateResourceOwnerString(resourceOwner));
            ps.setInt(2, domainId);
            ps.setString(3, groupName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean setResourcePolicyOwnership(String domainName, String policyName, ResourcePolicyOwnership resourceOwner) {
        final String caller = "setResourcePolicyOwnership";
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_SET_POLICY_RESOURCE_OWNERSHIP)) {
            ps.setString(1, ResourceOwnership.generateResourceOwnerString(resourceOwner));
            ps.setInt(2, domainId);
            ps.setString(3, policyName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean setResourceServiceOwnership(String domainName, String serviceName, ResourceServiceIdentityOwnership resourceOwner) {
        final String caller = "setResourceServiceOwnership";
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_SET_SERVICE_RESOURCE_OWNERSHIP)) {
            ps.setString(1, ResourceOwnership.generateResourceOwnerString(resourceOwner));
            ps.setInt(2, domainId);
            ps.setString(3, serviceName);
            affectedRows = executeUpdate(ps, caller);
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
}
