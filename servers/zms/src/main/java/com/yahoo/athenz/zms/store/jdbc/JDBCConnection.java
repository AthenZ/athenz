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
package com.yahoo.athenz.zms.store.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import com.yahoo.athenz.zms.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.UUID;

public class JDBCConnection implements ObjectStoreConnection {

    private static final Logger LOG = LoggerFactory.getLogger(JDBCConnection.class);

    private static final int MYSQL_ER_OPTION_PREVENTS_STATEMENT = 1290;
    private static final int MYSQL_ER_OPTION_DUPLICATE_ENTRY = 1062;

    private static final String SQL_DELETE_DOMAIN = "DELETE FROM domain WHERE name=?;";
    private static final String SQL_GET_DOMAIN = "SELECT * FROM domain WHERE name=?;";
    private static final String SQL_GET_DOMAIN_ID = "SELECT domain_id FROM domain WHERE name=?;";
    private static final String SQL_GET_ACTIVE_DOMAIN_ID = "SELECT domain_id FROM domain WHERE name=? AND enabled=true;";
    private static final String SQL_GET_DOMAINS_WITH_NAME = "SELECT name FROM domain WHERE name LIKE ?;";
    private static final String SQL_GET_DOMAIN_WITH_ACCOUNT = "SELECT name FROM domain WHERE account=?;";
    private static final String SQL_GET_DOMAIN_WITH_PRODUCT_ID = "SELECT name FROM domain WHERE ypm_id=?;";
    private static final String SQL_INSERT_DOMAIN = "INSERT INTO domain "
            + "(name, description, org, uuid, enabled, audit_enabled, account, ypm_id, application_id, cert_dns_domain) VALUES (?,?,?,?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_DOMAIN = "UPDATE domain "
            + "SET description=?, org=?, uuid=?, enabled=?, audit_enabled=?, account=?, ypm_id=?, application_id=?, cert_dns_domain=? WHERE name=?;";
    private static final String SQL_UPDATE_DOMAIN_MOD_TIMESTAMP = "UPDATE domain "
            + "SET modified=CURRENT_TIMESTAMP(3) WHERE name=?;";
    private static final String SQL_GET_DOMAIN_MOD_TIMESTAMP = "SELECT modified FROM domain WHERE name=?;";
    private static final String SQL_LIST_DOMAIN = "SELECT name, modified, account, ypm_id FROM domain;";
    private static final String SQL_LIST_DOMAIN_PREFIX = "SELECT name, modified FROM domain WHERE name>=? AND name<?;";
    private static final String SQL_LIST_DOMAIN_MODIFIED = "SELECT name, modified, account, ypm_id FROM domain WHERE modified>?;";
    private static final String SQL_LIST_DOMAIN_PREFIX_MODIFIED = "SELECT name, modified FROM domain "
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
    private static final String SQL_LIST_DOMAIN_AWS = "SELECT name, account FROM domain WHERE account!='';";
    private static final String SQL_GET_ROLE = "SELECT * FROM role "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "WHERE domain.name=? AND role.name=?;";
    private static final String SQL_GET_ROLE_ID = "SELECT role_id FROM role WHERE domain_id=? AND name=?;";
    private static final String SQL_INSERT_ROLE = "INSERT INTO role (name, domain_id, trust) VALUES (?,?,?);";
    private static final String SQL_UPDATE_ROLE = "UPDATE role SET trust=? WHERE role_id=?;";
    private static final String SQL_DELETE_ROLE = "DELETE FROM role WHERE domain_id=? AND name=?;";
    private static final String SQL_UPDATE_ROLE_MOD_TIMESTAMP = "UPDATE role "
            + "SET modified=CURRENT_TIMESTAMP(3) WHERE role_id=?;";
    private static final String SQL_LIST_ROLE = "SELECT name FROM role WHERE domain_id=?;";
    private static final String SQL_COUNT_ROLE = "SELECT COUNT(*) FROM role WHERE domain_id=?;";
    private static final String SQL_GET_ROLE_MEMBER = "SELECT principal.principal_id, role_member.expiration FROM principal "
            + "JOIN role_member ON role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role.role_id=? AND principal.name=?;";
    private static final String SQL_GET_ROLE_MEMBER_EXISTS = "SELECT principal_id FROM role_member WHERE role_id=? AND principal_id=?;";
    private static final String SQL_LIST_ROLE_MEMBERS = "SELECT principal.name, role_member.expiration FROM principal "
            + "JOIN role_member ON role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role.role_id=?;";
    private static final String SQL_COUNT_ROLE_MEMBERS = "SELECT COUNT(*) FROM role_member WHERE role_id=?;";
    private static final String SQL_GET_PRINCIPAL_ID = "SELECT principal_id FROM principal WHERE name=?;";
    private static final String SQL_INSERT_PRINCIPAL = "INSERT INTO principal (name) VALUES (?);";
    private static final String SQL_DELETE_PRINCIPAL = "DELETE FROM principal WHERE name=?;";
    private static final String SQL_DELETE_SUB_PRINCIPALS = "DELETE FROM principal WHERE name LIKE ?;";
    private static final String SQL_LIST_PRINCIPAL = "SELECT * FROM principal;";
    private static final String SQL_LIST_PRINCIPAL_DOMAIN = "SELECT * FROM principal WHERE name LIKE ?;";
    private static final String SQL_LAST_INSERT_ID = "SELECT LAST_INSERT_ID();";
    private static final String SQL_INSERT_ROLE_MEMBER = "INSERT INTO role_member (role_id, principal_id, expiration) VALUES (?,?,?);";
    private static final String SQL_DELETE_ROLE_MEMBER = "DELETE FROM role_member WHERE role_id=? AND principal_id=?;";
    private static final String SQL_UPDATE_ROLE_MEMBER = "UPDATE role_member SET expiration=? WHERE role_id=? AND principal_id=?;";
    private static final String SQL_INSERT_ROLE_AUDIT_LOG = "INSERT INTO role_audit_log "
            + "(role_id, admin, member, action, audit_ref) VALUES (?,?,?,?,?);";
    private static final String SQL_LIST_ROLE_AUDIT_LOGS = "SELECT * FROM role_audit_log WHERE role_id=?;";
    private static final String SQL_GET_POLICY = "SELECT * FROM policy "
            + "JOIN domain ON domain.domain_id=policy.domain_id WHERE domain.name=? AND policy.name=?;";
    private static final String SQL_INSERT_POLICY = "INSERT INTO policy (name, domain_id) VALUES (?,?);";
    private static final String SQL_UPDATE_POLICY = "UPDATE policy SET name=? WHERE policy_id=?;";
    private static final String SQL_UPDATE_POLICY_MOD_TIMESTAMP = "UPDATE policy "
            + "SET modified=CURRENT_TIMESTAMP(3) WHERE policy_id=?;";
    private static final String SQL_GET_POLICY_ID = "SELECT policy_id FROM policy WHERE domain_id=? AND name=?;";
    private static final String SQL_DELETE_POLICY = "DELETE FROM policy WHERE domain_id=? AND name=?;";
    private static final String SQL_LIST_POLICY = "SELECT name FROM policy WHERE domain_id=?";
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
    private static final String SQL_DELETE_DOMAIN_TEMPLATE = "DELETE FROM domain_template WHERE domain_id=? AND template=?;";
    private static final String SQL_LIST_DOMAIN_TEMPLATE = "SELECT template FROM domain_template "
            + "JOIN domain ON domain_template.domain_id=domain.domain_id "
            + "WHERE domain.name=?;";
    private static final String SQL_GET_DOMAIN_ROLES = "SELECT * FROM role WHERE domain_id=?;";
    private static final String SQL_GET_DOMAIN_ROLE_MEMBERS = "SELECT role.name, principal.name, role_member.expiration FROM principal "
            + "JOIN role_member ON role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role.domain_id=?;";
    private static final String SQL_GET_DOMAIN_POLICIES = "SELECT * FROM policy WHERE domain_id=?;";
    private static final String SQL_GET_DOMAIN_POLICY_ASSERTIONS = "SELECT policy.name, "
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
    private static final String SQL_LIST_ROLE_PRINCIPALS = "SELECT principal.name, role.domain_id, "
            + "role.name AS role_name FROM principal "
            + "JOIN role_member ON principal.principal_id=role_member.principal_id "
            + "JOIN role ON role_member.role_id=role.role_id";
    private static final String SQL_LIST_ROLE_PRINCIPALS_USER_ONLY = " WHERE principal.name LIKE ?;";
    private static final String SQL_LIST_ROLE_PRINCIPALS_QUERY = " WHERE principal.name=?;";
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
    private static final String SQL_LIST_PRINCIPAL_ROLES = "SELECT domain.name, "
            + "role.name AS role_name FROM role_member "
            + "JOIN role ON role_member.role_id=role.role_id "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "WHERE role_member.principal_id=?;";
    private static final String SQL_LIST_PRINCIPAL_DOMAIN_ROLES = "SELECT role.name AS role_name FROM role_member "
            + "JOIN role ON role_member.role_id=role.role_id "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "WHERE role_member.principal_id=? AND domain.domain_id=?;";
    private static final String SQL_GET_QUOTA = "SELECT * FROM quota WHERE domain_id=?;";
    private static final String SQL_INSERT_QUOTA = "INSERT INTO quota (domain_id, role, role_member, "
            + "policy, assertion, service, service_host, public_key, entity, subdomain) "
            + "VALUES (?,?,?,?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_QUOTA = "UPDATE quota SET role=?, role_member=?, "
            + "policy=?, assertion=?, service=?, service_host=?, public_key=?, entity=?, "
            + "subdomain=? WHERE domain_id=?;";
    private static final String SQL_DELETE_QUOTA = "DELETE FROM quota WHERE domain_id=?;";

    private static final String CACHE_DOMAIN    = "d:";
    private static final String CACHE_ROLE      = "r:";
    private static final String CACHE_POLICY    = "p:";
    private static final String CACHE_SERVICE   = "s:";
    private static final String CACHE_PRINCIPAL = "u:";
    private static final String CACHE_HOST      = "h:";
    private static final String ALL_PRINCIPALS  = "*";

    private static final String AWS_ARN_PREFIX  = "arn:aws:iam::";
    
    Connection con;
    boolean transactionCompleted;
    int queryTimeout = 60;
    Map<String, Integer> objectMap;
    
    public JDBCConnection(Connection con, boolean autoCommit) throws SQLException {
        this.con = con;
        con.setAutoCommit(autoCommit);
        transactionCompleted = autoCommit;
        objectMap = new HashMap<>();
    }

    @Override
    public void setOperationTimeout(int queryTimeout) {
        this.queryTimeout = queryTimeout;
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
            LOG.error("close: state - " + ex.getSQLState() +
                    ", code - " + ex.getErrorCode() + ", message - " + ex.getMessage());
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
            LOG.error("rollbackChanges: state - " + ex.getSQLState() +
                    ", code - " + ex.getErrorCode() + ", message - " + ex.getMessage());
        }
        transactionCompleted = true;
        try {
            con.setAutoCommit(true);
        } catch (SQLException ex) {
            LOG.error("rollback auto-commit after failure: state - " + ex.getSQLState() +
                    ", code - " + ex.getErrorCode() + ", message - " + ex.getMessage());
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
            LOG.error("commitChanges: state - " + ex.getSQLState() +
                    ", code - " + ex.getErrorCode() + ", message - " + ex.getMessage());
            transactionCompleted = true;
            throw sqlError(ex, caller);
        }
    }
    
    int executeUpdate(PreparedStatement ps, String caller) throws SQLException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(caller + ": " + ps.toString());
        }
        ps.setQueryTimeout(queryTimeout);
        return ps.executeUpdate();
    }
    
    ResultSet executeQuery(PreparedStatement ps, String caller) throws SQLException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(caller + ": " + ps.toString());
        }
        ps.setQueryTimeout(queryTimeout);
        return ps.executeQuery();
    }

    Domain saveDomainSettings(String domainName, ResultSet rs, String caller) {
        try {
            return new Domain().setName(domainName)
                    .setAuditEnabled(rs.getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED))
                    .setEnabled(rs.getBoolean(ZMSConsts.DB_COLUMN_ENABLED))
                    .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                    .setDescription(saveValue(rs.getString(ZMSConsts.DB_COLUMN_DESCRIPTION)))
                    .setOrg(saveValue(rs.getString(ZMSConsts.DB_COLUMN_ORG)))
                    .setId(saveUuidValue(rs.getString(ZMSConsts.DB_COLUMN_UUID)))
                    .setAccount(saveValue(rs.getString(ZMSConsts.DB_COLUMN_ACCOUNT)))
                    .setYpmId(rs.getInt(ZMSConsts.DB_COLUMN_PRODUCT_ID))
                    .setCertDnsDomain(rs.getString(ZMSConsts.DB_COLUMN_CERT_DNS_DOMAIN));
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }
    
    @Override
    public Domain getDomain(String domainName) {
        
        final String caller = "getDomain";
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN)) {
            ps.setString(1, domainName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    return saveDomainSettings(domainName, rs, caller);
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
        
        verifyDomainAccountUniqueness(domain.getName(), domain.getAccount(), caller);
        verifyDomainProductIdUniqueness(domain.getName(), domain.getYpmId(), caller);
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

    void verifyDomainProductIdUniqueness(String name, Integer productId, String caller) {
        
        if (productId == null || productId == 0) {
            return;
        }
        
        String domainName = lookupDomainById(null, productId);
        if (domainName != null && !domainName.equals(name)) {
            throw requestError(caller, "Product Id: " + productId +
                    " is already assigned to domain: " + domainName);
        }
    }
    
    void verifyDomainAccountUniqueness(String name, String account, String caller) {
        
        if (account == null || account.isEmpty()) {
            return;
        }
        
        String domainName = lookupDomainById(account, 0);
        if (domainName != null && !domainName.equals(name)) {
            throw requestError(caller, "Account Id: " + account +
                    " is already assigned to domain: " + domainName);
        }
    }

    @Override
    public boolean updateDomain(Domain domain) {
        
        int affectedRows;
        final String caller = "updateDomain";

        // we need to verify that our account and product ids are unique
        // in the store. we can't rely on db uniqueness check since
        // some of the domains will not have these attributes set
        
        verifyDomainAccountUniqueness(domain.getName(), domain.getAccount(), caller);
        verifyDomainProductIdUniqueness(domain.getName(), domain.getYpmId(), caller);
        
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
            ps.setString(10, domain.getName());
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
        if (prefix != null && prefix.length() > 0) {
            int len = prefix.length();
            char c = (char) (prefix.charAt(len - 1) + 1);
            String stop = prefix.substring(0, len - 1) + c;
            if (modifiedSince != 0) {
                ps = con.prepareStatement(SQL_LIST_DOMAIN_PREFIX_MODIFIED);
                ps.setString(1, prefix);
                ps.setString(2, stop);
                Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
                ps.setTimestamp(3, new java.sql.Timestamp(modifiedSince), cal);
            } else {
                ps = con.prepareStatement(SQL_LIST_DOMAIN_PREFIX);
                ps.setString(1, prefix);
                ps.setString(2, stop);
            }
        } else if (modifiedSince != 0) {
            ps = con.prepareStatement(SQL_LIST_DOMAIN_MODIFIED);
            Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
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
    public String lookupDomainById(String account, int productId) {
        
        final String caller = "lookupDomain";
        final String sqlCmd = (account != null) ? SQL_GET_DOMAIN_WITH_ACCOUNT : SQL_GET_DOMAIN_WITH_PRODUCT_ID;

        String domainName = null;
        try (PreparedStatement ps = con.prepareStatement(sqlCmd)) {
            
            if (account != null) {
                ps.setString(1, account.trim());
            } else {
                ps.setInt(1, productId);
            }
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
            LOG.error("unable to get domain id for name: " + domainName +
                    " error code: " + ex.getErrorCode() + " msg: " + ex.getMessage());
        }
        
        // before returning the value update our cache
        
        if (domainId != 0) {
            objectMap.put(cacheKey, domainId);
        }
        
        return domainId;
    }
    
    int getPolicyId(int domainId, String policyName) {
        
        final String caller = "getPolicyId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server

        final String cacheKey = CACHE_POLICY + domainId + '.' + policyName;
        
        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }
        
        int policyId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_POLICY_ID)) {
            ps.setInt(1, domainId);
            ps.setString(2, policyName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    policyId = rs.getInt(1);
                }
            }
        } catch (SQLException ex) {
            LOG.error("unable to get polcy id for name: " + policyName +
                    " error code: " + ex.getErrorCode() + " msg: " + ex.getMessage());
        }
        
        // before returning the value update our cache
        
        if (policyId != 0) {
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
            LOG.error("unable to get role id for name: " + roleName +
                    " error code: " + ex.getErrorCode() + " msg: " + ex.getMessage());
        }
        
        // before returning the value update our cache
        
        if (roleId != 0) {
            objectMap.put(cacheKey, roleId);
        }
        
        return roleId;
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
            LOG.error("unable to get service id for name: " + serviceName +
                    " error code: " + ex.getErrorCode() + " msg: " + ex.getMessage());
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
            LOG.error("unable to get principal id for name: " + principal +
                    " error code: " + ex.getErrorCode() +
                    " msg: " + ex.getMessage());
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
            LOG.error("unable to get host id for name: " + hostName +
                    " error code: " + ex.getErrorCode() + " msg: " + ex.getMessage());
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
            LOG.error("unable to get last insert id - error code: " + ex.getErrorCode() +
                    " msg: " + ex.getMessage());
        }
        return lastInsertId;
    }
    
    PreparedStatement preparePrincipalScanStatement(String domainName)
            throws SQLException {
        
        PreparedStatement ps;
        if (domainName != null && domainName.length() > 0) {
            final String principalPattern = domainName + ".%";
            ps = con.prepareStatement(SQL_LIST_PRINCIPAL_DOMAIN);
            ps.setString(1, principalPattern);
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
                    return new Role().setName(ZMSUtils.roleResourceName(domainName, roleName))
                            .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                            .setTrust(saveValue(rs.getString(ZMSConsts.DB_COLUMN_TRUST)));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return null;
    }

    String extractObjectName(String domainName, String fullName, String objType) {
        
        // generate prefix to compare with

        final String prefix = domainName + objType;
        if (!fullName.startsWith(prefix)) {
            return null;
        }
        return fullName.substring(prefix.length());
    }
    
    String extractRoleName(String domainName, String fullRoleName) {
        return extractObjectName(domainName, fullRoleName, ":role.");
    }
    
    String extractPolicyName(String domainName, String fullPolicyName) {
        return extractObjectName(domainName, fullPolicyName, ":policy.");
    }
    
    String extractServiceName(String domainName, String fullServiceName) {
        return extractObjectName(domainName, fullServiceName, ".");
    }
    
    @Override
    public boolean insertRole(String domainName, Role role) {

        int affectedRows;
        final String caller = "insertRole";

        String roleName = extractRoleName(domainName, role.getName());
        if (roleName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " insert role name: " + role.getName());
        }
        
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ROLE)) {
            ps.setString(1, roleName);
            ps.setInt(2, domainId);
            ps.setString(3, processInsertValue(role.getTrust()));
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

        String roleName = extractRoleName(domainName, role.getName());
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
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
        }
        
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ROLE)) {
            ps.setString(1, processInsertValue(role.getTrust()));
            ps.setInt(2, roleId);
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
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
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
    public boolean updateServiceIdentityModTimestamp(String domainName, String serviceName) {
        
        int affectedRows;
        final String caller = "updateServiceIdentityModTimestamp";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
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

    @Override
    public List<RoleMember> listRoleMembers(String domainName, String roleName) {
        
        final String caller = "listRoleMembers";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
        }
        List<RoleMember> members = new ArrayList<>();
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
                    members.add(roleMember);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
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
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
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
    public List<PrincipalRole> listPrincipalRoles(String domainName, String principalName) {
        
        final String caller = "listPrincipalRoles";
        if (domainName == null) {
            return listPrincipalRolesForAllDomains(principalName, caller);
        } else {
            return listPrincipalRolesForOneDomain(domainName, principalName, caller);
        }
    }

    List<PrincipalRole> listPrincipalRolesForAllDomains(String principalName, String caller) {

        int principalId = getPrincipalId(principalName);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principalName);
        }
        List<PrincipalRole> roles = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_PRINCIPAL_ROLES)) {
            ps.setInt(1, principalId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    PrincipalRole role = new PrincipalRole();
                    role.setDomainName(rs.getString(ZMSConsts.DB_COLUMN_NAME));
                    role.setRoleName(rs.getString(ZMSConsts.DB_COLUMN_ROLE_NAME));
                    roles.add(role);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return roles;
    }

    List<PrincipalRole> listPrincipalRolesForOneDomain(String domainName, String principalName, String caller) {

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int principalId = getPrincipalId(principalName);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principalName);
        }
        List<PrincipalRole> roles = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_PRINCIPAL_DOMAIN_ROLES)) {
            ps.setInt(1, principalId);
            ps.setInt(2, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    PrincipalRole role = new PrincipalRole();
                    role.setRoleName(rs.getString(ZMSConsts.DB_COLUMN_ROLE_NAME));
                    roles.add(role);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return roles;
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
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
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
    
    @Override
    public Membership getRoleMember(String domainName, String roleName, String member) {
        
        final String caller = "getRoleMember";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
        }
        
        Membership membership = new Membership()
                .setMemberName(member)
                .setRoleName(ZMSUtils.roleResourceName(domainName, roleName))
                .setIsMember(false);
        
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ROLE_MEMBER)) {
            ps.setInt(1, roleId);
            ps.setString(2, member);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    membership.setIsMember(true);
                    java.sql.Timestamp expiration = rs.getTimestamp(2);
                    if (expiration != null) {
                        membership.setExpiration(Timestamp.fromMillis(expiration.getTime()));
                    }
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
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
            // we're just going to lookup the principal id and return
            // that instead of returning an exception
            
            if (ex.getErrorCode() == MYSQL_ER_OPTION_DUPLICATE_ENTRY) {
                return getPrincipalId(principal);
            }

            throw sqlError(ex, caller);
        }
        
        int principalId = 0;
        if (affectedRows == 1) {
            principalId = getLastInsertId();
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
    
    @Override
    public boolean insertRoleMember(String domainName, String roleName, RoleMember roleMember,
            String admin, String auditRef) {

        final String caller = "insertRoleMember";

        String principal = roleMember.getMemberName();
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
        }
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
        //need to check if entry already exists
        int affectedRows;
        boolean roleMemberExists = false;
        boolean result;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ROLE_MEMBER_EXISTS)) {
            ps.setInt(1, roleId);
            ps.setInt(2, principalId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    roleMemberExists = true;
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        java.sql.Timestamp expiration = null;
        if (roleMember.getExpiration() != null) {
            expiration = new java.sql.Timestamp(roleMember.getExpiration().toDate().getTime());
        }
        if (roleMemberExists) {
           if (expiration == null) {
               //return true instead of throwing 400 Entry already exists
               return true;
           }
           try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ROLE_MEMBER)) {
                ps.setTimestamp(1, expiration);
                ps.setInt(2, roleId);
                ps.setInt(3, principalId);
                affectedRows = executeUpdate(ps, caller);
           } catch (SQLException ex) {
                throw sqlError(ex, caller);
           }
           result = (affectedRows > 0);
           if (result) {
               result = insertRoleAuditLog(roleId, admin, principal, "UPDATE", auditRef);
           }
        } else {
            try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ROLE_MEMBER)) {
                ps.setInt(1, roleId);
                ps.setInt(2, principalId);
                if (expiration != null) {
                    ps.setTimestamp(3, expiration);
                } else {
                    ps.setTimestamp(3, null);
                }
                affectedRows = executeUpdate(ps, caller);
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }

            result = (affectedRows > 0);
            
            // add audit log entry for this change if the add was successful
            // add return the result of the audit log insert operation
            
            if (result) {
                result = insertRoleAuditLog(roleId, admin, principal, "ADD", auditRef);
            }
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
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
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
                    assertion.setRole(ZMSUtils.roleResourceName(domainName, rs.getString(ZMSConsts.DB_COLUMN_ROLE)));
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
    public Policy getPolicy(String domainName, String policyName) {
        
        final String caller = "getPolicy";

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_POLICY)) {
            ps.setString(1, domainName);
            ps.setString(2, policyName);
            try (ResultSet rs = executeQuery(ps, caller)) {
                if (rs.next()) {
                    return new Policy().setName(ZMSUtils.policyResourceName(domainName, policyName))
                            .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()));
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

        String policyName = extractPolicyName(domainName, policy.getName());
        if (policyName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " insert policy name: " + policy.getName());
        }
        
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_POLICY)) {
            ps.setString(1, policyName);
            ps.setInt(2, domainId);
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

        String policyName = extractPolicyName(domainName, policy.getName());
        if (policyName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " update policy name: " + policy.getName());
        }
        
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ZMSUtils.policyResourceName(domainName, policyName));
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
    public boolean updatePolicyModTimestamp(String domainName, String policyName) {

        int affectedRows;
        final String caller = "updatePolicyModTimestamp";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ZMSUtils.policyResourceName(domainName, policyName));
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
    public boolean insertAssertion(String domainName, String policyName, Assertion assertion) {
        
        final String caller = "insertAssertion";

        String roleName = extractRoleName(domainName, assertion.getRole());
        if (roleName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " assertion role name: " + assertion.getRole());
        }
        
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ZMSUtils.policyResourceName(domainName, policyName));
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
    public boolean deleteAssertion(String domainName, String policyName, Long assertionId) {
        
        final String caller = "deleteAssertion";
        
        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ZMSUtils.policyResourceName(domainName, policyName));
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
    public List<Assertion> listAssertions(String domainName, String policyName) {
        
        final String caller = "listAssertions";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ZMSUtils.policyResourceName(domainName, policyName));
        }
        List<Assertion> assertions = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ASSERTION)) {
            ps.setInt(1, policyId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    Assertion assertion = new Assertion();
                    assertion.setRole(ZMSUtils.roleResourceName(domainName, rs.getString(ZMSConsts.DB_COLUMN_ROLE)));
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
        return assertions;
    }

    @Override
    public int countAssertions(String domainName, String policyName) {
        
        final String caller = "countAssertions";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(domainId, policyName);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ZMSUtils.policyResourceName(domainName, policyName));
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
                            .setName(ZMSUtils.serviceResourceName(domainName, serviceName))
                            .setDescription(saveValue(rs.getString(ZMSConsts.DB_COLUMN_DESCRIPTION)))
                            .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                            .setProviderEndpoint(saveValue(rs.getString(ZMSConsts.DB_COLUMN_PROVIDER_ENDPOINT)))
                            .setExecutable(saveValue(rs.getString(ZMSConsts.DB_COLUMN_EXECTUABLE)))
                            .setUser(saveValue(rs.getString(ZMSConsts.DB_COLUMN_SVC_USER)))
                            .setGroup(saveValue(rs.getString(ZMSConsts.DB_COLUMN_SVC_GROUP)));
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

        String serviceName = extractServiceName(domainName, service.getName());
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

        String serviceName = extractServiceName(domainName, service.getName());
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
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
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
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
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
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
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
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
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
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
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
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
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
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
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
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
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
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
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
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
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

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ENTITY)) {
            ps.setInt(1, domainId);
            ps.setString(2, entity.getName());
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

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ENTITY)) {
            ps.setString(1, JSON.string(entity.getValue()));
            ps.setInt(2, domainId);
            ps.setString(3, entity.getName());
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
                    return new Entity().setName(entityName)
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
    
    void getAthenzDomainRoles(String domainName, int domainId, AthenzDomain athenzDomain) {

        final String caller = "getAthenzDomain";
        Map<String, Role> roleMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_ROLES)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String roleName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    Role role = new Role().setName(ZMSUtils.roleResourceName(domainName, roleName))
                            .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                            .setTrust(saveValue(rs.getString(ZMSConsts.DB_COLUMN_TRUST)));
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
                    members.add(roleMember);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        
        athenzDomain.getRoles().addAll(roleMap.values());
    }
    
    void getAthenzDomainPolicies(String domainName, int domainId, AthenzDomain athenzDomain) {

        final String caller = "getAthenzDomain";
        Map<String, Policy> policyMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_POLICIES)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String policyName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    Policy policy = new Policy().setName(ZMSUtils.policyResourceName(domainName, policyName))
                            .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()));
                    policyMap.put(policyName, policy);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_POLICY_ASSERTIONS)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String policyName = rs.getString(1);
                    Policy policy = policyMap.get(policyName);
                    if (policy == null) {
                        continue;
                    }
                    List<Assertion> assertions = policy.getAssertions();
                    if (assertions == null) {
                        assertions = new ArrayList<>();
                        policy.setAssertions(assertions);
                    }
                    Assertion assertion = new Assertion();
                    assertion.setRole(ZMSUtils.roleResourceName(domainName, rs.getString(ZMSConsts.DB_COLUMN_ROLE)));
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
        
        athenzDomain.getPolicies().addAll(policyMap.values());
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
                            .setName(ZMSUtils.serviceResourceName(domainName, serviceName))
                            .setProviderEndpoint(saveValue(rs.getString(ZMSConsts.DB_COLUMN_PROVIDER_ENDPOINT)))
                            .setExecutable(saveValue(rs.getString(ZMSConsts.DB_COLUMN_EXECTUABLE)))
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
        
        athenzDomain.getServices().addAll(serviceMap.values());
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
                    Domain domain = saveDomainSettings(domainName, rs, caller);
                    athenzDomain.setDomain(domain);
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
        getAthenzDomainPolicies(domainName, domainId, athenzDomain);
        getAthenzDomainServices(domainName, domainId, athenzDomain);
        
        return athenzDomain;
    }
    
    @Override
    public DomainModifiedList listModifiedDomains(long modifiedSince) {
        
        final String caller = "listModifiedDomains";

        DomainModifiedList domainModifiedList = new DomainModifiedList();
        List<DomainModified> nameMods = new ArrayList<>();

        try (PreparedStatement ps = prepareDomainScanStatement(null, modifiedSince)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    DomainModified dm = new DomainModified()
                            .setName(rs.getString(ZMSConsts.DB_COLUMN_NAME))
                            .setModified(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime())
                            .setAccount(saveValue(rs.getString(ZMSConsts.DB_COLUMN_ACCOUNT)))
                            .setYpmId(rs.getInt(ZMSConsts.DB_COLUMN_PRODUCT_ID));
                    nameMods.add(dm);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    
        domainModifiedList.setNameModList(nameMods);
        return domainModifiedList;
    }
    
    boolean validatePrincipalDomain(String principal) {
        // special case for all principals
        if (ALL_PRINCIPALS.equals(principal)) {
            return true;
        }
        int idx = principal.lastIndexOf('.');
        if (idx == -1 || idx == 0 || idx == principal.length() - 1) {
            return false;
        }
        return getDomainId(principal.substring(0, idx)) != 0;
    }
    
    String roleIndex(String domainId, String roleName) {
        return domainId + ':' + roleName;
    }
    
    PreparedStatement prepareRoleAssertionsStatement(String action)
            throws SQLException {
        
        PreparedStatement ps;
        if (action != null && action.length() > 0) {
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
                    assertion.setRole(ZMSUtils.roleResourceName(domainName, roleName));
                    assertion.setResource(rs.getString(ZMSConsts.DB_COLUMN_RESOURCE));
                    assertion.setAction(rs.getString(ZMSConsts.DB_COLUMN_ACTION));
                    assertion.setEffect(AssertionEffect.valueOf(rs.getString(ZMSConsts.DB_COLUMN_EFFECT)));
                    assertion.setId((long) rs.getInt(ZMSConsts.DB_COLUMN_ASSERT_ID));

                    String index = roleIndex(rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID), roleName);
                    List<Assertion> assertions = roleAssertions.computeIfAbsent(index, k -> new ArrayList<>());

                    if (LOG.isDebugEnabled()) {
                        LOG.debug(caller + ": adding assertion " + assertion + " for " + index);
                    }
                    
                    assertions.add(assertion);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        
        return roleAssertions;
    }
    
    PreparedStatement prepareRolePrincipalsStatement(String principal,
            String userDomain, boolean awsQuery) throws SQLException {
        
        PreparedStatement ps;
        if (principal != null && principal.length() > 0) {
            ps = con.prepareStatement(SQL_LIST_ROLE_PRINCIPALS + SQL_LIST_ROLE_PRINCIPALS_QUERY);
            ps.setString(1, principal);
        } else if (awsQuery) {
            final String principalPattern = userDomain + ".%";
            ps = con.prepareStatement(SQL_LIST_ROLE_PRINCIPALS + SQL_LIST_ROLE_PRINCIPALS_USER_ONLY);
            ps.setString(1, principalPattern);
        } else {
            ps = con.prepareStatement(SQL_LIST_ROLE_PRINCIPALS);
        }
        return ps;
    }
    
    Map<String, List<String>> getRolePrincipals(String principal, boolean awsQuery,
            String userDomain, String caller) {

        Map<String, List<String>> rolePrincipals = new HashMap<>();
        try (PreparedStatement ps = prepareRolePrincipalsStatement(principal, userDomain, awsQuery)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    String principalName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    String roleName = rs.getString(ZMSConsts.DB_COLUMN_ROLE_NAME);

                    String index = roleIndex(rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID), roleName);
                    List<String> principals = rolePrincipals.computeIfAbsent(index, k -> new ArrayList<>());

                    if (LOG.isDebugEnabled()) {
                        LOG.debug(caller + ": adding principal " + principalName + " for " + index);
                    }
                    
                    principals.add(principalName);
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
    
    Map<String, List<String>> getTrustedRoles(String caller) {
        
        Map<String, List<String>> trustedRoles = new HashMap<>();
        getTrustedSubTypeRoles(SQL_LIST_TRUSTED_STANDARD_ROLES, trustedRoles, caller);
        getTrustedSubTypeRoles(SQL_LIST_TRUSTED_WILDCARD_ROLES, trustedRoles, caller);
        return trustedRoles;
    }
    
    Map<String, String> getAwsDomains(String caller) {
        
        Map<String, String> awsDomains = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_DOMAIN_AWS)) {
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    awsDomains.put(rs.getString(ZMSConsts.DB_COLUMN_NAME), rs.getString(ZMSConsts.DB_COLUMN_ACCOUNT));
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        
        return awsDomains;
    }
    
    boolean skipAwsUserQuery(Map<String, String> awsDomains, String queryPrincipal,
            String rolePincipal, String userDomain) {

        // if no aws domains specified then it's not an aws query
        
        if (awsDomains == null) {
            return false;
        }
        
        // check if our query principal is not specified
        
        if (queryPrincipal != null && !queryPrincipal.isEmpty()) {
            return false;
        }
        
        // so now we know this is a global aws role query so we're only
        // going to keep actual users - everyone else is skipped
        
        // make sure the principal starts with the user domain prefix
        
        String userDomainPrefix = userDomain + ".";
        if (!rolePincipal.startsWith(userDomainPrefix)) {
            return true;
        }
        
        // make sure this is not a service within the user's
        // personal domain

        return rolePincipal.substring(userDomainPrefix.length()).indexOf('.') != -1;
    }
    
    void addRoleAssertions(List<Assertion> principalAssertions, List<Assertion> roleAssertions,
            Map<String, String> awsDomains) {
        
        // if the role assertions is empty then we have nothing to do
        
        if (roleAssertions == null || roleAssertions.isEmpty()) {

            if (LOG.isDebugEnabled()) {
                LOG.debug("addRoleAssertions: role assertion list is empty");
            }
            
            return;
        }
        
        // if this is not an aws request or the awsDomain list is empty,
        // then we're just going to add the role assertions to the
        // principal's assertion list as is
        
        if (awsDomains == null || awsDomains.isEmpty()) {
            principalAssertions.addAll(roleAssertions);
            return;
        }
        
        // we're going to update each assertion and generate the
        // resource in the expected aws role format. however, we
        // going to skip any assertions where we do not have a
        // valid syntax or no aws domain
        
        for (Assertion assertion : roleAssertions) {
            
            final String resource = assertion.getResource();

            if (LOG.isDebugEnabled()) {
                LOG.debug("addRoleAssertions: processing assertion: {}", resource);
            }
            
            // first we need to check if the assertion has already
            // been processed and as such the resource has been
            // rewritten to have aws format
            
            if (resource.startsWith(AWS_ARN_PREFIX)) {
                principalAssertions.add(assertion);
                continue;
            }
            
            // otherwise we're going to look for the domain component
            
            int idx = resource.indexOf(':');
            if (idx == -1) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("addRoleAssertions: resource without domain component: {}", resource);
                }
                continue;
            }
            
            final String resourceDomain = resource.substring(0, idx);
            String awsDomain = awsDomains.get(resourceDomain);
            if (awsDomain == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("addRoleAssertions: resource without aws domain: {}", resourceDomain);
                }
                continue;
            }

            assertion.setResource(AWS_ARN_PREFIX + awsDomain + ":role/" + resource.substring(idx + 1));
            principalAssertions.add(assertion);
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

        // check to see if this an aws request based on
        // the action query
        
        boolean awsQuery = (action != null && action.equals(ZMSConsts.ACTION_ASSUME_AWS_ROLE));
        boolean singlePrincipalQuery = (principal != null && !principal.isEmpty());
        
        // first let's get the principal list that we're asked to check for
        // since if we have no matches then we have nothing to do
        
        Map<String, List<String>> rolePrincipals = getRolePrincipals(principal, awsQuery,
                userDomain, caller);
        if (rolePrincipals.isEmpty()) {
            if (singlePrincipalQuery) {
                
                // so the given principal is not available as a role member
                // so before returning an empty response let's make sure
                // that it has been registered in Athenz otherwise we'll
                // just return 404 - not found exception
                
                if (getPrincipalId(principal) == 0) {
                    throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
                }
                
                resources.add(getResourceAccessObject(principal, null));
            }
            return rsrcAccessList;
        }
        
        // now let's get the list of role assertions. if we have
        // no matches, then we have nothing to do
        
        Map<String, List<Assertion>> roleAssertions = getRoleAssertions(action, caller);
        if (roleAssertions.isEmpty()) {
            if (singlePrincipalQuery) {
                resources.add(getResourceAccessObject(principal, null));
            }
            return rsrcAccessList;
        }
        
        // finally we need to get all the trusted role maps
        
        Map<String, List<String>> trustedRoles = getTrustedRoles(caller);
        
        // couple of special cases - if we're asked for action assume_aws_role
        // then we're looking for role access in AWS. So we're going to retrieve
        // the domains that have aws account configured only and update
        // the resource to generate aws role resources. If the action is
        // assume_aws_role with no principal - then another special case to
        // look for actual users only
        
        Map<String, String> awsDomains = null;
        if (awsQuery) {
            awsDomains = getAwsDomains(caller);
        }
        
        // now let's go ahead and combine all of our data together
        // we're going to go through each principal, lookup
        // the assertions for the role and add them to the return object
        // if the role has no corresponding assertions, then we're going
        // to look at the trust role map in case it's a trusted role
        
        Map<String, List<Assertion>> principalAssertions = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : rolePrincipals.entrySet()) {
            
            String roleIndex = entry.getKey();
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": processing role: " + roleIndex);
            }
            
            // get the list of principals for this role
            
            List<String> rPrincipals = entry.getValue();
            for (String rPrincipal : rPrincipals) {
                
                if (LOG.isDebugEnabled()) {
                    LOG.debug(caller + ": processing role principal: " + rPrincipal);
                }
                
                // if running an aws query with no principals specified then make
                // sure this is real user and not some service
                
                if (skipAwsUserQuery(awsDomains, principal, rPrincipal, userDomain)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(caller + ": skipping non-user: " + rPrincipal);
                    }
                    continue;
                }

                List<Assertion> assertions = principalAssertions.computeIfAbsent(rPrincipal, k -> new ArrayList<>());

                // retrieve the assertions for this role
                
                addRoleAssertions(assertions, roleAssertions.get(roleIndex), awsDomains);
                    
                // check to see if this is a trusted role. There might be multiple
                // roles all being mapped as trusted, so we need to process them all
                
                List<String> mappedTrustedRoles = trustedRoles.get(roleIndex);
                if (mappedTrustedRoles != null) {
                    for (String mappedTrustedRole : mappedTrustedRoles) {
                        
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(caller + ": processing trusted role: " + mappedTrustedRole);
                        }
                        
                        addRoleAssertions(assertions, roleAssertions.get(mappedTrustedRole), awsDomains);
                    }
                }
            }
        }
        
        // finally we need to create resource access list objects and return
        
        for (Map.Entry<String, List<Assertion>> entry : principalAssertions.entrySet()) {
            
            // if this is a query for all principals in Athenz then we're
            // automatically going to skip any principals who have no
            // assertions
            
            List<Assertion> assertions = entry.getValue();
            if (!singlePrincipalQuery && (assertions == null || assertions.isEmpty())) {
                continue;
            }
            
            resources.add(getResourceAccessObject(entry.getKey(), assertions));
        }
        
        return rsrcAccessList;
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
            ps.setInt(10, domainId);
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

        final String caller = "listDomainRoleMembers";

        int domainId = getDomainId(domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        DomainRoleMembers domainRoleMembers = new DomainRoleMembers();
        domainRoleMembers.setDomainName(domainName);

        Map<String, DomainRoleMember> memberMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_ROLE_MEMBERS)) {
            ps.setInt(1, domainId);
            try (ResultSet rs = executeQuery(ps, caller)) {
                while (rs.next()) {
                    final String roleName = rs.getString(1);
                    final String memberName = rs.getString(2);
                    java.sql.Timestamp expiration = rs.getTimestamp(3);

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
                    if (expiration != null) {
                        memberRole.setExpiration(Timestamp.fromMillis(expiration.getTime()));
                    }
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
        
        String sqlState = ex.getSQLState();
        int code = ResourceException.INTERNAL_SERVER_ERROR;
        String msg;
        if ("08S01".equals(sqlState) || "40001".equals(sqlState)) {
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
}
