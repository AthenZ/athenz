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
package com.yahoo.athenz.zms.store.jdbc;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.AssertionEffect;
import com.yahoo.athenz.zms.Domain;
import com.yahoo.athenz.zms.DomainModified;
import com.yahoo.athenz.zms.DomainModifiedList;
import com.yahoo.athenz.zms.Entity;
import com.yahoo.athenz.zms.Membership;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.athenz.zms.ResourceAccess;
import com.yahoo.athenz.zms.ResourceAccessList;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleAuditLog;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ServiceIdentity;
import com.yahoo.athenz.zms.ZMSConsts;
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
    private static final String SQL_GET_DOMAIN_WITH_ACCOUNT = "SELECT name FROM domain WHERE account=?;";
    private static final String SQL_GET_DOMAIN_WITH_PRODUCT_ID = "SELECT name FROM domain WHERE ypm_id=?;";
    private static final String SQL_INSERT_DOMAIN = "INSERT INTO domain "
            + "(name, description, org, uuid, enabled, audit_enabled, account, ypm_id) VALUES (?,?,?,?,?,?,?,?);";
    private static final String SQL_UPDATE_DOMAIN = "UPDATE domain "
            + "SET description=?, org=?, uuid=?, enabled=?, audit_enabled=?, account=?, ypm_id=? WHERE name=?;";
    private static final String SQL_UPDATE_DOMAIN_MOD_TIMESTAMP = "UPDATE domain "
            + "SET modified=CURRENT_TIMESTAMP(3) WHERE name=?;";
    private static final String SQL_GET_DOMAIN_MOD_TIMESTAMP = "SELECT modified FROM domain WHERE name=?;";
    private static final String SQL_LIST_DOMAIN = "SELECT name, modified FROM domain;";
    private static final String SQL_LIST_DOMAIN_PREFIX = "SELECT name, modified FROM domain WHERE name>=? AND name<?;";
    private static final String SQL_LIST_DOMAIN_MODIFIED = "SELECT name, modified FROM domain WHERE modified>?;";
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
    private static final String SQL_GET_ROLE_MEMBER = "SELECT principal.principal_id, role_member.expiration FROM principal "
            + "JOIN role_member ON role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role.role_id=? AND principal.name=?;";
    private static final String SQL_GET_ROLE_MEMBER_EXISTS = "SELECT principal_id FROM role_member WHERE role_id=? AND principal_id=?;";
    private static final String SQL_LIST_ROLE_MEMBERS = "SELECT principal.name, role_member.expiration FROM principal "
            + "JOIN role_member ON role_member.principal_id=principal.principal_id "
            + "JOIN role ON role.role_id=role_member.role_id "
            + "WHERE role.role_id=?;";
    private static final String SQL_GET_PRINCIPAL_ID = "SELECT principal_id FROM principal WHERE name=?;";
    private static final String SQL_INSERT_PRINCIPAL = "INSERT INTO principal (name) VALUES (?);";
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
    private static final String SQL_LIST_ASSERTION = "SELECT * FROM assertion WHERE policy_id=?";
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
            + "(name, provider_endpoint, executable, svc_user, svc_group, domain_id) VALUES (?,?,?,?,?,?);";
    private static final String SQL_UPDATE_SERVICE = "UPDATE service SET "
            + "provider_endpoint=?, executable=?, svc_user=?, svc_group=?  WHERE service_id=?;";
    private static final String SQL_DELETE_SERVICE = "DELETE FROM service WHERE domain_id=? AND name=?;";
    private static final String SQL_GET_SERVICE_ID = "SELECT service_id FROM service WHERE domain_id=? AND name=?;";
    private static final String SQL_LIST_SERVICE = "SELECT name FROM service WHERE domain_id=?;";
    private static final String SQL_LIST_PUBLIC_KEY = "SELECT * FROM public_key WHERE service_id=?;";
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
    private static final String SQL_LIST_ROLE_PRINCIPALS_YBY_ONLY = " WHERE principal.name LIKE 'yby.%';";
    private static final String SQL_LIST_ROLE_PRINCIPALS_QUERY = " WHERE principal.name=?;";
    private static final String SQL_LIST_TRUSTED_ROLES = "SELECT role.domain_id, role.name, "
            + "policy.domain_id AS assert_domain_id, assertion.role FROM role "
            + "JOIN domain ON domain.domain_id=role.domain_id "
            + "JOIN assertion ON (assertion.resource=CONCAT(domain.name, \":role.\", role.name) OR assertion.resource=CONCAT(\"*:role.\", role.name)) "
            + "JOIN policy ON policy.policy_id=assertion.policy_id "
            + "WHERE assertion.action='assume_role';";

    private static final String CACHE_DOMAIN    = "d:";
    private static final String CACHE_ROLE      = "r:";
    private static final String CACHE_POLICY    = "p:";
    private static final String CACHE_SERVICE   = "s:";
    private static final String CACHE_PRINCIPAL = "u:";
    private static final String CACHE_HOST      = "h:";

    Connection con = null;
    boolean transactionCompleted = true;
    Map<String, Integer> objectMap = null;
    
    public JDBCConnection(Connection con, boolean autoCommit) throws SQLException {
        this.con = con;
        con.setAutoCommit(autoCommit);
        transactionCompleted = autoCommit;
        objectMap = new HashMap<>();
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
    
    Domain saveDomainSettings(String domainName, ResultSet rs, String caller) {
        try {
            Domain domain = new Domain().setName(domainName)
                    .setAuditEnabled(rs.getBoolean(ZMSConsts.DB_COLUMN_AUDIT_ENABLED))
                    .setEnabled(rs.getBoolean(ZMSConsts.DB_COLUMN_ENABLED))
                    .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                    .setDescription(saveValue(rs.getString(ZMSConsts.DB_COLUMN_DESCRIPTION)))
                    .setOrg(saveValue(rs.getString(ZMSConsts.DB_COLUMN_ORG)))
                    .setId(saveUuidValue(rs.getString(ZMSConsts.DB_COLUMN_UUID)))
                    .setAccount(saveValue(rs.getString(ZMSConsts.DB_COLUMN_ACCOUNT)))
                    .setYpmId(rs.getInt(ZMSConsts.DB_COLUMN_PRODUCT_ID));
            return domain;
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
    }
    
    @Override
    public Domain getDomain(String domainName) {
        
        final String caller = "getDomain";
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN)) {
            ps.setString(1, domainName);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
        
        int affectedRows = 0;
        final String caller = "insertDomain";
        
        // we need to verify that our account and product ids are unique
        // in the store. we can't rely on db uniqueness check since
        // some of the domains will not have these attributes set
        
        verifyDomainAccountUniqueness(domain.getName(), domain.getAccount(), caller);
        verifyDomainProductIdUniqueness(domain.getName(), domain.getYpmId(), caller);
        
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_DOMAIN)) {
            ps.setString(1, domain.getName());
            ps.setString(2, processInsertValue(domain.getDescription()));
            ps.setString(3, processInsertValue(domain.getOrg()));
            ps.setString(4, processInsertUuidValue(domain.getId()));
            ps.setBoolean(5, processInsertValue(domain.getEnabled(), true));
            ps.setBoolean(6, processInsertValue(domain.getAuditEnabled(), false));
            ps.setString(7, processInsertValue(domain.getAccount()));
            ps.setInt(8, processInsertValue(domain.getYpmId()));
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    void verifyDomainProductIdUniqueness(String name, Integer productId, String caller) {
        
        if (productId == null || productId.intValue() == 0) {
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
        
        int affectedRows = 0;
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
            ps.setString(8, domain.getName());
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean updateDomainModTimestamp(String domainName) {
        
        int affectedRows = 0;
        final String caller = "updateDomainModTimestamp";

        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_DOMAIN_MOD_TIMESTAMP)) {
            ps.setString(1, domainName);
            affectedRows = ps.executeUpdate();
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
        
        int affectedRows = 0;
        final String caller = "deleteDomain";

        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_DOMAIN)) {
            ps.setString(1, domainName);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    PreparedStatement prepareScanStatement(Connection con, String prefix, long modifiedSince)
            throws SQLException {
        
        PreparedStatement ps = null;
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
    
    PreparedStatement prepareScanByRoleStatement(Connection con, String roleMember, String roleName)
            throws SQLException {
        
        PreparedStatement ps = null;
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
        try (PreparedStatement ps = prepareScanByRoleStatement(con, roleMember, roleName)) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
        
        String sqlCmd = null;
        if (account != null) {
            sqlCmd = SQL_GET_DOMAIN_WITH_ACCOUNT;
        } else {
            sqlCmd = SQL_GET_DOMAIN_WITH_PRODUCT_ID;
        }
        
        String domainName = null;
        try (PreparedStatement ps = con.prepareStatement(sqlCmd)) {
            
            if (account != null) {
                ps.setString(1, account.trim());
            } else {
                ps.setInt(1, productId);
            }
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
        try (PreparedStatement ps = prepareScanStatement(con, prefix, modifiedSince)) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_DOMAIN_TEMPLATE)) {
            ps.setInt(1, domainId);
            ps.setString(2, templateName);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deleteDomainTemplate(String domainName, String templateName, String params) {
        
        final String caller = "deleteDomainTemplate";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_DOMAIN_TEMPLATE)) {
            ps.setInt(1, domainId);
            ps.setString(2, templateName);
            affectedRows = ps.executeUpdate();
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    int getDomainId(Connection con, String domainName) {
        
        final String caller = "getDomainId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server
        
        StringBuilder cacheKeyBldr = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
        cacheKeyBldr.append(CACHE_DOMAIN).append(domainName);
        String cacheKey = cacheKeyBldr.toString();
        
        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }
        
        int domainId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_ID)) {
            ps.setString(1, domainName);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    int getPolicyId(Connection con, int domainId, String policyName) {
        
        final String caller = "getPolicyId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server
        
        StringBuilder cacheKeyBldr = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
        cacheKeyBldr.append(CACHE_POLICY).append(domainId).append('.').append(policyName);
        String cacheKey = cacheKeyBldr.toString();
        
        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }
        
        int policyId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_POLICY_ID)) {
            ps.setInt(1, domainId);
            ps.setString(2, policyName);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    int getRoleId(Connection con, int domainId, String roleName) {
        
        final String caller = "getRoleId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server
        
        StringBuilder cacheKeyBldr = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
        cacheKeyBldr.append(CACHE_ROLE).append(domainId).append('.').append(roleName);
        String cacheKey = cacheKeyBldr.toString();
        
        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }
        
        int roleId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ROLE_ID)) {
            ps.setInt(1, domainId);
            ps.setString(2, roleName);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    int getServiceId(Connection con, int domainId, String serviceName) {
        
        final String caller = "getServiceId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server
        
        StringBuilder cacheKeyBldr = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
        cacheKeyBldr.append(CACHE_SERVICE).append(domainId).append('.').append(serviceName);
        String cacheKey = cacheKeyBldr.toString();
        
        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }
        
        int serviceId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_SERVICE_ID)) {
            ps.setInt(1, domainId);
            ps.setString(2, serviceName);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    int getPrincipalId(Connection con, String principal) {
        
        final String caller = "getPrincipalId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server
        
        StringBuilder cacheKeyBldr = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
        cacheKeyBldr.append(CACHE_PRINCIPAL).append(principal);
        String cacheKey = cacheKeyBldr.toString();
        
        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }
        
        int principalId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_PRINCIPAL_ID)) {
            ps.setString(1, principal);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    int getHostId(Connection con, String hostName) {
        
        final String caller = "getHostId";

        // first check to see if our cache contains this value
        // otherwise we'll contact the MySQL Server
        
        StringBuilder cacheKeyBldr = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
        cacheKeyBldr.append(CACHE_HOST).append(hostName);
        String cacheKey = cacheKeyBldr.toString();
        
        Integer value = objectMap.get(cacheKey);
        if (value != null) {
            return value;
        }
        
        int hostId = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_HOST_ID)) {
            ps.setString(1, hostName);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    int getLastInsertId(Connection con) {

        int lastInsertId = 0;
        final String caller = "getLastInsertId";

        try (PreparedStatement ps = con.prepareStatement(SQL_LAST_INSERT_ID)) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    @Override
    public Role getRole(String domainName, String roleName) {
        
        final String caller = "getRole";

        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ROLE)) {
            ps.setString(1, domainName);
            ps.setString(2, roleName);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    Role role = new Role().setName(ZMSUtils.roleResourceName(domainName, roleName))
                            .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                            .setTrust(saveValue(rs.getString(ZMSConsts.DB_COLUMN_TRUST)));
                    return role;
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return null;
    }

    String extractObjectName(String domainName, String fullName, String objType) {
        
        // generate prefix to compare with
        
        StringBuilder prefixBuffer = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT)
                .append(domainName).append(objType);
        String prefix = prefixBuffer.toString();
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
        
        int affectedRows = 0;
        final String caller = "insertRole";

        String roleName = extractRoleName(domainName, role.getName());
        if (roleName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " insert role name: " + role.getName());
        }
        
        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ROLE)) {
            ps.setString(1, roleName);
            ps.setInt(2, domainId);
            ps.setString(3, processInsertValue(role.getTrust()));
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateRole(String domainName, Role role) {
        
        int affectedRows = 0;
        final String caller = "updateRole";

        String roleName = extractRoleName(domainName, role.getName());
        if (roleName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " update role name: " + role.getName());
        }
        
        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(con, domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
        }
        
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ROLE)) {
            ps.setString(1, processInsertValue(role.getTrust()));
            ps.setInt(2, roleId);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        
        return (affectedRows > 0);
    }

    @Override
    public boolean updateRoleModTimestamp(String domainName, String roleName) {
        
        int affectedRows = 0;
        final String caller = "updateRoleModTimestamp";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(con, domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
        }
        
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ROLE_MOD_TIMESTAMP)) {
            ps.setInt(1, roleId);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean deleteRole(String domainName, String roleName) {

        final String caller = "deleteRole";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_ROLE)) {
            ps.setInt(1, domainId);
            ps.setString(2, roleName);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public List<String> listRoles(String domainName) {

        final String caller = "listRoles";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        List<String> roles = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ROLE)) {
            ps.setInt(1, domainId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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

    public static Comparator<RoleMember> RoleMemberComparator = new Comparator<RoleMember>() {
        public int compare(RoleMember roleMember1, RoleMember roleMember2) {
            String roleMember1Name = roleMember1.getMemberName().toLowerCase();
            String roleMember2Name = roleMember2.getMemberName().toLowerCase();
            return roleMember1Name.compareTo(roleMember2Name);
        }
    };

    @Override
    public List<RoleMember> listRoleMembers(String domainName, String roleName) {
        
        final String caller = "listRoleMembers";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(con, domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
        }
        List<RoleMember> members = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ROLE_MEMBERS)) {
            ps.setInt(1, roleId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
        Collections.sort(members, RoleMemberComparator);
        return members;
    }

    @Override
    public List<RoleAuditLog> listRoleAuditLogs(String domainName, String roleName) {
        
        final String caller = "listRoleAuditLogs";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(con, domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
        }
        List<RoleAuditLog> logs = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ROLE_AUDIT_LOGS)) {
            ps.setInt(1, roleId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
        domain.append(principal.substring(0, idx));
        name.append(principal.substring(idx + 1));
        return true;
    }
    
    @Override
    public Membership getRoleMember(String domainName, String roleName, String member) {
        
        final String caller = "getRoleMember";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(con, domainId, roleName);
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    int insertPrincipal(Connection con, String principal) {
        
        int affectedRows = 0;
        final String caller = "insertPrincipal";

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_PRINCIPAL)) {
            ps.setString(1, principal);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        
        int principalId = 0;
        if (affectedRows == 1) {
            principalId = getLastInsertId(con);
        }
        return principalId;
    }
    
    int insertHost(Connection con, String hostName) {
        
        int affectedRows = 0;
        final String caller = "insertHost";

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_HOST)) {
            ps.setString(1, hostName);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        
        int hostId = 0;
        if (affectedRows == 1) {
            hostId = getLastInsertId(con);
        }
        return hostId;
    }
    
    @Override
    public boolean insertRoleMember(String domainName, String roleName, RoleMember roleMember,
            String admin, String auditRef) {

        final String caller = "insertRoleMember";

        String principal = roleMember.getMemberName();
        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(con, domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
        }
        if (!validatePrincipalDomain(principal)) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, principal);
        }
        int principalId = getPrincipalId(con, principal);
        if (principalId == 0) {
            principalId = insertPrincipal(con, principal);
            if (principalId == 0) {
                throw internalServerError(caller, "Unable to insert principal: " + principal);
            }
        }
        //need to check if entry already exists
        int affectedRows = 0;
        boolean roleMemberExists = false;
        boolean result = false;
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ROLE_MEMBER_EXISTS)) {
            ps.setInt(1, roleId);
            ps.setInt(2, principalId);
            try (ResultSet rs = ps.executeQuery()) {
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
                affectedRows = ps.executeUpdate();
           } catch (SQLException ex) {
                throw sqlError(ex, caller);
           }
           result = (affectedRows > 0);
           if (result) {
               result = insertRoleAuditLog(con, roleId, admin, principal, "UPDATE", auditRef);
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
                affectedRows = ps.executeUpdate();
            } catch (SQLException ex) {
                throw sqlError(ex, caller);
            }

            result = (affectedRows > 0);
            
            // add audit log entry for this change if the add was successful
            // add return the result of the audit log insert operation
            
            if (result) {
                result = insertRoleAuditLog(con, roleId, admin, principal, "ADD", auditRef);
            }
        }
        return result;
    }
    
    @Override
    public boolean deleteRoleMember(String domainName, String roleName, String principal,
            String admin, String auditRef) {

        final String caller = "deleteRoleMember";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int roleId = getRoleId(con, domainId, roleName);
        if (roleId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_ROLE, ZMSUtils.roleResourceName(domainName, roleName));
        }
        int principalId = getPrincipalId(con, principal);
        if (principalId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_PRINCIPAL, principal);
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_ROLE_MEMBER)) {
            ps.setInt(1, roleId);
            ps.setInt(2, principalId);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        
        boolean result = (affectedRows > 0);
        
        // add audit log entry for this change if the delete was successful
        // add return the result of the audit log insert operation
        
        if (result) {
            result = insertRoleAuditLog(con, roleId, admin, principal, "DELETE", auditRef);
        }
        
        return result;
    }

    boolean insertRoleAuditLog(Connection con, int roleId, String admin, String member,
            String action, String auditRef) {
        
        int affectedRows = 0;
        final String caller = "insertRoleAuditEntry";

        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ROLE_AUDIT_LOG)) {
            ps.setInt(1, roleId);
            ps.setString(2, processInsertValue(admin));
            ps.setString(3, member);
            ps.setString(4, action);
            ps.setString(5, processInsertValue(auditRef));
            affectedRows = ps.executeUpdate();
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    Policy policy = new Policy().setName(ZMSUtils.policyResourceName(domainName, policyName))
                            .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()));
                    return policy;
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return null;
    }

    @Override
    public boolean insertPolicy(String domainName, Policy policy) {
        
        int affectedRows = 0;
        final String caller = "insertPolicy";

        String policyName = extractPolicyName(domainName, policy.getName());
        if (policyName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " insert policy name: " + policy.getName());
        }
        
        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_POLICY)) {
            ps.setString(1, policyName);
            ps.setInt(2, domainId);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean updatePolicy(String domainName, Policy policy) {
        
        int affectedRows = 0;
        final String caller = "updatePolicy";

        String policyName = extractPolicyName(domainName, policy.getName());
        if (policyName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " update policy name: " + policy.getName());
        }
        
        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(con, domainId, policyName);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ZMSUtils.policyResourceName(domainName, policyName));
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_POLICY)) {
            ps.setString(1, policyName);
            ps.setInt(2, policyId);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean updatePolicyModTimestamp(String domainName, String policyName) {
        
        int affectedRows = 0;
        final String caller = "updatePolicyModTimestamp";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(con, domainId, policyName);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ZMSUtils.policyResourceName(domainName, policyName));
        }
        
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_POLICY_MOD_TIMESTAMP)) {
            ps.setInt(1, policyId);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean deletePolicy(String domainName, String policyName) {
        
        final String caller = "deletePolicy";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_POLICY)) {
            ps.setInt(1, domainId);
            ps.setString(2, policyName);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public List<String> listPolicies(String domainName, String assertionRoleName) {

        final String caller = "listPolicies";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        List<String> policies = new ArrayList<>();
        String sqlStatement = null;
        if (assertionRoleName == null) {
            sqlStatement = SQL_LIST_POLICY;
        } else {
            sqlStatement = SQL_LIST_POLICY_REFERENCING_ROLE;
        }
        try (PreparedStatement ps = con.prepareStatement(sqlStatement)) {
            ps.setInt(1, domainId);
            if (assertionRoleName != null) {
                ps.setString(2, assertionRoleName);
            }
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    public boolean insertAssertion(String domainName, String policyName, Assertion assertion) {
        
        final String caller = "insertAssertion";

        String roleName = extractRoleName(domainName, assertion.getRole());
        if (roleName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " assertion role name: " + assertion.getRole());
        }
        
        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(con, domainId, policyName);
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return true;
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        
        // at this point we know we don't have another assertion with the same
        // values so we'll go ahead and add one
        
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ASSERTION)) {
            ps.setInt(1, policyId);
            ps.setString(2, roleName);
            ps.setString(3, assertion.getResource());
            ps.setString(4, assertion.getAction());
            ps.setString(5, processInsertValue(assertion.getEffect()));
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        
        boolean result = (affectedRows > 0);

        if (result) {
            assertion.setId((long) getLastInsertId(con));
        }
        return result;
    }

    @Override
    public boolean deleteAssertion(String domainName, String policyName, Long assertionId) {
        
        final String caller = "deleteAssertion";
        
        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(con, domainId, policyName);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ZMSUtils.policyResourceName(domainName, policyName));
        }
        
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_ASSERTION)) {
            ps.setInt(1, policyId);
            ps.setInt(2, assertionId.intValue());
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public List<Assertion> listAssertions(String domainName, String policyName) {
        
        final String caller = "listAssertions";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int policyId = getPolicyId(con, domainId, policyName);
        if (policyId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_POLICY, ZMSUtils.policyResourceName(domainName, policyName));
        }
        List<Assertion> assertions = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ASSERTION)) {
            ps.setInt(1, policyId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    ServiceIdentity serviceIdentity = new ServiceIdentity()
                            .setName(ZMSUtils.serviceResourceName(domainName, serviceName))
                            .setModified(Timestamp.fromMillis(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime()))
                            .setProviderEndpoint(saveValue(rs.getString(ZMSConsts.DB_COLUMN_PROVIDER_ENDPOINT)))
                            .setExecutable(saveValue(rs.getString(ZMSConsts.DB_COLUMN_EXECTUABLE)))
                            .setUser(saveValue(rs.getString(ZMSConsts.DB_COLUMN_SVC_USER)))
                            .setGroup(saveValue(rs.getString(ZMSConsts.DB_COLUMN_SVC_GROUP)));

                    return serviceIdentity;
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return null;
    }
    
    int processInsertValue(Integer value) {
        return (value == null) ? 0 : value.intValue();
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
        
        int affectedRows = 0;
        final String caller = "insertServiceIdentity";

        String serviceName = extractServiceName(domainName, service.getName());
        if (serviceName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " insert service name: " + service.getName());
        }
        
        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_SERVICE)) {
            ps.setString(1, serviceName);
            ps.setString(2, processInsertValue(service.getProviderEndpoint()));
            ps.setString(3, processInsertValue(service.getExecutable()));
            ps.setString(4, processInsertValue(service.getUser()));
            ps.setString(5, processInsertValue(service.getGroup()));
            ps.setInt(6, domainId);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean updateServiceIdentity(String domainName, ServiceIdentity service) {
        
        int affectedRows = 0;
        final String caller = "updateServiceIdentity";

        String serviceName = extractServiceName(domainName, service.getName());
        if (serviceName == null) {
            throw requestError(caller, "domain name mismatch: " + domainName +
                    " update service name: " + service.getName());
        }
        
        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(con, domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_SERVICE)) {
            ps.setString(1, processInsertValue(service.getProviderEndpoint()));
            ps.setString(2, processInsertValue(service.getExecutable()));
            ps.setString(3, processInsertValue(service.getUser()));
            ps.setString(4, processInsertValue(service.getGroup()));
            ps.setInt(5, serviceId);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deleteServiceIdentity(String domainName, String serviceName) {

        final String caller = "deleteServiceIdentity";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_SERVICE)) {
            ps.setInt(1, domainId);
            ps.setString(2, serviceName);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public List<String> listServiceIdentities(String domainName) {
        
        final String caller = "listServiceIdentities";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        List<String> services = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_SERVICE)) {
            ps.setInt(1, domainId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    public List<PublicKeyEntry> listPublicKeys(String domainName, String serviceName) {
        
        final String caller = "listPublicKeys";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(con, domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
        }
        List<PublicKeyEntry> publicKeys = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_PUBLIC_KEY)) {
            ps.setInt(1, serviceId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    public PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName, String keyId) {
        
        final String caller = "getPublicKeyEntry";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(con, domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_PUBLIC_KEY)) {
            ps.setInt(1, serviceId);
            ps.setString(2, keyId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    PublicKeyEntry publicKey = new PublicKeyEntry().setId(keyId)
                            .setKey(rs.getString(ZMSConsts.DB_COLUMN_KEY_VALUE));
                    return publicKey;
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

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(con, domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_PUBLIC_KEY)) {
            ps.setInt(1, serviceId);
            ps.setString(2, publicKey.getId());
            ps.setString(3, publicKey.getKey());
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updatePublicKeyEntry(String domainName, String serviceName, PublicKeyEntry publicKey) {
        
        final String caller = "updatePublicKeyEntry";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(con, domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_PUBLIC_KEY)) {
            ps.setString(1, publicKey.getKey());
            ps.setInt(2, serviceId);
            ps.setString(3, publicKey.getId());
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deletePublicKeyEntry(String domainName, String serviceName, String keyId) {
        
        final String caller = "deletePublicKeyEntry";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(con, domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_PUBLIC_KEY)) {
            ps.setInt(1, serviceId);
            ps.setString(2, keyId);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public List<String> listServiceHosts(String domainName, String serviceName) {

        final String caller = "listServiceHosts";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(con, domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
        }
        List<String> hosts = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_SERVICE_HOST)) {
            ps.setInt(1, serviceId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(con, domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
        }
        int hostId = getHostId(con, hostName);
        if (hostId == 0) {
            hostId = insertHost(con, hostName);
            if (hostId == 0) {
                throw internalServerError(caller, "Unable to insert host: " + hostName);
            }
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_SERVICE_HOST)) {
            ps.setInt(1, serviceId);
            ps.setInt(2, hostId);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deleteServiceHost(String domainName, String serviceName, String hostName) {
        
        final String caller = "deleteServiceHost";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int serviceId = getServiceId(con, domainId, serviceName);
        if (serviceId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_SERVICE, ZMSUtils.serviceResourceName(domainName, serviceName));
        }
        int hostId = getHostId(con, hostName);
        if (hostId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_HOST, hostName);
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_SERVICE_HOST)) {
            ps.setInt(1, serviceId);
            ps.setInt(2, hostId);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public boolean insertEntity(String domainName, Entity entity) {
        
        final String caller = "insertEntity";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_INSERT_ENTITY)) {
            ps.setInt(1, domainId);
            ps.setString(2, entity.getName());
            ps.setString(3, JSON.string(entity.getValue()));
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean updateEntity(String domainName, Entity entity) {
        
        final String caller = "updateEntity";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_UPDATE_ENTITY)) {
            ps.setString(1, JSON.string(entity.getValue()));
            ps.setInt(2, domainId);
            ps.setString(3, entity.getName());
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }

    @Override
    public boolean deleteEntity(String domainName, String entityName) {
        
        final String caller = "deleteEntity";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        int affectedRows = 0;
        try (PreparedStatement ps = con.prepareStatement(SQL_DELETE_ENTITY)) {
            ps.setInt(1, domainId);
            ps.setString(2, entityName);
            affectedRows = ps.executeUpdate();
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        return (affectedRows > 0);
    }
    
    @Override
    public Entity getEntity(String domainName, String entityName) {
        
        final String caller = "getEntity";

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_ENTITY)) {
            ps.setInt(1, domainId);
            ps.setString(2, entityName);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    Entity entity = new Entity().setName(entityName)
                            .setValue(JSON.fromString(rs.getString(ZMSConsts.DB_COLUMN_VALUE), Struct.class));
                    return entity;
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

        int domainId = getDomainId(con, domainName);
        if (domainId == 0) {
            throw notFoundError(caller, ZMSConsts.OBJECT_DOMAIN, domainName);
        }
        List<String> entities = new ArrayList<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_ENTITY)) {
            ps.setInt(1, domainId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    void getAthenzDomainRoles(String domainName, int domainId, AthenzDomain athenzDomain, String caller) {
        
        Map<String, Role> roleMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_ROLES)) {
            ps.setInt(1, domainId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    void getAthenzDomainPolicies(String domainName, int domainId, AthenzDomain athenzDomain, String caller) {
        
        Map<String, Policy> policyMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_POLICIES)) {
            ps.setInt(1, domainId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
    
    void getAthenzDomainServices(String domainName, int domainId, AthenzDomain athenzDomain, String caller) {

        Map<String, ServiceIdentity> serviceMap = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_GET_DOMAIN_SERVICES)) {
            ps.setInt(1, domainId);
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
        
        getAthenzDomainRoles(domainName, domainId, athenzDomain, caller);
        getAthenzDomainPolicies(domainName, domainId, athenzDomain, caller);
        getAthenzDomainServices(domainName, domainId, athenzDomain, caller);
        
        return athenzDomain;
    }
    
    @Override
    public DomainModifiedList listModifiedDomains(long modifiedSince) {
        
        final String caller = "listModifiedDomains";

        DomainModifiedList domainModifiedList = new DomainModifiedList();
        List<DomainModified> nameMods = new ArrayList<DomainModified>();

        try (PreparedStatement ps = prepareScanStatement(con, null, modifiedSince)) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    DomainModified dm = new DomainModified()
                            .setName(rs.getString(ZMSConsts.DB_COLUMN_NAME))
                            .setModified(rs.getTimestamp(ZMSConsts.DB_COLUMN_MODIFIED).getTime());
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
        int idx = principal.lastIndexOf('.');
        if (idx == -1 || idx == 0 || idx == principal.length() - 1) {
            return false;
        }
        if (getDomainId(con, principal.substring(0, idx)) == 0) {
            return false;
        }
        return true;
    }
    
    String roleIndex(String domainId, String roleName) {
        StringBuilder index = new StringBuilder(512);
        index.append(domainId).append(':').append(roleName);
        return index.toString();
    }
    
    PreparedStatement prepareRoleAssertionsStatement(Connection con, String action)
            throws SQLException {
        
        PreparedStatement ps = null;
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
        try (PreparedStatement ps = prepareRoleAssertionsStatement(con, action)) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
                    List<Assertion> assertions = roleAssertions.get(index);
                    if (assertions == null) {
                        assertions = new ArrayList<>();
                        roleAssertions.put(index, assertions);
                    }
                    
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
    
    PreparedStatement prepareRolePrincipalsStatement(Connection con, String principal, boolean awsQuery)
            throws SQLException {
        
        PreparedStatement ps = null;
        if (principal != null && principal.length() > 0) {
            ps = con.prepareStatement(SQL_LIST_ROLE_PRINCIPALS + SQL_LIST_ROLE_PRINCIPALS_QUERY);
            ps.setString(1, principal);
        } else if (awsQuery) {
            ps = con.prepareStatement(SQL_LIST_ROLE_PRINCIPALS + SQL_LIST_ROLE_PRINCIPALS_YBY_ONLY);
        } else {
            ps = con.prepareStatement(SQL_LIST_ROLE_PRINCIPALS);
        }
        return ps;
    }
    
    Map<String, List<String>> getRolePrincipals(String principal, boolean awsQuery, String caller) {

        Map<String, List<String>> rolePrincipals = new HashMap<>();
        try (PreparedStatement ps = prepareRolePrincipalsStatement(con, principal, awsQuery)) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String principalName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    String roleName = rs.getString(ZMSConsts.DB_COLUMN_ROLE_NAME);

                    String index = roleIndex(rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID), roleName);
                    List<String> principals = rolePrincipals.get(index);
                    if (principals == null) {
                        principals = new ArrayList<>();
                        rolePrincipals.put(index, principals);
                    }
                    
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
    
    Map<String, List<String>> getTrustedRoles(String caller) {
        
        Map<String, List<String>> trustedRoles = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_TRUSTED_ROLES)) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String trustDomainId = rs.getString(ZMSConsts.DB_COLUMN_DOMAIN_ID);
                    String trustRoleName = rs.getString(ZMSConsts.DB_COLUMN_NAME);
                    String assertDomainId = rs.getString(ZMSConsts.DB_COLUMN_ASSERT_DOMAIN_ID);
                    String assertRoleName = rs.getString(ZMSConsts.DB_COLUMN_ROLE);

                    String index = roleIndex(assertDomainId, assertRoleName);
                    List<String> roles = trustedRoles.get(index);
                    if (roles == null) {
                        roles = new ArrayList<>();
                        trustedRoles.put(index, roles);
                    }
                    
                    String tRoleName = roleIndex(trustDomainId, trustRoleName);
                    
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(caller + ": adding trusted role " + tRoleName + " for " + index);
                    }
                    
                    roles.add(tRoleName);
                }
            }
        } catch (SQLException ex) {
            throw sqlError(ex, caller);
        }
        
        return trustedRoles;
    }
    
    Map<String, String> getAwsDomains(String caller) {
        
        Map<String, String> awsDomains = new HashMap<>();
        try (PreparedStatement ps = con.prepareStatement(SQL_LIST_DOMAIN_AWS)) {
            
            if (LOG.isDebugEnabled()) {
                LOG.debug(caller + ": " + ps.toString());
            }
            
            try (ResultSet rs = ps.executeQuery()) {
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
        // going to keep yby users - everyone else is skipped
        
        // make sure the principal starts with yby prefix
        
        String userDomainPrefix = userDomain + ".";
        if (!rolePincipal.startsWith(userDomainPrefix)) {
            return true;
        }
        
        // make sure this is not a service within the user's
        // personal domain
        
        if (rolePincipal.substring(userDomainPrefix.length()).indexOf('.') != -1) {
            return true;
        }
        
        return false;
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
        // resource in the expected aws role format
        
        for (Assertion assertion : roleAssertions) {
            
            String resource = assertion.getResource();
            int idx = resource.indexOf(':');
            if (idx == -1) {
                principalAssertions.add(assertion);
                continue;
            }
            
            String awsDomain = awsDomains.get(resource.substring(0, idx));
            if (awsDomain == null) {
                principalAssertions.add(assertion);
                continue;
            }

            StringBuilder awsRole = new StringBuilder(512);
            awsRole.append("arn:aws:iam::").append(awsDomain).append(":role/").append(resource.substring(idx + 1));
            assertion.setResource(awsRole.toString());
            principalAssertions.add(assertion);
        }
    }
    
    ResourceAccess getResourceAccessObject(String principal, List<Assertion> assertions) {
        ResourceAccess rsrcAccess = new ResourceAccess();
        rsrcAccess.setPrincipal(principal);
        rsrcAccess.setAssertions(assertions != null ? assertions : new ArrayList<Assertion>());
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
        
        Map<String, List<String>> rolePrincipals = getRolePrincipals(principal, awsQuery, caller);
        if (rolePrincipals.isEmpty()) {
            if (singlePrincipalQuery) {
                
                // so the given principal is not available as a role member
                // so before returning an empty response let's make sure
                // that it has been registered in Athenz otherwise we'll
                // just return 404 - not found exception
                
                if (getPrincipalId(con, principal) == 0) {
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
        // look for yby users only
        
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
                
                List<Assertion> assertions = principalAssertions.get(rPrincipal);
                if (assertions == null) {
                    assertions = new ArrayList<>();
                    principalAssertions.put(rPrincipal, assertions);
                }
                
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
        String msg = null;
        if ("08S01".equals(sqlState) || "40001".equals(sqlState)) {
            code = ResourceException.CONFLICT;
            msg = "Concurrent update conflict, please retry your operation later.";
        } else if (ex.getErrorCode() == MYSQL_ER_OPTION_PREVENTS_STATEMENT) {
            code = ResourceException.GONE;
            msg = "MySQL Database running in read-only mode";
        } else if (ex.getErrorCode() == MYSQL_ER_OPTION_DUPLICATE_ENTRY) {
            code = ResourceException.BAD_REQUEST;
            msg = "Entry already exists";
        } else {
            msg = ex.getMessage() + ", state: " + sqlState + ", code: " + ex.getErrorCode();
        }
        rollbackChanges();
        return ZMSUtils.error(code, msg, caller);
    }
}
