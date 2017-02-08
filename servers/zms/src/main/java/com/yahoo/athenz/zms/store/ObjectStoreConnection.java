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
package com.yahoo.athenz.zms.store;

import java.io.Closeable;
import java.util.List;

import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.Domain;
import com.yahoo.athenz.zms.DomainModifiedList;
import com.yahoo.athenz.zms.Entity;
import com.yahoo.athenz.zms.Membership;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.athenz.zms.ResourceAccessList;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleAuditLog;
import com.yahoo.athenz.zms.RoleMember;
import com.yahoo.athenz.zms.ServiceIdentity;

public interface ObjectStoreConnection extends Closeable {
    
    // Transaction commands
    
    void commitChanges();
    void rollbackChanges();
    void close();

    // Domain commands
    
    Domain getDomain(String domainName);
    boolean insertDomain(Domain domain);
    boolean updateDomain(Domain domain);
    boolean deleteDomain(String domainName);
    long getDomainModTimestamp(String domainName);
    boolean updateDomainModTimestamp(String domainName);
    List<String> listDomains(String prefix, long modifiedSince);
    String lookupDomainById(String account, int productId);
    List<String> lookupDomainByRole(String roleMember, String roleName);
    
    AthenzDomain getAthenzDomain(String domainName);
    DomainModifiedList listModifiedDomains(long modifiedSince);

    // Template commands
    
    boolean insertDomainTemplate(String domainName, String templateName, String params);
    boolean deleteDomainTemplate(String domainName, String templateName, String params);
    List<String> listDomainTemplates(String domainName);

    // Role commands
    
    Role getRole(String domainName, String roleName);
    boolean insertRole(String domainName, Role role);
    boolean updateRole(String domainName, Role role);
    boolean deleteRole(String domainName, String roleName);
    boolean updateRoleModTimestamp(String domainName, String roleName);
    List<String> listRoles(String domainName);
    List<RoleAuditLog> listRoleAuditLogs(String domainName, String roleName);
    
    List<RoleMember> listRoleMembers(String domainName, String roleName);
    Membership getRoleMember(String domainName, String roleName, String member);
    boolean insertRoleMember(String domainName, String roleName, RoleMember roleMember, String principal, String auditRef);
    boolean deleteRoleMember(String domainName, String roleName, String member, String principal, String auditRef);

    // Policy commands
    
    Policy getPolicy(String domainName, String policyName);
    boolean insertPolicy(String domainName, Policy policy);
    boolean updatePolicy(String domainName, Policy policy);
    boolean deletePolicy(String domainName, String policyName);
    List<String> listPolicies(String domainName, String assertionRoleName);
    boolean updatePolicyModTimestamp(String domainName, String policyName);

    Assertion getAssertion(String domainName, String policyName, Long assertionId);
    boolean insertAssertion(String domainName, String policyName, Assertion assertion);
    boolean deleteAssertion(String domainName, String policyName, Long assertionId);
    List<Assertion> listAssertions(String domainName, String policyName);
    ResourceAccessList listResourceAccess(String principal, String action, String userDomain);

    // Service commands

    ServiceIdentity getServiceIdentity(String domainName, String serviceName);
    boolean insertServiceIdentity(String domainName, ServiceIdentity service);
    boolean updateServiceIdentity(String domainName, ServiceIdentity service);
    boolean deleteServiceIdentity(String domainName, String serviceName);
    List<String> listServiceIdentities(String domainName);

    PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName, String keyId);
    boolean insertPublicKeyEntry(String domainName, String serviceName, PublicKeyEntry publicKey);
    boolean updatePublicKeyEntry(String domainName, String serviceName, PublicKeyEntry publicKey);
    boolean deletePublicKeyEntry(String domainName, String serviceName, String keyId);
    List<PublicKeyEntry> listPublicKeys(String domainName, String serviceName);

    List<String> listServiceHosts(String domainName, String serviceName);
    boolean insertServiceHost(String domainName, String serviceName, String hostName);
    boolean deleteServiceHost(String domainName, String serviceName, String hostName);
    
    // Entity commands

    Entity getEntity(String domainName, String entityName);
    boolean insertEntity(String domainName, Entity entity);
    boolean updateEntity(String domainName, Entity entity);
    boolean deleteEntity(String domainName, String entityName);
    List<String> listEntities(String domainName);
}
