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
package com.yahoo.athenz.zms.store;

import java.io.Closeable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.yahoo.athenz.zms.*;

public interface ObjectStoreConnection extends Closeable {

    // Transaction commands

    void commitChanges();
    void rollbackChanges();
    void close();
    void setOperationTimeout(int opTimout);
    void setTagLimit(int domainLimit, int roleLimit);

    // Domain commands

    Domain getDomain(String domainName);
    boolean insertDomain(Domain domain);
    boolean updateDomain(Domain domain);
    boolean deleteDomain(String domainName);
    long getDomainModTimestamp(String domainName);
    boolean updateDomainModTimestamp(String domainName);
    List<String> listDomains(String prefix, long modifiedSince);
    String lookupDomainById(String account, String subscription, int productId);
    List<String> lookupDomainByRole(String roleMember, String roleName);
    List<String> lookupDomainByBusinessService(String businessService);

    AthenzDomain getAthenzDomain(String domainName);
    DomainMetaList listModifiedDomains(long modifiedSince);

    // Domain tags
    Map<String, TagValueList> getDomainTags(String domainName);
    boolean insertDomainTags(String domainName, Map<String, TagValueList> tags);
    boolean deleteDomainTags(String domainName, Set<String> tagsToRemove);
    List<String> lookupDomainByTags(String tagKey, String tagValue);

    // Principal commands

    boolean deletePrincipal(String principalName, boolean subDomains);
    List<String> listPrincipals(String domainName);

    // Template commands

    boolean insertDomainTemplate(String domainName, String templateName, String params);
    boolean deleteDomainTemplate(String domainName, String templateName, String params);
    List<String> listDomainTemplates(String domainName);
    Map<String, List<String>> getDomainFromTemplateName(Map<String, Integer> templateDetails);

    // Role commands

    Role getRole(String domainName, String roleName);
    boolean insertRole(String domainName, Role role);
    boolean updateRole(String domainName, Role role);
    boolean deleteRole(String domainName, String roleName);
    boolean updateRoleModTimestamp(String domainName, String roleName);
    List<String> listRoles(String domainName);
    int countRoles(String domainName);
    List<RoleAuditLog> listRoleAuditLogs(String domainName, String roleName);
    boolean updateRoleReviewTimestamp(String domainName, String roleName);

    List<RoleMember> listRoleMembers(String domainName, String roleName, Boolean pending);
    int countRoleMembers(String domainName, String roleName);
    Membership getRoleMember(String domainName, String roleName, String member, long expiration, boolean pending);
    boolean insertRoleMember(String domainName, String roleName, RoleMember roleMember, String principal, String auditRef);
    boolean deleteRoleMember(String domainName, String roleName, String member, String principal, String auditRef);
    boolean updateRoleMemberDisabledState(String domainName, String roleName, String member, String principal, int disabledState, String auditRef);
    boolean deletePendingRoleMember(String domainName, String roleName, String member, String principal, String auditRef);
    boolean confirmRoleMember(String domainName, String roleName, RoleMember roleMember, String principal, String auditRef);

    DomainRoleMembers listDomainRoleMembers(String domainName);
    DomainRoleMember getPrincipalRoles(String principal, String domainName);
    List<PrincipalRole> listRolesWithUserAuthorityRestrictions();

    // Group commands

    Group getGroup(String domainName, String groupName);
    boolean insertGroup(String domainName, Group group);
    boolean updateGroup(String domainName, Group group);
    boolean deleteGroup(String domainName, String groupName);
    boolean updateGroupModTimestamp(String domainName, String groupName);
    int countGroups(String domainName);
    List<GroupAuditLog> listGroupAuditLogs(String domainName, String groupName);
    boolean updateGroupReviewTimestamp(String domainName, String groupName);

    List<GroupMember> listGroupMembers(String domainName, String groupName, Boolean pending);
    int countGroupMembers(String domainName, String groupName);
    GroupMembership getGroupMember(String domainName, String groupName, String member, long expiration, boolean pending);
    boolean insertGroupMember(String domainName, String groupName, GroupMember groupMember, String principal, String auditRef);
    boolean deleteGroupMember(String domainName, String groupName, String member, String principal, String auditRef);
    boolean updateGroupMemberDisabledState(String domainName, String groupName, String member, String principal, int disabledState, String auditRef);
    boolean deletePendingGroupMember(String domainName, String groupName, String member, String principal, String auditRef);
    boolean confirmGroupMember(String domainName, String groupName, GroupMember groupMember, String principal, String auditRef);

    DomainGroupMember getPrincipalGroups(String principal, String domainName);
    List<PrincipalGroup> listGroupsWithUserAuthorityRestrictions();

    // Policy commands

    Policy getPolicy(String domainName, String policyName, String version);
    boolean insertPolicy(String domainName, Policy policy);
    boolean updatePolicy(String domainName, Policy policy);
    boolean deletePolicy(String domainName, String policyName);
    boolean deletePolicyVersion(String domainName, String policyName, String version);
    List<String> listPolicies(String domainName, String assertionRoleName);
    List<String> listPolicyVersions(String domainName, String policyName);
    int countPolicies(String domainName);
    boolean updatePolicyModTimestamp(String domainName, String policyName, String version);
    boolean setActivePolicyVersion(String domainName, String policyName, String version);

    Assertion getAssertion(String domainName, String policyName, Long assertionId);
    boolean insertAssertion(String domainName, String policyName, String version, Assertion assertion);
    boolean deleteAssertion(String domainName, String policyName, String version, Long assertionId);
    List<Assertion> listAssertions(String domainName, String policyName, String version);
    int countAssertions(String domainName, String policyName, String version);
    ResourceAccessList listResourceAccess(String principal, String action, String userDomain);

    // Service commands

    ServiceIdentity getServiceIdentity(String domainName, String serviceName);
    boolean insertServiceIdentity(String domainName, ServiceIdentity service);
    boolean updateServiceIdentity(String domainName, ServiceIdentity service);
    boolean deleteServiceIdentity(String domainName, String serviceName);
    List<String> listServiceIdentities(String domainName);
    int countServiceIdentities(String domainName);
    boolean updateServiceIdentityModTimestamp(String domainName, String serviceName);

    PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName, String keyId, boolean domainStateCheck);
    boolean insertPublicKeyEntry(String domainName, String serviceName, PublicKeyEntry publicKey);
    boolean updatePublicKeyEntry(String domainName, String serviceName, PublicKeyEntry publicKey);
    boolean deletePublicKeyEntry(String domainName, String serviceName, String keyId);
    List<PublicKeyEntry> listPublicKeys(String domainName, String serviceName);
    int countPublicKeys(String domainName, String serviceName);

    List<String> listServiceHosts(String domainName, String serviceName);
    boolean insertServiceHost(String domainName, String serviceName, String hostName);
    boolean deleteServiceHost(String domainName, String serviceName, String hostName);

    // Entity commands

    Entity getEntity(String domainName, String entityName);
    boolean insertEntity(String domainName, Entity entity);
    boolean updateEntity(String domainName, Entity entity);
    boolean deleteEntity(String domainName, String entityName);
    List<String> listEntities(String domainName);
    int countEntities(String domainName);

    // Quota commands

    Quota getQuota(String domainName);
    boolean insertQuota(String domainName, Quota quota);
    boolean updateQuota(String domainName, Quota quota);
    boolean deleteQuota(String domainName);

    Map<String, List<DomainRoleMember>> getPendingDomainRoleMembers(String principal);
    Map<String, List<DomainRoleMember>> getExpiredPendingDomainRoleMembers(int pendingRoleMemberLifespan);
    Set<String> getPendingMembershipApproverRoles(String server, long timestamp);
    boolean updatePendingRoleMembersNotificationTimestamp(String server, long timestamp, int delayDays);

    Map<String, DomainRoleMember> getNotifyTemporaryRoleMembers(String server, long timestamp);
    boolean updateRoleMemberExpirationNotificationTimestamp(String server, long timestamp, int delayDays, boolean metricsOnly);

    Map<String, DomainRoleMember> getNotifyReviewRoleMembers(String server, long timestamp);
    boolean updateRoleMemberReviewNotificationTimestamp(String server, long timestamp, int delayDays);

    DomainRoleMembers listOverdueReviewRoleMembers(String domainName);

    Map<String, List<DomainGroupMember>> getPendingDomainGroupMembers(String principal);
    Map<String, List<DomainGroupMember>> getExpiredPendingDomainGroupMembers(int pendingGroupMemberLifespan);
    Set<String> getPendingGroupMembershipApproverRoles(String server, long timestamp);
    boolean updatePendingGroupMembersNotificationTimestamp(String server, long timestamp, int delayDays);

    Map<String, DomainGroupMember> getNotifyTemporaryGroupMembers(String server, long timestamp);
    boolean updateGroupMemberExpirationNotificationTimestamp(String server, long timestamp, int delayDays);

    List<TemplateMetaData> getDomainTemplates(String domainName);
    boolean updateDomainTemplate(String domainName, String templateName, TemplateMetaData templateMetaData);

    boolean updatePrincipal(String principal, int newState);
    List<String> getPrincipals(int queriedState);

    boolean insertRoleTags(String roleName, String domainName, Map<String, TagValueList> roleTags);
    boolean deleteRoleTags(String roleName, String domainName, Set<String> tagKeys);
    Map<String, TagValueList> getRoleTags(String domainName, String roleName);

    int countAssertionConditions(long assertionId);
    int getNextConditionId(long assertionId, String caller);
    List<AssertionCondition> getAssertionConditions(long assertionId);
    AssertionCondition getAssertionCondition(long assertionId, int conditionId);
    boolean insertAssertionConditions(long assertionId, AssertionConditions assertionConditions);
    boolean deleteAssertionConditions(long assertionId);
    boolean insertAssertionCondition(long assertionId, AssertionCondition assertionCondition);
    boolean deleteAssertionCondition(long assertionId, int conditionId);
}
