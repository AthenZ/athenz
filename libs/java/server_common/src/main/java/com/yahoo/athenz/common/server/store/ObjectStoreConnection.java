/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License") throws ServerResourceException;
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
package com.yahoo.athenz.common.server.store;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.Timestamp;

import java.io.Closeable;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface ObjectStoreConnection extends Closeable {

    String PROVIDER_AWS   = "aws";
    String PROVIDER_AZURE = "azure";
    String PROVIDER_GCP   = "gcp";

    // Transaction commands

    void commitChanges() throws ServerResourceException;
    void rollbackChanges() throws ServerResourceException;
    void close();
    void setOperationTimeout(int opTimout);
    void setTagLimit(int domainLimit, int roleLimit, int groupLimit, int policyLimit, int serviceLimit);

    // Domain commands

    Domain getDomain(String domainName) throws ServerResourceException;
    boolean insertDomain(Domain domain) throws ServerResourceException;
    boolean updateDomain(Domain domain) throws ServerResourceException;
    boolean deleteDomain(String domainName) throws ServerResourceException;
    long getDomainModTimestamp(String domainName) throws ServerResourceException;
    boolean updateDomainModTimestamp(String domainName) throws ServerResourceException;
    List<String> listDomains(String prefix, long modifiedSince) throws ServerResourceException;
    String lookupDomainByProductId(int productId) throws ServerResourceException;
    String lookupDomainByProductId(String productId) throws ServerResourceException;
    String lookupDomainByCloudProvider(String provider, String value) throws ServerResourceException;
    Map<String, String> listDomainsByCloudProvider(String provider) throws ServerResourceException;
    List<String> lookupDomainByRole(String roleMember, String roleName) throws ServerResourceException;
    List<String> lookupDomainByBusinessService(String businessService) throws ServerResourceException;
    AthenzDomain getAthenzDomain(String domainName) throws ServerResourceException;
    DomainMetaList listModifiedDomains(long modifiedSince) throws ServerResourceException;
    void setDomainOptions(DomainOptions domainOptions) throws ServerResourceException;

    // Domain tags

    boolean insertDomainTags(String domainName, Map<String, TagValueList> tags) throws ServerResourceException;
    boolean deleteDomainTags(String domainName, Set<String> tagsToRemove) throws ServerResourceException;
    List<String> lookupDomainByTags(String tagKey, String tagValue) throws ServerResourceException;

    // Principal commands

    boolean deletePrincipal(String principalName, boolean subDomains) throws ServerResourceException;
    List<String> listPrincipals(String domainName) throws ServerResourceException;
    boolean updatePrincipal(String principal, int newState) throws ServerResourceException;
    List<PrincipalMember> getPrincipals(int queriedState) throws ServerResourceException;
    PrincipalMember getPrincipal(String principalName) throws ServerResourceException;

    // Template commands

    boolean insertDomainTemplate(String domainName, String templateName, String params) throws ServerResourceException;
    boolean deleteDomainTemplate(String domainName, String templateName, String params) throws ServerResourceException;
    List<String> listDomainTemplates(String domainName) throws ServerResourceException;
    Map<String, List<String>> getDomainFromTemplateName(Map<String, Integer> templateDetails) throws ServerResourceException;

    // Role commands

    Role getRole(String domainName, String roleName) throws ServerResourceException;
    boolean insertRole(String domainName, Role role) throws ServerResourceException;
    boolean updateRole(String domainName, Role role) throws ServerResourceException;
    boolean deleteRole(String domainName, String roleName) throws ServerResourceException;
    boolean updateRoleModTimestamp(String domainName, String roleName) throws ServerResourceException;
    List<String> listRoles(String domainName) throws ServerResourceException;
    List<String> listTrustedRolesWithWildcards(String domainName, String roleName, String trustDomainName) throws ServerResourceException;

    int countRoles(String domainName) throws ServerResourceException;
    List<RoleAuditLog> listRoleAuditLogs(String domainName, String roleName) throws ServerResourceException;
    boolean updateRoleReviewTimestamp(String domainName, String roleName) throws ServerResourceException;

    List<RoleMember> listRoleMembers(String domainName, String roleName, Boolean pending) throws ServerResourceException;
    int countRoleMembers(String domainName, String roleName) throws ServerResourceException;
    Membership getRoleMember(String domainName, String roleName, String member, long expiration, boolean pending) throws ServerResourceException;
    boolean insertRoleMember(String domainName, String roleName, RoleMember roleMember, String principal, String auditRef) throws ServerResourceException;
    boolean deleteRoleMember(String domainName, String roleName, String member, String principal, String auditRef) throws ServerResourceException;
    boolean deleteExpiredRoleMember(String domainName, String roleName, String member, String principal, Timestamp expiration, String auditRef) throws ServerResourceException;
    boolean updateRoleMemberDisabledState(String domainName, String roleName, String member, String principal, int disabledState, String auditRef) throws ServerResourceException;
    boolean deletePendingRoleMember(String domainName, String roleName, String member, String principal, String auditRef) throws ServerResourceException;
    boolean confirmRoleMember(String domainName, String roleName, RoleMember roleMember, String principal, String auditRef) throws ServerResourceException;
    RoleMember getPendingRoleMember(String domainName, String roleName, String memberName) throws ServerResourceException;

    DomainRoleMembers listDomainRoleMembers(String domainName) throws ServerResourceException;
    DomainRoleMember getPrincipalRoles(String principal, String domainName) throws ServerResourceException;
    List<PrincipalRole> listRolesWithUserAuthorityRestrictions() throws ServerResourceException;

    // Group commands

    Group getGroup(String domainName, String groupName) throws ServerResourceException;
    boolean insertGroup(String domainName, Group group) throws ServerResourceException;
    boolean updateGroup(String domainName, Group group) throws ServerResourceException;
    boolean deleteGroup(String domainName, String groupName) throws ServerResourceException;
    boolean updateGroupModTimestamp(String domainName, String groupName) throws ServerResourceException;
    List<String> listGroups(String domainName) throws ServerResourceException;
    int countGroups(String domainName) throws ServerResourceException;
    List<GroupAuditLog> listGroupAuditLogs(String domainName, String groupName) throws ServerResourceException;
    boolean updateGroupReviewTimestamp(String domainName, String groupName) throws ServerResourceException;

    List<GroupMember> listGroupMembers(String domainName, String groupName, Boolean pending) throws ServerResourceException;
    int countGroupMembers(String domainName, String groupName) throws ServerResourceException;
    GroupMembership getGroupMember(String domainName, String groupName, String member, long expiration, boolean pending) throws ServerResourceException;
    boolean insertGroupMember(String domainName, String groupName, GroupMember groupMember, String principal, String auditRef) throws ServerResourceException;
    boolean deleteGroupMember(String domainName, String groupName, String member, String principal, String auditRef) throws ServerResourceException;
    boolean deleteExpiredGroupMember(String domainName, String groupName, String member, String principal, Timestamp expiration, String auditRef) throws ServerResourceException;

    boolean updateGroupMemberDisabledState(String domainName, String groupName, String member, String principal, int disabledState, String auditRef) throws ServerResourceException;
    boolean deletePendingGroupMember(String domainName, String groupName, String member, String principal, String auditRef) throws ServerResourceException;
    boolean confirmGroupMember(String domainName, String groupName, GroupMember groupMember, String principal, String auditRef) throws ServerResourceException;

    DomainGroupMembers listDomainGroupMembers(String domainName) throws ServerResourceException;
    DomainGroupMember getPrincipalGroups(String principal, String domainName) throws ServerResourceException;
    List<PrincipalGroup> listGroupsWithUserAuthorityRestrictions() throws ServerResourceException;
    GroupMember getPendingGroupMember(String domainName, String groupName, String memberName) throws ServerResourceException;

    // Policy commands

    Policy getPolicy(String domainName, String policyName, String version) throws ServerResourceException;
    boolean insertPolicy(String domainName, Policy policy) throws ServerResourceException;
    boolean updatePolicy(String domainName, Policy policy) throws ServerResourceException;
    boolean deletePolicy(String domainName, String policyName) throws ServerResourceException;
    boolean deletePolicyVersion(String domainName, String policyName, String version) throws ServerResourceException;
    List<String> listPolicies(String domainName, String assertionRoleName) throws ServerResourceException;
    List<String> listPolicyVersions(String domainName, String policyName) throws ServerResourceException;
    int countPolicies(String domainName) throws ServerResourceException;
    boolean updatePolicyModTimestamp(String domainName, String policyName, String version) throws ServerResourceException;
    boolean setActivePolicyVersion(String domainName, String policyName, String version) throws ServerResourceException;

    Assertion getAssertion(String domainName, String policyName, Long assertionId) throws ServerResourceException;
    boolean insertAssertion(String domainName, String policyName, String version, Assertion assertion) throws ServerResourceException;
    boolean deleteAssertion(String domainName, String policyName, String version, Long assertionId) throws ServerResourceException;
    List<Assertion> listAssertions(String domainName, String policyName, String version) throws ServerResourceException;
    int countAssertions(String domainName, String policyName, String version) throws ServerResourceException;
    ResourceAccessList listResourceAccess(String principal, String action, String userDomain) throws ServerResourceException;

    // Service commands

    ServiceIdentity getServiceIdentity(String domainName, String serviceName) throws ServerResourceException;
    boolean insertServiceIdentity(String domainName, ServiceIdentity service) throws ServerResourceException;
    boolean updateServiceIdentity(String domainName, ServiceIdentity service) throws ServerResourceException;
    boolean deleteServiceIdentity(String domainName, String serviceName) throws ServerResourceException;
    List<String> listServiceIdentities(String domainName) throws ServerResourceException;
    int countServiceIdentities(String domainName) throws ServerResourceException;
    boolean updateServiceIdentityModTimestamp(String domainName, String serviceName) throws ServerResourceException;

    PublicKeyEntry getPublicKeyEntry(String domainName, String serviceName, String keyId, boolean domainStateCheck) throws ServerResourceException;
    boolean insertPublicKeyEntry(String domainName, String serviceName, PublicKeyEntry publicKey) throws ServerResourceException;
    boolean updatePublicKeyEntry(String domainName, String serviceName, PublicKeyEntry publicKey) throws ServerResourceException;
    boolean deletePublicKeyEntry(String domainName, String serviceName, String keyId) throws ServerResourceException;
    List<PublicKeyEntry> listPublicKeys(String domainName, String serviceName) throws ServerResourceException;
    int countPublicKeys(String domainName, String serviceName) throws ServerResourceException;

    List<String> listServiceHosts(String domainName, String serviceName) throws ServerResourceException;
    boolean insertServiceHost(String domainName, String serviceName, String hostName) throws ServerResourceException;
    boolean deleteServiceHost(String domainName, String serviceName, String hostName) throws ServerResourceException;

    ServiceIdentities searchServiceIdentities(String serviceName, Boolean substringMatch, String domainFilter, int limit) throws ServerResourceException;

    // Entity commands

    Entity getEntity(String domainName, String entityName) throws ServerResourceException;
    boolean insertEntity(String domainName, Entity entity) throws ServerResourceException;
    boolean updateEntity(String domainName, Entity entity) throws ServerResourceException;
    boolean deleteEntity(String domainName, String entityName) throws ServerResourceException;
    List<String> listEntities(String domainName) throws ServerResourceException;
    int countEntities(String domainName) throws ServerResourceException;

    // Quota commands

    Quota getQuota(String domainName) throws ServerResourceException;
    boolean insertQuota(String domainName, Quota quota) throws ServerResourceException;
    boolean updateQuota(String domainName, Quota quota) throws ServerResourceException;
    boolean deleteQuota(String domainName) throws ServerResourceException;

    // Stats command

    Stats getStats(String domainName) throws ServerResourceException;

    // Review commands

    ReviewObjects getRolesForReview(String principal) throws ServerResourceException;
    ReviewObjects getGroupsForReview(String principal) throws ServerResourceException;

    Map<String, List<DomainRoleMember>> getPendingDomainRoleMembersByPrincipal(String principal) throws ServerResourceException;
    Map<String, List<DomainRoleMember>> getPendingDomainRoleMembersByDomain(String domainName) throws ServerResourceException;
    Map<String, List<DomainRoleMember>> getExpiredPendingDomainRoleMembers(int pendingRoleMemberLifespan) throws ServerResourceException;
    Set<String> getPendingMembershipApproverRoles(String server, long timestamp) throws ServerResourceException;
    boolean updatePendingRoleMembersNotificationTimestamp(String server, long timestamp, int delayDays) throws ServerResourceException;

    Map<String, DomainRoleMember> getNotifyTemporaryRoleMembers(String server, long timestamp) throws ServerResourceException;
    boolean updateRoleMemberExpirationNotificationTimestamp(String server, long timestamp, int delayDays) throws ServerResourceException;

    Map<String, DomainRoleMember> getNotifyReviewRoleMembers(String server, long timestamp) throws ServerResourceException;
    boolean updateRoleMemberReviewNotificationTimestamp(String server, long timestamp, int delayDays) throws ServerResourceException;

    DomainRoleMembers listOverdueReviewRoleMembers(String domainName) throws ServerResourceException;

    Map<String, List<DomainGroupMember>> getPendingDomainGroupMembersByPrincipal(String principal) throws ServerResourceException;
    Map<String, List<DomainGroupMember>> getPendingDomainGroupMembersByDomain(String domainName) throws ServerResourceException;
    Map<String, List<DomainGroupMember>> getExpiredPendingDomainGroupMembers(int pendingGroupMemberLifespan) throws ServerResourceException;
    Set<String> getPendingGroupMembershipApproverRoles(String server, long timestamp) throws ServerResourceException;
    boolean updatePendingGroupMembersNotificationTimestamp(String server, long timestamp, int delayDays) throws ServerResourceException;

    Map<String, DomainGroupMember> getNotifyTemporaryGroupMembers(String server, long timestamp) throws ServerResourceException;
    boolean updateGroupMemberExpirationNotificationTimestamp(String server, long timestamp, int delayDays) throws ServerResourceException;

    List<TemplateMetaData> getDomainTemplates(String domainName) throws ServerResourceException;
    boolean updateDomainTemplate(String domainName, String templateName, TemplateMetaData templateMetaData) throws ServerResourceException;

    boolean insertRoleTags(String roleName, String domainName, Map<String, TagValueList> roleTags) throws ServerResourceException;
    boolean deleteRoleTags(String roleName, String domainName, Set<String> tagKeys) throws ServerResourceException;
    Map<String, TagValueList> getRoleTags(String domainName, String roleName) throws ServerResourceException;

    boolean insertGroupTags(String groupName, String domainName, Map<String, TagValueList> groupTags) throws ServerResourceException;
    boolean deleteGroupTags(String groupName, String domainName, Set<String> tagKeys) throws ServerResourceException;
    Map<String, TagValueList> getGroupTags(String domainName, String groupName) throws ServerResourceException;

    boolean insertServiceTags(String serviceName, String domainName, Map<String, TagValueList> serviceTags) throws ServerResourceException;
    boolean deleteServiceTags(String serviceName, String domainName, Set<String> tagKeys) throws ServerResourceException;
    Map<String, TagValueList> getServiceTags(String domainName, String serviceName) throws ServerResourceException;

    int countAssertionConditions(long assertionId) throws ServerResourceException;
    int getNextConditionId(long assertionId, String caller) throws ServerResourceException;
    List<AssertionCondition> getAssertionConditions(long assertionId) throws ServerResourceException;
    AssertionCondition getAssertionCondition(long assertionId, int conditionId) throws ServerResourceException;
    boolean insertAssertionConditions(long assertionId, AssertionConditions assertionConditions) throws ServerResourceException;
    boolean deleteAssertionConditions(long assertionId) throws ServerResourceException;
    boolean insertAssertionCondition(long assertionId, AssertionCondition assertionCondition) throws ServerResourceException;
    boolean deleteAssertionCondition(long assertionId, int conditionId) throws ServerResourceException;

    // Domain Dependencies Commands

    boolean insertDomainDependency(String domainName, String service) throws ServerResourceException;
    boolean deleteDomainDependency(String domainName, String service) throws ServerResourceException;
    List<String> listServiceDependencies(String domainName) throws ServerResourceException;
    List<String> listDomainDependencies(String service) throws ServerResourceException;

    // purge commands

    List<ExpiryMember> getAllExpiredRoleMembers(int limit, int offset, int serverPurgeExpiryDays) throws ServerResourceException;
    List<ExpiryMember> getAllExpiredGroupMembers(int limit, int offset, int serverPurgeExpiryDays) throws ServerResourceException;

    boolean insertPolicyTags(String policyName, String domainName, Map<String, TagValueList> policyTags, String version) throws ServerResourceException;
    boolean deletePolicyTags(String policyName, String domainName, Set<String> tagKeys, String version) throws ServerResourceException;
    Map<String, TagValueList> getPolicyTags(String domainName, String policyName, String version) throws ServerResourceException;

    // domain contacts api

    boolean insertDomainContact(String domainName, String contactType, String username) throws ServerResourceException;
    boolean updateDomainContact(String domainName, String contactType, String username) throws ServerResourceException;
    boolean deleteDomainContact(String domainName, String contactType) throws ServerResourceException;
    Map<String, List<String>> listContactDomains(String username) throws ServerResourceException;

    // set resource ownership commands

    boolean setResourceDomainOwnership(String domainName, ResourceDomainOwnership resourceOwner) throws ServerResourceException;
    boolean setResourceRoleOwnership(String domainName, String roleName, ResourceRoleOwnership resourceOwner) throws ServerResourceException;
    boolean setResourceGroupOwnership(String domainName, String groupName, ResourceGroupOwnership resourceOwner) throws ServerResourceException;
    boolean setResourcePolicyOwnership(String domainName, String policyName, ResourcePolicyOwnership resourceOwner) throws ServerResourceException;
    boolean setResourceServiceOwnership(String domainName, String serviceName, ResourceServiceIdentityOwnership resourceOwner) throws ServerResourceException;
}
