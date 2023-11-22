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
package com.yahoo.athenz.zms;

import java.util.List;

import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.Timestamp;

class QuotaChecker {

    private final Quota defaultQuota;
    private boolean quotaCheckEnabled;
    int assertionConditionsQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_ASSERTION_CONDITIONS, "10"));

    public QuotaChecker() {
        
        // first check if the quota check is enabled or not
        
        quotaCheckEnabled = Boolean.parseBoolean(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_CHECK, "true"));
        
        // retrieve default quota values
        
        int roleQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_ROLE, "1000"));
        int roleMemberQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_ROLE_MEMBER, "100"));
        int policyQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_POLICY, "1000"));
        int assertionQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_ASSERTION, "100"));
        int serviceQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_SERVICE, "250"));
        int serviceHostQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_SERVICE_HOST, "10"));
        int publicKeyQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_PUBLIC_KEY, "100"));
        int entityQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_ENTITY, "100"));
        int subDomainQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_SUBDOMAIN, "100"));
        int groupQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_GROUP, "100"));
        int groupMemberQuota = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_QUOTA_GROUP_MEMBER, "100"));

        defaultQuota = new Quota().setName("server-default")
                .setAssertion(assertionQuota).setEntity(entityQuota)
                .setPolicy(policyQuota).setPublicKey(publicKeyQuota)
                .setRole(roleQuota).setRoleMember(roleMemberQuota)
                .setService(serviceQuota).setServiceHost(serviceHostQuota)
                .setSubdomain(subDomainQuota).setGroup(groupQuota)
                .setGroupMember(groupMemberQuota).setModified(Timestamp.fromCurrentTime());
    }
    
    public Quota getDomainQuota(ObjectStoreConnection con, String domainName) {
        Quota quota = con.getQuota(domainName);
        return (quota == null) ? defaultQuota : quota;
    }

    void setQuotaCheckEnabled(boolean quotaCheckEnabled) {
        this.quotaCheckEnabled = quotaCheckEnabled;
    }

    int getListSize(List<?> list) {
        return (list == null) ? 0 : list.size();
    }
    
    void checkSubdomainQuota(ObjectStoreConnection con, String domainName, String caller) {
        
        // if quota check is disabled we have nothing to do
        
        if (!quotaCheckEnabled) {
            return;
        }
        
        // for sub-domains we need to run the quota check against
        // the top level domain so let's get that first. If we are
        // creating a top level domain then there is no need for
        // quota check
        
        int idx = domainName.indexOf('.');
        if (idx == -1) {
            return;
        }
        
        final String topLevelDomain = domainName.substring(0, idx);
        
        // now get the quota for the top level domain
        
        final Quota quota = getDomainQuota(con, topLevelDomain);
        
        // get the list of sub-domains for our given top level domain
        
        final String domainPrefix = topLevelDomain + ".";
        int objectCount = con.listDomains(domainPrefix, 0).size() + 1;

        if (quota.getSubdomain() < objectCount) {
            throw ZMSUtils.quotaLimitError("subdomain quota exceeded - limit: "
                    + quota.getSubdomain() + " actual: " + objectCount, caller);
        }
    }
    
    void checkRoleQuota(ObjectStoreConnection con, String domainName, Role role, String caller) {

        // if our role is null then there is no quota check
        
        if (role == null) {
            return;
        }

        // before doing the quota check let's see if our max member
        // limit is configured for the role and it is satisfied

        int objectCount = getListSize(role.getRoleMembers());
        if (role.getMaxMembers() != null && role.getMaxMembers() != 0 && role.getMaxMembers() < objectCount) {
            throw ZMSUtils.quotaLimitError("role max members exceeded - limit: "
                    + role.getMaxMembers() + " actual: " + objectCount, caller);
        }

        // if quota check is disabled we have nothing else to do

        if (!quotaCheckEnabled) {
            return;
        }

        // first retrieve the domain quota
        
        final Quota quota = getDomainQuota(con, domainName);
        
        // first we're going to verify the elements that do not
        // require any further data from the object store
        
        if (quota.getRoleMember() < objectCount) {
            throw ZMSUtils.quotaLimitError("role member quota exceeded - limit: "
                    + quota.getRoleMember() + " actual: " + objectCount, caller);
        }
        
        // now we're going to check if we'll be allowed
        // to create this role in the domain
        
        objectCount = con.countRoles(domainName) + 1;
        if (quota.getRole() < objectCount) {
            throw ZMSUtils.quotaLimitError("role quota exceeded - limit: "
                    + quota.getRole() + " actual: " + objectCount, caller);
        }
    }

    void checkGroupQuota(ObjectStoreConnection con, String domainName, Group group, String caller) {

        // if our group is null then there is no quota check

        if (group == null) {
            return;
        }

        // before doing the quota check let's see if our max member
        // limit is configured for the group and it is satisfied

        int objectCount = getListSize(group.getGroupMembers());
        if (group.getMaxMembers() != null && group.getMaxMembers() != 0 && group.getMaxMembers() < objectCount) {
            throw ZMSUtils.quotaLimitError("group max members exceeded - limit: "
                    + group.getMaxMembers() + " actual: " + objectCount, caller);
        }

        // if quota check is disabled we have nothing else to do

        if (!quotaCheckEnabled) {
            return;
        }

        // first retrieve the domain quota

        final Quota quota = getDomainQuota(con, domainName);

        // first we're going to verify the elements that do not
        // require any further data from the object store

        if (quota.getGroupMember() < objectCount) {
            throw ZMSUtils.quotaLimitError("group member quota exceeded - limit: "
                    + quota.getGroupMember() + " actual: " + objectCount, caller);
        }

        // now we're going to check if we'll be allowed
        // to create this group in the domain

        objectCount = con.countGroups(domainName) + 1;
        if (quota.getGroup() < objectCount) {
            throw ZMSUtils.quotaLimitError("group quota exceeded - limit: "
                    + quota.getGroup() + " actual: " + objectCount, caller);
        }
    }

    void checkRoleMembershipQuota(ObjectStoreConnection con, final String domainName,
            final String roleName, final String memberName, Integer maxMembers, final String caller) {

        // if quota check is disabled or the max member limit is not set
        // on the role then we have nothing to do

        if (!quotaCheckEnabled && (maxMembers == null || maxMembers == 0)) {
            return;
        }

        // we're going to check if the current member is already either
        // a standard or pending member in the role. If that's the case
        // then we don't need to enforce the quota since we're modifying
        // an existing entry

        Membership membership = con.getRoleMember(domainName, roleName, memberName, 0, false);
        if (membership.getIsMember()) {
            return;
        }

        // so at this point we know that we'll be adding a new member to the
        // role. so first let's count the number of role members

        int roleMemberCount = con.countRoleMembers(domainName, roleName);

        // first, let's verify the max member limit if it is set

        if (maxMembers != null && maxMembers > 0 && roleMemberCount >= maxMembers) {
            throw ZMSUtils.quotaLimitError("role max members exceeded - limit: "
                    + maxMembers + " actual: " + roleMemberCount, caller);
        }

        // next, let's retrieve the domain quota
        
        final Quota quota = getDomainQuota(con, domainName);
        
        // now check to make sure we can add 1 more member
        // to this role without exceeding the quota
        
        if (quota.getRoleMember() <= roleMemberCount) {
            throw ZMSUtils.quotaLimitError("role member quota exceeded - limit: "
                    + quota.getRoleMember() + " actual: " + roleMemberCount, caller);
        }
    }

    void checkGroupMembershipQuota(ObjectStoreConnection con, final String domainName,
             final String groupName, final String memberName, Integer maxMembers, final String caller) {

        // if quota check is disabled or the max member limit is not set
        // on the group then we have nothing to do

        if (!quotaCheckEnabled && (maxMembers == null || maxMembers == 0)) {
            return;
        }

        // we're going to check if the current member is already either
        // a standard or pending member in the group. If that's the case
        // then we don't need to enforce the quota since we're modifying
        // an existing entry

        GroupMembership membership = con.getGroupMember(domainName, groupName, memberName, 0, false);
        if (membership.getIsMember()) {
            return;
        }

        // so at this point we know that we'll be adding a new member to the
        // group. so first let's count the number of group members

        int groupMemberCount = con.countGroupMembers(domainName, groupName);

        // first, let's verify the max member limit if it is set

        if (maxMembers != null && maxMembers > 0 && groupMemberCount >= maxMembers) {
            throw ZMSUtils.quotaLimitError("group max members exceeded - limit: "
                    + maxMembers + " actual: " + groupMemberCount, caller);
        }

        // next, let's retrieve the domain quota

        final Quota quota = getDomainQuota(con, domainName);

        // now check to make sure we can add 1 more member
        // to this group without exceeding the quota

        if (quota.getGroupMember() <= groupMemberCount) {
            throw ZMSUtils.quotaLimitError("group member quota exceeded - limit: "
                    + quota.getGroupMember() + " actual: " + groupMemberCount, caller);
        }
    }

    void checkPolicyQuota(ObjectStoreConnection con, String domainName, Policy policy, String caller) {
        
        // if quota check is disabled we have nothing to do
        
        if (!quotaCheckEnabled) {
            return;
        }
        
        // if our policy is null then there is no quota check
        
        if (policy == null) {
            return;
        }
        
        // first retrieve the domain quota
        
        final Quota quota = getDomainQuota(con, domainName);
        
        // first we're going to verify the elements that do not
        // require any further data from the object store
        
        int objectCount = getListSize(policy.getAssertions());
        if (quota.getAssertion() < objectCount) {
            throw ZMSUtils.quotaLimitError("policy assertion quota exceeded - limit: "
                    + quota.getAssertion() + " actual: " + objectCount, caller);
        }
        
        // now we're going to check if we'll be allowed
        // to create this policy in the domain
        
        objectCount = con.countPolicies(domainName) + 1;
        if (quota.getPolicy() < objectCount) {
            throw ZMSUtils.quotaLimitError("policy quota exceeded - limit: "
                    + quota.getPolicy() + " actual: " + objectCount, caller);
        }
    }
    
    void checkPolicyAssertionQuota(ObjectStoreConnection con, final String domainName,
            final String policyName, final String version, final String caller) {
        
        // if quota check is disabled we have nothing to do
        
        if (!quotaCheckEnabled) {
            return;
        }
        
        // first retrieve the domain quota
        
        final Quota quota = getDomainQuota(con, domainName);
        
        // now check to make sure we can add 1 more assertion
        // to this policy without exceeding the quota
        
        int objectCount = con.countAssertions(domainName, policyName, version) + 1;
        if (quota.getAssertion() < objectCount) {
            throw ZMSUtils.quotaLimitError("policy assertion quota exceeded - limit: "
                    + quota.getAssertion() + " actual: " + objectCount, caller);
        }
    }
    
    void checkServiceIdentityQuota(ObjectStoreConnection con, String domainName,
            ServiceIdentity service, String caller) {
        
        // if quota check is disabled we have nothing to do
        
        if (!quotaCheckEnabled) {
            return;
        }
        
        // if our service is null then there is no quota check
        
        if (service == null) {
            return;
        }
        
        // first retrieve the domain quota
        
        final Quota quota = getDomainQuota(con, domainName);
        
        // first we're going to verify the elements that do not
        // require any further data from the object store
        
        int objectCount = getListSize(service.getHosts());
        if (quota.getServiceHost() < objectCount) {
            throw ZMSUtils.quotaLimitError("service host quota exceeded - limit: "
                    + quota.getServiceHost() + " actual: " + objectCount, caller);
        }
        
        objectCount = getListSize(service.getPublicKeys());
        if (quota.getPublicKey() < objectCount) {
            throw ZMSUtils.quotaLimitError("service public key quota exceeded - limit: "
                    + quota.getPublicKey() + " actual: " + objectCount, caller);
        }
        
        // now we're going to check if we'll be allowed
        // to create this service in the domain
        
        objectCount = con.countServiceIdentities(domainName) + 1;
        if (quota.getService() < objectCount) {
            throw ZMSUtils.quotaLimitError("service quota exceeded - limit: "
                    + quota.getService() + " actual: " + objectCount, caller);
        }
    }
    
    void checkServiceIdentityPublicKeyQuota(ObjectStoreConnection con, String domainName,
            String serviceName, String caller) {
        
        // if quota check is disabled we have nothing to do
        
        if (!quotaCheckEnabled) {
            return;
        }
        
        // first retrieve the domain quota
        
        final Quota quota = getDomainQuota(con, domainName);
        
        // now check to make sure we can add 1 more public key
        // to this policy without exceeding the quota
        
        int objectCount = con.countPublicKeys(domainName, serviceName) + 1;
        if (quota.getPublicKey() < objectCount) {
            throw ZMSUtils.quotaLimitError("service public key quota exceeded - limit: "
                    + quota.getPublicKey() + " actual: " + objectCount, caller);
        }
    }
    
    void checkEntityQuota(ObjectStoreConnection con, String domainName, Entity entity,
            String caller) {
        
        // if quota check is disabled we have nothing to do
        
        if (!quotaCheckEnabled) {
            return;
        }
        
        // if our entity is null then there is no quota check
        
        if (entity == null) {
            return;
        }
        
        // first retrieve the domain quota
        
        final Quota quota = getDomainQuota(con, domainName);
        
        // we're going to check if we'll be allowed
        // to create this entity in the domain
        
        int objectCount = con.countEntities(domainName) + 1;
        if (quota.getEntity() < objectCount) {
            throw ZMSUtils.quotaLimitError("entity quota exceeded - limit: "
                    + quota.getEntity() + " actual: " + objectCount, caller);
        }
    }
    void checkAssertionConditionsQuota(ObjectStoreConnection con, long assertionId, AssertionConditions assertionConditions,
                                       String caller) {

        // if quota check is disabled we have nothing to do
        if (!quotaCheckEnabled) {
            return;
        }

        // if our assertionConditions is null then there is no quota check
        if (assertionConditions == null || assertionConditions.getConditionsList() == null ||
                assertionConditions.getConditionsList().isEmpty()) {
            return;
        }

        // we're going to check if we'll be allowed to create given assertionConditions
        int newCount = assertionConditions.getConditionsList().stream().map(c -> c.getConditionsMap().size()).reduce(0, Integer::sum);
        countAssertionConditions(con, assertionId, newCount, caller);
    }

    void checkAssertionConditionQuota(ObjectStoreConnection con, long assertionId, AssertionCondition assertionCondition,
                                      String caller) {

        // if quota check is disabled we have nothing to do
        if (!quotaCheckEnabled) {
            return;
        }
        if (assertionCondition == null) {
            return;
        }
        countAssertionConditions(con, assertionId, assertionCondition.getConditionsMap().size(), caller);

    }

    void countAssertionConditions(ObjectStoreConnection con, long assertionId, int newCount, String caller) {
        // we're going to check if we'll be allowed to create given assertionConditions
        int objectCount = con.countAssertionConditions(assertionId) + newCount;
        if (assertionConditionsQuota < objectCount) {
            throw ZMSUtils.quotaLimitError("assertion conditions quota exceeded - limit: "
                    + assertionConditionsQuota + " actual: " + objectCount, caller);
        }
    }
}
