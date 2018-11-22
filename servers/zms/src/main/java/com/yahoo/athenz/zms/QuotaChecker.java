/*
 * Copyright 2017 Yahoo Holdings, Inc.
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
        
        defaultQuota = new Quota().setName("server-default")
                .setAssertion(assertionQuota).setEntity(entityQuota)
                .setPolicy(policyQuota).setPublicKey(publicKeyQuota)
                .setRole(roleQuota).setRoleMember(roleMemberQuota)
                .setService(serviceQuota).setServiceHost(serviceHostQuota)
                .setSubdomain(subDomainQuota).setModified(Timestamp.fromCurrentTime());
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
        
        // if quota check is disabled we have nothing to do
        
        if (!quotaCheckEnabled) {
            return;
        }
        
        // if our role is null then there is no quota check
        
        if (role == null) {
            return;
        }
        
        // first retrieve the domain quota
        
        final Quota quota = getDomainQuota(con, domainName);
        
        // first we're going to verify the elements that do not
        // require any further data from the object store
        
        int objectCount = getListSize(role.getRoleMembers());
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
    
    void checkRoleMembershipQuota(ObjectStoreConnection con, String domainName,
            String roleName, String caller) {
        
        // if quota check is disabled we have nothing to do
        
        if (!quotaCheckEnabled) {
            return;
        }
        
        // first retrieve the domain quota
        
        final Quota quota = getDomainQuota(con, domainName);
        
        // now check to make sure we can add 1 more member
        // to this role without exceeding the quota
        
        int objectCount = con.countRoleMembers(domainName, roleName) + 1;
        if (quota.getRoleMember() < objectCount) {
            throw ZMSUtils.quotaLimitError("role member quota exceeded - limit: "
                    + quota.getRoleMember() + " actual: " + objectCount, caller);
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
    
    void checkPolicyAssertionQuota(ObjectStoreConnection con, String domainName,
            String policyName, String caller) {
        
        // if quota check is disabled we have nothing to do
        
        if (!quotaCheckEnabled) {
            return;
        }
        
        // first retrieve the domain quota
        
        final Quota quota = getDomainQuota(con, domainName);
        
        // now check to make sure we can add 1 more assertion
        // to this policy without exceeding the quota
        
        int objectCount = con.countAssertions(domainName, policyName) + 1;
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
}
