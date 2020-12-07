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
package com.yahoo.athenz.zms;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.auth.util.StringUtils;
import com.yahoo.athenz.common.server.audit.AuditReferenceValidator;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.util.AuthzHelper;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class DBService implements RolesProvider {

    ObjectStore store;
    BitSet auditRefSet;
    AuditLogger auditLogger;
    Cache<String, DataCache> cacheStore;
    QuotaChecker quotaCheck;
    int retrySleepTime;
    int defaultRetryCount;
    int defaultOpTimeout;
    ZMSConfig zmsConfig;

    private static final Logger LOG = LoggerFactory.getLogger(DBService.class);

    public static int AUDIT_TYPE_ROLE     = 0;
    public static int AUDIT_TYPE_POLICY   = 1;
    public static int AUDIT_TYPE_SERVICE  = 2;
    public static int AUDIT_TYPE_DOMAIN   = 3;
    public static int AUDIT_TYPE_ENTITY   = 4;
    public static int AUDIT_TYPE_TENANCY  = 5;
    public static int AUDIT_TYPE_TEMPLATE = 6;
    public static int AUDIT_TYPE_GROUP    = 7;

    private static final String ROLE_PREFIX = "role.";
    private static final String POLICY_PREFIX = "policy.";
    private static final String TEMPLATE_DOMAIN_NAME = "_domain_";
    private static final String AUDIT_REF = "Athenz User Authority Enforcer";

    AuditReferenceValidator auditReferenceValidator;
    private ScheduledExecutorService userAuthorityFilterExecutor;

    public DBService(ObjectStore store, AuditLogger auditLogger, ZMSConfig zmsConfig, AuditReferenceValidator auditReferenceValidator) {

        this.store = store;
        this.zmsConfig = zmsConfig;
        this.auditLogger = auditLogger;
        cacheStore = CacheBuilder.newBuilder().concurrencyLevel(25).build();

        // default timeout in seconds for object store commands

        defaultOpTimeout = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_STORE_OP_TIMEOUT, "60"));
        if (defaultOpTimeout < 0) {
            defaultOpTimeout = 60;
        }
        if (this.store != null) {
            this.store.setOperationTimeout(defaultOpTimeout);
        }

        // retrieve the concurrent update retry count. If we're given an invalid negative
        // value for count, we'll default back to our default configured value of 120 retries
        // which would result up to 30 seconds sleeping 250ms each time

        defaultRetryCount = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_COUNT, "120"));
        if (defaultRetryCount < 0) {
            defaultRetryCount = 120;
        }

        retrySleepTime = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_CONFLICT_RETRY_SLEEP_TIME, "250"));
        if (retrySleepTime < 0) {
            retrySleepTime = 250;
        }

        // check what objects we're going to enforce audit reference flag

        setAuditRefObjectBits();
        this.auditReferenceValidator = auditReferenceValidator;

        // create our quota checker class

        quotaCheck = new QuotaChecker();

        // start our thread to process user authority changes daily

        userAuthorityFilterExecutor = Executors.newScheduledThreadPool(1);
        userAuthorityFilterExecutor.scheduleAtFixedRate(
                new UserAuthorityFilterEnforcer(), 0, 1, TimeUnit.DAYS);
    }

    void setAuditRefObjectBits() {

        auditRefSet = new BitSet();

        // by default we're only going to handle audit enabled roles and groups
        // the value is a comma separated list of supported objects:
        // role, group, policy, service, domain, entity, tenancy, and template

        final String auditCheck = System.getProperty(ZMSConsts.ZMS_PROP_AUDIT_REF_CHECK_OBJECTS, "role,group");

        String[] objects = auditCheck.split(",");
        for (String object : objects) {
            switch (object) {
                case ZMSConsts.ZMS_AUDIT_TYPE_ROLE:
                    auditRefSet.set(AUDIT_TYPE_ROLE);
                    break;
                case ZMSConsts.ZMS_AUDIT_TYPE_GROUP:
                    auditRefSet.set(AUDIT_TYPE_GROUP);
                    break;
                case ZMSConsts.ZMS_AUDIT_TYPE_POLICY:
                    auditRefSet.set(AUDIT_TYPE_POLICY);
                    break;
                case ZMSConsts.ZMS_AUDIT_TYPE_SERVICE:
                    auditRefSet.set(AUDIT_TYPE_SERVICE);
                    break;
                case ZMSConsts.ZMS_AUDIT_TYPE_DOMAIN:
                    auditRefSet.set(AUDIT_TYPE_DOMAIN);
                    break;
                case ZMSConsts.ZMS_AUDIT_TYPE_ENTITY:
                    auditRefSet.set(AUDIT_TYPE_ENTITY);
                    break;
                case ZMSConsts.ZMS_AUDIT_TYPE_TENANCY:
                    auditRefSet.set(AUDIT_TYPE_TENANCY);
                    break;
                case ZMSConsts.ZMS_AUDIT_TYPE_TEMPLATE:
                    auditRefSet.set(AUDIT_TYPE_TEMPLATE);
                    break;
            }
        }
    }

    public DomainRoleMembers listOverdueReviewRoleMembers(String domainName) {
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.listOverdueReviewRoleMembers(domainName);
        }
    }

    @Override
    public List<Role> getRolesByDomain(String domain) {
        AthenzDomain athenzDomain = getAthenzDomain(domain, false);
        return athenzDomain.getRoles();
    }

    static class DataCache {
        AthenzDomain athenzDomain;
        long modTime;

        DataCache(AthenzDomain athenzDomain, long modTime) {
            this.athenzDomain = athenzDomain;
            this.modTime = modTime;
        }

        AthenzDomain getAthenzDomain() {
            return athenzDomain;
        }

        long getModTime() {
            return modTime;
        }
    }

    AthenzDomain getAthenzDomainFromCache(ObjectStoreConnection con, String domainName) {

        DataCache data = cacheStore.getIfPresent(domainName);
        if (data == null) {
            return null;
        }

        // if we have a match for a given domain name then we're going
        // to check if the last modified domain timestamp matches to what's
        // in the db: So if there is no match, then we'll take the hit
        // of extra db read, however, in most cases the domain data is not
        // changed that often so we'll satisfy the request with just
        // verifying the last modification time as oppose to reading the
        // full domain data from db

        long modTime = 0;

        try {
            modTime = con.getDomainModTimestamp(domainName);
        } catch (ResourceException ignored) {
            // if the exception is due to timeout or we were not able
            // to get a connection to the object store then we're
            // going to use our cache as is instead of rejecting
            // the operation
        }

        // if our cache data is same or newer than db then return
        // data from the cache (it could be newer if we just updated
        // the cache based on write db but during read, the server
        // hasn't replicated the data yet)

        if (data.getModTime() >= modTime) {
            return data.getAthenzDomain();
        }

        cacheStore.invalidate(domainName);
        return null;
    }

    String getPrincipalName(ResourceContext ctx) {
        if (ctx == null) {
            return null;
        }
        Principal principal = ((RsrcCtxWrapper) ctx).principal();
        if (principal == null) {
            return null;
        }
        return principal.getFullName();
    }

    void saveChanges(ObjectStoreConnection con, String domainName) {

        // we're first going to commit our changes which will
        // also set the connection in auto-commit mode. we are
        // going to change the domain timestamp in auto-commit
        // mode so that we don't have a contention

        con.commitChanges();
        con.updateDomainModTimestamp(domainName);
        cacheStore.invalidate(domainName);
    }

    void auditLogRequest(ResourceContext ctx, String domainName, String auditRef,
            String caller, String operation, String entityName, String auditDetails) {
        auditLogger.log(getAuditLogMsgBuilder(ctx, domainName, auditRef, caller, operation, entityName, auditDetails));
    }

    void auditLogRequest(String principal, String domainName, String auditRef,
            String caller, String operation, String entityName, String auditDetails) {
        AuditLogMsgBuilder msgBldr = getAuditLogMsgBuilder(null, domainName, auditRef, caller, operation, entityName, auditDetails);
        msgBldr.who(principal);
        auditLogger.log(msgBldr);
    }

    private AuditLogMsgBuilder getAuditLogMsgBuilder(ResourceContext ctx, String domainName,
            String auditRef, String caller, String operation, String entityName, String auditDetails) {
        AuditLogMsgBuilder msgBldr = ZMSUtils.getAuditLogMsgBuilder(ctx, auditLogger,
                domainName, auditRef, caller, operation);
        msgBldr.when(Timestamp.fromCurrentTime().toString()).whatEntity(entityName);
        if (auditDetails != null) {
            msgBldr.whatDetails(auditDetails);
        }
        return msgBldr;
    }

    Domain makeDomain(ResourceContext ctx, Domain domain, List<String> adminUsers,
            List<String> solutionTemplates, String auditRef) {

        final String caller = "makedomain";
        final String domainName = domain.getName();
        String principalName = getPrincipalName(ctx);
        if (principalName == null) {
            principalName = "system-account";
        }

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            // get our connection object

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // before adding this domain we need to verify our
                // quota check for sub-domains

                quotaCheck.checkSubdomainQuota(con, domainName, caller);

                boolean objectsInserted = con.insertDomain(domain);
                if (!objectsInserted) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError("makeDomain: Cannot create domain: " +
                            domainName + " - already exists", caller);
                }

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"domain\": ");
                auditLogDomain(auditDetails, domain);

                // first create and process the admin role

                Role adminRole = ZMSUtils.makeAdminRole(domainName, adminUsers);
                auditDetails.append(", \"role\": ");
                if (!processRole(con, null, domainName, ZMSConsts.ADMIN_ROLE_NAME, adminRole,
                        principalName, auditRef, false, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("makeDomain: Cannot process role: '" +
                            adminRole.getName(), caller);
                }

                // now create and process the admin policy

                Policy adminPolicy = ZMSUtils.makeAdminPolicy(domainName, adminRole);
                auditDetails.append(", \"policy\": ");
                if (!processPolicy(con, null, domainName, ZMSConsts.ADMIN_POLICY_NAME, adminPolicy,
                        false, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("makeDomain: Cannot process policy: '" +
                            adminPolicy.getName(), caller);
                }

                // go through our list of templates and add the specified
                // roles and polices to our domain

                if (solutionTemplates != null) {
                    for (String templateName : solutionTemplates) {
                        auditDetails.append(", \"template\": ");
                        if (!addSolutionTemplate(con, domainName, templateName, principalName,
                                null, auditRef, auditDetails)) {
                            con.rollbackChanges();
                            throw ZMSUtils.internalServerError("makeDomain: Cannot apply templates: '" +
                                    domain, caller);
                        }
                    }
                }
                auditDetails.append("}");

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log entry

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_POST,
                        domainName, auditDetails.toString());

                return domain;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    boolean processPolicy(ObjectStoreConnection con, Policy originalPolicy, String domainName,
            String policyName, Policy policy, boolean ignoreDeletes, StringBuilder auditDetails) {

        // check to see if we need to insert the policy or update it

        boolean requestSuccess;
        if (originalPolicy == null) {
            requestSuccess = con.insertPolicy(domainName, policy);
        } else {
            requestSuccess = con.updatePolicy(domainName, policy);
        }

        // if we didn't update any policies then we need to return failure

        if (!requestSuccess) {
            return false;
        }

        // open our audit record

        auditDetails.append("{\"name\": \"").append(policyName).append('\"');

        // now we need process our policy assertions depending this is
        // a new insert operation or an update

        List<Assertion> newAssertions = policy.getAssertions();
        if (originalPolicy == null) {

            // we're just going to process our new assertions

            if (newAssertions != null) {
                for (Assertion assertion : newAssertions) {
                    if (!con.insertAssertion(domainName, policyName, assertion)) {
                        return false;
                    }
                }
                auditLogAssertions(auditDetails, "added-assertions", newAssertions);
            }

        } else {

            // first we need to retrieve the current set of assertions

            List<Assertion> curAssertions = originalPolicy.getAssertions();
            if (curAssertions == null) {
                curAssertions = new ArrayList<>();
            }
            List<Assertion> addAssertions = new ArrayList<>();
            List<Assertion> delAssertions = new ArrayList<>();
            policyAssertionChanges(newAssertions, curAssertions, addAssertions, delAssertions);

            if (!ignoreDeletes) {
                for (Assertion assertion : delAssertions) {
                    if (!con.deleteAssertion(domainName, policyName, assertion.getId())) {
                        return false;
                    }
                }
                auditLogAssertions(auditDetails, "deleted-assertions", delAssertions);
            }

            for (Assertion assertion : addAssertions) {
                if (!con.insertAssertion(domainName, policyName, assertion)) {
                    return false;
                }
            }
            auditLogAssertions(auditDetails, "added-assertions", addAssertions);
        }

        auditDetails.append('}');
        return true;
    }

    boolean removeMatchedAssertion(Assertion assertion, List<Assertion> assertions, List<Assertion> matchedAssertions) {

        AssertionEffect effect = AssertionEffect.ALLOW;
        if (assertion.getEffect() != null) {
            effect = assertion.getEffect();
        }

        Iterator<Assertion> itr = assertions.iterator();
        while (itr.hasNext()) {

            Assertion checkAssertion = itr.next();

            if (!assertion.getAction().equals(checkAssertion.getAction())) {
                continue;
            }
            if (!assertion.getResource().equals(checkAssertion.getResource())) {
                continue;
            }
            if (!assertion.getRole().equals(checkAssertion.getRole())) {
                continue;
            }

            AssertionEffect checkEffect = AssertionEffect.ALLOW;
            if (checkAssertion.getEffect() != null) {
                checkEffect = checkAssertion.getEffect();
            }

            if (effect != checkEffect) {
                continue;
            }

            itr.remove();
            matchedAssertions.add(checkAssertion);
            return true;
        }

        return false;
    }

    void policyAssertionChanges(List<Assertion> newAssertions, List<Assertion> curAssertions,
            List<Assertion> addAssertions, List<Assertion> delAssertions) {

        // let's iterate through the new list and the ones that are
        // not in the current list should be added to the add list

        List<Assertion> matchedAssertions = new ArrayList<>();
        if (newAssertions != null) {
            for (Assertion assertion : newAssertions) {
                if (!removeMatchedAssertion(assertion, curAssertions, matchedAssertions)) {
                    addAssertions.add(assertion);
                }
            }
        }

        // now our current list has been updated as well and
        // all the assertions that were present moved to the
        // matched assertion list so whatever left in the
        // current list must be deleted

        delAssertions.addAll(curAssertions);

        // now let's go back and re-add the matched assertions
        // back to our list so we can get the right audit data

        curAssertions.addAll(matchedAssertions);
    }

    boolean processRole(ObjectStoreConnection con, Role originalRole, String domainName,
            String roleName, Role role, String admin, String auditRef, boolean ignoreDeletes,
            StringBuilder auditDetails) {

        // check to see if we need to insert the role or update it

        boolean requestSuccess;
        if (originalRole == null) {
            // auditEnabled can only be set with system admin privileges
            role.setAuditEnabled(false);
            requestSuccess = con.insertRole(domainName, role);
        } else {
            // carrying over auditEnabled from original role
            role.setAuditEnabled(originalRole.getAuditEnabled());
            requestSuccess = con.updateRole(domainName, role);
        }

        // if we didn't update any roles then we need to return failure

        if (!requestSuccess) {
            return false;
        }

        // open our audit record and log our trust field if one is available

        auditDetails.append("{\"name\": \"").append(roleName)
            .append("\", \"trust\": \"").append(role.getTrust()).append('\"');

        // now we need process our role members depending this is
        // a new insert operation or an update

        List<RoleMember> roleMembers = role.getRoleMembers();
        if (originalRole == null) {

            // we are just going to process all members as new inserts

            if (roleMembers != null) {

                for (RoleMember member : roleMembers) {
                    if (!con.insertRoleMember(domainName, roleName, member, admin, auditRef)) {
                        return false;
                    }
                }
                auditLogRoleMembers(auditDetails, "added-members", roleMembers);
            }
        } else {
            if (!processUpdateRoleMembers(con, originalRole, roleMembers, ignoreDeletes,
                    domainName, roleName, admin, auditRef, auditDetails)) {
                return false;
            }
        }

        if (!processRoleTags(role, roleName, domainName, originalRole, con)) {
            return false;
        }

        auditDetails.append('}');
        return true;
    }

    private boolean processRoleTags(Role role, String roleName, String domainName,
                                    Role originalRole, ObjectStoreConnection con) {
        if (role.getTags() != null && !role.getTags().isEmpty()) {
            if (originalRole == null) {
                return con.insertRoleTags(roleName, domainName, role.getTags());
            } else {
                return processUpdateRoleTags(role, originalRole, con, roleName, domainName);
            }
        }
        return true;
    }

    private boolean processUpdateRoleTags(Role role, Role originalRole, ObjectStoreConnection con, String roleName, String domainName) {
        if (originalRole.getTags() == null || originalRole.getTags().isEmpty()) {
            return con.insertRoleTags(roleName, domainName, role.getTags());
        }
        Map<String, StringList> originalRoleTags = originalRole.getTags();
        Map<String, StringList> currentTags = role.getTags();

        Set<String> tagsToRemove = originalRoleTags.entrySet().stream()
                .filter(curTag -> currentTags.get(curTag.getKey()) == null
                        || !currentTags.get(curTag.getKey()).equals(curTag.getValue()))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());

        Map<String, StringList> tagsToAdd = currentTags.entrySet().stream()
                .filter(curTag -> originalRoleTags.get(curTag.getKey()) == null
                        || !originalRoleTags.get(curTag.getKey()).equals(curTag.getValue()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        boolean res = con.deleteRoleTags(roleName, domainName, tagsToRemove);

        return res && con.insertRoleTags(roleName, domainName, tagsToAdd);
    }

    boolean processGroup(ObjectStoreConnection con, Group originalGroup, final String domainName,
                        final String groupName, Group group, final String admin, final String auditRef,
                        StringBuilder auditDetails) {

        // check to see if we need to insert the group or update it

        boolean requestSuccess;
        if (originalGroup == null) {
            // auditEnabled can only be set with system admin privileges
            group.setAuditEnabled(false);
            requestSuccess = con.insertGroup(domainName, group);
        } else {
            // carrying over auditEnabled from original group
            group.setAuditEnabled(originalGroup.getAuditEnabled());
            requestSuccess = con.updateGroup(domainName, group);
        }

        // if we didn't update any groups then we need to return failure

        if (!requestSuccess) {
            return false;
        }

        // open our audit record and log our trust field if one is available

        auditDetails.append("{\"name\": \"").append(groupName).append('\"');

        // now we need process our groups members depending this is
        // a new insert operation or an update

        List<GroupMember> groupMembers = group.getGroupMembers();

        if (originalGroup == null) {

            // we are just going to process all members as new inserts

            for (GroupMember member : groupMembers) {
                if (!con.insertGroupMember(domainName, groupName, member, admin, auditRef)) {
                    return false;
                }
            }
            auditLogGroupMembers(auditDetails, "added-members", groupMembers);

        } else {

            if (!processUpdateGroupMembers(con, originalGroup, groupMembers, domainName, groupName,
                    admin, auditRef, auditDetails)) {
                return false;
            }
        }

        auditDetails.append('}');
        return true;
    }

    void mergeOriginalRoleAndMetaRoleAttributes(Role originalRole, Role templateRole) {
        //Only if the template rolemeta value is null, update with original role value
        //else use the rolemeta value from template
        if (templateRole.getSelfServe() == null) {
            templateRole.setSelfServe(originalRole.getSelfServe());
        }
        if (templateRole.getMemberExpiryDays() == null) {
            templateRole.setMemberExpiryDays(originalRole.getMemberExpiryDays());
        }
        if (templateRole.getServiceExpiryDays() == null) {
            templateRole.setServiceExpiryDays(originalRole.getServiceExpiryDays());
        }
        if (templateRole.getGroupExpiryDays() == null) {
            templateRole.setGroupExpiryDays(originalRole.getGroupExpiryDays());
        }
        if (templateRole.getTokenExpiryMins() == null) {
            templateRole.setTokenExpiryMins(originalRole.getTokenExpiryMins());
        }
        if (templateRole.getCertExpiryMins() == null) {
            templateRole.setCertExpiryMins(originalRole.getCertExpiryMins());
        }
        if (templateRole.getSignAlgorithm() == null) {
            templateRole.setSignAlgorithm(originalRole.getSignAlgorithm());
        }
        if (templateRole.getReviewEnabled() == null) {
            templateRole.setReviewEnabled(originalRole.getReviewEnabled());
        }
        if (templateRole.getNotifyRoles() == null) {
            templateRole.setNotifyRoles(originalRole.getNotifyRoles());
        }
        if (templateRole.getMemberReviewDays() == null) {
            templateRole.setMemberReviewDays(originalRole.getMemberReviewDays());
        }
        if (templateRole.getServiceReviewDays() == null) {
            templateRole.setServiceReviewDays(originalRole.getServiceReviewDays());
        }
        if (templateRole.getUserAuthorityFilter() == null) {
            templateRole.setUserAuthorityFilter(originalRole.getUserAuthorityFilter());
        }
        if (templateRole.getUserAuthorityExpiration() == null) {
            templateRole.setUserAuthorityExpiration(originalRole.getUserAuthorityExpiration());
        }
    }

    private boolean processUpdateRoleMembers(ObjectStoreConnection con, Role originalRole,
            List<RoleMember> roleMembers, boolean ignoreDeletes, String domainName,
            String roleName, String admin, String auditRef, StringBuilder auditDetails) {

        // first we need to retrieve the current set of members

        List<RoleMember> originalMembers = originalRole.getRoleMembers();
        List<RoleMember> curMembers = (null == originalMembers) ? new ArrayList<>() : new ArrayList<>(originalMembers);
        List<RoleMember> delMembers = new ArrayList<>(curMembers);
        ArrayList<RoleMember> newMembers = (null == roleMembers) ? new ArrayList<>() : new ArrayList<>(roleMembers);

        // remove current members from new members

        AuthzHelper.removeRoleMembers(newMembers, curMembers);

        // remove new members from current members
        // which leaves the deleted members.

        AuthzHelper.removeRoleMembers(delMembers, roleMembers);

        if (!ignoreDeletes) {
            for (RoleMember member : delMembers) {
                if (!con.deleteRoleMember(domainName, roleName, member.getMemberName(), admin, auditRef)) {
                    return false;
                }
            }
            auditLogRoleMembers(auditDetails, "deleted-members", delMembers);
        }

        for (RoleMember member : newMembers) {
            if (!con.insertRoleMember(domainName, roleName, member, admin, auditRef)) {
                return false;
            }
        }
        auditLogRoleMembers(auditDetails, "added-members", newMembers);
        return true;
    }

    private boolean processUpdateGroupMembers(ObjectStoreConnection con, Group originalGroup,
                                              List<GroupMember> groupMembers, final String domainName,
                                              final String groupName, final String admin, final String auditRef,
                                              StringBuilder auditDetails) {

        // first we need to retrieve the current set of members

        List<GroupMember> originalMembers = originalGroup.getGroupMembers();
        List<GroupMember> curMembers = new ArrayList<>(originalMembers);
        List<GroupMember> delMembers = new ArrayList<>(curMembers);
        ArrayList<GroupMember> newMembers = new ArrayList<>(groupMembers);

        // remove current members from new members

        AuthzHelper.removeGroupMembers(newMembers, curMembers);

        // remove new members from current members
        // which leaves the deleted members.

        AuthzHelper.removeGroupMembers(delMembers, groupMembers);

        for (GroupMember member : delMembers) {
            if (!con.deleteGroupMember(domainName, groupName, member.getMemberName(), admin, auditRef)) {
                return false;
            }
        }
        auditLogGroupMembers(auditDetails, "deleted-members", delMembers);

        for (GroupMember member : newMembers) {
            if (!con.insertGroupMember(domainName, groupName, member, admin, auditRef)) {
                return false;
            }
        }
        auditLogGroupMembers(auditDetails, "added-members", newMembers);
        return true;
    }

    boolean processServiceIdentity(ObjectStoreConnection con, ServiceIdentity originalService,
            String domainName, String serviceName, ServiceIdentity service,
            boolean ignoreDeletes, StringBuilder auditDetails) {

        boolean requestSuccess;
        if (originalService == null) {
            // provider endpoint can only be set with system admin privileges
            service.setProviderEndpoint(null);
            requestSuccess = con.insertServiceIdentity(domainName, service);
        } else {
            // carrying over provider endpoint from original service
            service.setProviderEndpoint(originalService.getProviderEndpoint());
            requestSuccess = con.updateServiceIdentity(domainName, service);
        }

        // if we didn't update any services then we need to return failure

        if (!requestSuccess) {
            return false;
        }

        // open our audit record and log our service details

        auditDetails.append("{\"name\": \"").append(serviceName).append('\"')
            .append(", \"executable\": \"").append(service.getExecutable()).append('\"')
            .append(", \"user\": \"").append(service.getUser()).append('\"')
            .append(", \"group\": \"").append(service.getGroup()).append('\"')
            .append(", \"description\": \"").append(service.getDescription()).append('\"');

        // now we need process our public keys depending this is
        // a new insert operation or an update

        List<PublicKeyEntry> publicKeys = service.getPublicKeys();
        if (originalService == null) {

            // we are just going to process all public keys as new inserts

            if (publicKeys != null) {

                for (PublicKeyEntry publicKey : publicKeys) {
                    if (!con.insertPublicKeyEntry(domainName, serviceName, publicKey)) {
                        return false;
                    }
                }
                auditLogPublicKeyEntries(auditDetails, "added-publickeys", publicKeys);
            }

        } else {

            // first we need to retrieve the current set of public keys

            List<PublicKeyEntry> curPublicKeys = originalService.getPublicKeys();
            Map<String, PublicKeyEntry> curPublicKeysMap = new HashMap<>();
            if (curPublicKeys != null) {
                for (PublicKeyEntry publicKey : curPublicKeys) {
                    curPublicKeysMap.put(publicKey.getId(), publicKey);
                }
            }
            Map<String, PublicKeyEntry> publicKeysMap = new HashMap<>();
            if (publicKeys != null) {
                for (PublicKeyEntry publicKey : publicKeys) {
                    publicKeysMap.put(publicKey.getId(), publicKey);
                }
            }
            Set<String> curPublicKeysSet = new HashSet<>(curPublicKeysMap.keySet());
            Set<String> delPublicKeysSet = new HashSet<>(curPublicKeysSet);
            Set<String> newPublicKeysSet = new HashSet<>(publicKeysMap.keySet());
            newPublicKeysSet.removeAll(curPublicKeysSet);
            delPublicKeysSet.removeAll(new HashSet<>(publicKeysMap.keySet()));

            if (!ignoreDeletes) {
                for (String publicKey : delPublicKeysSet) {
                    if (!con.deletePublicKeyEntry(domainName, serviceName, publicKey)) {
                        return false;
                    }
                }
                auditLogPublicKeyEntries(auditDetails, "deleted-publickeys", delPublicKeysSet);
            }

            for (String publicKey : newPublicKeysSet) {
                if (!con.insertPublicKeyEntry(domainName, serviceName, publicKeysMap.get(publicKey))) {
                    return false;
                }
            }
            auditLogPublicKeyEntries(auditDetails, "added-publickeys", newPublicKeysSet, publicKeysMap);
        }

        // now we need to process the hosts defined for this service

        Set<String> curHosts;
        if (originalService != null && originalService.getHosts() != null) {
            curHosts = new HashSet<>(originalService.getHosts());
        } else {
            curHosts = new HashSet<>();
        }

        Set<String> newHosts;
        if (service.getHosts() != null) {
            newHosts = new HashSet<>(service.getHosts());
        } else {
            newHosts = new HashSet<>();
        }

        Set<String> delHosts = new HashSet<>(curHosts);
        delHosts.removeAll(newHosts);
        newHosts.removeAll(curHosts);

        for (String host : delHosts) {
            if (!con.deleteServiceHost(domainName, serviceName, host)) {
                return false;
            }
        }
        auditLogStrings(auditDetails, "deleted-hosts", delHosts);

        for (String host : newHosts) {
            if (!con.insertServiceHost(domainName, serviceName, host)) {
                return false;
            }
        }
        auditLogStrings(auditDetails, "added-hosts", newHosts);

        auditDetails.append('}');
        return true;
    }

    boolean shouldRetryOperation(ResourceException ex, int retryCount) {

        // before doing anything else let's check to see if
        // we still have the option to retry the operation

        if (retryCount <= 1) {
            return false;
        }

        // if we got a conflict result it means we either had
        // no connection or deadlock was detected and as such
        // the changes were aborted

        boolean retry = false;
        switch (ex.getCode()) {

            case ResourceException.CONFLICT:

                retry = true;
                break;

            case ResourceException.GONE:

                // this error indicates that the server is reporting it is in
                // read-only mode which indicates a fail-over has taken place
                // and we need to clear all connections and start new ones
                // this could only happen with write operations against the
                // read-write object store

                store.clearConnections();
                retry = true;
                break;
        }

        // if we're asked to retry then we're going to
        // wait for a short period of time to allow the other
        // connection to finish its work

        if (retry) {

            if (LOG.isDebugEnabled()) {
                LOG.debug(": possible deadlock, retries available: " + retryCount);
            }

            ZMSUtils.threadSleep(retrySleepTime);
        }

        // return our response

        return retry;
    }

    void executePutPolicy(ResourceContext ctx, String domainName, String policyName, Policy policy,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // check that quota is not exceeded

                quotaCheck.checkPolicyQuota(con, domainName, policy, caller);

                // retrieve our original policy

                Policy originalPolicy = getPolicy(con, domainName, policyName);

                // now process the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                if (!processPolicy(con, originalPolicy, domainName, policyName, policy, false, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put policy: " + policy.getName(), caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        policyName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutRole(ResourceContext ctx, String domainName, String roleName, Role role,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal, AUDIT_TYPE_ROLE);

                // check that quota is not exceeded

                quotaCheck.checkRoleQuota(con, domainName, role, caller);

                // retrieve our original role

                Role originalRole = getRole(con, domainName, roleName, false, false, false);

                if (originalRole != null &&
                        (originalRole.getAuditEnabled() == Boolean.TRUE || originalRole.getReviewEnabled() == Boolean.TRUE)) {
                    throw ZMSUtils.requestError("Can not update auditEnabled and/or reviewEnabled roles", caller);
                }

                // now process the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                if (!processRole(con, originalRole, domainName, roleName, role,
                        principal, auditRef, false, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put role: " + role.getName(), caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        roleName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutGroup(ResourceContext ctx, final String domainName, final String groupName, Group group, final String auditRef) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, ctx.getApiName(), principal, AUDIT_TYPE_GROUP);

                // check that quota is not exceeded

                quotaCheck.checkGroupQuota(con, domainName, group, ctx.getApiName());

                // retrieve our original group

                Group originalGroup = getGroup(con, domainName, groupName, false, false);

                if (originalGroup != null &&
                        (originalGroup.getAuditEnabled() == Boolean.TRUE || originalGroup.getReviewEnabled() == Boolean.TRUE)) {
                    throw ZMSUtils.requestError("Can not update auditEnabled and/or reviewEnabled groups", ctx.getApiName());
                }

                // now process the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                if (!processGroup(con, originalGroup, domainName, groupName, group,
                        principal, auditRef, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put group: " + group.getName(), ctx.getApiName());
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), ZMSConsts.HTTP_PUT,
                        groupName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutServiceIdentity(ResourceContext ctx, String domainName, String serviceName,
            ServiceIdentity service, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_SERVICE);

                // check that quota is not exceeded

                quotaCheck.checkServiceIdentityQuota(con, domainName, service, caller);

                // retrieve our original service identity object

                ServiceIdentity originalService = getServiceIdentity(con, domainName, serviceName, false);

                // now process the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                if (!processServiceIdentity(con, originalService, domainName, serviceName,
                        service, false, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put service: " + service.getName(), caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        serviceName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutPublicKeyEntry(ResourceContext ctx, String domainName, String serviceName,
            PublicKeyEntry keyEntry, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_SERVICE);

                // check to see if this key already exists or not

                PublicKeyEntry originalKeyEntry = con.getPublicKeyEntry(domainName, serviceName,
                        keyEntry.getId(), false);

                // now we need verify our quota check if we know that
                // that we'll be adding another public key

                if (originalKeyEntry == null) {
                    quotaCheck.checkServiceIdentityPublicKeyQuota(con, domainName, serviceName, caller);
                }

                // now process the request

                boolean requestSuccess;
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);

                if (originalKeyEntry == null) {
                    requestSuccess = con.insertPublicKeyEntry(domainName, serviceName, keyEntry);
                    auditDetails.append("{\"added-publicKeys\": [");
                } else {
                    requestSuccess = con.updatePublicKeyEntry(domainName, serviceName, keyEntry);
                    auditDetails.append("{\"updated-publicKeys\": [");
                }

                if (!requestSuccess) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put public key: " + keyEntry.getId() +
                            " in service " + ZMSUtils.serviceResourceName(domainName, serviceName), caller);
                }

                // update our service and domain time-stamp and save changes

                con.updateServiceIdentityModTimestamp(domainName, serviceName);
                saveChanges(con, domainName);

                // audit log the request

                auditLogPublicKeyEntry(auditDetails, keyEntry, true);
                auditDetails.append("]}");

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        serviceName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeletePublicKeyEntry(ResourceContext ctx, String domainName, String serviceName,
            String keyId, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_SERVICE);

                // now process the request

                if (!con.deletePublicKeyEntry(domainName, serviceName, keyId)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError("unable to delete public key: " + keyId +
                            " in service " + ZMSUtils.serviceResourceName(domainName, serviceName), caller);
                }

                // update our service and domain time-stamp and save changes

                con.updateServiceIdentityModTimestamp(domainName, serviceName);
                saveChanges(con, domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"deleted-publicKeys\": [{\"id\": \"").append(keyId).append("\"}]}");

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        serviceName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    boolean isTrustRole(Role role) {

        if (role == null) {
            return false;
        }

        return role.getTrust() != null && !role.getTrust().isEmpty();
    }

    void executePutMembership(ResourceContext ctx, String domainName, String roleName,
            RoleMember roleMember, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal, AUDIT_TYPE_ROLE);

                // make sure the role auditing requirements are met

                Role originalRole = con.getRole(domainName, roleName);
                if (originalRole == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": Unknown role: " + roleName, caller);
                }

                checkObjectAuditEnabled(con, originalRole.getAuditEnabled(), originalRole.getName(),
                        auditRef, caller, principal);

                // before inserting a member we need to verify that
                // this is a group role and not a delegated one.

                if (isTrustRole(originalRole)) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError(caller + ": " + roleName +
                            "is a delegated role", caller);
                }

                // now we need verify our quota check

                quotaCheck.checkRoleMembershipQuota(con, domainName, roleName, caller);

                // process our insert role member support. since this is a "single"
                // operation, we are not using any transactions.

                if (!con.insertRoleMember(domainName, roleName, roleMember,
                        principal, auditRef)) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError(caller + ": unable to insert role member: " +
                            roleMember.getMemberName() + " to role: " + roleName, caller);
                }

                // update our role and domain time-stamps, and invalidate local cache entry

                con.updateRoleModTimestamp(domainName, roleName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogRoleMember(auditDetails, roleMember, true);
                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT, roleName,
                        auditDetails.toString());

                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutGroupMembership(ResourceContext ctx, final String domainName, Group group,
                                   GroupMember groupMember, final String auditRef) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, ctx.getApiName(), principal, AUDIT_TYPE_GROUP);

                // make sure the group auditing requirements are met

                checkObjectAuditEnabled(con, group.getAuditEnabled(), group.getName(),
                        auditRef, ctx.getApiName(), principal);

                // now we need verify our quota check

                final String groupName = ZMSUtils.extractGroupName(domainName, group.getName());
                quotaCheck.checkGroupMembershipQuota(con, domainName, groupName, ctx.getApiName());

                // process our insert group member support. since this is a "single"
                // operation, we are not using any transactions.

                if (!con.insertGroupMember(domainName, groupName, groupMember, principal, auditRef)) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError("unable to insert group member: " +
                            groupMember.getMemberName() + " to group: " + groupName, ctx.getApiName());
                }

                // update our group and domain time-stamps, and invalidate local cache entry

                con.updateGroupModTimestamp(domainName, groupName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogGroupMember(auditDetails, groupMember, true);
                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), ZMSConsts.HTTP_PUT, groupName,
                        auditDetails.toString());

                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutEntity(ResourceContext ctx, String domainName, String entityName,
            Entity entity, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_ENTITY);

                // check that quota is not exceeded

                quotaCheck.checkEntityQuota(con, domainName, entity, caller);

                // check to see if this key already exists or not

                Entity originalEntity = con.getEntity(domainName, entityName);

                // now process the request

                boolean requestSuccess;
                if (originalEntity == null) {
                    requestSuccess = con.insertEntity(domainName, entity);
                } else {
                    requestSuccess = con.updateEntity(domainName, entity);
                }

                if (!requestSuccess) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put entity: "
                            + entity.getName(), caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        entity.getName(), JSON.string(entity.getValue()));

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteMembership(ResourceContext ctx, String domainName, String roleName,
            String normalizedMember, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal, AUDIT_TYPE_ROLE);

                // if this is the admin role then we need to make sure
                // the admin is not himself who happens to be the last
                // member in the role

                if (ZMSConsts.ADMIN_ROLE_NAME.equals(roleName)) {
                    List<RoleMember> members = con.listRoleMembers(domainName, roleName, false);
                    if (members.size() == 1 && members.get(0).getMemberName().equals(normalizedMember)) {
                        throw ZMSUtils.forbiddenError(caller +
                                ": Cannot delete last member of 'admin' role", caller);
                    }
                }

                // process our delete role member operation

                if (!con.deleteRoleMember(domainName, roleName, normalizedMember,
                        principal, auditRef)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to delete role member: " +
                            normalizedMember + " from role: " + roleName, caller);
                }

                // update our role and domain time-stamps, and invalidate local cache entry

                con.updateRoleModTimestamp(domainName, roleName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        roleName, "{\"member\": \"" + normalizedMember + "\"}");

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeletePendingMembership(ResourceContext ctx, String domainName, String roleName,
                String normalizedMember, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal, AUDIT_TYPE_ROLE);

                // process our delete role member operation

                if (!con.deletePendingRoleMember(domainName, roleName, normalizedMember,
                        principal, auditRef)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to delete pending role member: " +
                            normalizedMember + " from role: " + roleName, caller);
                }

                // update our role and domain time-stamps, and invalidate local cache entry

                con.updateRoleModTimestamp(domainName, roleName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        roleName, "{\"pending-member\": \"" + normalizedMember + "\"}");

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteGroupMembership(ResourceContext ctx, final String domainName, final String groupName,
                                      final String normalizedMember, final String auditRef) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, ctx.getApiName(), principal, AUDIT_TYPE_GROUP);

                // process our delete group member operation

                if (!con.deleteGroupMember(domainName, groupName, normalizedMember, principal, auditRef)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError("unable to delete group member: " +
                            normalizedMember + " from group: " + groupName, ctx.getApiName());
                }

                // update our group and domain time-stamps, and invalidate local cache entry

                con.updateGroupModTimestamp(domainName, groupName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), ZMSConsts.HTTP_DELETE,
                        groupName, "{\"member\": \"" + normalizedMember + "\"}");

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeletePendingGroupMembership(ResourceContext ctx, final String domainName, final String groupName,
                                             final String normalizedMember, final String auditRef) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, ctx.getApiName(), principal, AUDIT_TYPE_GROUP);

                // process our delete pending group member operation

                if (!con.deletePendingGroupMember(domainName, groupName, normalizedMember, principal, auditRef)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError("unable to delete pending group member: " +
                            normalizedMember + " from group: " + groupName, ctx.getApiName());
                }

                // update our group and domain time-stamps, and invalidate local cache entry

                con.updateGroupModTimestamp(domainName, groupName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), ZMSConsts.HTTP_DELETE,
                        groupName, "{\"pending-member\": \"" + normalizedMember + "\"}");

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteServiceIdentity(ResourceContext ctx, String domainName, String serviceName,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_SERVICE);

                // process our delete service request

                if (!con.deleteServiceIdentity(domainName, serviceName)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to delete service: " + serviceName, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        serviceName, null);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteEntity(ResourceContext ctx, String domainName, String entityName,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_ENTITY);

                // process our delete role request

                if (!con.deleteEntity(domainName, entityName)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to delete entity: " + entityName, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        entityName, null);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteRole(ResourceContext ctx, String domainName, String roleName,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_ROLE);

                // process our delete role request

                if (!con.deleteRole(domainName, roleName)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to delete role: " + roleName, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        roleName, null);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteGroup(ResourceContext ctx, final String domainName, final String groupName, final String auditRef) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, ctx.getApiName(), getPrincipalName(ctx), AUDIT_TYPE_GROUP);

                // process our delete group request

                if (!con.deleteGroup(domainName, groupName)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError("unable to delete group: " + groupName, ctx.getApiName());
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), ZMSConsts.HTTP_DELETE,
                        groupName, null);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeletePolicy(ResourceContext ctx, String domainName, String policyName,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // process our delete policy request

                if (!con.deletePolicy(domainName, policyName)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to delete policy: " + policyName, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        policyName, null);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    /**
     * If the domain has audit enabled, and user did not provide the auditRef,
     * an exception will be thrown
     **/
    void checkDomainAuditEnabled(ObjectStoreConnection con, final String domainName,
            final String auditRef, final String caller, final String principal, int objectType) {

        // before retrieving the domain details make sure we are
        // configured to enforce audit reference field on the given
        // object type

        if (!auditRefSet.get(objectType)) {
            return;
        }

        Domain domain = con.getDomain(domainName);
        if (domain == null) {
            con.rollbackChanges();
            throw ZMSUtils.notFoundError(caller + ": Unknown domain: " + domainName, caller);
        }

        auditReferenceCheck(con, domain, auditRef, caller, principal);
    }

    void checkDomainAuditEnabled(ObjectStoreConnection con, Domain domain,
            final String auditRef, final String caller, final String principal, int objectType) {

        if (!auditRefSet.get(objectType)) {
            return;
        }

        auditReferenceCheck(con, domain, auditRef, caller, principal);
    }

    void auditReferenceCheck(ObjectStoreConnection con, Domain domain, final String auditRef,
            final String caller, final String principal) {

        if (domain.getAuditEnabled() == Boolean.TRUE) {
            if (auditRef == null || auditRef.length() == 0) {
                con.rollbackChanges();
                throw ZMSUtils.requestError(caller + ": Audit reference required for domain: " + domain.getName(), caller);
            }

            if (auditReferenceValidator != null && !auditReferenceValidator.validateReference(auditRef, principal, caller)) {
                con.rollbackChanges();
                throw ZMSUtils.requestError(caller + ": Audit reference validation failed for domain: " + domain.getName() + ", auditRef: " + auditRef, caller);
            }
        }
    }

    void executeDeleteDomain(ResourceContext ctx, String domainName, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_DOMAIN);

                // now process the request

                con.deleteDomain(domainName);
                con.commitChanges();
                cacheStore.invalidate(domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        domainName, null);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    List<String> listPrincipals(String domainName, boolean domainOnly) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {

            List<String> principals = con.listPrincipals(domainName);

            // if no further filtering is necessary, return the data
            // right away

            if (!domainOnly) {
                return principals;
            }

            // generate our return list

            List<String> users = new ArrayList<>();

            // if we're asked for domain only then we need to match
            // the domain name, if specified, and make sure the response
            // only includes a single period/domain separator
            // we need to skip an extra byte to accommodate for the
            // domain separator (e.g. <domainName>.<userName>)

            int prefixLength = 0;
            if (domainName != null) {
                prefixLength = domainName.length() + 1;
            }

            for (String principal : principals) {

                // make sure the principal name doesn't have multiple
                // components - e.g. user.joe.test since it represents
                // a service or a sub-domain and we're only interested
                // in actual users

                if (prefixLength > 0) {
                    if (principal.substring(prefixLength).indexOf('.') == -1) {
                        users.add(principal);
                    }
                } else {

                    // we have a single separator when the first index
                    // and the last index are the same

                    if (principal.indexOf('.') == principal.lastIndexOf('.')) {
                        users.add(principal);
                    }
                }
            }

            return users;
        }
    }

    void removePrincipalFromDomainRoles(ObjectStoreConnection con, String domainName, String principalName,
            String adminUser, String auditRef) {

        // extract all the roles that this principal is member of
        // we have to this here so that there are records of
        // entries in the role member audit logs and the domain
        // entries are properly invalidated

        List<PrincipalRole> roles = con.listPrincipalRoles(domainName, principalName);

        // we want to check if we had any roles otherwise
        // we don't want to update the domain mod timestamp

        if (roles.isEmpty()) {
            return;
        }

        for (PrincipalRole role : roles) {

            final String roleName = role.getRoleName();

            // process our delete role member operation

            if (LOG.isDebugEnabled()) {
                LOG.debug("removePrincipalFromDomainRoles: removing member {} from {}:role.{}",
                        principalName, domainName, roleName);
            }

            // we are going to ignore all errors here rather than
            // rejecting the full operation

            try {
                con.deleteRoleMember(domainName, roleName, principalName, adminUser, auditRef);
            } catch (ResourceException ex) {
                LOG.error("removePrincipalFromDomainRoles: unable to remove {} from {}:role.{} - error {}",
                        principalName, domainName, roleName, ex.getMessage());
            }

            // update our role and domain time-stamps, and invalidate local cache entry

            con.updateRoleModTimestamp(domainName, roleName);
        }

        con.updateDomainModTimestamp(domainName);
    }

    void removePrincipalFromAllRoles(ObjectStoreConnection con, String principalName,
            String adminUser, String auditRef) {

        // extract all the roles that this principal is member of
        // we have to this here so that there are records of
        // entries in the role member audit logs and the domain
        // entries are properly invalidated

        List<PrincipalRole> roles;
        try {
            roles = con.listPrincipalRoles(null, principalName);
        } catch (ResourceException ex) {

            // if there is no such principal then we have nothing to do

            if (ex.getCode() == ResourceException.NOT_FOUND) {
                return;
            } else {
                throw ex;
            }
        }

        for (PrincipalRole role : roles) {

            final String domainName = role.getDomainName();
            final String roleName = role.getRoleName();

            // process our delete role member operation

            if (LOG.isDebugEnabled()) {
                LOG.debug("removePrincipalFromAllRoles: removing member {} from {}:role.{}",
                        principalName, domainName, roleName);
            }

            // we are going to ignore all errors here rather than
            // rejecting the full operation. our delete user will
            // eventually remove all these principals

            try {
                con.deleteRoleMember(domainName, roleName, principalName, adminUser, auditRef);
            } catch (ResourceException ex) {
                LOG.error("removePrincipalFromAllRoles: unable to remove {} from {}:role.{} - error {}",
                        principalName, domainName, roleName, ex.getMessage());
            }

            // update our role and domain time-stamps, and invalidate local cache entry

            con.updateRoleModTimestamp(domainName, roleName);
            con.updateDomainModTimestamp(domainName);
        }
    }

    void removePrincipalDomains(ObjectStoreConnection con, String principalName) {

        // first we're going to retrieve the list domains for
        // the given user

        final String domainPrefix = principalName + ".";
        List<String> subDomains = con.listDomains(domainPrefix, 0);

        // first we're going to delete the user domain if
        // one exists and then all the sub-domains. We're not
        // going to fail the operation for these steps - only
        // if the actual user is not deleted

        con.deleteDomain(principalName);
        cacheStore.invalidate(principalName);

        for (String subDomain : subDomains) {
            con.deleteDomain(subDomain);
            cacheStore.invalidate(subDomain);
        }
    }

    void executeDeleteDomainRoleMember(ResourceContext ctx, String domainName,
             String memberName, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                // remove this user from all roles manually so that we
                // can have an audit log record for each role

                removePrincipalFromDomainRoles(con, domainName, memberName,
                        getPrincipalName(ctx), auditRef);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        memberName, null);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteUser(ResourceContext ctx, String userName, String domainName,
             String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                // remove all principal domains

                removePrincipalDomains(con, domainName);

                // extract all principals that this user has - this would
                // include the user self plus all services this user
                // has created in the personal domain + sub-domains

                List<String> userSvcPrincipals = con.listPrincipals(domainName);

                // remove this user from all roles manually so that we
                // can have an audit log record for each role

                final String adminPrincipal = getPrincipalName(ctx);
                removePrincipalFromAllRoles(con, userName, adminPrincipal, auditRef);
                for (String userSvcPrincipal : userSvcPrincipals) {
                    removePrincipalFromAllRoles(con, userSvcPrincipal, adminPrincipal, auditRef);
                }

                // finally delete the principal object. any roles that were
                // left behind will be cleaned up from this operation

                if (!con.deletePrincipal(userName, true)) {
                    throw ZMSUtils.notFoundError(caller + ": unable to delete user: "
                            + userName, caller);
                }

                // audit log the request

                auditLogRequest(ctx, userName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        userName, null);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    ServiceIdentity getServiceIdentity(String domainName, String serviceName, boolean attrsOnly) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return getServiceIdentity(con, domainName, serviceName, attrsOnly);
        }
    }

    DomainTemplateList listDomainTemplates(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            DomainTemplateList domainTemplateList = new DomainTemplateList();
            domainTemplateList.setTemplateNames(con.listDomainTemplates(domainName));
            return domainTemplateList;
        }
    }

    ServiceIdentity getServiceIdentity(ObjectStoreConnection con, String domainName,
            String serviceName, boolean attrsOnly) {

        ServiceIdentity service = con.getServiceIdentity(domainName, serviceName);
        if (service != null && !attrsOnly) {
            service.setPublicKeys(con.listPublicKeys(domainName, serviceName));
            List<String> hosts = con.listServiceHosts(domainName, serviceName);
            if (hosts != null && !hosts.isEmpty()) {
                service.setHosts(hosts);
            }
        }
        return service;
    }

    PublicKeyEntry getPublicKeyFromCache(String domainName, String serviceName, String keyId) {

        DataCache data = cacheStore.getIfPresent(domainName);
        if (data == null) {
            return null;
        }

        AthenzDomain athenzDomain = data.getAthenzDomain();
        if (athenzDomain == null) {
            return null;
        }

        List<ServiceIdentity> services = athenzDomain.getServices();
        if (services == null) {
            return null;
        }

        final String fullServiceName = ZMSUtils.serviceResourceName(domainName, serviceName);
        for (ServiceIdentity service : services) {
            if (fullServiceName.equals(service.getName())) {
                List<PublicKeyEntry> publicKeys = service.getPublicKeys();
                if (publicKeys != null) {
                    for (PublicKeyEntry publicKey : publicKeys) {
                        if (keyId.equals(publicKey.getId())) {
                            return publicKey;
                        }
                    }
                }
                break;
            }
        }

        return null;
    }

    PublicKeyEntry getServicePublicKeyEntry(String domainName, String serviceName,
            String keyId, boolean domainStateCheck) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.getPublicKeyEntry(domainName, serviceName, keyId, domainStateCheck);
        } catch (ResourceException ex) {
            if (ex.getCode() != ResourceException.SERVICE_UNAVAILABLE) {
                throw ex;
            }
        }

        // if we got this far it means we couldn't get our public key
        // from our DB store either due to timeout or communication
        // error so we're going to see if we have the public key in
        // our cache and use that for our requests

        PublicKeyEntry keyEntry = getPublicKeyFromCache(domainName, serviceName, keyId);
        if (keyEntry == null) {
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE,
                    "Unable to retrieve public key from DB store");
        }
        return keyEntry;
    }

    public ResourceAccessList getResourceAccessList(String principal, String action) {

        // this commands takes a quite a bit of time due to joining tables
        // and needs to be optimized. For now we'll configure it with
        // default timeout of 30 minutes to avoid any issues

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            con.setOperationTimeout(1800);
            return con.listResourceAccess(principal, action, zmsConfig.getUserDomain());
        }
    }

    Domain getDomain(String domainName, boolean masterCopy) {

        try (ObjectStoreConnection con = store.getConnection(true, masterCopy)) {
            return con.getDomain(domainName);
        }
    }

    List<String> listDomains(String prefix, long modifiedSince, boolean masterCopy) {

        try (ObjectStoreConnection con = store.getConnection(true, masterCopy)) {
            return con.listDomains(prefix, modifiedSince);
        }
    }

    DomainList lookupDomainById(final String account, final String subscription, int productId) {

        DomainList domList = new DomainList();
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            String domain = con.lookupDomainById(account, subscription, productId);
            if (domain != null) {
                domList.setNames(Collections.singletonList(domain));
            }
        }
        return domList;
    }

    DomainList lookupDomainByAWSAccount(String account) {
        return lookupDomainById(account, null, 0);
    }

    DomainList lookupDomainByAzureSubscription(String subscription) {
        return lookupDomainById(null, subscription, 0);
    }

    DomainList lookupDomainByProductId(Integer productId) {
        return lookupDomainById(null, null, productId);
    }

    DomainList lookupDomainByRole(String roleMember, String roleName) {

        DomainList domList = new DomainList();
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            domList.setNames(con.lookupDomainByRole(roleMember, roleName));
        }
        return domList;
    }

    List<String> listRoles(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.listRoles(domainName);
        }
    }

    Membership getMembership(String domainName, String roleName, String principal,
            long expiryTimestamp, boolean pending) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            Membership membership = con.getRoleMember(domainName, roleName, principal, expiryTimestamp, pending);
            Timestamp expiration = membership.getExpiration();

            //need to check expiration and set isMember if expired

            if (expiration != null && expiration.millis() < System.currentTimeMillis()) {
                membership.setIsMember(false);
            }

            return membership;
        }
    }

    GroupMembership getGroupMembership(final String domainName, final String groupName, final String principal,
                                       long expiryTimestamp, boolean pending) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            GroupMembership membership = con.getGroupMember(domainName, groupName, principal, expiryTimestamp, pending);
            Timestamp expiration = membership.getExpiration();

            //need to check expiration and set isMember if expired

            if (expiration != null && expiration.millis() < System.currentTimeMillis()) {
                membership.setIsMember(false);
            }

            return membership;
        }
    }

    DomainRoleMembers listDomainRoleMembers(String domainName) {
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.listDomainRoleMembers(domainName);
        }
    }

    DomainRoleMember getPrincipalRoles(String principal, String domainName) {
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.getPrincipalRoles(principal, domainName);
        }
    }

    DomainGroupMember getPrincipalGroups(String principal, String domainName) {
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.getPrincipalGroups(principal, domainName);
        }
    }

    Group getGroup(final String domainName, final String groupName, Boolean auditLog, Boolean pending) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return getGroup(con, domainName, groupName, auditLog, pending);
        }
    }

    Group getGroup(ObjectStoreConnection con, final String domainName, final String groupName,
                 Boolean auditLog, Boolean pending) {

        Group group = con.getGroup(domainName, groupName);
        if (group == null) {
            return null;
        }

        // let's retrieve our standard group members

        group.setGroupMembers(con.listGroupMembers(domainName, groupName, pending));

        if (auditLog == Boolean.TRUE) {
            group.setAuditLog(con.listGroupAuditLogs(domainName, groupName));
        }

        return group;
    }

    Role getRole(String domainName, String roleName, Boolean auditLog, Boolean expand, Boolean pending) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return getRole(con, domainName, roleName, auditLog, expand, pending);
        }
    }

    Timestamp memberStrictExpiration(Timestamp groupExpiration, Timestamp memberExpiration) {
        if (groupExpiration == null) {
            return memberExpiration;
        } else if (memberExpiration == null) {
            return groupExpiration;
        } else if (groupExpiration.millis() < memberExpiration.millis()) {
            return groupExpiration;
        } else {
            return memberExpiration;
        }
    }

    RoleMember convertGroupToRoleMember(GroupMember groupMember, Timestamp groupExpiration) {
        return new RoleMember()
                .setMemberName(groupMember.getMemberName())
                .setActive(groupMember.getActive())
                .setApproved(groupMember.getApproved())
                .setAuditRef(groupMember.getAuditRef())
                .setSystemDisabled(groupMember.getSystemDisabled())
                .setRequestTime(groupMember.getRequestTime())
                .setExpiration(memberStrictExpiration(groupExpiration, groupMember.getExpiration()));
    }

    void expandRoleGroupMembers(ObjectStoreConnection con, Role role, List<RoleMember> roleMembers, Boolean pending) {

        List<RoleMember> expandedMembers = new ArrayList<>();
        for (RoleMember roleMember : roleMembers) {
            final String memberName = roleMember.getMemberName();

            int idx = memberName.indexOf(AuthorityConsts.GROUP_SEP);
            if (idx == -1) {
                expandedMembers.add(roleMember);
            } else {
                final String domainName = memberName.substring(0, idx);
                final String groupName = memberName.substring(idx + AuthorityConsts.GROUP_SEP.length());
                List<GroupMember> groupMembers = con.listGroupMembers(domainName, groupName, pending);
                for (GroupMember groupMember : groupMembers) {
                    expandedMembers.add(convertGroupToRoleMember(groupMember, roleMember.getExpiration()));
                }
            }
        }
        role.setRoleMembers(expandedMembers);
    }

    Role getRole(ObjectStoreConnection con, String domainName, String roleName,
            Boolean auditLog, Boolean expand, Boolean pending) {

        Role role = con.getRole(domainName, roleName);
        if (role != null) {

            if (role.getTrust() == null) {

                // if we have no trust field specified then we need to
                // retrieve our standard group role members. However,
                // since we can have groups as members in roles check
                // to see if we're asked to expand them

                if (expand == Boolean.TRUE) {
                    expandRoleGroupMembers(con, role, con.listRoleMembers(domainName, roleName, pending), pending);
                } else {
                    role.setRoleMembers(con.listRoleMembers(domainName, roleName, pending));
                }

                if (auditLog == Boolean.TRUE) {
                    role.setAuditLog(con.listRoleAuditLogs(domainName, roleName));
                }

            } else if (expand == Boolean.TRUE) {

                // otherwise, if asked, let's expand the delegated
                // membership and return the list of members

                role.setRoleMembers(getDelegatedRoleMembers(con, domainName, role.getTrust(), roleName));
            }

            Map<String, StringList> roleTags = con.getRoleTags(domainName, roleName);
            if (roleTags != null) {
                role.setTags(roleTags);
            }
        }
        return role;
    }

    List<RoleMember> getDelegatedRoleMembers(ObjectStoreConnection con, final String domainName,
                                             final String trustDomain, final String roleName) {

        // verify that the domain and trust domain are not the same

        if (domainName.equals(trustDomain)) {
            return null;
        }

        // retrieve our trust domain

        AthenzDomain domain = null;
        try {
            domain = getAthenzDomain(con, trustDomain);
        } catch (ResourceException ex) {
            LOG.error("unable to fetch domain {}: {}", trustDomain, ex.getMessage());
        }

        if (domain == null) {
            return null;
        }

        // we need to use a set since we might be matching
        // multiple assertions and we want to automatically
        // skip any duplicate members

        Map<String, RoleMember> roleMembers = new HashMap<>();

        // generate our full role name

        String fullRoleName = ZMSUtils.roleResourceName(domainName, roleName);

        // iterate through all policies to see which one has the
        // assume_role assertion for the given role

        for (Policy policy : domain.getPolicies()) {

            List<Assertion> assertions = policy.getAssertions();
            if (assertions == null) {
                continue;
            }

            for (Assertion assertion : assertions) {

                if (!AuthzHelper.assumeRoleResourceMatch(fullRoleName, assertion)) {
                    continue;
                }

                String rolePattern = StringUtils.patternFromGlob(assertion.getRole());
                for (Role role : domain.getRoles()) {

                    // make sure we have members before trying to match the name

                    List<RoleMember> members = role.getRoleMembers();
                    if (members == null || members.isEmpty()) {
                        continue;
                    }

                    if (!role.getName().matches(rolePattern)) {
                        continue;
                    }

                    for (RoleMember member : members) {
                        String memberName = member.getMemberName();
                        if (!roleMembers.containsKey(memberName)) {
                            roleMembers.put(memberName, member);
                        }
                    }
                }
            }
        }

        return new ArrayList<>(roleMembers.values());
    }

    Policy getPolicy(String domainName, String policyName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return getPolicy(con, domainName, policyName);
        }
    }

    Assertion getAssertion(String domainName, String policyName, Long assertionId) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.getAssertion(domainName, policyName, assertionId);
        }
    }

    void executePutAssertion(ResourceContext ctx, String domainName, String policyName,
            Assertion assertion, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // now we need verify our quota check

                quotaCheck.checkPolicyAssertionQuota(con, domainName, policyName, caller);

                // process our insert assertion. since this is a "single"
                // operation, we are not using any transactions.

                if (!con.insertAssertion(domainName, policyName, assertion)) {
                    throw ZMSUtils.requestError(caller + ": unable to insert assertion: " +
                            " to policy: " + policyName, caller);
                }

                // update our policy and domain time-stamps, and invalidate local cache entry

                con.updatePolicyModTimestamp(domainName, policyName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogAssertion(auditDetails, assertion, true);

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        policyName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteAssertion(ResourceContext ctx, String domainName, String policyName,
            Long assertionId, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // process our delete assertion. since this is a "single"
                // operation, we are not using any transactions.

                if (!con.deleteAssertion(domainName, policyName, assertionId)) {
                    throw ZMSUtils.requestError(caller + ": unable to delete assertion: " +
                            assertionId + " from policy: " + policyName, caller);
                }

                // update our policy and domain time-stamps, and invalidate local cache entry

                con.updatePolicyModTimestamp(domainName, policyName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                final String auditDetails = "{\"policy\": \"" + policyName +
                        "\", \"assertionId\": \"" + assertionId + "\"}";
                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        policyName, auditDetails);

                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    List<String> listEntities(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.listEntities(domainName);
        }
    }

    Entity getEntity(String domainName, String entityName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.getEntity(domainName, entityName);
        }
    }

    Policy getPolicy(ObjectStoreConnection con, String domainName, String policyName) {

        Policy policy = con.getPolicy(domainName, policyName);
        if (policy != null) {
            policy.setAssertions(con.listAssertions(domainName, policyName));
        }
        return policy;
    }

    List<String> listPolicies(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.listPolicies(domainName, null);
        }
    }

    List<String> listServiceIdentities(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.listServiceIdentities(domainName);
        }
    }

    void executePutDomainMeta(ResourceContext ctx, String domainName, DomainMeta meta,
            final String systemAttribute, boolean deleteAllowed, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                Domain domain = con.getDomain(domainName);
                if (domain == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": Unknown domain: " + domainName, caller);
                }

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domain, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_DOMAIN);

                // now process the request. first we're going to make a
                // copy of our domain

                Domain updatedDomain = new Domain()
                        .setName(domain.getName())
                        .setEnabled(domain.getEnabled())
                        .setId(domain.getId())
                        .setAuditEnabled(domain.getAuditEnabled())
                        .setDescription(domain.getDescription())
                        .setOrg(domain.getOrg())
                        .setApplicationId(domain.getApplicationId())
                        .setAccount(domain.getAccount())
                        .setAzureSubscription(domain.getAzureSubscription())
                        .setYpmId(domain.getYpmId())
                        .setCertDnsDomain(domain.getCertDnsDomain())
                        .setMemberExpiryDays(domain.getMemberExpiryDays())
                        .setServiceExpiryDays(domain.getServiceExpiryDays())
                        .setGroupExpiryDays(domain.getGroupExpiryDays())
                        .setTokenExpiryMins(domain.getTokenExpiryMins())
                        .setRoleCertExpiryMins(domain.getRoleCertExpiryMins())
                        .setServiceCertExpiryMins(domain.getServiceCertExpiryMins())
                        .setSignAlgorithm(domain.getSignAlgorithm())
                        .setUserAuthorityFilter(domain.getUserAuthorityFilter());

                // then we're going to apply the updated fields
                // from the given object

                if (systemAttribute != null) {
                    updateSystemMetaFields(updatedDomain, systemAttribute, deleteAllowed, meta);
                } else {
                    updateDomainMetaFields(updatedDomain, meta);
                }

                con.updateDomain(updatedDomain);
                con.commitChanges();
                cacheStore.invalidate(domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogDomain(auditDetails, updatedDomain);

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        domainName, auditDetails.toString());

                // if the domain member expiry date has changed then we're going
                // process all the members in the domain and update the expiration
                // date accordingly

                updateDomainMembersExpiration(ctx, con, domain, updatedDomain, auditRef, caller);

                // if the domain user attribute expiry has changed we need to
                // process all the members in the domain accordingly

                updateDomainMembersUserAuthorityFilter(ctx, con, domain, updatedDomain, auditRef, caller);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void updateDomainMembersUserAuthorityFilter(ResourceContext ctx, ObjectStoreConnection con, Domain domain,
                                               Domain updatedDomain, String auditRef, String caller) {

        // check if the authority filter has changed otherwise we have
        // nothing to do

        if (!isUserAuthorityFilterChanged(domain.getUserAuthorityFilter(), updatedDomain.getUserAuthorityFilter())) {
            return;
        }

        final String domainName = domain.getName();
        AthenzDomain athenzDomain;
        try {
            athenzDomain = getAthenzDomain(con, domainName);
        } catch (ResourceException ex) {
            LOG.error("unable to fetch domain {}: {}", domainName, ex.getMessage());
            return;
        }

        final String principal = getPrincipalName(ctx);
        for (Role role : athenzDomain.getRoles()) {

            // if it's a delegated role then we have nothing to do

            if (role.getTrust() != null && !role.getTrust().isEmpty()) {
                continue;
            }

            // if no role members, then there is nothing to do

            final List<RoleMember> roleMembers = role.getRoleMembers();
            if (roleMembers == null || roleMembers.isEmpty()) {
                continue;
            }

            // process our role members and if there were any changes processed then update
            // our role and domain time-stamps, and invalidate local cache entry

            final String roleName = AthenzUtils.extractRoleName(role.getName());
            List<RoleMember> roleMembersWithUpdatedDisabledState = getRoleMembersWithUpdatedDisabledState(roleMembers,
                    role.getUserAuthorityFilter(), updatedDomain.getUserAuthorityFilter());
            if (updateRoleMemberDisabledState(ctx, con, roleMembersWithUpdatedDisabledState, domainName,
                    roleName, principal, auditRef, caller)) {

                // update our role and domain time-stamps, and invalidate local cache entry

                con.updateRoleModTimestamp(domainName, roleName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);
            }
        }
    }

    void updateDomainMembersExpiration(ResourceContext ctx, ObjectStoreConnection con, Domain domain,
            Domain updatedDomain, String auditRef, String caller) {

        // we only need to process the domain role members if the new expiration
        // is more restrictive than what we had before

        boolean userMemberExpiryDayReduced = isNumOfDaysReduced(domain.getMemberExpiryDays(),
                updatedDomain.getMemberExpiryDays());
        boolean serviceMemberExpiryDayReduced = isNumOfDaysReduced(domain.getServiceExpiryDays(),
                updatedDomain.getServiceExpiryDays());

        if (!userMemberExpiryDayReduced && !serviceMemberExpiryDayReduced) {
            return;
        }

        AthenzDomain athenzDomain;
        try {
            athenzDomain = getAthenzDomain(con, domain.getName());
        } catch (ResourceException ex) {
            LOG.error("unable to fetch domain {}: {}", domain.getName(), ex.getMessage());
            return;
        }

        long userExpiryMillis = userMemberExpiryDayReduced ? System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(updatedDomain.getMemberExpiryDays(), TimeUnit.DAYS) : 0;
        long serviceExpiryMillis = serviceMemberExpiryDayReduced ? System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(updatedDomain.getServiceExpiryDays(), TimeUnit.DAYS) : 0;
        Timestamp userExpiration = Timestamp.fromMillis(userExpiryMillis);
        Timestamp serviceExpiration = Timestamp.fromMillis(serviceExpiryMillis);
        final String principal = getPrincipalName(ctx);

        for (Role role : athenzDomain.getRoles()) {

            // if the role already has a specific expiry date set then we
            // will automatically skip this role

            if (role.getMemberExpiryDays() != null || role.getServiceExpiryDays() != null) {
                continue;
            }

            // if it's a delegated role then we have nothing to do

            if (role.getTrust() != null && !role.getTrust().isEmpty()) {
                continue;
            }

            // if no role members, then there is nothing to do

            final List<RoleMember> roleMembers = role.getRoleMembers();
            if (roleMembers == null || roleMembers.isEmpty()) {
                continue;
            }

            // process our role members and if there were any changes processed then update
            // our role and domain time-stamps, and invalidate local cache entry

            final String roleName = AthenzUtils.extractRoleName(role.getName());
            List<RoleMember> roleMembersWithUpdatedDueDates = getRoleMembersWithUpdatedDueDates(roleMembers,
                    userExpiration, userExpiryMillis, serviceExpiration, serviceExpiryMillis,
                    null, 0, null, 0, null);
            if (insertRoleMembers(ctx, con, roleMembersWithUpdatedDueDates, domain.getName(),
                    roleName, principal, auditRef, caller)) {

                // update our role and domain time-stamps, and invalidate local cache entry

                con.updateRoleModTimestamp(domain.getName(), roleName);
                con.updateDomainModTimestamp(domain.getName());
                cacheStore.invalidate(domain.getName());
            }
        }
    }

    void updateDomainMetaFields(Domain domain, DomainMeta meta) {

        domain.setApplicationId(meta.getApplicationId());
        domain.setDescription(meta.getDescription());
        if (meta.getMemberExpiryDays() != null) {
            domain.setMemberExpiryDays(meta.getMemberExpiryDays());
        }
        if (meta.getServiceExpiryDays() != null) {
            domain.setServiceExpiryDays(meta.getServiceExpiryDays());
        }
        if (meta.getGroupExpiryDays() != null) {
            domain.setGroupExpiryDays(meta.getGroupExpiryDays());
        }
        if (meta.getRoleCertExpiryMins() != null) {
            domain.setRoleCertExpiryMins(meta.getRoleCertExpiryMins());
        }
        if (meta.getServiceCertExpiryMins() != null) {
            domain.setServiceCertExpiryMins(meta.getServiceCertExpiryMins());
        }
        if (meta.getTokenExpiryMins() != null) {
            domain.setTokenExpiryMins(meta.getTokenExpiryMins());
        }
        if (meta.getSignAlgorithm() != null) {
            domain.setSignAlgorithm(meta.getSignAlgorithm());
        }
    }

    boolean isDeleteSystemMetaAllowed(boolean deleteAllowed, final String oldValue, final String newValue) {

        // if authorized or old value is not set, then there is
        // no need to check any value

        if (deleteAllowed || oldValue == null || oldValue.isEmpty()) {
            return true;
        }

        // since our old value is not null then we will only
        // allow if the new value is identical

        return (newValue != null) ? oldValue.equals(newValue) : false;
    }

    boolean isDeleteSystemMetaAllowed(boolean deleteAllowed, Integer oldValue, Integer newValue) {

        // if authorized or old value is not set, then there is
        // no need to check any value

        if (deleteAllowed || oldValue == null || oldValue == 0) {
            return true;
        }

        // since our old value is not null then we will only
        // allow if the new value is identical

        return (newValue != null) ? newValue.intValue() == oldValue.intValue() : false;
    }

    void updateSystemMetaFields(Domain domain, final String attribute, boolean deleteAllowed,
            DomainMeta meta) {

        final String caller = "putdomainsystemmeta";

        // system attributes we'll only set if they're available
        // in the given object

        switch (attribute) {
            case ZMSConsts.SYSTEM_META_ACCOUNT:
                if (!isDeleteSystemMetaAllowed(deleteAllowed, domain.getAccount(), meta.getAccount())) {
                    throw ZMSUtils.forbiddenError("unauthorized to reset system meta attribute: " + attribute, caller);
                }
                domain.setAccount(meta.getAccount());
                break;
            case ZMSConsts.SYSTEM_META_AZURE_SUBSCRIPTION:
                if (!isDeleteSystemMetaAllowed(deleteAllowed, domain.getAzureSubscription(), meta.getAzureSubscription())) {
                    throw ZMSUtils.forbiddenError("unauthorized to reset system meta attribute: " + attribute, caller);
                }
                domain.setAzureSubscription(meta.getAzureSubscription());
                break;
            case ZMSConsts.SYSTEM_META_PRODUCT_ID:
                if (!isDeleteSystemMetaAllowed(deleteAllowed, domain.getYpmId(), meta.getYpmId())) {
                    throw ZMSUtils.forbiddenError("unauthorized to reset system meta attribute: " + attribute, caller);
                }
                domain.setYpmId(meta.getYpmId());
                break;
            case ZMSConsts.SYSTEM_META_CERT_DNS_DOMAIN:
                if (!isDeleteSystemMetaAllowed(deleteAllowed, domain.getCertDnsDomain(), meta.getCertDnsDomain())) {
                    throw ZMSUtils.forbiddenError("unauthorized to reset system meta attribute: " + attribute, caller);
                }
                domain.setCertDnsDomain(meta.getCertDnsDomain());
                break;
            case ZMSConsts.SYSTEM_META_ORG:
                if (!isDeleteSystemMetaAllowed(deleteAllowed, domain.getOrg(), meta.getOrg())) {
                    throw ZMSUtils.forbiddenError("unauthorized to reset system meta attribute: " + attribute, caller);
                }
                domain.setOrg(meta.getOrg());
                break;
            case ZMSConsts.SYSTEM_META_AUDIT_ENABLED:
                domain.setAuditEnabled(meta.getAuditEnabled());
                break;
            case ZMSConsts.SYSTEM_META_USER_AUTH_FILTER:
                domain.setUserAuthorityFilter(meta.getUserAuthorityFilter());
                break;
            case ZMSConsts.SYSTEM_META_ENABLED:
                domain.setEnabled(meta.getEnabled());
                break;
            default:
                throw ZMSUtils.requestError("unknown system meta attribute: " + attribute, caller);
        }
    }

    void updateRoleSystemMetaFields(ObjectStoreConnection con, Role updatedRole, Role originalRole,
                                    final String attribute, RoleSystemMeta meta, final String caller) {

        // system attributes we'll only set if they're available
        // in the given object

        if (ZMSConsts.SYSTEM_META_AUDIT_ENABLED.equals(attribute)) {
            updatedRole.setAuditEnabled(meta.getAuditEnabled());

            // we also need to verify that if we have any group members
            // then those groups have the audit enabled flag as well

            if (updatedRole.getAuditEnabled() == Boolean.TRUE && originalRole.getRoleMembers() != null) {
                for (RoleMember roleMember : originalRole.getRoleMembers()) {
                    final String memberName = roleMember.getMemberName();
                    if (ZMSUtils.principalType(memberName, zmsConfig.getUserDomainPrefix(),
                            zmsConfig.getAddlUserCheckDomainPrefixList()) != Principal.Type.GROUP) {
                        continue;
                    }

                    int idx = memberName.indexOf(AuthorityConsts.GROUP_SEP);
                    final String domainName = memberName.substring(0, idx);
                    final String groupName = memberName.substring(idx + AuthorityConsts.GROUP_SEP.length());
                    Group group = con.getGroup(domainName, groupName);
                    if (group == null) {
                        throw ZMSUtils.requestError("role has invalid group member: " + memberName, caller);
                    }
                    if (group.getAuditEnabled() != Boolean.TRUE) {
                        throw ZMSUtils.requestError("role member: " + memberName + " must have audit flag enabled", caller);
                    }
                }
            }
        } else {
            throw ZMSUtils.requestError("unknown role system meta attribute: " + attribute, caller);
        }
    }

    void updateGroupSystemMetaFields(Group group, final String attribute, GroupSystemMeta meta, final String caller) {

        // system attributes we'll only set if they're available
        // in the given object

        if (ZMSConsts.SYSTEM_META_AUDIT_ENABLED.equals(attribute)) {
            group.setAuditEnabled(meta.getAuditEnabled());
        } else {
            throw ZMSUtils.requestError("unknown group system meta attribute: " + attribute, caller);
        }
    }

    void updateServiceIdentitySystemMetaFields(ServiceIdentity service, final String attribute,
            ServiceIdentitySystemMeta meta, final String caller) {

        // system attributes we'll only set if they're available
        // in the given object

        if (ZMSConsts.SYSTEM_META_PROVIDER_ENDPOINT.equals(attribute)) {
            service.setProviderEndpoint(meta.getProviderEndpoint());
        } else {
            throw ZMSUtils.requestError("unknown service system meta attribute: " + attribute, caller);
        }
    }

    void executePutDomainTemplate(ResourceContext ctx, String domainName, DomainTemplate domainTemplate,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_TEMPLATE);

                // go through our list of templates and add the specified
                // roles and polices to our domain

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"add-templates\": ");
                boolean firstEntry = true;

                for (String templateName : domainTemplate.getTemplateNames()) {
                    firstEntry = auditLogSeparator(auditDetails, firstEntry);
                    if (!addSolutionTemplate(con, domainName, templateName, getPrincipalName(ctx),
                            domainTemplate.getParams(), auditRef, auditDetails)) {
                        con.rollbackChanges();
                        throw ZMSUtils.internalServerError("unable to put domain templates: " + domainName, caller);
                    }
                }
                auditDetails.append("}");

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        domainName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteDomainTemplate(ResourceContext ctx, String domainName, String templateName,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_TEMPLATE);

                // go through our list of templates and add the specified
                // roles and polices to our domain

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"templates\": ");

                Template template = zmsConfig.getServerSolutionTemplates().get(templateName);
                if (!deleteSolutionTemplate(con, domainName, templateName, template, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to delete domain template: " + domainName, caller);
                }

                auditDetails.append("}");

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        domainName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    boolean addSolutionTemplate(ObjectStoreConnection con, String domainName, String templateName,
            String admin, List<TemplateParam> templateParams, String auditRef, StringBuilder auditDetails) {

        auditDetails.append("{\"name\": \"").append(templateName).append('\"');

        // we have already verified that our template is valid but
        // we'll just double check to make sure it's not null

        Template template = zmsConfig.getServerSolutionTemplates().get(templateName);
        if (template == null) {
            auditDetails.append("}");
            return true;
        }

        boolean firstEntry = true;

        // iterate through roles in the list.
        // When adding a template, if the role does not exist in our domain
        // then insert it otherwise only apply the changes to the member list.

        List<Role> templateRoles = template.getRoles();
        if (templateRoles != null) {
            for (Role role : templateRoles) {

                Role templateRole = updateTemplateRole(role, domainName, templateParams);

                String roleName = ZMSUtils.removeDomainPrefix(templateRole.getName(),
                    domainName, ROLE_PREFIX);

                // retrieve our original role

                Role originalRole = getRole(con, domainName, roleName, false, false, false);

                // Merge original role with template role to handle role meta data
                // if original role is null then it is an insert operation and no need of merging

                if (originalRole != null) {
                    mergeOriginalRoleAndMetaRoleAttributes(originalRole, templateRole);
                }

                // now process the request

                firstEntry = auditLogSeparator(auditDetails, firstEntry);
                auditDetails.append(" \"add-role\": ");
                if (!processRole(con, originalRole, domainName, roleName, templateRole,
                        admin, auditRef, true, auditDetails)) {
                    return false;
                }
            }
        }

        // iterate through policies in the list.
        // When adding a template, if the policy does not exist in our domain
        // then insert it otherwise only apply the changes to the assertions

        List<Policy> templatePolicies = template.getPolicies();
        if (templatePolicies != null) {
            for (Policy policy : templatePolicies) {

                Policy templatePolicy = updateTemplatePolicy(policy, domainName, templateParams);

                String policyName = ZMSUtils.removeDomainPrefix(templatePolicy.getName(),
                    domainName, POLICY_PREFIX);

                // retrieve our original policy

                Policy originalPolicy = getPolicy(con, domainName, policyName);

                // now process the request

                firstEntry = auditLogSeparator(auditDetails, firstEntry);
                auditDetails.append(" \"add-policy\": ");
                if (!processPolicy(con, originalPolicy, domainName, policyName, templatePolicy,
                        true, auditDetails)) {
                    return false;
                }
            }
        }

        // iterate through service identities in the list.
        // When adding a template, if the service identity does not exist in our domain
        // then insert it otherwise only apply the changes

        List<ServiceIdentity> templateServiceIdentities = template.getServices();
        if (templateServiceIdentities != null) {
            for (ServiceIdentity serviceIdentity : templateServiceIdentities) {

                ServiceIdentity templateServiceIdentity = updateTemplateServiceIdentity(
                        serviceIdentity, domainName, templateParams);

                String serviceIdentityName = ZMSUtils.removeDomainPrefixForService(
                        templateServiceIdentity.getName(), domainName);

                // retrieve our original service

                ServiceIdentity originalServiceIdentity = getServiceIdentity(con, domainName,
                        serviceIdentityName, false);

                // now process the request

                firstEntry = auditLogSeparator(auditDetails, firstEntry);
                auditDetails.append(" \"add-service\": ");
                if (!processServiceIdentity(con, originalServiceIdentity, domainName,
                        serviceIdentityName, templateServiceIdentity, true, auditDetails)) {
                    return false;
                }
            }
        }

        // if adding a template, only add if it is not in our current list
        // check to see if the template is already listed for the domain

        List<String> currentTemplateList = con.listDomainTemplates(domainName);
        if (!currentTemplateList.contains(templateName)) {
            con.insertDomainTemplate(domainName, templateName, null);
        }

        //on both insert and update templates, bump up the version of the template to latest version.
        if (template.getMetadata().getLatestVersion() != null) {
            con.updateDomainTemplate(domainName, templateName, template.getMetadata());
        }

        auditDetails.append("}");
        return true;
    }

    boolean deleteSolutionTemplate(ObjectStoreConnection con, String domainName, String templateName,
            Template template, StringBuilder auditDetails) {

        // currently there is no support for dynamic templates since the
        // DELETE request has no payload and we can't pass our parameters

        auditDetails.append("{\"name\": \"").append(templateName).append('\"');

        // we have already verified that our template is valid but
        // we'll just double check to make sure it's not null

        if (template == null) {
            auditDetails.append("}");
            return true;
        }

        boolean firstEntry = true;

        // iterate through roles in the list and delete the role

        List<Role> templateRoles = template.getRoles();
        if (templateRoles != null) {
            for (Role role : templateRoles) {
                String roleName = ZMSUtils.removeDomainPrefix(role.getName(),
                    TEMPLATE_DOMAIN_NAME, ROLE_PREFIX);

                con.deleteRole(domainName, roleName);
                firstEntry = auditLogSeparator(auditDetails, firstEntry);
                auditDetails.append(" \"delete-role\": \"").append(roleName).append('\"');
            }
        }

        // iterate through policies in the list and delete the policy

        List<Policy> templatePolicies = template.getPolicies();
        if (templatePolicies != null) {
            for (Policy policy : templatePolicies) {
                String policyName = ZMSUtils.removeDomainPrefix(policy.getName(),
                    TEMPLATE_DOMAIN_NAME, POLICY_PREFIX);

                con.deletePolicy(domainName, policyName);
                firstEntry = auditLogSeparator(auditDetails, firstEntry);
                auditDetails.append(" \"delete-policy\": \"").append(policyName).append('\"');
            }
        }

        // iterate through services in the list and delete the service

        List<ServiceIdentity> templateServices = template.getServices();
        if (templateServices != null) {
            for (ServiceIdentity serviceIdentity : templateServices) {
                String serviceName = ZMSUtils.removeDomainPrefixForService(serviceIdentity.getName(),
                    TEMPLATE_DOMAIN_NAME);
                con.deleteServiceIdentity(domainName, serviceName);
                firstEntry = auditLogSeparator(auditDetails, firstEntry);
                auditDetails.append(" \"delete-service\": \"").append(serviceName).append('\"');
            }
        }

        // delete the template from the current list

        con.deleteDomainTemplate(domainName, templateName, null);

        auditDetails.append("}");
        return true;
    }

    Role updateTemplateRole(Role role, String domainName, List<TemplateParam> params) {

        // first process our given role name and carry out any
        // requested substitutions

        String templateRoleName = role.getName().replace(TEMPLATE_DOMAIN_NAME, domainName);
        if (params != null) {
            for (TemplateParam param : params) {
                final String paramKey = "_" + param.getName() + "_";
                templateRoleName = templateRoleName.replace(paramKey, param.getValue());
            }
        }
        Role templateRole = new Role()
                .setName(templateRoleName)
                .setTrust(role.getTrust())
                //adding additional role meta attributes if present in template->roles
                .setCertExpiryMins(role.getCertExpiryMins())
                .setSelfServe(role.getSelfServe())
                .setMemberExpiryDays(role.getMemberExpiryDays())
                .setTokenExpiryMins(role.getTokenExpiryMins())
                .setSignAlgorithm(role.getSignAlgorithm())
                .setServiceExpiryDays(role.getServiceExpiryDays())
                .setGroupExpiryDays(role.getGroupExpiryDays())
                .setMemberReviewDays(role.getMemberReviewDays())
                .setServiceReviewDays(role.getServiceReviewDays())
                .setReviewEnabled(role.getReviewEnabled())
                .setNotifyRoles(role.getNotifyRoles())
                .setUserAuthorityFilter(role.getUserAuthorityFilter())
                .setUserAuthorityExpiration(role.getUserAuthorityExpiration());

        List<RoleMember> roleMembers = role.getRoleMembers();
        List<RoleMember> newMembers = new ArrayList<>();
        if (roleMembers != null && !roleMembers.isEmpty()) {
            for (RoleMember roleMember : roleMembers) {
                RoleMember newRoleMember = new RoleMember();

                // process our role members for any requested substitutions

                String memberName = roleMember.getMemberName().replace(TEMPLATE_DOMAIN_NAME, domainName);
                if (params != null) {
                    for (TemplateParam param : params) {
                        final String paramKey = "_" + param.getName() + "_";
                        memberName = memberName.replace(paramKey, param.getValue());
                    }
                }
                newRoleMember.setMemberName(memberName);
                newRoleMember.setExpiration(roleMember.getExpiration());
                newMembers.add(newRoleMember);
            }
        }
        templateRole.setRoleMembers(newMembers);
        return templateRole;
    }

    Policy updateTemplatePolicy(Policy policy, String domainName, List<TemplateParam> params) {

        // first process our given role name and carry out any
        // requested substitutions

        String templatePolicyName = policy.getName().replace(TEMPLATE_DOMAIN_NAME, domainName);
        if (params != null) {
            for (TemplateParam param : params) {
                final String paramKey = "_" + param.getName() + "_";
                templatePolicyName = templatePolicyName.replace(paramKey, param.getValue());
            }
        }

        Policy templatePolicy = new Policy().setName(templatePolicyName);
        List<Assertion> assertions = policy.getAssertions();
        List<Assertion> newAssertions = new ArrayList<>();
        if (assertions != null && !assertions.isEmpty()) {
            for (Assertion assertion : assertions) {
                Assertion newAssertion = new Assertion();
                newAssertion.setAction(assertion.getAction());
                newAssertion.setEffect(assertion.getEffect());

                // process our assertion resource and role for any requested substitutions

                String resource = assertion.getResource().replace(TEMPLATE_DOMAIN_NAME, domainName);
                String role = assertion.getRole().replace(TEMPLATE_DOMAIN_NAME, domainName);
                if (params != null) {
                    for (TemplateParam param : params) {
                        final String paramKey = "_" + param.getName() + "_";
                        resource = resource.replace(paramKey, param.getValue());
                        role = role.replace(paramKey, param.getValue());
                    }
                }
                newAssertion.setResource(resource);
                newAssertion.setRole(role);
                newAssertions.add(newAssertion);
            }
        }
        templatePolicy.setAssertions(newAssertions);
        return templatePolicy;
    }

    ServiceIdentity updateTemplateServiceIdentity(ServiceIdentity serviceIdentity,
            String domainName, List<TemplateParam> params) {

        String templateServiceName = serviceIdentity.getName().replace(TEMPLATE_DOMAIN_NAME, domainName);
        if (params != null) {
            for (TemplateParam param : params) {
                final String paramKey = "_" + param.getName() + "_";
                templateServiceName = templateServiceName.replace(paramKey, param.getValue());
            }
        }

        ServiceIdentity templateServiceIdentity = new ServiceIdentity().setName(templateServiceName);

        templateServiceIdentity.setDescription(serviceIdentity.getDescription());
        templateServiceIdentity.setExecutable(serviceIdentity.getExecutable());
        templateServiceIdentity.setGroup(serviceIdentity.getGroup());
        templateServiceIdentity.setUser(serviceIdentity.getUser());
        templateServiceIdentity.setProviderEndpoint(serviceIdentity.getProviderEndpoint());

        List<PublicKeyEntry> publicKeyEntries = serviceIdentity.getPublicKeys();
        List<PublicKeyEntry> newPublicKeyEntries = new ArrayList<>();
        if (publicKeyEntries != null && !publicKeyEntries.isEmpty()) {
            for (PublicKeyEntry publicKeyEntry : publicKeyEntries) {
                PublicKeyEntry newPublicKeyEntry = new PublicKeyEntry();
                newPublicKeyEntry.setId(publicKeyEntry.getId());
                newPublicKeyEntry.setKey(publicKeyEntry.getKey());
                newPublicKeyEntries.add(newPublicKeyEntry);
            }
        }
        templateServiceIdentity.setPublicKeys(newPublicKeyEntries);

        List<String> hosts = serviceIdentity.getHosts();

        if (hosts != null) {
            templateServiceIdentity.setHosts(new ArrayList<>(hosts));
        }

        return templateServiceIdentity;
    }

    void setupTenantAdminPolicy(String tenantDomain, String provSvcDomain,
            String provSvcName, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, tenantDomain, auditRef, caller, provSvcDomain + "." + provSvcName, AUDIT_TYPE_TENANCY);

                String domainAdminRole = ZMSUtils.roleResourceName(tenantDomain, ZMSConsts.ADMIN_ROLE_NAME);
                String serviceRoleResourceName = ZMSUtils.getTrustedResourceGroupRolePrefix(provSvcDomain,
                        provSvcName, tenantDomain, null) + ZMSConsts.ADMIN_ROLE_NAME;

                // our tenant admin role/policy name

                final String tenancyResource = "tenancy." + provSvcDomain + '.' + provSvcName;

                String adminName = tenancyResource + ".admin";
                String tenantAdminRole = ZMSUtils.roleResourceName(tenantDomain, adminName);

                // tenant admin role - if it already exists then we skip it
                // by default it has no members.

                if (con.getRole(tenantDomain, adminName) == null) {
                    con.insertRole(tenantDomain, new Role().setName(tenantAdminRole));
                }

                // tenant admin policy - check to see if this already exists. If it does
                // then we don't have anything to do

                if (con.getPolicy(tenantDomain, adminName) == null) {

                    Policy adminPolicy = new Policy().setName(ZMSUtils.policyResourceName(tenantDomain, adminName));
                    con.insertPolicy(tenantDomain, adminPolicy);

                    // we are going to create 2 assertions - one for the domain admin role
                    // and another for the tenant admin role

                    Assertion assertion = new Assertion().setRole(domainAdminRole)
                            .setResource(serviceRoleResourceName).setAction(ZMSConsts.ACTION_ASSUME_ROLE)
                            .setEffect(AssertionEffect.ALLOW);
                    con.insertAssertion(tenantDomain, adminName, assertion);

                    assertion = new Assertion().setRole(tenantAdminRole)
                            .setResource(serviceRoleResourceName).setAction(ZMSConsts.ACTION_ASSUME_ROLE)
                            .setEffect(AssertionEffect.ALLOW);
                    con.insertAssertion(tenantDomain, adminName, assertion);

                    // the tenant admin role must have the capability to provision
                    // new resource groups in the domain which requires update
                    // action capability on resource tenancy.<prov_domain>.<prov_svc>

                    String tenantResourceName = tenantDomain + ":" + tenancyResource;
                    assertion = new Assertion().setRole(tenantAdminRole)
                            .setResource(tenantResourceName).setAction(ZMSConsts.ACTION_UPDATE)
                            .setEffect(AssertionEffect.ALLOW);
                    con.insertAssertion(tenantDomain, adminName, assertion);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, tenantDomain);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutTenantRoles(ResourceContext ctx, String provSvcDomain, String provSvcName, String tenantDomain,
            String resourceGroup, List<TenantRoleAction> roles, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, provSvcDomain, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_TENANCY);

                String trustedRolePrefix = ZMSUtils.getTrustedResourceGroupRolePrefix(provSvcDomain,
                        provSvcName, tenantDomain, resourceGroup);

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"put-tenant-roles\": [");
                boolean firstEntry = true;

                for (TenantRoleAction ra : roles) {

                    String tenantRole = ra.getRole();
                    String tenantAction = ra.getAction();
                    String trustedRole = trustedRolePrefix + tenantRole;
                    String trustedName = trustedRole.substring((provSvcDomain + AuthorityConsts.ROLE_SEP).length());

                    Role role = new Role().setName(trustedRole).setTrust(tenantDomain);

                    if (LOG.isInfoEnabled()) {
                        LOG.info(caller + ": add trusted Role to domain " + provSvcDomain +
                                ": " + trustedRole + " -> " + role);
                    }

                    // retrieve our original role in case one exists

                    Role originalRole = getRole(con, provSvcDomain, trustedName, false, false, false);

                    // now process the request

                    firstEntry = auditLogSeparator(auditDetails, firstEntry);

                    auditDetails.append("{\"role\": ");
                    if (!processRole(con, originalRole, provSvcDomain, trustedName, role,
                            getPrincipalName(ctx), auditRef, false, auditDetails)) {
                        con.rollbackChanges();
                        throw ZMSUtils.internalServerError("unable to put role: " + trustedRole, caller);
                    }

                    String policyResourceName = ZMSUtils.policyResourceName(provSvcDomain, trustedName);
                    final String resourceName = provSvcDomain + ":service." +
                            ZMSUtils.getTenantResourceGroupRolePrefix(provSvcName, tenantDomain, resourceGroup) + '*';
                    List<Assertion> assertions = Collections.singletonList(
                            new Assertion().setRole(trustedRole)
                                    .setResource(resourceName)
                                    .setAction(tenantAction));

                    Policy policy = new Policy().setName(policyResourceName).setAssertions(assertions);

                    if (LOG.isInfoEnabled()) {
                        LOG.info(caller + ": add trust policy to domain " + provSvcDomain +
                                ": " + trustedRole + " -> " + policy);
                    }

                    // retrieve our original policy

                    Policy originalPolicy = getPolicy(con, provSvcDomain, trustedName);

                    // now process the request

                    auditDetails.append(", \"policy\": ");
                    if (!processPolicy(con, originalPolicy, provSvcDomain, trustedName, policy, false, auditDetails)) {
                        con.rollbackChanges();
                        throw ZMSUtils.internalServerError("unable to put policy: " + policy.getName(), caller);
                    }
                    auditDetails.append('}');
                }

                // update our domain time-stamp and save changes

                saveChanges(con, provSvcDomain);

                // audit log the request

                auditLogRequest(ctx, provSvcDomain, auditRef, caller, ZMSConsts.HTTP_PUT,
                        tenantDomain, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void addAssumeRolePolicy(ObjectStoreConnection con, String rolePrefix,
            String trustedRolePrefix, String role, List<RoleMember> roleMembers,
            String tenantDomain, String admin, String auditRef,
            StringBuilder auditDetails, String caller) {

        // first create the role in the domain. We're going to create it
        // only if the role does not already exist

        String roleName = rolePrefix + role;
        String roleResourceName = ZMSUtils.roleResourceName(tenantDomain, roleName);

        // retrieve our original role in case one exists

        Role originalRole = getRole(con, tenantDomain, roleName, false, false, false);

        // we need to add the original role members to the new one

        if (originalRole != null && originalRole.getRoleMembers() != null) {
            roleMembers.addAll(originalRole.getRoleMembers());
        }

        // now process the request

        Role roleObj = new Role().setName(roleResourceName).setRoleMembers(roleMembers);
        auditDetails.append("{\"role\": ");
        if (!processRole(con, originalRole, tenantDomain, roleName, roleObj,
                admin, auditRef, false, auditDetails)) {
            con.rollbackChanges();
            throw ZMSUtils.internalServerError("unable to put role: " + roleName, caller);
        }

        // now create the corresponding policy. We're going to create it
        // only if the policy does not exist otherwise we'll just
        // add a new assertion

        String policyName = "tenancy." + roleName;
        String policyResourceName = ZMSUtils.policyResourceName(tenantDomain, policyName);
        String serviceRoleResourceName = trustedRolePrefix + role;
        Assertion assertion = new Assertion().setRole(roleResourceName)
                .setResource(serviceRoleResourceName).setAction(ZMSConsts.ACTION_ASSUME_ROLE)
                .setEffect(AssertionEffect.ALLOW);

        if (LOG.isInfoEnabled()) {
            LOG.info("executePutProviderRoles: ---- ASSUME_ROLE policyName is " + policyName);
        }

        // retrieve our original policy

        Policy originalPolicy = getPolicy(con, tenantDomain, policyName);

        // we need to add the original policy assertions to the new one

        List<Assertion> newAssertions = new ArrayList<>();
        if (originalPolicy != null && originalPolicy.getAssertions() != null) {
            newAssertions.addAll(originalPolicy.getAssertions());
        }

        // if our new assertion is not already in the list then that will be added to

        if (!newAssertions.contains(assertion)) {
            newAssertions.add(assertion);
        }

        // now process the request

        Policy assumeRolePolicy = new Policy().setName(policyResourceName).setAssertions(newAssertions);

        auditDetails.append(", \"policy\": ");
        if (!processPolicy(con, originalPolicy, tenantDomain, policyName, assumeRolePolicy,
                false, auditDetails)) {
            con.rollbackChanges();
            throw ZMSUtils.internalServerError("unable to put policy: " +
                    assumeRolePolicy.getName(), caller);
        }
        auditDetails.append('}');
    }

    void executePutProviderRoles(ResourceContext ctx, String tenantDomain, String provSvcDomain,
            String provSvcName, String resourceGroup, List<String> roles, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, tenantDomain, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_TENANCY);

                // we're going to create a separate role for each one of tenant roles returned
                // based on its action and set the caller as a member in each role

                final String principalName = getPrincipalName(ctx);

                // now set up the roles and policies for all the provider roles returned.

                final String rolePrefix = ZMSUtils.getProviderResourceGroupRolePrefix(provSvcDomain,
                        provSvcName, resourceGroup);
                final String trustedRolePrefix = ZMSUtils.getTrustedResourceGroupRolePrefix(provSvcDomain,
                        provSvcName, tenantDomain, resourceGroup);

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"put-provider-roles\": [");
                boolean firstEntry = true;

                for (String role : roles) {

                    // we need to create a new object for each role since the list is updated
                    // in case the role already has existing members, but we don't want to
                    // add those members to other roles in our list

                    List<RoleMember> roleMembers = new ArrayList<>();
                    if (principalName != null) {
                        RoleMember roleMember = new RoleMember();
                        roleMember.setMemberName(principalName);
                        roleMembers.add(roleMember);
                    }

                    role = role.toLowerCase();

                    if (LOG.isInfoEnabled()) {
                        LOG.info("executePutProviderRoles: provision ASSUME_ROLE policy for access remote role in "
                                + provSvcDomain + "." + provSvcName + ": " + resourceGroup + "." + role);
                    }

                    firstEntry = auditLogSeparator(auditDetails, firstEntry);

                    addAssumeRolePolicy(con, rolePrefix, trustedRolePrefix, role, roleMembers,
                            tenantDomain, principalName, auditRef, auditDetails, caller);
                }

                auditDetails.append("]}");

                // update our domain time-stamp and save changes

                saveChanges(con, tenantDomain);

                // audit log the request

                auditLogRequest(ctx, tenantDomain, auditRef, caller, ZMSConsts.HTTP_PUT,
                        provSvcDomain, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteTenancy(ResourceContext ctx, String tenantDomain, String provSvcDomain,
            String provSvcName, String resourceGroup, String auditRef, String caller) {

        // create list of policies and delete them from the tenant domain
        // have to get all policies that match "tenant.<provider>.*"
        // ex: tenancy.weather.storage.admin

        String rnamePrefix = ZMSUtils.getProviderResourceGroupRolePrefix(provSvcDomain, provSvcName,
                resourceGroup);

        final String pnamePrefix = "tenancy." + rnamePrefix;

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, tenantDomain, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_TENANCY);

                // first let's process and remove any policies that start with our
                // provider prefix

                List<String> pnames = con.listPolicies(tenantDomain, null);

                for (String pname : pnames) {

                    if (!validResourceGroupObjectToDelete(pname, pnamePrefix)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(caller + ": --ignore policy " + pname);
                        }
                        continue;
                    }

                    if (LOG.isInfoEnabled()) {
                        LOG.info(caller + ": --delete policy " + pname);
                    }

                    con.deletePolicy(tenantDomain, pname);
                }

                // now we're going to find any roles that have the provider prefix as
                // well but we're going to be careful about removing them. We'll check
                // and if we have no more policies referencing them then we'll remove

                List<String> rnames = con.listRoles(tenantDomain);
                for (String rname : rnames) {

                    if (!validResourceGroupObjectToDelete(rname, rnamePrefix)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(caller + ": --ignore role " + rname);
                        }
                        continue;
                    }

                    if (!con.listPolicies(tenantDomain, rname).isEmpty()) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(caller + ": --ignore role " + rname + " due to active references");
                        }
                        continue;
                    }

                    if (LOG.isInfoEnabled()) {
                        LOG.info(caller + ": --delete role " + rname);
                    }

                    con.deleteRole(tenantDomain, rname);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, tenantDomain);

                // audit log the request

                auditLogRequest(ctx, tenantDomain, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        ZMSUtils.entityResourceName(provSvcDomain, provSvcName), null);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    boolean validResourceGroupObjectToDelete(String name, String prefix) {

        if (!name.startsWith(prefix)) {
            return false;
        }

        // the suffix must be the action which should only be
        // simple-name thus it cannot contain any more .'s
        // otherwise we don't want to make a mistake
        // and match substring resource groups - e.g:
        // system.engine and system.engine.test

        return (name.indexOf('.', prefix.length()) == -1);
    }

    void executeDeleteTenantRoles(ResourceContext ctx, String provSvcDomain, String provSvcName,
            String tenantDomain, String resourceGroup, String auditRef, String caller) {

        // look for this tenants roles, ex: storage.tenant.sports.reader

        String rolePrefix = ZMSUtils.getTenantResourceGroupRolePrefix(provSvcName, tenantDomain, resourceGroup);

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, provSvcDomain, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_TENANCY);

                // find roles and policies matching the prefix

                List<String> rnames = con.listRoles(provSvcDomain);

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"tenant-roles\": [");
                boolean firstEntry = true;
                for (String rname : rnames) {
                    if (isTrustRoleForTenant(con, provSvcDomain, rname, rolePrefix,
                            resourceGroup, tenantDomain)) {

                        // good, its exactly what we are looking for

                        con.deleteRole(provSvcDomain, rname);
                        con.deletePolicy(provSvcDomain, rname);
                        firstEntry = auditLogString(auditDetails, rname, firstEntry);
                    }
                }
                auditDetails.append("]}");

                // update our domain time-stamp and save changes

                saveChanges(con, provSvcDomain);

                // audit log the request

                auditLogRequest(ctx, tenantDomain, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        provSvcDomain, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    boolean isTrustRoleForTenant(ObjectStoreConnection con, String provSvcDomain, String roleName,
            String rolePrefix, String resourceGroup, String tenantDomain) {

        // first make sure the role name starts with the given prefix

        if (!isTenantRolePrefixMatch(con, roleName, rolePrefix, resourceGroup, tenantDomain)) {
            return false;
        }

        Role role = con.getRole(provSvcDomain, roleName);
        if (role == null) {
            return false;
        }

        // ensure it is a trust role for the tenant

        String trustDom = role.getTrust();
        return trustDom != null && trustDom.equals(tenantDomain);

    }

    boolean isTrustRoleForTenant(String provSvcDomain, String roleName, String rolePrefix,
            String resourceGroup, String tenantDomain) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return isTrustRoleForTenant(con, provSvcDomain, roleName, rolePrefix, resourceGroup, tenantDomain);
        }
    }

    boolean isTenantRolePrefixMatch(String roleName, String rolePrefix, String resourceGroup,
            String tenantDomain) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return isTenantRolePrefixMatch(con, roleName, rolePrefix, resourceGroup, tenantDomain);
        }
    }

    boolean isTenantRolePrefixMatch(ObjectStoreConnection con, String roleName, String rolePrefix,
            String resourceGroup, String tenantDomain) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("isTenantRolePrefixMatch: role-name=" + roleName + ", role-prefix=" +
                    rolePrefix + ", resource-group=" + resourceGroup + ", tenant-domain=" + tenantDomain);
        }

        // first make sure the role name starts with the given prefix

        if (!roleName.startsWith(rolePrefix)) {
            return false;
        }

        // if we're dealing with a resource group then we need
        // to make sure we're not going to match a substring
        // resource group. Since we expect to see a SimpleName
        // action after the name, if we get another '.' then
        // we're dealing with a substring so the role does
        // match the expected format

        if (resourceGroup != null) {
            return (roleName.indexOf('.', rolePrefix.length()) == -1);
        }

        // otherwise we're going to split the remaining value
        // into components. If we have 2 components then we'll
        // check if we have a domain for the first component
        // if we don't then it's a resource group and as such
        // it can be removed otherwise, we'll leave it alone

        String[] comps = roleName.substring(rolePrefix.length()).split("\\.");
        if (comps.length == 2) {

            // check to see if we have a subdomain - if we do then
            // we're not going to include this role as we don't know
            // for sure if this for a resource group or not

            String subDomain = tenantDomain + "." + comps[0];

            if (LOG.isDebugEnabled()) {
                LOG.debug("isTenantRolePrefixMatch: verifying tenant subdomain: " + subDomain);
            }

            return con.getDomain(subDomain) == null;

        } else {

            // if we have more than 2 subcomponents then we're
            // definitely not dealing with resource groups

            return comps.length <= 2;
        }

    }

    public AthenzDomain getAthenzDomain(final String domainName, boolean masterCopy) {

        try (ObjectStoreConnection con = store.getConnection(true, masterCopy)) {
            return getAthenzDomain(con, domainName);
        }
    }

    AthenzDomain getAthenzDomain(ObjectStoreConnection con, final String domainName) {

        // first check to see if we our data is in the cache

        AthenzDomain athenzDomain = getAthenzDomainFromCache(con, domainName);
        if (athenzDomain != null) {
            return athenzDomain;
        }

        athenzDomain = con.getAthenzDomain(domainName);
        athenzDomain.setRoleMemberPrincipalTypes(zmsConfig.getUserDomainPrefix(), zmsConfig.getAddlUserCheckDomainPrefixList());

        DataCache dataCache = new DataCache(athenzDomain,
                athenzDomain.getDomain().getModified().millis());
        cacheStore.put(domainName, dataCache);

        return athenzDomain;
    }

    DomainMetaList listModifiedDomains(long modifiedSince) {

        // since this is the operation executed by ZTS servers to
        // retrieve latest domain changes, we're going to use
        // the read-write store as oppose to read-only store to
        // get our up-to-date data

        try (ObjectStoreConnection con = store.getConnection(true, true)) {
            return con.listModifiedDomains(modifiedSince);
        }
    }

    boolean auditLogSeparator(StringBuilder auditDetails, boolean firstEntry) {
        if (!firstEntry) {
            auditDetails.append(',');
        }
        // regardless of the current state, the new state is no
        // longer the first entry so we return false
        return false;
    }

    void auditLogStrings(StringBuilder auditDetails, String label, Collection<String> values) {
        auditDetails.append(", \"").append(label).append("\": [");
        boolean firstEntry = true;
        for (String value : values) {
            firstEntry = auditLogString(auditDetails, value, firstEntry);
        }
        auditDetails.append(']');
    }

    boolean auditLogString(StringBuilder auditDetails, String value, boolean firstEntry) {
        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        auditDetails.append('\"').append(value).append('\"');
        return firstEntry;
    }

    void auditLogRoleMembers(StringBuilder auditDetails, String label,
            Collection<RoleMember> values) {
        auditDetails.append(", \"").append(label).append("\": [");
        boolean firstEntry = true;
        for (RoleMember value : values) {
            firstEntry = auditLogRoleMember(auditDetails, value, firstEntry);
        }
        auditDetails.append(']');
    }

    boolean auditLogRoleMember(StringBuilder auditDetails, RoleMember roleMember, boolean firstEntry) {
        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        auditDetails.append("{\"member\": \"").append(roleMember.getMemberName()).append('"');
        if (roleMember.getExpiration() != null) {
            auditDetails.append(", \"expiration\": \"").append(roleMember.getExpiration().toString()).append('"');
        }
        auditDetails.append(", \"approved\": ");
        auditDetails.append(roleMember.getApproved() == Boolean.FALSE ? "false" : "true");
        auditDetails.append(", \"system-disabled\": ");
        auditDetails.append(roleMember.getSystemDisabled() == null ? 0 : roleMember.getSystemDisabled());
        auditDetails.append("}");
        return firstEntry;
    }

    void auditLogGroupMembers(StringBuilder auditDetails, String label,
                             Collection<GroupMember> values) {
        auditDetails.append(", \"").append(label).append("\": [");
        boolean firstEntry = true;
        for (GroupMember value : values) {
            firstEntry = auditLogGroupMember(auditDetails, value, firstEntry);
        }
        auditDetails.append(']');
    }

    boolean auditLogGroupMember(StringBuilder auditDetails, GroupMember groupMember, boolean firstEntry) {
        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        auditDetails.append("{\"member\": \"").append(groupMember.getMemberName()).append('"');
        if (groupMember.getExpiration() != null) {
            auditDetails.append(", \"expiration\": \"").append(groupMember.getExpiration().toString()).append('"');
        }
        auditDetails.append(", \"approved\": ");
        auditDetails.append(auditLogBooleanDefault(groupMember.getApproved(), Boolean.FALSE));
        auditDetails.append(", \"system-disabled\": ");
        auditDetails.append(groupMember.getSystemDisabled() == null ? 0 : groupMember.getSystemDisabled());
        auditDetails.append("}");
        return firstEntry;
    }

    String auditLogBooleanDefault(Boolean value, Boolean checkValue) {
        if (checkValue == Boolean.TRUE) {
            return value == Boolean.TRUE ? "true" : "false";
        } else {
            return value == Boolean.FALSE ? "false" : "true";
        }
    }

    void auditLogPublicKeyEntries(StringBuilder auditDetails, String label,
            List<PublicKeyEntry> values) {
        auditDetails.append(", \"").append(label).append("\": [");
        boolean firstEntry = true;
        for (PublicKeyEntry value : values) {
            firstEntry = auditLogPublicKeyEntry(auditDetails, value, firstEntry);
        }
        auditDetails.append(']');
    }

    void auditLogPublicKeyEntries(StringBuilder auditDetails, String label, Set<String> values,
            Map<String, PublicKeyEntry> publicKeysMap) {
        auditDetails.append(", \"").append(label).append("\": [");
        boolean firstEntry = true;
        for (String value : values) {
            firstEntry = auditLogPublicKeyEntry(auditDetails, publicKeysMap.get(value), firstEntry);
        }
        auditDetails.append(']');
    }

    void auditLogPublicKeyEntries(StringBuilder auditDetails, String label, Set<String> values) {
        auditDetails.append(", \"").append(label).append("\": [");
        boolean firstEntry = true;
        for (String value : values) {
            firstEntry = auditLogPublicKeyEntry(auditDetails, value, firstEntry);
        }
        auditDetails.append(']');
    }

    boolean auditLogPublicKeyEntry(StringBuilder auditDetails, PublicKeyEntry publicKey, boolean firstEntry) {
        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        auditDetails.append("{\"key\": \"").append(publicKey.getKey())
            .append("\", \"id\": \"").append(publicKey.getId()).append("\"}");
        return firstEntry;
    }

    boolean auditLogPublicKeyEntry(StringBuilder auditDetails, String publicKeyId, boolean firstEntry) {
        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        auditDetails.append("{\"id\": \"").append(publicKeyId).append("\"}");
        return firstEntry;
    }

    void auditLogAssertions(StringBuilder auditDetails, String label, Collection<Assertion> values) {
        auditDetails.append(", \"").append(label).append("\": [");
        boolean firstEntry = true;
        for (Assertion value : values) {
            firstEntry = auditLogAssertion(auditDetails, value, firstEntry);
        }
        auditDetails.append(']');
    }

    boolean auditLogAssertion(StringBuilder auditDetails, Assertion assertion, boolean firstEntry) {
        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        String assertionEffect = "ALLOW";
        if (assertion.getEffect() != null) {
            assertionEffect = assertion.getEffect().toString();
        }
        auditDetails.append("{\"role\": \"").append(assertion.getRole())
                .append("\", \"action\": \"").append(assertion.getAction())
                .append("\", \"effect\": \"").append(assertionEffect)
                .append("\", \"resource\": \"").append(assertion.getResource())
                .append("\"}");
        return firstEntry;
    }

    void auditLogDomain(StringBuilder auditDetails, Domain domain) {
        auditDetails.append("{\"description\": \"").append(domain.getDescription())
                .append("\", \"org\": \"").append(domain.getOrg())
                .append("\", \"auditEnabled\": \"").append(domain.getAuditEnabled())
                .append("\", \"enabled\": \"").append(domain.getEnabled())
                .append("\", \"account\": \"").append(domain.getAccount())
                .append("\", \"acctId\": \"").append(domain.getApplicationId())
                .append("\", \"ypmid\": \"").append(domain.getYpmId())
                .append("\", \"id\": \"").append(domain.getId())
                .append("\", \"memberExpiryDays\": \"").append(domain.getMemberExpiryDays())
                .append("\", \"serviceExpiryDays\": \"").append(domain.getServiceExpiryDays())
                .append("\", \"tokenExpiryMins\": \"").append(domain.getTokenExpiryMins())
                .append("\", \"serviceCertExpiryMins\": \"").append(domain.getServiceCertExpiryMins())
                .append("\", \"roleCertExpiryMins\": \"").append(domain.getRoleCertExpiryMins())
                .append("\", \"signAlgorithm\": \"").append(domain.getSignAlgorithm())
                .append("\", \"userAuthorityFilter\": \"").append(domain.getUserAuthorityFilter())
                .append("\"}");
    }

    void auditLogRoleSystemMeta(StringBuilder auditDetails, Role role, String roleName) {
        auditDetails.append("{\"name\": \"").append(roleName)
                .append("\", \"auditEnabled\": \"").append(role.getAuditEnabled())
                .append("\"}");
    }

    void auditLogGroupSystemMeta(StringBuilder auditDetails, Group group, final String groupName) {
        auditDetails.append("{\"name\": \"").append(groupName)
                .append("\", \"auditEnabled\": \"").append(group.getAuditEnabled())
                .append("\"}");
    }

    void auditLogServiceIdentitySystemMeta(StringBuilder auditDetails, ServiceIdentity service, String serviceName) {
        auditDetails.append("{\"name\": \"").append(serviceName)
                .append("\", \"providerEndpoint\": \"").append(service.getProviderEndpoint())
                .append("\"}");
    }

    void auditLogRoleMeta(StringBuilder auditDetails, Role role, String roleName) {
        auditDetails.append("{\"name\": \"").append(roleName)
                .append("\", \"selfServe\": \"").append(role.getSelfServe())
                .append("\", \"memberExpiryDays\": \"").append(role.getMemberExpiryDays())
                .append("\", \"serviceExpiryDays\": \"").append(role.getServiceExpiryDays())
                .append("\", \"tokenExpiryMins\": \"").append(role.getTokenExpiryMins())
                .append("\", \"certExpiryMins\": \"").append(role.getCertExpiryMins())
                .append("\", \"memberReviewDays\": \"").append(role.getMemberReviewDays())
                .append("\", \"serviceReviewDays\": \"").append(role.getServiceReviewDays())
                .append("\", \"reviewEnabled\": \"").append(role.getReviewEnabled())
                .append("\", \"notifyRoles\": \"").append(role.getNotifyRoles())
                .append("\", \"signAlgorithm\": \"").append(role.getSignAlgorithm())
                .append("\", \"userAuthorityFilter\": \"").append(role.getUserAuthorityFilter())
                .append("\", \"userAuthorityExpiration\": \"").append(role.getUserAuthorityExpiration())
                .append("\"}");
    }

    void auditLogGroupMeta(StringBuilder auditDetails, Group group, final String groupName) {
        auditDetails.append("{\"name\": \"").append(groupName)
                .append("\", \"selfServe\": \"").append(group.getSelfServe())
                .append("\", \"reviewEnabled\": \"").append(group.getReviewEnabled())
                .append("\", \"notifyRoles\": \"").append(group.getNotifyRoles())
                .append("\", \"userAuthorityFilter\": \"").append(group.getUserAuthorityFilter())
                .append("\", \"userAuthorityExpiration\": \"").append(group.getUserAuthorityExpiration())
                .append("\"}");
    }

    void executePutQuota(ResourceContext ctx, String domainName, Quota quota,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                // process our insert quota. since this is a "single"
                // operation, we are not using any transactions.

                if (con.getQuota(domainName) != null) {
                    con.updateQuota(domainName, quota);
                } else {
                    con.insertQuota(domainName, quota);
                }

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        domainName, null);

                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteQuota(ResourceContext ctx, String domainName, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                // process our delete quota request - it's a single
                // operation so no need to make it a transaction

                if (!con.deleteQuota(domainName)) {
                    throw ZMSUtils.notFoundError(caller + ": unable to delete quota: " + domainName, caller);
                }

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        domainName, null);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    public Quota getQuota(String domainName) {
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return quotaCheck.getDomainQuota(con, domainName);
        }
    }

    public void executePutRoleSystemMeta(ResourceContext ctx, final String domainName, final String roleName,
           RoleSystemMeta meta, final String attribute, final String auditRef, final String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                Domain domain = con.getDomain(domainName);
                if (domain == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": Unknown domain: " + domainName, caller);
                }

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domain, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_ROLE);

                if (domain.getAuditEnabled() != Boolean.TRUE) {
                    throw ZMSUtils.requestError(caller + ": auditEnabled flag not set for domain: " + domainName + " to add it on the role: " + roleName, caller);
                }

                Role originalRole = getRole(con, domainName, roleName, false, false, false);

                // now process the request. first we're going to make a
                // copy of our role

                Role updatedRole = new Role()
                        .setName(originalRole.getName())
                        .setAuditEnabled(originalRole.getAuditEnabled())
                        .setTrust(originalRole.getTrust())
                        .setSelfServe(originalRole.getSelfServe())
                        .setMemberExpiryDays(originalRole.getMemberExpiryDays())
                        .setServiceExpiryDays(originalRole.getServiceExpiryDays())
                        .setGroupExpiryDays(originalRole.getGroupExpiryDays())
                        .setTokenExpiryMins(originalRole.getTokenExpiryMins())
                        .setCertExpiryMins(originalRole.getCertExpiryMins())
                        .setMemberReviewDays(originalRole.getMemberReviewDays())
                        .setServiceReviewDays(originalRole.getServiceReviewDays())
                        .setSignAlgorithm(originalRole.getSignAlgorithm())
                        .setReviewEnabled(originalRole.getReviewEnabled())
                        .setNotifyRoles(originalRole.getNotifyRoles());

                // then we're going to apply the updated fields
                // from the given object

                updateRoleSystemMetaFields(con, updatedRole, originalRole, attribute, meta, ctx.getApiName());

                con.updateRole(domainName, updatedRole);
                saveChanges(con, domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogRoleSystemMeta(auditDetails, updatedRole, roleName);

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        domainName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    public void executePutGroupSystemMeta(ResourceContext ctx, final String domainName, final String groupName,
                                          GroupSystemMeta meta, final String attribute, final String auditRef) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                Domain domain = con.getDomain(domainName);
                if (domain == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(": Unknown domain: " + domainName, ctx.getApiName());
                }

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domain, auditRef, ctx.getApiName(), getPrincipalName(ctx), AUDIT_TYPE_GROUP);

                if (domain.getAuditEnabled() != Boolean.TRUE) {
                    throw ZMSUtils.requestError("auditEnabled flag not set for domain: " + domainName +
                            " to add it on the group: " + groupName, ctx.getApiName());
                }

                Group originalGroup = getGroup(con, domainName, groupName, false, false);

                // now process the request. first we're going to make a
                // copy of our group

                Group updatedGroup = new Group()
                        .setName(originalGroup.getName())
                        .setAuditEnabled(originalGroup.getAuditEnabled())
                        .setSelfServe(originalGroup.getSelfServe())
                        .setReviewEnabled(originalGroup.getReviewEnabled())
                        .setNotifyRoles(originalGroup.getNotifyRoles());

                // then we're going to apply the updated fields
                // from the given object

                updateGroupSystemMetaFields(updatedGroup, attribute, meta, ctx.getApiName());

                con.updateGroup(domainName, updatedGroup);
                saveChanges(con, domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogGroupSystemMeta(auditDetails, updatedGroup, groupName);

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), ZMSConsts.HTTP_PUT,
                        domainName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    public void executePutServiceIdentitySystemMeta(ResourceContext ctx, String domainName, String serviceName,
            ServiceIdentitySystemMeta meta, String attribute, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                Domain domain = con.getDomain(domainName);
                if (domain == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": Unknown domain: " + domainName, caller);
                }

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domain, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_SERVICE);

                // retrieve our original service identity object

                ServiceIdentity serviceIdentity = getServiceIdentity(con, domainName, serviceName, false);

                // then we're going to apply the updated fields
                // from the given object

                updateServiceIdentitySystemMetaFields(serviceIdentity, attribute, meta, ctx.getApiName());

                con.updateServiceIdentity(domainName, serviceIdentity);
                saveChanges(con, domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogServiceIdentitySystemMeta(auditDetails, serviceIdentity, serviceName);

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        domainName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void updateRoleMetaFields(Role role, RoleMeta meta) {

        if (meta.getSelfServe() != null) {
            role.setSelfServe(meta.getSelfServe());
        }
        if (meta.getMemberExpiryDays() != null) {
            role.setMemberExpiryDays(meta.getMemberExpiryDays());
        }
        if (meta.getServiceExpiryDays() != null) {
            role.setServiceExpiryDays(meta.getServiceExpiryDays());
        }
        if (meta.getGroupExpiryDays() != null) {
            role.setGroupExpiryDays(meta.getGroupExpiryDays());
        }
        if (meta.getTokenExpiryMins() != null) {
            role.setTokenExpiryMins(meta.getTokenExpiryMins());
        }
        if (meta.getCertExpiryMins() != null) {
            role.setCertExpiryMins(meta.getCertExpiryMins());
        }
        if (meta.getSignAlgorithm() != null) {
            role.setSignAlgorithm(meta.getSignAlgorithm());
        }
        if (meta.getReviewEnabled() != null) {
            role.setReviewEnabled(meta.getReviewEnabled());
        }
        if (meta.getNotifyRoles() != null) {
            role.setNotifyRoles(meta.getNotifyRoles());
        }
        if (meta.getMemberReviewDays() != null) {
            role.setMemberReviewDays(meta.getMemberReviewDays());
        }
        if (meta.getServiceReviewDays() != null) {
            role.setServiceReviewDays(meta.getServiceReviewDays());
        }
        if (meta.getUserAuthorityFilter() != null) {
            role.setUserAuthorityFilter(meta.getUserAuthorityFilter());
        }
        if (meta.getUserAuthorityExpiration() != null) {
            role.setUserAuthorityExpiration(meta.getUserAuthorityExpiration());
        }
    }

    public void executePutRoleMeta(ResourceContext ctx, String domainName, String roleName, Role originalRole,
                                   RoleMeta meta, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                checkObjectAuditEnabled(con, originalRole.getAuditEnabled(), originalRole.getName(),
                        auditRef, caller, getPrincipalName(ctx));

                // now process the request. first we're going to make a
                // copy of our role

                Role updatedRole = new Role()
                        .setName(originalRole.getName())
                        .setAuditEnabled(originalRole.getAuditEnabled())
                        .setTrust(originalRole.getTrust())
                        .setSelfServe(originalRole.getSelfServe())
                        .setMemberExpiryDays(originalRole.getMemberExpiryDays())
                        .setServiceExpiryDays(originalRole.getServiceExpiryDays())
                        .setGroupExpiryDays(originalRole.getGroupExpiryDays())
                        .setTokenExpiryMins(originalRole.getTokenExpiryMins())
                        .setCertExpiryMins(originalRole.getCertExpiryMins())
                        .setMemberReviewDays(originalRole.getMemberReviewDays())
                        .setServiceReviewDays(originalRole.getServiceReviewDays())
                        .setSignAlgorithm(originalRole.getSignAlgorithm())
                        .setReviewEnabled(originalRole.getReviewEnabled())
                        .setNotifyRoles(originalRole.getNotifyRoles())
                        .setUserAuthorityFilter(originalRole.getUserAuthorityFilter())
                        .setUserAuthorityExpiration(originalRole.getUserAuthorityExpiration());

                // then we're going to apply the updated fields
                // from the given object

                updateRoleMetaFields(updatedRole, meta);

                con.updateRole(domainName, updatedRole);
                saveChanges(con, domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogRoleMeta(auditDetails, updatedRole, roleName);

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        domainName, auditDetails.toString());

                // if the role member expiry date or review date has changed then we're going
                // process all the members in the role and update the expiration and review
                // date accordingly

                updateRoleMembersDueDates(ctx, con, domainName, roleName, originalRole,
                        updatedRole, auditRef, caller);

                // if there was a change in the role user attribute filter then we need
                // to make the necessary changes as well.

                updateRoleMembersSystemDisabledState(ctx, con, domainName, roleName, originalRole,
                        updatedRole, auditRef, caller);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void updateGroupMetaFields(Group group, GroupMeta meta) {

        // these two fields have default values so after validation
        // we'll never have nulls

        group.setSelfServe(meta.getSelfServe());
        group.setReviewEnabled(meta.getReviewEnabled());

        if (meta.getNotifyRoles() != null) {
            group.setNotifyRoles(meta.getNotifyRoles());
        }
        if (meta.getUserAuthorityFilter() != null) {
            group.setUserAuthorityFilter(meta.getUserAuthorityFilter());
        }
        if (meta.getUserAuthorityExpiration() != null) {
            group.setUserAuthorityExpiration(meta.getUserAuthorityExpiration());
        }
    }

    public void executePutGroupMeta(ResourceContext ctx, final String domainName, final String groupName,
                                    GroupMeta meta, final String auditRef) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                Group originalGroup = getGroup(con, domainName, groupName, false, false);
                if (originalGroup == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError("Unknown group: " + groupName, ctx.getApiName());
                }

                checkObjectAuditEnabled(con, originalGroup.getAuditEnabled(), originalGroup.getName(),
                        auditRef, ctx.getApiName(), getPrincipalName(ctx));

                // now process the request. first we're going to make a
                // copy of our group

                Group updatedGroup = new Group()
                        .setName(originalGroup.getName())
                        .setAuditEnabled(originalGroup.getAuditEnabled())
                        .setSelfServe(originalGroup.getSelfServe())
                        .setReviewEnabled(originalGroup.getReviewEnabled())
                        .setNotifyRoles(originalGroup.getNotifyRoles())
                        .setUserAuthorityFilter(originalGroup.getUserAuthorityFilter())
                        .setUserAuthorityExpiration(originalGroup.getUserAuthorityExpiration());

                // then we're going to apply the updated fields
                // from the given object

                updateGroupMetaFields(updatedGroup, meta);

                // if either the filter or the expiry has been removed we need to make
                // sure the group is not a member in a role that requires it

                validateGroupUserAuthorityAttrRequirements(con, originalGroup, updatedGroup, ctx.getApiName());

                // update the group in the database

                con.updateGroup(domainName, updatedGroup);
                saveChanges(con, domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogGroupMeta(auditDetails, updatedGroup, groupName);

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), ZMSConsts.HTTP_PUT,
                        domainName, auditDetails.toString());

                // if the group user authority expiration attribute has changed, we're going
                // process all the members in the group and update the expiration date accordingly

                updateGroupMembersDueDates(ctx, con, domainName, groupName, originalGroup,
                        updatedGroup, auditRef);

                // if there was a change in the role user attribute filter then we need
                // to make the necessary changes as well.

                updateGroupMembersSystemDisabledState(ctx, con, domainName, groupName, originalGroup,
                        updatedGroup, auditRef);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    String getDomainUserAuthorityFilterFromMap(ObjectStoreConnection con, Map<String, String> domainFitlerMap, final String domainName) {
        String domainUserAuthorityFilter = domainFitlerMap.get(domainName);
        if (domainUserAuthorityFilter == null) {
            final String domainFilter = getDomainUserAuthorityFilter(con, domainName);
            domainUserAuthorityFilter = domainFilter == null ? "" : domainFilter;
            domainFitlerMap.put(domainName, domainUserAuthorityFilter);
        }
        return domainUserAuthorityFilter;
    }

    void validateGroupUserAuthorityAttrRequirements(ObjectStoreConnection con, Group originalGroup, Group updatedGroup,
                                                    final String caller)  {

        // check to see if the attribute filter or expiration values have been removed

        boolean filterRemoved = ZMSUtils.userAuthorityAttrMissing(originalGroup.getUserAuthorityFilter(),
                updatedGroup.getUserAuthorityFilter());
        boolean expiryRemoved = ZMSUtils.userAuthorityAttrMissing(originalGroup.getUserAuthorityExpiration(),
                updatedGroup.getUserAuthorityExpiration());

        // if nothing was removed then we're done with our checks

        if (!filterRemoved && !expiryRemoved) {
            return;
        }

        // obtain all the roles that have the given group as member
        // if we get back 404 then the group is not a member of any
        // role which is success otherwise we'll re-throw the exception

        DomainRoleMember domainRoleMember;
        try {
            domainRoleMember = con.getPrincipalRoles(updatedGroup.getName(), null);
        } catch (ResourceException ex) {
            if (ex.getCode() == ResourceException.NOT_FOUND) {
                return;
            }
            throw ex;
        }

        Map<String, String> domainFitlerMap = new HashMap<>();
        for (MemberRole memberRole : domainRoleMember.getMemberRoles()) {

            // first let's fetch the role and skip if it doesn't exist
            // (e.g. got deleted right after we run the query)

            Role role = con.getRole(memberRole.getDomainName(), memberRole.getRoleName());
            if (role == null) {
                continue;
            }

            // first process if the user attribute filter was removed

            if (filterRemoved) {

                // if the user attribute filter is removed, then we need to
                // also obtain the domain level setting

                String domainUserAuthorityFilter = getDomainUserAuthorityFilterFromMap(con, domainFitlerMap, memberRole.getDomainName());
                final String roleUserAuthorityFilter = ZMSUtils.combineUserAuthorityFilters(role.getUserAuthorityFilter(),
                        domainUserAuthorityFilter);
                if (ZMSUtils.userAuthorityAttrMissing(roleUserAuthorityFilter, updatedGroup.getUserAuthorityFilter())) {
                    throw ZMSUtils.requestError("Setting " + updatedGroup.getUserAuthorityFilter() +
                            " user authority filter on the group will not satisfy "
                            + ZMSUtils.roleResourceName(memberRole.getDomainName(), memberRole.getRoleName())
                            + " role filter requirements", caller);
                }
            }

            // now process if the expiry attribute was removed

            if (expiryRemoved) {
                if (ZMSUtils.userAuthorityAttrMissing(role.getUserAuthorityExpiration(), updatedGroup.getUserAuthorityExpiration())) {
                    throw ZMSUtils.requestError("Setting " + updatedGroup.getUserAuthorityExpiration() +
                            " user authority expiration on the group will not satisfy "
                            + ZMSUtils.roleResourceName(memberRole.getDomainName(), memberRole.getRoleName())
                            + " role expiration requirements", caller);
                }
            }
        }
    }

    private boolean isEarlierDueDate(long newDueDateMillis, Timestamp currentDueDate) {
        return newDueDateMillis != 0 && (currentDueDate == null || currentDueDate.millis() > newDueDateMillis);
    }

    int getMemberUserAuthorityState(final String roleMemberName, final String authorityFilter, int currentState) {

        boolean bUser = ZMSUtils.isUserDomainPrincipal(roleMemberName, zmsConfig.getUserDomainPrefix(),
                zmsConfig.getAddlUserCheckDomainPrefixList());

        // if we have a user then we'll check if the filter is still valid
        // for the user. for services, we just ignore from any checks

        int newState;
        if (bUser) {
            if (ZMSUtils.isUserAuthorityFilterValid(zmsConfig.getUserAuthority(), authorityFilter, roleMemberName)) {
                newState = currentState & ~ZMSConsts.ZMS_DISABLED_AUTHORITY_FILTER;
            } else {
                newState = currentState | ZMSConsts.ZMS_DISABLED_AUTHORITY_FILTER;
            }
        } else {
            newState = currentState;
        }
        return newState;
    }

    boolean updateUserAuthorityFilter(RoleMember roleMember, final String userAuthorityFilter) {

        int currentState = roleMember.getSystemDisabled() == null ? 0 : roleMember.getSystemDisabled();
        int newState = getMemberUserAuthorityState(roleMember.getMemberName(), userAuthorityFilter, currentState);

        if (newState != currentState) {
            roleMember.setSystemDisabled(newState);
            return true;
        }
        return false;
    }

    boolean updateUserAuthorityFilter(GroupMember groupMember, final String userAuthorityFilter) {

        int currentState = groupMember.getSystemDisabled() == null ? 0 : groupMember.getSystemDisabled();
        int newState = getMemberUserAuthorityState(groupMember.getMemberName(), userAuthorityFilter, currentState);

        if (newState != currentState) {
            groupMember.setSystemDisabled(newState);
            return true;
        }
        return false;
    }

    boolean updateUserAuthorityExpiry(RoleMember roleMember, final String userAuthorityExpiry) {

        // if we have a service then there is no processing taking place
        // as the service is not managed by the user authority

        if (!ZMSUtils.isUserDomainPrincipal(roleMember.getMemberName(), zmsConfig.getUserDomainPrefix(),
                zmsConfig.getAddlUserCheckDomainPrefixList())) {
            return false;
        }

        Date authorityExpiry = zmsConfig.getUserAuthority().getDateAttribute(roleMember.getMemberName(), userAuthorityExpiry);

        // if we don't have a date then we'll expiry the user right away
        // otherwise we'll set the date as imposed by the user authority

        boolean expiryDateUpdated = false;
        Timestamp memberExpiry = roleMember.getExpiration();

        if (authorityExpiry == null) {

            // we'll update the expiration date to be the current time
            // if the user doesn't have one or it's expires sometime
            // in the future

            if (memberExpiry == null || memberExpiry.millis() > System.currentTimeMillis()) {
                roleMember.setExpiration(Timestamp.fromCurrentTime());
                expiryDateUpdated = true;
            }
        } else {

            // update the expiration date if it does not match to the
            // value specified by the user authority value

            if (memberExpiry == null || memberExpiry.millis() != authorityExpiry.getTime()) {
                roleMember.setExpiration(Timestamp.fromDate(authorityExpiry));
                expiryDateUpdated = true;
            }
        }
        return expiryDateUpdated;
    }

    boolean updateUserAuthorityExpiry(GroupMember groupMember, final String userAuthorityExpiry) {

        // if we have a service then there is no processing taking place
        // as the service is not managed by the user authority

        if (!ZMSUtils.isUserDomainPrincipal(groupMember.getMemberName(), zmsConfig.getUserDomainPrefix(),
                zmsConfig.getAddlUserCheckDomainPrefixList())) {
            return false;
        }

        Date authorityExpiry = zmsConfig.getUserAuthority().getDateAttribute(groupMember.getMemberName(), userAuthorityExpiry);

        // if we don't have a date then we'll expiry the user right away
        // otherwise we'll set the date as imposed by the user authority

        boolean expiryDateUpdated = false;
        Timestamp memberExpiry = groupMember.getExpiration();

        if (authorityExpiry == null) {

            // we'll update the expiration date to be the current time
            // if the user doesn't have one or it's expires sometime
            // in the future

            if (memberExpiry == null || memberExpiry.millis() > System.currentTimeMillis()) {
                groupMember.setExpiration(Timestamp.fromCurrentTime());
                expiryDateUpdated = true;
            }
        } else {

            // update the expiration date if it does not match to the
            // value specified by the user authority value

            if (memberExpiry == null || memberExpiry.millis() != authorityExpiry.getTime()) {
                groupMember.setExpiration(Timestamp.fromDate(authorityExpiry));
                expiryDateUpdated = true;
            }
        }
        return expiryDateUpdated;
    }

    List<RoleMember> getRoleMembersWithUpdatedDisabledState(List<RoleMember> roleMembers, final String roleUserAuthorityFilter,
                                                            final String domainUserAuthorityFilter) {

        List<RoleMember> roleMembersWithUpdatedDisabledStates = new ArrayList<>();

        // combine the user and domain authority lists to have a single value

        final String userAuthorityFilter = ZMSUtils.combineUserAuthorityFilters(roleUserAuthorityFilter,
                domainUserAuthorityFilter);

        // if the authority filter is null or empty then we're going to go
        // through all of the members and remove the system disabled bit
        // set for user authority

        for (RoleMember roleMember : roleMembers) {

            int currentState = roleMember.getSystemDisabled() == null ? 0 : roleMember.getSystemDisabled();

            // if the filter is disabled then we're going through the list and
            // make sure the disabled bit for the filter is unset

            int newState;
            if (userAuthorityFilter == null) {
                newState = currentState & ~ZMSConsts.ZMS_DISABLED_AUTHORITY_FILTER;
            } else {
                newState = getMemberUserAuthorityState(roleMember.getMemberName(), userAuthorityFilter, currentState);
            }

            if (newState != currentState) {
                roleMember.setSystemDisabled(newState);
                roleMembersWithUpdatedDisabledStates.add(roleMember);
            }
        }

        return roleMembersWithUpdatedDisabledStates;
    }

    List<GroupMember> getGroupMembersWithUpdatedDisabledState(List<GroupMember> groupMembers,
                                                              final String groupUserAuthorityFilter,
                                                              final String domainUserAuthorityFilter) {

        List<GroupMember> groupMembersWithUpdatedDisabledStates = new ArrayList<>();

        // combine the user and domain authority lists to have a single value

        final String userAuthorityFilter = ZMSUtils.combineUserAuthorityFilters(groupUserAuthorityFilter,
                domainUserAuthorityFilter);

        // if the authority filter is null or empty then we're going to go
        // through all of the members and remove the system disabled bit
        // set for user authority

        for (GroupMember groupMember : groupMembers) {

            int currentState = groupMember.getSystemDisabled() == null ? 0 : groupMember.getSystemDisabled();

            // if the filter is disabled then we're going through the list and
            // make sure the disabled bit for the filter is unset

            int newState;
            if (userAuthorityFilter == null) {
                newState = currentState & ~ZMSConsts.ZMS_DISABLED_AUTHORITY_FILTER;
            } else {
                newState = getMemberUserAuthorityState(groupMember.getMemberName(), userAuthorityFilter, currentState);
            }

            if (newState != currentState) {
                groupMember.setSystemDisabled(newState);
                groupMembersWithUpdatedDisabledStates.add(groupMember);
            }
        }

        return groupMembersWithUpdatedDisabledStates;
    }

    List<GroupMember> getGroupMembersWithUpdatedDueDates(List<GroupMember> groupMembers, final String userAuthorityExpiry) {

        List<GroupMember> groupMembersWithUpdatedDueDates = new ArrayList<>();
        for (GroupMember groupMember : groupMembers) {

            boolean dueDateUpdated = false;

            if (ZMSUtils.isUserDomainPrincipal(groupMember.getMemberName(), zmsConfig.getUserDomainPrefix(),
                    zmsConfig.getAddlUserCheckDomainPrefixList())) {

                if (groupMember.getExpiration() != null && userAuthorityExpiry == null) {
                    groupMember.setExpiration(null);
                    dueDateUpdated = true;
                } else if (userAuthorityExpiry != null && updateUserAuthorityExpiry(groupMember, userAuthorityExpiry)) {
                    dueDateUpdated = true;
                }
            }

            if (dueDateUpdated) {
                groupMembersWithUpdatedDueDates.add(groupMember);
            }
        }

        return groupMembersWithUpdatedDueDates;
    }

    List<RoleMember> getRoleMembersWithUpdatedDueDates(List<RoleMember> roleMembers, Timestamp userExpiration,
            long userExpiryMillis, Timestamp serviceExpiration, long serviceExpiryMillis,
            Timestamp userReview, long userReviewMillis, Timestamp serviceReview,
            long serviceReviewMillis, final String userAuthorityExpiry) {

        List<RoleMember> roleMembersWithUpdatedDueDates = new ArrayList<>();
        for (RoleMember roleMember : roleMembers) {

            boolean bUser = ZMSUtils.isUserDomainPrincipal(roleMember.getMemberName(), zmsConfig.getUserDomainPrefix(),
                    zmsConfig.getAddlUserCheckDomainPrefixList());

            Timestamp expiration = roleMember.getExpiration();
            Timestamp reviewDate = roleMember.getReviewReminder();
            boolean dueDateUpdated = false;

            if (bUser) {
                if (isEarlierDueDate(userExpiryMillis, expiration)) {
                    roleMember.setExpiration(userExpiration);
                    dueDateUpdated = true;
                }
                if (isEarlierDueDate(userReviewMillis, reviewDate)) {
                    roleMember.setReviewReminder(userReview);
                    dueDateUpdated = true;
                }

                // if we have a user filter and/or expiry configured we need
                // to make sure that the user still satisfies the filter
                // otherwise we'll just expire the user right away

                if (userAuthorityExpiry != null && updateUserAuthorityExpiry(roleMember, userAuthorityExpiry)) {
                    dueDateUpdated = true;
                }
            } else {
                if (isEarlierDueDate(serviceExpiryMillis, expiration)) {
                    roleMember.setExpiration(serviceExpiration);
                    dueDateUpdated = true;
                }
                if (isEarlierDueDate(serviceReviewMillis, reviewDate)) {
                    roleMember.setReviewReminder(serviceReview);
                    dueDateUpdated = true;
                }
            }

            if (dueDateUpdated) {
                roleMembersWithUpdatedDueDates.add(roleMember);
            }
        }

        return roleMembersWithUpdatedDueDates;
    }

    private boolean insertRoleMembers(ResourceContext ctx, ObjectStoreConnection con, List<RoleMember> roleMembers,
                                      final String domainName, final String roleName, final String principal,
                                      final String auditRef, final String caller) {

        boolean bDataChanged = false;
        for (RoleMember roleMember : roleMembers) {
            try {
                if (!con.insertRoleMember(domainName, roleName, roleMember, principal, auditRef)) {
                    LOG.error("unable to update member {}", roleMember.getMemberName());
                    continue;
                }
            } catch (Exception ex) {
                LOG.error("unable to update member {} error: {}", roleMember.getMemberName(), ex.getMessage());
                continue;
            }

            // audit log the request

            StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            auditLogRoleMember(auditDetails, roleMember, true);
            auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT, roleName,
                    auditDetails.toString());

            bDataChanged = true;
        }

        return bDataChanged;
    }

    boolean insertGroupMembers(ResourceContext ctx, ObjectStoreConnection con, List<GroupMember> groupMembers,
                               final String domainName, final String groupName, final String principal,
                               final String auditRef, final String caller) {

        boolean bDataChanged = false;
        for (GroupMember groupMember : groupMembers) {
            try {
                if (!con.insertGroupMember(domainName, groupName, groupMember, principal, auditRef)) {
                    LOG.error("unable to update group member {}", groupMember.getMemberName());
                    continue;
                }
            } catch (Exception ex) {
                LOG.error("unable to update member {} error: {}", groupMember.getMemberName(), ex.getMessage());
                continue;
            }

            // audit log the request

            StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            auditLogGroupMember(auditDetails, groupMember, true);
            auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT, groupName,
                    auditDetails.toString());

            bDataChanged = true;
        }

        return bDataChanged;
    }

    boolean updateRoleMemberDisabledState(ResourceContext ctx, ObjectStoreConnection con, List<RoleMember> roleMembers,
                                          final String domainName, final String roleName, final String principal,
                                          final String auditRef, final String caller) {

        boolean bDataChanged = false;
        for (RoleMember roleMember : roleMembers) {
            try {
                if (!con.updateRoleMemberDisabledState(domainName, roleName, roleMember.getMemberName(), principal,
                        roleMember.getSystemDisabled(), auditRef)) {
                    LOG.error("unable to update member {}", roleMember.getMemberName());
                    continue;
                }
            } catch (Exception ex) {
                LOG.error("unable to update member {} error: {}", roleMember.getMemberName(), ex.getMessage());
                continue;
            }

            // audit log the request

            StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            auditLogRoleMember(auditDetails, roleMember, true);
            auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT, roleName,
                    auditDetails.toString());

            bDataChanged = true;
        }

        return bDataChanged;
    }

    boolean updateGroupMemberDisabledState(ResourceContext ctx, ObjectStoreConnection con, List<GroupMember> groupMembers,
                                           final String domainName, final String groupName, final String principal,
                                           final String auditRef, final String caller) {

        boolean bDataChanged = false;
        for (GroupMember groupMember : groupMembers) {
            try {
                if (!con.updateGroupMemberDisabledState(domainName, groupName, groupMember.getMemberName(), principal,
                        groupMember.getSystemDisabled(), auditRef)) {
                    LOG.error("unable to update group member {}", groupMember.getMemberName());
                    continue;
                }
            } catch (Exception ex) {
                LOG.error("unable to update group member {} error: {}", groupMember.getMemberName(), ex.getMessage());
                continue;
            }

            // audit log the request

            StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
            auditLogGroupMember(auditDetails, groupMember, true);
            auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT, groupName,
                    auditDetails.toString());

            bDataChanged = true;
        }

        return bDataChanged;
    }

    boolean isUserAuthorityExpiryChanged(String originalValue, String newValue) {

        // if we don't have a user authority defined then
        // we assume there are no changes

        if (zmsConfig.getUserAuthority() == null) {
            return false;
        }

        // first let's make sure if we're given empty strings
        // we treat them as nulls

        if (originalValue != null && originalValue.isEmpty()) {
            originalValue = null;
        }
        if (newValue != null && newValue.isEmpty()) {
            newValue = null;
        }

        // we're only concerned if the value was either set or changed
        // if the value was set and now was unset, it has no impact
        // on the existing members so we're going to treat that as
        // if the setting was not changed

        if (newValue == null) {
            return false;
        } else {
            return originalValue == null || !originalValue.equalsIgnoreCase(newValue);
        }
    }

    boolean isUserAuthorityFilterChanged(String originalValue, String newValue) {

        // if we don't have a user authority defined then
        // we assume there are no changes

        if (zmsConfig.getUserAuthority() == null) {
            return false;
        }

        // first let's make sure if we're given empty strings
        // we treat them as nulls

        if (originalValue != null && originalValue.isEmpty()) {
            originalValue = null;
        }
        if (newValue != null && newValue.isEmpty()) {
            newValue = null;
        }

        if (newValue == null && originalValue == null) {
            return false;
        } else if (newValue == null || originalValue == null) {
            return true;
        } else {
            return !originalValue.equalsIgnoreCase(newValue);
        }
    }

    void updateRoleMembersSystemDisabledState(ResourceContext ctx, ObjectStoreConnection con, final String domainName,
                                              final String roleName, Role originalRole, Role updatedRole,
                                              final String auditRef, final String caller) {

        // if it's a delegated role then we have nothing to do

        if (originalRole.getTrust() != null && !originalRole.getTrust().isEmpty()) {
            return;
        }

        // if no role members, then there is nothing to do

        final List<RoleMember> roleMembers = originalRole.getRoleMembers();
        if (roleMembers == null || roleMembers.isEmpty()) {
            return;
        }

        // check if the authority filter has changed otherwise we have
        // nothing to do

        if (!isUserAuthorityFilterChanged(originalRole.getUserAuthorityFilter(), updatedRole.getUserAuthorityFilter())) {
            return;
        }

        final String principal = getPrincipalName(ctx);

        // process our role members and if there were any changes processed then update
        // our role and domain time-stamps, and invalidate local cache entry

        List<RoleMember> roleMembersWithUpdatedDisabledState = getRoleMembersWithUpdatedDisabledState(roleMembers,
                updatedRole.getUserAuthorityFilter(), getDomainUserAuthorityFilter(con, domainName));
        if (updateRoleMemberDisabledState(ctx, con, roleMembersWithUpdatedDisabledState, domainName,
                roleName, principal, auditRef, caller)) {

            // update our role and domain time-stamps, and invalidate local cache entry

            con.updateRoleModTimestamp(domainName, roleName);
            con.updateDomainModTimestamp(domainName);
            cacheStore.invalidate(domainName);
        }
    }

    void updateGroupMembersSystemDisabledState(ResourceContext ctx, ObjectStoreConnection con, final String domainName,
                                               final String groupName, Group originalGroup, Group updatedGroup, final String auditRef) {

        // if no group members, then there is nothing to do

        final List<GroupMember> groupMembers = originalGroup.getGroupMembers();
        if (groupMembers == null || groupMembers.isEmpty()) {
            return;
        }

        // check if the authority filter has changed otherwise we have
        // nothing to do

        if (!isUserAuthorityFilterChanged(originalGroup.getUserAuthorityFilter(), updatedGroup.getUserAuthorityFilter())) {
            return;
        }

        final String principal = getPrincipalName(ctx);

        // process our group members and if there were any changes processed then update
        // our group and domain time-stamps, and invalidate local cache entry

        List<GroupMember> groupMembersWithUpdatedDisabledState = getGroupMembersWithUpdatedDisabledState(groupMembers,
                updatedGroup.getUserAuthorityFilter(), getDomainUserAuthorityFilter(con, domainName));
        if (updateGroupMemberDisabledState(ctx, con, groupMembersWithUpdatedDisabledState, domainName,
                groupName, principal, auditRef, ctx.getApiName())) {

            // update our group and domain time-stamps, and invalidate local cache entry

            con.updateGroupModTimestamp(domainName, groupName);
            con.updateDomainModTimestamp(domainName);
            cacheStore.invalidate(domainName);
        }
    }

    String getDomainUserAuthorityFilter(ObjectStoreConnection con, final String domainName) {
        Domain domain = con.getDomain(domainName);
        if (domain == null) {
            return null;
        }
        return domain.getUserAuthorityFilter();
    }

    void updateGroupMembersDueDates(ResourceContext ctx, ObjectStoreConnection con, final String domainName,
                                    final String groupName, Group originalGroup, Group updatedGroup, final String auditRef) {

        // if no group members, then there is nothing to do

        final List<GroupMember> groupMembers = originalGroup.getGroupMembers();
        if (groupMembers == null || groupMembers.isEmpty()) {
            return;
        }

        // check if the user authority expiration attribute has been
        // changed in which case we need to verify and update members
        // accordingly

        if (!isUserAuthorityExpiryChanged(originalGroup.getUserAuthorityExpiration(), updatedGroup.getUserAuthorityExpiration())) {
            return;
        }

        final String principal = getPrincipalName(ctx);

        // process our group members and if there were any changes processed then update
        // our role and domain time-stamps, and invalidate local cache entry

        final String userAuthorityExpiry = updatedGroup.getUserAuthorityExpiration();
        List<GroupMember> groupMembersWithUpdatedDueDates = getGroupMembersWithUpdatedDueDates(groupMembers, userAuthorityExpiry);
        if (insertGroupMembers(ctx, con, groupMembersWithUpdatedDueDates, domainName,
                groupName, principal, auditRef, ctx.getApiName())) {

            // update our group and domain time-stamps, and invalidate local cache entry

            con.updateGroupModTimestamp(domainName, groupName);
            con.updateDomainModTimestamp(domainName);
            cacheStore.invalidate(domainName);
        }
    }

    void updateRoleMembersDueDates(ResourceContext ctx, ObjectStoreConnection con, final String domainName,
            final String roleName, Role originalRole, Role updatedRole, final String auditRef, final String caller) {

        // if it's a delegated role then we have nothing to do

        if (originalRole.getTrust() != null && !originalRole.getTrust().isEmpty()) {
            return;
        }

        // if no role members, then there is nothing to do

        final List<RoleMember> roleMembers = originalRole.getRoleMembers();
        if (roleMembers == null || roleMembers.isEmpty()) {
            return;
        }

        // check if the user authority expiration attribute has been
        // changed in which case we need to verify and update members
        // accordingly

        boolean userAuthorityExpiryChanged = isUserAuthorityExpiryChanged(originalRole.getUserAuthorityExpiration(),
                updatedRole.getUserAuthorityExpiration());

        // we only need to process the role members if the new due date
        // is more restrictive than what we had before

        boolean userMemberExpiryDayReduced = isNumOfDaysReduced(originalRole.getMemberExpiryDays(),
                updatedRole.getMemberExpiryDays());
        boolean serviceMemberExpiryDayReduced = isNumOfDaysReduced(originalRole.getServiceExpiryDays(),
                updatedRole.getServiceExpiryDays());

         boolean userMemberReviewDayReduced = isNumOfDaysReduced(originalRole.getMemberReviewDays(),
                 updatedRole.getMemberReviewDays());
         boolean serviceMemberReviewDayReduced = isNumOfDaysReduced(originalRole.getServiceReviewDays(),
                 updatedRole.getServiceReviewDays());

        if (!userMemberExpiryDayReduced && !serviceMemberExpiryDayReduced &&
                !userMemberReviewDayReduced && !serviceMemberReviewDayReduced &&
                !userAuthorityExpiryChanged) {
            return;
        }

        // we're only going to process those role members whose
        // due date is either not set or longer than the new limit

        long userExpiryMillis = userMemberExpiryDayReduced ? System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(updatedRole.getMemberExpiryDays(), TimeUnit.DAYS) : 0;
        long serviceExpiryMillis = serviceMemberExpiryDayReduced ? System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(updatedRole.getServiceExpiryDays(), TimeUnit.DAYS) : 0;

         long userReviewMillis = userMemberReviewDayReduced ? System.currentTimeMillis()
                 + TimeUnit.MILLISECONDS.convert(updatedRole.getMemberReviewDays(), TimeUnit.DAYS) : 0;
         long serviceReviewMillis = serviceMemberReviewDayReduced ? System.currentTimeMillis()
                 + TimeUnit.MILLISECONDS.convert(updatedRole.getServiceReviewDays(), TimeUnit.DAYS) : 0;

        Timestamp userExpiration = Timestamp.fromMillis(userExpiryMillis);
        Timestamp serviceExpiration = Timestamp.fromMillis(serviceExpiryMillis);

        Timestamp userReview = Timestamp.fromMillis(userReviewMillis);
        Timestamp serviceReview = Timestamp.fromMillis(serviceReviewMillis);

        final String principal = getPrincipalName(ctx);

        // process our role members and if there were any changes processed then update
        // our role and domain time-stamps, and invalidate local cache entry

        final String userAuthorityExpiry = userAuthorityExpiryChanged ? updatedRole.getUserAuthorityExpiration() : null;
        List<RoleMember> roleMembersWithUpdatedDueDates = getRoleMembersWithUpdatedDueDates(roleMembers,
                userExpiration, userExpiryMillis, serviceExpiration, serviceExpiryMillis,
                userReview, userReviewMillis, serviceReview, serviceReviewMillis, userAuthorityExpiry);
        if (insertRoleMembers(ctx, con, roleMembersWithUpdatedDueDates, domainName,
                roleName, principal, auditRef, caller)) {

            // update our role and domain time-stamps, and invalidate local cache entry

            con.updateRoleModTimestamp(domainName, roleName);
            con.updateDomainModTimestamp(domainName);
            cacheStore.invalidate(domainName);
        }
    }

    boolean isNumOfDaysReduced(Integer oldNumberOfDays, Integer newNumberOfDays) {
        if (newNumberOfDays == null || newNumberOfDays <= 0) {
            return false;
        }
        if (oldNumberOfDays == null || oldNumberOfDays <= 0) {
            return true;
        }
        return newNumberOfDays < oldNumberOfDays;
    }

    /**
     * If the role has audit enabled, and user did not provide the auditRef,
     * an exception will be thrown.
     **/
    void checkObjectAuditEnabled(ObjectStoreConnection con, Boolean auditEnabled, final String objectName,
                                 final String auditRef, final String caller, final String principal) {

        if (auditEnabled == Boolean.TRUE) {
            if (auditRef == null || auditRef.length() == 0) {
                con.rollbackChanges();
                throw ZMSUtils.requestError(caller + ": Audit reference required for object: " + objectName, caller);
            }

            if (auditReferenceValidator != null && !auditReferenceValidator.validateReference(auditRef, principal, caller)) {
                con.rollbackChanges();
                throw ZMSUtils.requestError(caller + ": Audit reference validation failed for object: " + objectName +
                        ", auditRef: " + auditRef, caller);
            }
        }
    }

    void executePutMembershipDecision(ResourceContext ctx, String domainName, String roleName,
            RoleMember roleMember, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                String principal = getPrincipalName(ctx);

                // make sure the role auditing requirements are met

                Role originalRole = con.getRole(domainName, roleName);
                if (originalRole == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError("unknown role: " + roleName, caller);
                }

                checkObjectAuditEnabled(con, originalRole.getAuditEnabled(), originalRole.getName(),
                        auditRef, caller, principal);

                // process our confirm role member support

                if (!con.confirmRoleMember(domainName, roleName, roleMember, principal, auditRef)) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError("unable to apply role membership decision for member: " +
                            roleMember.getMemberName() + " and role: " + roleName, caller);
                }

                // update our domain time-stamp and save changes

                con.updateRoleModTimestamp(domainName, roleName);
                saveChanges(con, domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogRoleMember(auditDetails, roleMember, true);

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        roleName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutGroupMembershipDecision(ResourceContext ctx, final String domainName, Group group,
                                           GroupMember groupMember, final String auditRef) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                String principal = getPrincipalName(ctx);

                // make sure the role auditing requirements are met

                checkObjectAuditEnabled(con, group.getAuditEnabled(), group.getName(),
                        auditRef, ctx.getApiName(), principal);

                // process our confirm group member support

                final String groupName = ZMSUtils.extractGroupName(domainName, group.getName());
                if (!con.confirmGroupMember(domainName, groupName, groupMember, principal, auditRef)) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError("unable to apply group membership decision for member: " +
                            groupMember.getMemberName() + " and group: " + groupName, ctx.getApiName());
                }

                // update our domain time-stamp and save changes

                con.updateGroupModTimestamp(domainName, groupName);
                saveChanges(con, domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogGroupMember(auditDetails, groupMember, true);

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), ZMSConsts.HTTP_PUT,
                        groupName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    DomainRoleMembership getPendingDomainRoleMembers(final String principal) {

        DomainRoleMembership domainRoleMembership = new DomainRoleMembership();
        List<DomainRoleMembers> domainRoleMembersList = new ArrayList<>();
        DomainRoleMembers domainRoleMembers;

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            Map<String, List<DomainRoleMember>> domainRoleMembersMap = con.getPendingDomainRoleMembers(principal);
            if (domainRoleMembersMap != null) {
                for (String domain : domainRoleMembersMap.keySet()) {
                    domainRoleMembers = new DomainRoleMembers();
                    domainRoleMembers.setDomainName(domain);
                    domainRoleMembers.setMembers(domainRoleMembersMap.get(domain));
                    domainRoleMembersList.add(domainRoleMembers);
                }
                domainRoleMembership.setDomainRoleMembersList(domainRoleMembersList);
            }
        }
        return domainRoleMembership;
    }

    DomainGroupMembership getPendingDomainGroupMembers(final String principal) {

        DomainGroupMembership domainGroupMembership = new DomainGroupMembership();
        List<DomainGroupMembers> domainGroupMembersList = new ArrayList<>();
        DomainGroupMembers domainGroupMembers;

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            Map<String, List<DomainGroupMember>> domainGroupMembersMap = con.getPendingDomainGroupMembers(principal);
            if (domainGroupMembersMap != null) {
                for (String domain : domainGroupMembersMap.keySet()) {
                    domainGroupMembers = new DomainGroupMembers();
                    domainGroupMembers.setDomainName(domain);
                    domainGroupMembers.setMembers(domainGroupMembersMap.get(domain));
                    domainGroupMembersList.add(domainGroupMembers);
                }
                domainGroupMembership.setDomainGroupMembersList(domainGroupMembersList);
            }
        }
        return domainGroupMembership;
    }

    public Set<String> getPendingMembershipApproverRoles(int delayDays) {
        try (ObjectStoreConnection con = store.getConnection(true, true)) {
            long updateTs = System.currentTimeMillis();
            if (con.updatePendingRoleMembersNotificationTimestamp(zmsConfig.getServerHostName(), updateTs, delayDays)) {
                return con.getPendingMembershipApproverRoles(zmsConfig.getServerHostName(), updateTs);
            }
        }
        return null;
    }

    public Set<String> getPendingGroupMembershipApproverRoles(int delayDays) {
        try (ObjectStoreConnection con = store.getConnection(true, true)) {
            long updateTs = System.currentTimeMillis();
            if (con.updatePendingGroupMembersNotificationTimestamp(zmsConfig.getServerHostName(), updateTs, delayDays)) {
                return con.getPendingGroupMembershipApproverRoles(zmsConfig.getServerHostName(), updateTs);
            }
        }
        return null;
    }

    public Map<String, DomainRoleMember> getRoleExpiryMembers(int delayDays) {
        try (ObjectStoreConnection con = store.getConnection(true, true)) {
            long updateTs = System.currentTimeMillis();
            if (con.updateRoleMemberExpirationNotificationTimestamp(zmsConfig.getServerHostName(), updateTs, delayDays)) {
                return con.getNotifyTemporaryRoleMembers(zmsConfig.getServerHostName(), updateTs);
            }
        }
        return null;
    }

    public Map<String, DomainRoleMember> getRoleReviewMembers(int delayDays) {
        try (ObjectStoreConnection con = store.getConnection(true, true)) {
            long updateTs = System.currentTimeMillis();
            if (con.updateRoleMemberReviewNotificationTimestamp(zmsConfig.getServerHostName(), updateTs, delayDays)) {
                return con.getNotifyReviewRoleMembers(zmsConfig.getServerHostName(), updateTs);
            }
        }
        return null;
    }

    public Map<String, DomainGroupMember> getGroupExpiryMembers(int delayDays) {
        try (ObjectStoreConnection con = store.getConnection(true, true)) {
            long updateTs = System.currentTimeMillis();
            if (con.updateGroupMemberExpirationNotificationTimestamp(zmsConfig.getServerHostName(), updateTs, delayDays)) {
                return con.getNotifyTemporaryGroupMembers(zmsConfig.getServerHostName(), updateTs);
            }
        }
        return null;
    }

    public void processExpiredPendingMembers(int pendingRoleMemberLifespan, final String monitorIdentity) {

        final String auditRef = "Expired - auto reject";
        final String caller = "processExpiredPendingMembers";

        Map<String, List<DomainRoleMember>> memberList;
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            memberList = con.getExpiredPendingDomainRoleMembers(pendingRoleMemberLifespan);
        }

        // delete each member and record each expired member in audit log in a transaction

        for (String domainName : memberList.keySet()) {
            for (DomainRoleMember domainRoleMember : memberList.get(domainName)) {
                final String principalName = domainRoleMember.getMemberName();
                for (MemberRole memberRole : domainRoleMember.getMemberRoles()) {
                    try (ObjectStoreConnection con = store.getConnection(true, true)) {
                        if (con.deletePendingRoleMember(domainName, memberRole.getRoleName(),
                                principalName, monitorIdentity, auditRef)) {
                            auditLogRequest(monitorIdentity, domainName, auditRef, caller,
                                    "REJECT", memberRole.getRoleName(),
                                    "{\"member\": \"" + principalName + "\"}");
                        }
                    }
                }
            }
        }
    }

    public void processExpiredPendingGroupMembers(int pendingGroupMemberLifespan, final String monitorIdentity) {

        final String auditRef = "Expired - auto reject";
        final String caller = "processExpiredPendingGroupMembers";

        Map<String, List<DomainGroupMember>> memberList;
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            memberList = con.getExpiredPendingDomainGroupMembers(pendingGroupMemberLifespan);
        }

        // delete each member and record each expired member in audit log in a transaction

        for (String domainName : memberList.keySet()) {
            for (DomainGroupMember domainGroupMember : memberList.get(domainName)) {
                final String principalName = domainGroupMember.getMemberName();
                for (GroupMember groupMember : domainGroupMember.getMemberGroups()) {
                    try (ObjectStoreConnection con = store.getConnection(true, true)) {
                        if (con.deletePendingGroupMember(domainName, groupMember.getGroupName(),
                                principalName, monitorIdentity, auditRef)) {
                            auditLogRequest(monitorIdentity, domainName, auditRef, caller,
                                    "REJECT", groupMember.getGroupName(),
                                    "{\"member\": \"" + principalName + "\"}");
                        }
                    }
                }
            }
        }
    }

    void executePutGroupReview(ResourceContext ctx, final String domainName, final String groupName, Group group, final String auditRef) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                final String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, ctx.getApiName(), principal, AUDIT_TYPE_GROUP);

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);

                List<GroupMember> deletedMembers = new ArrayList<>();
                List<GroupMember> noActionMembers = new ArrayList<>();

                auditDetails.append("{\"name\": \"").append(groupName).append('\"')
                        .append(", \"selfServe\": ").append(auditLogBooleanDefault(group.getSelfServe(), Boolean.TRUE))
                        .append(", \"auditEnabled\": ").append(auditLogBooleanDefault(group.getAuditEnabled(), Boolean.TRUE));

                for (GroupMember member : group.getGroupMembers()) {

                    // if active flag is coming as false for the member, that means it's flagged for deletion

                    if (member.getActive() == Boolean.FALSE) {
                        if (!con.deleteGroupMember(domainName, groupName, member.getMemberName(), principal, auditRef)) {
                            con.rollbackChanges();
                            throw ZMSUtils.notFoundError("unable to delete group member: " +
                                    member.getMemberName() + " from group: " + groupName, ctx.getApiName());
                        }
                        deletedMembers.add(member);
                    } else {
                        noActionMembers.add(member);
                    }
                }

                // construct audit log details

                auditLogGroupMembers(auditDetails, "deleted-members", deletedMembers);
                auditLogGroupMembers(auditDetails, "no-action-members", noActionMembers);

                auditDetails.append("}");

                if (!deletedMembers.isEmpty()) {
                    con.updateGroupModTimestamp(domainName, groupName);
                }

                con.updateGroupReviewTimestamp(domainName, groupName);
                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), "REVIEW", groupName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutRoleReview(ResourceContext ctx, String domainName, String roleName, Role role,
                              String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                final String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal, AUDIT_TYPE_ROLE);

                // retrieve our original role

                Role originalRole = getRole(con, domainName, roleName, false, false, false);

                if (originalRole.getTrust() != null && !originalRole.getTrust().isEmpty()) {
                    throw ZMSUtils.requestError(caller + ": role " + roleName + " is delegated. Review should happen on the trusted role. ", caller);
                }

                // now process the request. first we're going to make a copy of our role

                Role updatedRole = new Role()
                        .setName(originalRole.getName());

                // then we're going to apply the updated expiry and/or active status from the incoming role

                List<RoleMember> noactionMembers = applyMembershipChanges(updatedRole, originalRole, role, auditRef);

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);

                List<RoleMember> deletedMembers = new ArrayList<>();
                List<RoleMember> extendedMembers = new ArrayList<>();

                auditDetails.append("{\"name\": \"").append(roleName).append('\"')
                        .append(", \"selfServe\": ").append(auditLogBooleanDefault(originalRole.getSelfServe(), Boolean.TRUE))
                        .append(", \"auditEnabled\": ").append(auditLogBooleanDefault(originalRole.getAuditEnabled(), Boolean.TRUE));

                for (RoleMember member : updatedRole.getRoleMembers()) {

                    // if active flag is coming as false for the member, that means it's flagged for deletion

                    if (member.getActive() == Boolean.FALSE) {
                        if (!con.deleteRoleMember(domainName, roleName, member.getMemberName(), principal, auditRef)) {
                            con.rollbackChanges();
                            throw ZMSUtils.notFoundError(caller + ": unable to delete role member: " +
                                    member.getMemberName() + " from role: " + roleName, caller);
                        }
                        deletedMembers.add(member);

                    } else {
                        // if not marked for deletion, then we are going to extend the member

                        if (!con.insertRoleMember(domainName, roleName, member, principal, auditRef)) {
                            con.rollbackChanges();
                            throw ZMSUtils.notFoundError(caller + ": unable to extend role member: " +
                                    member.getMemberName() + " for the role: " + roleName, caller);
                        }
                        extendedMembers.add(member);
                    }
                }

                // construct audit log details

                auditLogRoleMembers(auditDetails, "deleted-members", deletedMembers);
                auditLogRoleMembers(auditDetails, "extended-members", extendedMembers);
                auditLogRoleMembers(auditDetails, "no-action-members", noactionMembers);

                auditDetails.append("}");

                if (!deletedMembers.isEmpty() || !extendedMembers.isEmpty()) {
                    // we have one or more changes to the role. We should update
                    // both lastReviewed as well as modified timestamps
                    con.updateRoleModTimestamp(domainName, roleName);
                }

                con.updateRoleReviewTimestamp(domainName, roleName);
                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, "REVIEW", roleName, auditDetails.toString());

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    /**
     * This method takes the input role, creates a map using memberName as key,
     * copies members from original role from DB and only adds deleted / extended members to the updatedRole.
     * @param updatedRole updated role to be sent to DB to record changes
     * @param originalRole original role from DB
     * @param role incoming role containing changes from domain admin
     * @param auditRef audit ref for the change
     * @return List of rolemember where no action was taken
     */
    List<RoleMember> applyMembershipChanges(Role updatedRole, Role originalRole, Role role, String auditRef) {

        Map<String, RoleMember> incomingMemberMap =
                role.getRoleMembers().stream().collect(Collectors.toMap(RoleMember::getMemberName, item -> item));

        List<RoleMember> noActionMembers = new ArrayList<>(originalRole.getRoleMembers().size());

        // updatedMembers size is driven by input

        List<RoleMember> updatedMembers = new ArrayList<>(incomingMemberMap.size());
        updatedRole.setRoleMembers(updatedMembers);
        RoleMember updatedMember;

        // if original role is auditEnabled then all the extensions should be sent for approval again.

        boolean approvalStatus = originalRole.getAuditEnabled() != Boolean.TRUE;
        RoleMember tempMemberFromMap;

        for (RoleMember originalMember : originalRole.getRoleMembers()) {

            // we are only going to update the changed members

            if (incomingMemberMap.containsKey(originalMember.getMemberName())) {

                updatedMember = new RoleMember();
                updatedMember.setMemberName(originalMember.getMemberName());

                tempMemberFromMap = incomingMemberMap.get(updatedMember.getMemberName());

                // member's approval status is determined by auditEnabled flag set on original role

                updatedMember.setApproved(approvalStatus);

                // member's active status is determined by action taken in UI

                updatedMember.setActive(tempMemberFromMap.getActive());

                // member's new expiration is set by role / domain level expiration setting

                updatedMember.setExpiration(tempMemberFromMap.getExpiration());

                updatedMember.setAuditRef(auditRef);
                updatedMembers.add(updatedMember);
            } else {
                noActionMembers.add(originalMember);
            }
        }
        return noActionMembers;
    }

    void updateDomainModTimestamp(final String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true, true)) {

            // update domain time-stamps, and invalidate local cache entry

            con.updateDomainModTimestamp(domainName);
            cacheStore.invalidate(domainName);
        }
    }

    List<TemplateMetaData> getDomainTemplates(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.getDomainTemplates(domainName);
        }
    }

    void processRoleUserAuthorityRestrictions() {

        // if we don't have a user authority defined then there
        // is no work to be done

        if (zmsConfig.getUserAuthority() == null) {
            return;
        }

        // first we need to get all the roles that have the authority
        // filter or date expiry attributes set

        List<PrincipalRole> roles;
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            roles = con.listRolesWithUserAuthorityRestrictions();
        }

        if (roles == null) {
            return;
        }

        // for each role catch any exception and ignore since we
        // want to process all roles and not allow a single one
        // prevent updating others

        for (PrincipalRole role : roles) {
            try {
                enforceRoleUserAuthorityRestrictions(role.getDomainName(), role.getRoleName(),
                        role.getDomainUserAuthorityFilter());
            } catch (Exception ex) {
                LOG.error("Unable to process user authority restrictions for {}:role.{} - {}",
                        role.getDomainName(), role.getRoleName(), ex.getMessage());
            }
        }
    }

    void processGroupUserAuthorityRestrictions() {

        // if we don't have a user authority defined then there
        // is no work to be done

        if (zmsConfig.getUserAuthority() == null) {
            return;
        }

        // first we need to get all the groups that have the authority
        // filter or date expiry attributes set

        List<PrincipalGroup> groups;
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            groups = con.listGroupsWithUserAuthorityRestrictions();
        }

        if (groups == null) {
            return;
        }

        // for each group catch any exception and ignore since we
        // want to process all group and not allow a single one
        // prevent updating others

        for (PrincipalGroup group : groups) {
            try {
                enforceGroupUserAuthorityRestrictions(group.getDomainName(), group.getGroupName(),
                        group.getDomainUserAuthorityFilter());
            } catch (Exception ex) {
                LOG.error("Unable to process user authority restrictions for {}:group.{} - {}",
                        group.getDomainName(), group.getGroupName(), ex.getMessage());
            }
        }
    }

    Map<String, List<String>> applyTemplatesForListOfDomains(Map<String, Integer> templateDetails) {
        final String caller = "applyTemplatesForListOfDomains";
        final String auditRef = "AutoApplyTemplate";
        Map<String, List<String>> domainTemplateListMap;
        DomainTemplate domainTemplate = new DomainTemplate();
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
             domainTemplateListMap = con.getDomainFromTemplateName(templateDetails);
        }

        for (String domainName : domainTemplateListMap.keySet()) {
            domainTemplate.setTemplateNames(domainTemplateListMap.get(domainName));
            //Passing null context since it is an internal call during app start up
            //executePutDomainTemplate can bulk apply templates given a domain hence sending domainName and templatelist
            try {
                this.executePutDomainTemplate(null, domainName, domainTemplate, auditRef, caller);
            } catch (Exception ex) {
                LOG.error("unable to apply template for domain {} and template {} error: {}",
                        domainName, domainTemplate, ex.getMessage());
            }
        }
        return domainTemplateListMap;
    }

    void enforceRoleUserAuthorityRestrictions(final String domainName, final String roleName,
                                              final String domainUserAuthorityFilter) {

        final String caller = "enforceRoleUserAuthorityRestrictions";
        try (ObjectStoreConnection con = store.getConnection(true, true)) {

            // get the role from the storage system

            Role role = getRole(con, domainName, roleName, false, false, false);
            if (role == null) {
                return;
            }

            // update the role membership

            List<RoleMember> roleMembers = role.getRoleMembers();
            if (roleMembers == null) {
                return;
            }

            // first process the authority expiration restriction

            boolean expiryDBUpdated = false;
            final String userAuthorityExpiry = role.getUserAuthorityExpiration();
            if (userAuthorityExpiry != null) {
                List<RoleMember> updatedMembers = new ArrayList<>();
                for (RoleMember roleMember : roleMembers) {
                    if (updateUserAuthorityExpiry(roleMember, userAuthorityExpiry)) {
                        updatedMembers.add(roleMember);
                    }
                }

                expiryDBUpdated = insertRoleMembers(null, con, updatedMembers, domainName, roleName,
                        ZMSConsts.SYS_AUTH_MONITOR, AUDIT_REF, caller);
            }

            // now process authority filter restriction

            boolean filterDBUpdated = false;
            final String userAuthorityFilter = ZMSUtils.combineUserAuthorityFilters(role.getUserAuthorityFilter(),
                    domainUserAuthorityFilter);
            if (userAuthorityFilter != null) {
                List<RoleMember> updatedMembers = new ArrayList<>();

                for (RoleMember roleMember : roleMembers) {
                    if (updateUserAuthorityFilter(roleMember, userAuthorityFilter)) {
                        updatedMembers.add(roleMember);
                    }
                }

                filterDBUpdated = updateRoleMemberDisabledState(null, con, updatedMembers, domainName,
                        roleName, ZMSConsts.SYS_AUTH_MONITOR, AUDIT_REF, caller);
            }

            if (expiryDBUpdated || filterDBUpdated) {

                // update our role and domain time-stamps, and invalidate local cache entry

                con.updateRoleModTimestamp(domainName, roleName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);
            }
        }
    }

    void enforceGroupUserAuthorityRestrictions(final String domainName, final String groupName,
                                               final String domainUserAuthorityFilter) {

        final String caller = "enforceGroupUserAuthorityRestrictions";
        try (ObjectStoreConnection con = store.getConnection(true, true)) {

            // get the role from the storage system

            Group group = getGroup(con, domainName, groupName, false, false);
            if (group == null) {
                return;
            }

            // update the group membership

            List<GroupMember> groupMembers = group.getGroupMembers();
            if (groupMembers == null) {
                return;
            }

            // first process the authority expiration restriction

            boolean expiryDBUpdated = false;
            final String userAuthorityExpiry = group.getUserAuthorityExpiration();
            if (userAuthorityExpiry != null) {
                List<GroupMember> updatedMembers = new ArrayList<>();
                for (GroupMember groupMember : groupMembers) {
                    if (updateUserAuthorityExpiry(groupMember, userAuthorityExpiry)) {
                        updatedMembers.add(groupMember);
                    }
                }

                expiryDBUpdated = insertGroupMembers(null, con, updatedMembers, domainName, groupName,
                        ZMSConsts.SYS_AUTH_MONITOR, AUDIT_REF, caller);
            }

            // now process authority filter restriction

            boolean filterDBUpdated = false;
            final String userAuthorityFilter = ZMSUtils.combineUserAuthorityFilters(group.getUserAuthorityFilter(),
                    domainUserAuthorityFilter);
            if (userAuthorityFilter != null) {
                List<GroupMember> updatedMembers = new ArrayList<>();

                for (GroupMember groupMember : groupMembers) {
                    if (updateUserAuthorityFilter(groupMember, userAuthorityFilter)) {
                        updatedMembers.add(groupMember);
                    }
                }

                filterDBUpdated = updateGroupMemberDisabledState(null, con, updatedMembers, domainName,
                        groupName, ZMSConsts.SYS_AUTH_MONITOR, AUDIT_REF, caller);
            }

            if (expiryDBUpdated || filterDBUpdated) {

                // update our group and domain time-stamps, and invalidate local cache entry

                con.updateGroupModTimestamp(domainName, groupName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);
            }
        }
    }

    /**
     * This method returns list of Principals based on the state parameter supplied
     * @param queriedState state of principal
     * @return List of Principals from DB
     */
    List<Principal> getPrincipals(int queriedState) {
        List<Principal> principals = new ArrayList<>();
        Principal principal;
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
           List<String> dbPrincipals = con.getPrincipals(queriedState);
            Principal.State principalState = Principal.State.getState(queriedState);
           for (String dbPrincipal : dbPrincipals) {
               principal = ZMSUtils.createPrincipalForName(dbPrincipal, zmsConfig.getUserDomain(), null);
               ((SimplePrincipal) principal).setState(principalState);
               principals.add(principal);
           }
        }
        return principals;
    }

    /**
     * This method toggles state for supplied Principals based on the flag in DB
     * as well as modifies memberships of all roles and groups of current principal(s)
     * @param changedPrincipals List of Principals from User Authority
     * @param suspended boolean indicating principal's state
     */
    void updatePrincipalByStateFromAuthority(List<Principal> changedPrincipals, boolean suspended) {

        if (changedPrincipals.isEmpty()) {
            return;
        }

        final String caller = "updatePrincipalByStateFromAuthority";
        List<Principal> updatedUsers = new ArrayList<>();
        int newPrincipalState = suspended ? Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue() : Principal.State.ACTIVE.getValue();
        try (ObjectStoreConnection con = store.getConnection(true, true)) {

            // first lets update the new state in DB
            for (Principal changedPrincipal : changedPrincipals) {
                try {
                    if (con.updatePrincipal(changedPrincipal.getFullName(), newPrincipalState)) {
                        updatedUsers.add(changedPrincipal);
                    }
                } catch (ResourceException ex) {
                    // log the exception and continue with remaining principals
                    LOG.error("Exception in updating principal state from Authority {} Moving on.", ex.getMessage());
                }
            }
            // if new state is updated successfully
            // then we need to modify all roles and groups where given principal is member of
            if (!updatedUsers.isEmpty()) {
                for (Principal updatedUser : updatedUsers) {
                    // separate try blocks to treat group and role membership 404s separately
                    try {
                        updateRoleMembershipsByPrincipalState(suspended, caller, con, updatedUser);
                    } catch (ResourceException ex) {
                        if (ex.getCode() == ResourceException.NOT_FOUND) {
                            continue;
                        }
                        throw ex;
                    }
                    // separate try blocks to treat group and role membership 404s separately
                    try {
                        updateGroupMembershipByPrincipalState(suspended, caller, con, updatedUser);
                    } catch (ResourceException ex) {
                        if (ex.getCode() == ResourceException.NOT_FOUND) {
                            continue;
                        }
                        throw ex;
                    }
                }
            }
        }
    }

    private void updateGroupMembershipByPrincipalState(boolean suspended, String caller, ObjectStoreConnection con, Principal updatedUser) {
        List<GroupMember> groupMembersWithUpdatedState;
        GroupMember groupMember;
        DomainGroupMember domainGroupMember;
        int newState, oldState;
        Set<String> updatedDomains = new HashSet<>();
        domainGroupMember = con.getPrincipalGroups(updatedUser.getFullName(), null);
        if (!domainGroupMember.getMemberGroups().isEmpty()) {
            for (GroupMember currentGroup : domainGroupMember.getMemberGroups()) {
                groupMember = new GroupMember();
                groupMember.setMemberName(updatedUser.getFullName());
                oldState = 0;
                if (groupMember.getSystemDisabled() != null) {
                    oldState = groupMember.getSystemDisabled();
                }
                newState = suspended ? oldState | Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue() :
                        oldState & ~Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue();
                groupMember.setSystemDisabled(newState);
                groupMembersWithUpdatedState = Collections.singletonList(groupMember);
                // Following method does Audit entry as well
                if (updateGroupMemberDisabledState(null, con, groupMembersWithUpdatedState, currentGroup.getDomainName(),
                        currentGroup.getGroupName(), ZMSConsts.SYS_AUTH_MONITOR, AUDIT_REF, caller)) {
                    con.updateGroupModTimestamp(currentGroup.getDomainName(), currentGroup.getGroupName());
                    updatedDomains.add(currentGroup.getDomainName());
                }
            }
            updatedDomains.forEach(dom -> {
                con.updateDomainModTimestamp(dom);
                cacheStore.invalidate(dom);
            });
        }
    }

    private void updateRoleMembershipsByPrincipalState(boolean suspended, String caller, ObjectStoreConnection con, Principal updatedUser) {
        RoleMember roleMember;
        List<RoleMember> roleMembersWithUpdatedState;
        DomainRoleMember domainRoleMember;
        int newState, oldState;
        Set<String> updatedDomains = new HashSet<>();
        domainRoleMember = con.getPrincipalRoles(updatedUser.getFullName(), null);
        if (!domainRoleMember.getMemberRoles().isEmpty()) {
            for (MemberRole memberRole : domainRoleMember.getMemberRoles()) {
                roleMember = new RoleMember();
                roleMember.setMemberName(updatedUser.getFullName());
                oldState = 0;
                if (memberRole.getSystemDisabled() != null) {
                    oldState = memberRole.getSystemDisabled();
                }
                newState = suspended ? oldState | Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue() :
                        oldState & ~Principal.State.AUTHORITY_SYSTEM_SUSPENDED.getValue();
                roleMember.setSystemDisabled(newState);
                roleMembersWithUpdatedState = Collections.singletonList(roleMember);

                // Following method does Audit entry as well
                if (updateRoleMemberDisabledState(null, con, roleMembersWithUpdatedState, memberRole.getDomainName(),
                        memberRole.getRoleName(), ZMSConsts.SYS_AUTH_MONITOR, AUDIT_REF, caller)) {
                    con.updateRoleModTimestamp(memberRole.getDomainName(), memberRole.getRoleName());
                    updatedDomains.add(memberRole.getDomainName());
                }
            }
            updatedDomains.forEach(dom -> {
                con.updateDomainModTimestamp(dom);
                cacheStore.invalidate(dom);
            });
        }
    }

    class UserAuthorityFilterEnforcer implements Runnable {

        public UserAuthorityFilterEnforcer() {
        }

        @Override
        public void run() {

            LOG.info("UserAuthorityFilterEnforcer: Starting user authority filter enforcer thread...");

            try {
                processRoleUserAuthorityRestrictions();
            } catch (Throwable t) {
                LOG.error("UserAuthorityFilterEnforcer: unable to enforce role user authority restrictions: {}",
                        t.getMessage());
            }

            try {
                processGroupUserAuthorityRestrictions();
            } catch (Throwable t) {
                LOG.error("UserAuthorityFilterEnforcer: unable to enforce group user authority restrictions: {}",
                        t.getMessage());
            }

            LOG.info("UserAuthorityFilterEnforcer: Completed user authority filter enforcer thread");
        }
    }
}
