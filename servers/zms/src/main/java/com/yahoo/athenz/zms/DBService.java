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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.auth.util.StringUtils;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.server.audit.AuditReferenceValidator;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.util.AuthzHelper;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigInteger;
import com.yahoo.athenz.zms.config.MemberDueDays;
import com.yahoo.athenz.zms.store.*;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

public class DBService implements RolesProvider {

    ObjectStore store;
    BitSet auditRefSet;
    AuditLogger auditLogger;
    private final AuthHistoryStore authHistoryStore;
    Cache<String, DataCache> cacheStore;
    QuotaChecker quotaCheck;
    int retrySleepTime;
    int defaultRetryCount;
    int defaultOpTimeout;
    ZMSConfig zmsConfig;
    private final int maxPolicyVersions;
    long maxLastReviewDateOffsetMillisForNewObjects;
    long maxLastReviewDateOffsetMillisForUpdatedObjects;

    final String awsAssumeRoleAction;
    final String gcpAssumeRoleAction;
    final String gcpAssumeServiceAction;

    private static final Logger LOG = LoggerFactory.getLogger(DBService.class);

    public static int AUDIT_TYPE_ROLE     = 0;
    public static int AUDIT_TYPE_POLICY   = 1;
    public static int AUDIT_TYPE_SERVICE  = 2;
    public static int AUDIT_TYPE_DOMAIN   = 3;
    public static int AUDIT_TYPE_ENTITY   = 4;
    public static int AUDIT_TYPE_TENANCY  = 5;
    public static int AUDIT_TYPE_TEMPLATE = 6;
    public static int AUDIT_TYPE_GROUP    = 7;

    private static final String CALLER_TEMPLATE = "putSolutionTemplate";

    private static final String ROLE_PREFIX = "role.";
    private static final String POLICY_PREFIX = "policy.";
    private static final String TEMPLATE_DOMAIN_NAME = "_domain_";
    private static final String AUDIT_REF = "Athenz User Authority Enforcer";
    private static final String AWS_ARN_PREFIX  = "arn:aws:iam::";
    private static final String GCP_ARN_PREFIX  = "projects/";

    AuditReferenceValidator auditReferenceValidator;
    private final ScheduledExecutorService userAuthorityFilterExecutor;
    protected DynamicConfigInteger purgeMembersMaxDbCallsPerRun;
    protected DynamicConfigInteger purgeMembersLimitPerCall;
    protected DynamicConfigInteger purgeMemberExpiryDays;
    protected DynamicConfigInteger minReviewDaysPercentage;

    public DBService(ObjectStore store, AuditLogger auditLogger, ZMSConfig zmsConfig,
                     AuditReferenceValidator auditReferenceValidator, AuthHistoryStore authHistoryStore) {

        this.store = store;
        this.zmsConfig = zmsConfig;
        this.auditLogger = auditLogger;
        this.authHistoryStore = authHistoryStore;
        cacheStore = CacheBuilder.newBuilder().concurrencyLevel(25).build();

        awsAssumeRoleAction = System.getProperty(ZMSConsts.ZMS_PROP_AWS_ASSUME_ROLE_ACTION,
                ZMSConsts.ACTION_ASSUME_AWS_ROLE);
        gcpAssumeRoleAction = System.getProperty(ZMSConsts.ZMS_PROP_GCP_ASSUME_ROLE_ACTION,
                ZMSConsts.ACTION_ASSUME_GCP_ROLE);
        gcpAssumeServiceAction = System.getProperty(ZMSConsts.ZMS_PROP_GCP_ASSUME_SERVICE_ACTION,
                ZMSConsts.ACTION_ASSUME_GCP_SERVICE);

        // default timeout in seconds for object store commands

        defaultOpTimeout = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_STORE_OP_TIMEOUT, "60"));
        if (defaultOpTimeout < 0) {
            defaultOpTimeout = 60;
        }

        int roleTagsLimit = Integer.getInteger(ZMSConsts.ZMS_PROP_QUOTA_ROLE_TAG, ZMSConsts.ZMS_DEFAULT_TAG_LIMIT);
        int domainTagsLimit = Integer.getInteger(ZMSConsts.ZMS_PROP_QUOTA_DOMAIN_TAG, ZMSConsts.ZMS_DEFAULT_TAG_LIMIT);
        int groupTagsLimit = Integer.getInteger(ZMSConsts.ZMS_PROP_QUOTA_GROUP_TAG, ZMSConsts.ZMS_DEFAULT_TAG_LIMIT);
        int policyTagsLimit = Integer.getInteger(ZMSConsts.ZMS_PROP_QUOTA_POLICY_TAG, ZMSConsts.ZMS_DEFAULT_TAG_LIMIT);
        int serviceTagsLimit = Integer.getInteger(ZMSConsts.ZMS_PROP_QUOTA_SERVICE_TAG, ZMSConsts.ZMS_DEFAULT_TAG_LIMIT);

        DomainOptions domainOptions = new DomainOptions();
        domainOptions.setEnforceUniqueAWSAccounts(Boolean.parseBoolean(
                System.getProperty(ZMSConsts.ZMS_PROP_ENFORCE_UNIQUE_AWS_ACCOUNTS, "true")));
        domainOptions.setEnforceUniqueAzureSubscriptions(Boolean.parseBoolean(
                System.getProperty(ZMSConsts.ZMS_PROP_ENFORCE_UNIQUE_AZURE_SUBSCRIPTIONS, "true")));
        domainOptions.setEnforceUniqueGCPProjects(Boolean.parseBoolean(
                System.getProperty(ZMSConsts.ZMS_PROP_ENFORCE_UNIQUE_GCP_PROJECTS, "true")));
        domainOptions.setEnforceUniqueProductIds(Boolean.parseBoolean(
                System.getProperty(ZMSConsts.ZMS_PROP_ENFORCE_UNIQUE_PRODUCT_IDS, "true")));

        if (this.store != null) {
            this.store.setOperationTimeout(defaultOpTimeout);
            this.store.setTagLimit(domainTagsLimit, roleTagsLimit, groupTagsLimit, policyTagsLimit, serviceTagsLimit);
            this.store.setDomainOptions(domainOptions);
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
        userAuthorityFilterExecutor.scheduleAtFixedRate(new UserAuthorityFilterEnforcer(), 0, 1, TimeUnit.DAYS);

        maxPolicyVersions = Integer.parseInt(System.getProperty(ZMSConsts.ZMS_PROP_MAX_POLICY_VERSIONS,
                ZMSConsts.ZMS_PROP_MAX_POLICY_VERSIONS_DEFAULT));
        purgeMembersMaxDbCallsPerRun = new DynamicConfigInteger(CONFIG_MANAGER,
                ZMSConsts.ZMS_PROP_PURGE_TASK_MAX_DB_CALLS_PER_RUN, ZMSConsts.ZMS_PURGE_TASK_MAX_DB_CALLS_PER_RUN_DEF);
        purgeMembersLimitPerCall = new DynamicConfigInteger(CONFIG_MANAGER,
                ZMSConsts.ZMS_PROP_PURGE_TASK_LIMIT_PER_CALL, ZMSConsts.ZMS_PURGE_TASK_LIMIT_PER_CALL_DEF);
        purgeMemberExpiryDays = new DynamicConfigInteger(CONFIG_MANAGER,
                ZMSConsts.ZMS_PROP_PURGE_MEMBER_EXPIRY_DAYS, ZMSConsts.ZMS_PURGE_MEMBER_EXPIRY_DAYS_DEF);
        int maxLastReviewDateOffsetDays = Integer.parseInt(System.getProperty(
                ZMSConsts.ZMS_PROP_REVIEW_DATE_OFFSET_DAYS_UPDATED_OBJECT,
                ZMSConsts.ZMS_PROP_REVIEW_DATE_OFFSET_DAYS_UPDATED_OBJECT_DEFAULT));
        maxLastReviewDateOffsetMillisForUpdatedObjects = TimeUnit.MILLISECONDS.convert(maxLastReviewDateOffsetDays, TimeUnit.DAYS);
        maxLastReviewDateOffsetDays = Integer.parseInt(System.getProperty(
                ZMSConsts.ZMS_PROP_REVIEW_DATE_OFFSET_DAYS_NEW_OBJECT,
                ZMSConsts.ZMS_PROP_REVIEW_DATE_OFFSET_DAYS_NEW_OBJECT_DEFAULT));
        maxLastReviewDateOffsetMillisForNewObjects = TimeUnit.MILLISECONDS.convert(maxLastReviewDateOffsetDays, TimeUnit.DAYS);

        minReviewDaysPercentage = new DynamicConfigInteger(CONFIG_MANAGER,
                ZMSConsts.ZMS_PROP_REVIEW_DAYS_PERCENTAGE, ZMSConsts.ZMS_PROP_REVIEW_DAYS_PERCENTAGE_DEFAULT);
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

    public DomainList lookupDomainByTag(String tagKey, String tagValue) {
        DomainList domList = new DomainList();
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            domList.setNames(con.lookupDomainByTags(tagKey, tagValue));
        }
        return domList;
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

    void purgeTaskSaveDomainChanges(ResourceContext ctx, ObjectStoreConnection con, String domainName,
            List<ExpiryMember> purgeMemberList, String auditRef, String caller, DomainChangeMessage.ObjectType collectionType) {

        saveChanges(con, domainName);

        Set<String> collectionSet = new HashSet<>();

        for (ExpiryMember purgeMember: purgeMemberList) {
            // audit log the request
            auditLogRequest(ctx, purgeMember.getDomainName(), auditRef, caller, ZMSConsts.HTTP_DELETE,
                    purgeMember.getCollectionName(), "{\"member\": \"" + purgeMember.getPrincipalName() + "\"}");

            if (!collectionSet.contains(purgeMember.getCollectionName())) {
                // add domain change event
                addDomainChangeMessage(ctx, purgeMember.getDomainName(), purgeMember.getCollectionName(), collectionType);
                collectionSet.add(purgeMember.getCollectionName());
            }
        }
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
            principalName = "sys.auth.zms";
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
                objectsInserted &= processDomainTags(con, domain.getTags(), null, domainName);
                objectsInserted &= processDomainContacts(con, domainName, domain.getContacts(), null);

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
                    throw ZMSUtils.internalServerError("makeDomain: Cannot process role: " +
                            adminRole.getName(), caller);
                }

                // now create and process the admin policy

                Policy adminPolicy = ZMSUtils.makeAdminPolicy(domainName, adminRole);
                auditDetails.append(", \"policy\": ");
                if (!processPolicy(con, null, domainName, ZMSConsts.ADMIN_POLICY_NAME, adminPolicy,
                        false, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("makeDomain: Cannot process policy: " +
                            adminPolicy.getName(), caller);
                }

                // go through our list of templates and add the specified
                // roles and polices to our domain

                if (solutionTemplates != null) {
                    for (String templateName : solutionTemplates) {
                        auditDetails.append(", \"template\": ");
                        if (!addSolutionTemplate(ctx, con, domainName, templateName, principalName,
                                null, auditRef, auditDetails)) {
                            con.rollbackChanges();
                            throw ZMSUtils.internalServerError("makeDomain: Cannot apply templates: " +
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, domainName, DomainChangeMessage.ObjectType.DOMAIN);

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
                    if (!con.insertAssertion(domainName, policyName, policy.getVersion(), assertion)) {
                        return false;
                    }
                    // insert the new assertion conditions if any
                    if (assertion.getConditions() != null) {
                        if (!con.insertAssertionConditions(assertion.getId(), assertion.getConditions())) {
                            return false;
                        }
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

            // those lists are used to check for assertion condition changes for those assertions that are unchanged
            List<Assertion> newMatchedAssertions = new ArrayList<>();
            List<Assertion> oldMatchedAssertions = new ArrayList<>(curAssertions);

            policyAssertionChanges(newAssertions, curAssertions, addAssertions, delAssertions, newMatchedAssertions);

            // delAssertion are the ones that are in curr assertions but not in new assertions, means they are not matched
            oldMatchedAssertions.removeAll(delAssertions);

            if (!ignoreDeletes) {
                for (Assertion assertion : delAssertions) {
                    if (!con.deleteAssertion(domainName, policyName, policy.getVersion(), assertion.getId())) {
                        return false;
                    }
                }
                auditLogAssertions(auditDetails, "deleted-assertions", delAssertions);
            }

            for (Assertion assertion : addAssertions) {
                if (!con.insertAssertion(domainName, policyName, policy.getVersion(), assertion)) {
                    return false;
                }
                if (assertion.getConditions() != null) {
                    if (!con.insertAssertionConditions(assertion.getId(), assertion.getConditions())) {
                        return false;
                    }
                }
            }
            auditLogAssertions(auditDetails, "added-assertions", addAssertions);

            Map<Long, List<AssertionCondition>> addConditions = new HashMap<>();
            Map<Long, List<AssertionCondition>> delConditions = new HashMap<>();
            policyAssertionConditionsChanges(oldMatchedAssertions, newMatchedAssertions, addConditions, delConditions);

            for (Map.Entry<Long, List<AssertionCondition>> entry : delConditions.entrySet()) {
                Long assertionId = entry.getKey();
                if (!con.deleteAssertionConditions(assertionId)) {
                    return false;
                }
            }

            for (Map.Entry<Long, List<AssertionCondition>> entry : addConditions.entrySet()) {
                Long assertionId = entry.getKey();
                List<AssertionCondition> conditionsList = entry.getValue();
                if (!con.insertAssertionConditions(assertionId, new AssertionConditions().setConditionsList(conditionsList))) {
                    return false;
                }
            }
        }

        if (!processPolicyTags(policy, policyName, domainName, originalPolicy, con)) {
            return false;
        }
        auditLogTags(auditDetails, policy.getTags());

        auditDetails.append('}');
        return true;
    }

    private boolean processPolicyTags(Policy policy, String policyName, String domainName,
                                               Policy originalPolicy, ObjectStoreConnection con) {

        String policyVersion = policy.getVersion();

        BiFunction<ObjectStoreConnection, Map<String, TagValueList>, Boolean> insertOp =
                (ObjectStoreConnection c, Map<String, TagValueList> tags) ->
                        c.insertPolicyTags(policyName, domainName, tags, policyVersion);
        BiFunction<ObjectStoreConnection, Set<String>, Boolean> deleteOp =
                (ObjectStoreConnection c, Set<String> tagKeys) ->
                        c.deletePolicyTags(policyName, domainName, tagKeys, policyVersion);

        return processTags(con, policy.getTags(), (originalPolicy != null ? originalPolicy.getTags() : null) , insertOp, deleteOp);
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

            // we add the id to the assertion so that we can use it later to check for assertion conditions changes
            assertion.setId(checkAssertion.getId());

            itr.remove();
            matchedAssertions.add(checkAssertion);
            return true;
        }

        return false;
    }

    void mapAssertionsToConditions(List<Assertion> assertions, Map<Long, List<AssertionCondition>> assertionConditionsMap) {
        if (assertions == null) {
            return;
        }
        for (Assertion assertion : assertions) {
            if (assertion.getConditions() != null) {
                assertionConditionsMap.put(assertion.getId(), new ArrayList<>(assertion.getConditions().getConditionsList()));
            }
        }
    }

    boolean assertionConditionEqualsIgnoreConditionId(AssertionCondition c1, AssertionCondition c2) {
            return Objects.equals(c1.conditionsMap, c2.conditionsMap);
    }

    boolean isAssertionConditionsHasChanged(List<AssertionCondition> list1, List<AssertionCondition> list2) {
        if (list1 == null || list1.isEmpty()) {
            return list2 != null && !list2.isEmpty();
        }
        if (list2 == null) {
            return true;
        }
        if (list1.size() != list2.size()) {
            return true;
        }
        for (AssertionCondition ac1: list1) {
            if (list2.stream().noneMatch(ac2 -> assertionConditionEqualsIgnoreConditionId(ac1, ac2))) {
                return true;
            }
        }
        return false;
    }

    void policyAssertionConditionsChanges(List<Assertion> oldAssertions, List<Assertion> currentAssertions, Map<Long, List<AssertionCondition>> addConditions,
                                          Map<Long, List<AssertionCondition>> delConditions) {

        Set<Long> keysToRemove = new HashSet<>();

        mapAssertionsToConditions(oldAssertions, delConditions);
        mapAssertionsToConditions(currentAssertions, addConditions);

        // Iterate over old assertion conditions and check if they are changed
        for (Map.Entry<Long, List<AssertionCondition>> entry : delConditions.entrySet()) {
            Long assertionId = entry.getKey();
            List<AssertionCondition> delAcSet = entry.getValue();
            // if new assertion conditions has the same conditions then we need remove it from the maps, since no action is needed
            if (!isAssertionConditionsHasChanged(delAcSet, addConditions.getOrDefault(assertionId, new ArrayList<>()))) {
                keysToRemove.add(assertionId);
            }

        }

        for (Long assertionId : keysToRemove) {
            delConditions.remove(assertionId);
            addConditions.remove(assertionId);
        }
    }

    void policyAssertionChanges(List<Assertion> newAssertions, List<Assertion> curAssertions,
            List<Assertion> addAssertions, List<Assertion> delAssertions, List<Assertion> newMatchedAssertions) {

        // let's iterate through the new list and the ones that are
        // not in the current list should be added to the add list

        List<Assertion> matchedAssertions = new ArrayList<>();
        if (newAssertions != null) {
            for (Assertion assertion : newAssertions) {
                if (!removeMatchedAssertion(assertion, curAssertions, matchedAssertions)) {
                    addAssertions.add(assertion);
                } else {
                    newMatchedAssertions.add(assertion);
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

        auditLogRoleMeta(auditDetails, role, roleName, false);
        auditDetails.append(", \"trust\": \"").append(role.getTrust()).append('\"');

        // now we need process our role members depending on if this is
        // a new insert operation or an update

        List<RoleMember> roleMembers = role.getRoleMembers();
        if (originalRole == null) {

            // we are just going to process all members as new inserts

            if (roleMembers != null) {
                for (RoleMember member : roleMembers) {
                    String pendingState = member.getApproved() == Boolean.FALSE ? ZMSConsts.PENDING_REQUEST_ADD_STATE : null;
                    if (!con.insertRoleMember(domainName, roleName, member.setPendingState(pendingState), admin, auditRef)) {
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

        BiFunction<ObjectStoreConnection, Map<String, TagValueList>, Boolean> insertOp =
                (ObjectStoreConnection c, Map<String, TagValueList> tags) -> c.insertRoleTags(roleName, domainName, tags);
        BiFunction<ObjectStoreConnection, Set<String>, Boolean> deleteOp =
                (ObjectStoreConnection c, Set<String> tagKeys) -> c.deleteRoleTags(roleName, domainName, tagKeys);

        return processTags(con, role.getTags(), (originalRole != null ? originalRole.getTags() : null), insertOp, deleteOp);
    }
    
    boolean processGroup(ObjectStoreConnection con, Group originalGroup, final String domainName,
                        final String groupName, Group group, final String admin, final String auditRef,
                        StringBuilder auditDetails) {

        // check to see if we need to insert the group or update it

        boolean requestSuccess;
        if (originalGroup == null) {
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

        auditLogGroupMeta(auditDetails, group, groupName, false);

        // now we need process our groups members depending this is
        // a new insert operation or an update

        List<GroupMember> groupMembers = group.getGroupMembers();

        if (originalGroup == null) {

            // we are just going to process all members as new inserts

            if (groupMembers != null) {
                for (GroupMember member : groupMembers) {
                    String pendingState = member.getApproved() == Boolean.FALSE ? ZMSConsts.PENDING_REQUEST_ADD_STATE : null;
                    if (!con.insertGroupMember(domainName, groupName, member.setPendingState(pendingState), admin, auditRef)) {
                        return false;
                    }
                }
                auditLogGroupMembers(auditDetails, "added-members", groupMembers);
            }

        } else {

            if (!processUpdateGroupMembers(con, originalGroup, groupMembers, domainName, groupName,
                    admin, auditRef, auditDetails)) {
                return false;
            }
        }

        if (!processGroupTags(group, groupName, domainName, originalGroup, con)) {
            return false;
        }

        auditDetails.append('}');
        return true;
    }

    private boolean processGroupTags(Group group, String groupName, String domainName,
                                    Group originalGroup, ObjectStoreConnection con) {
        
        BiFunction<ObjectStoreConnection, Map<String, TagValueList>, Boolean> insertOp =
                (ObjectStoreConnection c, Map<String, TagValueList> tags) -> c.insertGroupTags(groupName, domainName, tags);
        BiFunction<ObjectStoreConnection, Set<String>, Boolean> deleteOp =
                (ObjectStoreConnection c, Set<String> tagKeys) -> c.deleteGroupTags(groupName, domainName, tagKeys);
        
        return processTags(con, group.getTags(), (originalGroup != null ? originalGroup.getTags() : null) , insertOp, deleteOp);
    }
    
    private boolean processTags(ObjectStoreConnection con, Map<String, TagValueList> currentTags,
                                Map<String, TagValueList> originalTags, 
                                BiFunction<ObjectStoreConnection, Map<String, TagValueList>, Boolean> insertOp,
                                BiFunction<ObjectStoreConnection, Set<String>, Boolean> deleteOp) {
        
        if (currentTags != null && !currentTags.isEmpty()) {
            if (originalTags == null) {
                return insertOp.apply(con, currentTags);
            } else {
                return processUpdateTags(currentTags, originalTags, con, insertOp, deleteOp);
            }
        }
        return true;
    }

    boolean processUpdateTags(Map<String, TagValueList> currentTags, Map<String, TagValueList> originalTags,
                                      ObjectStoreConnection con, BiFunction<ObjectStoreConnection, Map<String, TagValueList>, Boolean> insertOp,
                                      BiFunction<ObjectStoreConnection, Set<String>, Boolean> deleteOp) {
        
        if (originalTags == null || originalTags.isEmpty()) {
            if (currentTags == null || currentTags.isEmpty()) {
                // no tags to process..
                return true;
            }
            return insertOp.apply(con, currentTags);
        }
        
        Set<String> tagsToRemove = originalTags.entrySet().stream()
                .filter(curTag -> currentTags.get(curTag.getKey()) == null
                        || !currentTags.get(curTag.getKey()).equals(curTag.getValue()))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());

        Map<String, TagValueList> tagsToAdd = currentTags.entrySet().stream()
                .filter(curTag -> originalTags.get(curTag.getKey()) == null
                        || !originalTags.get(curTag.getKey()).equals(curTag.getValue()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        
        return deleteOp.apply(con, tagsToRemove) && insertOp.apply(con, tagsToAdd);
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
        if (templateRole.getGroupReviewDays() == null) {
            templateRole.setGroupReviewDays(originalRole.getGroupReviewDays());
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
        if (templateRole.getDescription() == null) {
            templateRole.setDescription(originalRole.getDescription());
        }
        if (templateRole.getUserAuthorityExpiration() == null) {
            templateRole.setUserAuthorityExpiration(originalRole.getUserAuthorityExpiration());
        }
        if (templateRole.getMaxMembers() == null) {
            templateRole.setMaxMembers(originalRole.getMaxMembers());
        }
        templateRole.setLastReviewedDate(originalRole.getLastReviewedDate());
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

        AuthzHelper.removeRoleMembers(newMembers, curMembers, false);

        // remove new members from current members
        // which leaves the deleted members.

        AuthzHelper.removeRoleMembers(delMembers, roleMembers, true);

        if (!ignoreDeletes) {
            for (RoleMember member : delMembers) {
                boolean pendingRequest = (member.getApproved() == Boolean.FALSE);
                if (!pendingRequest) {
                    if (!con.deleteRoleMember(domainName, roleName, member.getMemberName(), admin, auditRef)) {
                        return false;
                    }
                } else {
                    if (!con.insertRoleMember(domainName, roleName, member.setPendingState(ZMSConsts.PENDING_REQUEST_DELETE_STATE), admin, auditRef)) {
                        return false;
                    }
                }
            }
            auditLogRoleMembers(auditDetails, "deleted-members", delMembers);
        }

        for (RoleMember member : newMembers) {
            String pendingState = member.getApproved() == Boolean.FALSE ? ZMSConsts.PENDING_REQUEST_ADD_STATE : null;
            if (!con.insertRoleMember(domainName, roleName, member.setPendingState(pendingState), admin, auditRef)) {
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
        List<GroupMember> curMembers = (null == originalMembers) ? new ArrayList<>() : new ArrayList<>(originalMembers);
        List<GroupMember> delMembers = new ArrayList<>(curMembers);
        ArrayList<GroupMember> newMembers = (null == groupMembers) ? new ArrayList<>() : new ArrayList<>(groupMembers);

        // remove current members from new members

        AuthzHelper.removeGroupMembers(newMembers, curMembers, false);

        // remove new members from current members
        // which leaves the deleted members.

        AuthzHelper.removeGroupMembers(delMembers, groupMembers, true);

        for (GroupMember member : delMembers) {
            if (!con.deleteGroupMember(domainName, groupName, member.getMemberName(), admin, auditRef)) {
                return false;
            }
        }
        auditLogGroupMembers(auditDetails, "deleted-members", delMembers);

        for (GroupMember member : newMembers) {
            String pendingState = member.getApproved() == Boolean.FALSE ? ZMSConsts.PENDING_REQUEST_ADD_STATE : null;
            if (!con.insertGroupMember(domainName, groupName, member.setPendingState(pendingState), admin, auditRef)) {
                return false;
            }
        }
        auditLogGroupMembers(auditDetails, "added-members", newMembers);
        return true;
    }

    boolean processServiceIdentity(ResourceContext ctx, ObjectStoreConnection con, ServiceIdentity originalService,
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

        // add domain change event
        addDomainChangeMessage(ctx, domainName, serviceName, DomainChangeMessage.ObjectType.SERVICE);
        
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
            Map<String, PublicKeyEntry> updatePublicKeysMap = new HashMap<>();
            if (publicKeys != null) {
                for (PublicKeyEntry publicKey : publicKeys) {
                    // we want to update the pubKey if the pubKey with same id already exist but the key have changed
                    if (curPublicKeysMap.containsKey(publicKey.getId()) && !publicKey.getKey().equals(curPublicKeysMap.get(publicKey.getId()).getKey())) {
                        updatePublicKeysMap.put(publicKey.getId(), publicKey);
                    } else {
                        publicKeysMap.put(publicKey.getId(), publicKey);
                    }
                }
            }

            Set<String> curPublicKeysSet = new HashSet<>(curPublicKeysMap.keySet());
            Set<String> delPublicKeysSet = new HashSet<>(curPublicKeysSet);
            Set<String> newPublicKeysSet = new HashSet<>(publicKeysMap.keySet());
            Set<String> updatePublicKeysSet = new HashSet<>(updatePublicKeysMap.keySet());
            newPublicKeysSet.removeAll(curPublicKeysSet);
            delPublicKeysSet.removeAll(new HashSet<>(publicKeysMap.keySet()));
            delPublicKeysSet.removeAll(updatePublicKeysSet);

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

            for (String publicKey : updatePublicKeysSet) {
                if (!con.updatePublicKeyEntry(domainName, serviceName, updatePublicKeysMap.get(publicKey))) {
                    return false;
                }
            }
            auditLogPublicKeyEntries(auditDetails, "updated-publicKeys", updatePublicKeysSet, updatePublicKeysMap);
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

        if (!processServiceIdentityTags(service, serviceName, domainName, originalService, con)) {
            return false;
        }
        auditLogTags(auditDetails, service.getTags());

        auditDetails.append('}');
        return true;
    }

    private boolean processServiceIdentityTags(ServiceIdentity service, String serviceName, String domainName,
                                    ServiceIdentity originalService, ObjectStoreConnection con) {

        BiFunction<ObjectStoreConnection, Map<String, TagValueList>, Boolean> insertOp = (ObjectStoreConnection c, Map<String, TagValueList> tags) -> c.insertServiceTags(serviceName, domainName, tags);
        BiFunction<ObjectStoreConnection, Set<String>, Boolean> deleteOp = (ObjectStoreConnection c, Set<String> tagKeys) -> c.deleteServiceTags(serviceName, domainName, tagKeys);

        return processTags(con, service.getTags(), (originalService != null ? originalService.getTags() : null) , insertOp, deleteOp);
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
                LOG.debug(": possible deadlock, retries available: {}", retryCount);
            }

            ZMSUtils.threadSleep(retrySleepTime);
        }

        // return our response

        return retry;
    }

    public Policy executePutPolicyVersion(ResourceContext ctx, String domainName, String policyName, String version, String fromVersion,
                                        String auditRef, String caller, Boolean returnObj) {
        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // verify the policy hasn't reached maximum number of versions allowed

                List<String> policyVersions = con.listPolicyVersions(domainName, policyName);
                if (policyVersions.size() >= maxPolicyVersions) {
                    con.rollbackChanges();
                    throw ZMSUtils.quotaLimitError("unable to put policy: " + policyName + ", version: " + version
                            + ", max number of versions reached (" + maxPolicyVersions + ")", caller);
                }

                // retrieve our source policy version

                Policy originalPolicy = getPolicy(con, domainName, policyName, fromVersion);
                if (originalPolicy == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError("unable to fetch policy version: " + fromVersion, caller);
                }

                // check that quota is not exceeded

                quotaCheck.checkPolicyQuota(con, domainName, originalPolicy, caller);

                // now process the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                originalPolicy.setVersion(version);
                originalPolicy.setActive(false);
                if (!con.insertPolicy(domainName, originalPolicy)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put policy: " + originalPolicy.getName()
                            + ", version: " + version, caller);
                }

                // open our audit record

                auditDetails.append("{\"name\": \"").append(policyName);
                auditDetails.append("\", \"version\": \"").append(version);

                // now we need process our policy assertions

                if (!processPolicyCopyAssertions(con, originalPolicy, domainName, policyName, version, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put policy: " + originalPolicy.getName() +
                        ", version: " + version + ", fail copying assertions", caller);
                }

                // include all the tags from the original version

                if (!processPolicyTags(originalPolicy, policyName, domainName, null, con)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put policy: " + originalPolicy.getName() +
                            ", version: " + version + ", fail copying tags", caller);
                }

                auditLogTags(auditDetails, originalPolicy.getTags());
                auditDetails.append('}');

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        policyName, auditDetails.toString());

                // add domain change event

                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);

                return returnObj == Boolean.TRUE ?  getPolicy(con, domainName, policyName, version) :  null;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    boolean processPolicyCopyAssertions(ObjectStoreConnection con, Policy policy, final String domainName,
            final String policyName, final String version, StringBuilder auditDetails) {

        List<Assertion> assertions = policy.getAssertions();
        if (assertions == null) {
            return true;
        }

        auditLogAssertions(auditDetails, "copied-assertions", assertions);
        for (Assertion assertion : assertions) {

            // get assertion conditions for original assertion

            AssertionConditions assertionConditions = new AssertionConditions();
            if (assertion.getId() != null) {
                assertionConditions.setConditionsList(con.getAssertionConditions(assertion.getId()));
                auditLogAssertionConditions(auditDetails, assertionConditions.getConditionsList(),
                        "copied-assertion-conditions");
            }

            // insert assertion (and get new assertion id)

            if (!con.insertAssertion(domainName, policyName, version, assertion)) {
                return false;
            }

            // copy assertion conditions for new assertion id

            if (assertionConditions.getConditionsList() != null && !assertionConditions.getConditionsList().isEmpty()) {
                if (!con.insertAssertionConditions(assertion.getId(), assertionConditions)) {
                    return false;
                }
            }
        }
        return true;
    }

    Policy executePutPolicy(ResourceContext ctx, String domainName, String policyName, Policy policy,
            String auditRef, String caller, Boolean returnObj) {

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

                Policy originalPolicy = getPolicy(con, domainName, policyName, policy.getVersion());

                // validate if we have a proper version specified for our object
                // if no version is specified then we are dealing with
                // our active version thus no validation is necessary
                // otherwise we need to make sure our originalPolicy exists

                if (!StringUtil.isEmpty(policy.getVersion()) && originalPolicy == null) {
                    // unknown policy version - check to see if we already have a policy with that name
                    Policy activePolicy = getPolicy(con, domainName, policyName, null);
                    // If the new version is active and we already have a policy with that name - terminate with error
                    if (policy.getActive() && activePolicy != null) {
                        con.rollbackChanges();
                        throw ZMSUtils.requestError("Policy " + policyName + " already exists with an active version. ", caller);
                    }
                    // If the new version is not active and we don't have a policy with that name - terminate with error
                    if (!policy.getActive() && activePolicy == null) {
                        con.rollbackChanges();
                        throw ZMSUtils.notFoundError("Policy " + policyName + " doesn't exist, new version must be active ", caller);
                    }
                }

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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);

                return returnObj == Boolean.TRUE ? getPolicy(con, domainName, policyName, policy.getVersion()) : null;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeSetActivePolicy(ResourceContext ctx, String domainName, String policyName, String version,
                          String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // Get original active policy, so we'll have the version for audit log and to update timestamp

                Policy originalActivePolicy = con.getPolicy(domainName, policyName, null);
                if (originalActivePolicy == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError("unknown policy: " + policyName, caller);
                }

                // verify the new active policy version exists before executing the request

                Policy newActivePolicy = con.getPolicy(domainName, policyName, version);
                if (newActivePolicy == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError("unknown policy version: " + version, caller);
                }

                // now process the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                if (con.setActivePolicyVersion(domainName, policyName, version) &&
                        con.updatePolicyModTimestamp(domainName, policyName, version) &&
                        con.updatePolicyModTimestamp(domainName, policyName, originalActivePolicy.getVersion())) {
                    // get policy versions with updated timestamp
                    originalActivePolicy = con.getPolicy(domainName, policyName, originalActivePolicy.getVersion());
                    newActivePolicy = con.getPolicy(domainName, policyName, version);
                    auditLogPolicy(auditDetails, Arrays.asList(originalActivePolicy, newActivePolicy), "set-active-policy");
                } else {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to set active policy version: " + version + " for policy: " + policyName + " in domain: " + domainName, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        policyName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);
                
                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    Role executePutRole(ResourceContext ctx, String domainName, String roleName, Role role,
            String auditRef, String caller, Boolean returnObj) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                final String principal = getPrincipalName(ctx);

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

                // we need to validate and transfer the last reviewed date if necessary

                boolean isNewRole = originalRole == null;
                Timestamp originalLastReviewedTime = isNewRole ? null : originalRole.getLastReviewedDate();
                role.setLastReviewedDate(objectLastReviewDate(role.getLastReviewedDate(),
                        originalLastReviewedTime, isNewRole, caller));

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

                // add domain change event

                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);

                return returnObj == Boolean.TRUE ? getRole(con, domainName, roleName, true, false, true) : null;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    Timestamp objectLastReviewDate(Timestamp newLastReviewedDate, Timestamp oldLastReviewedDate,
            boolean isNewObject, final String caller) {

        // if the new last reviewed date is not specified then
        // we'll just return the old value

        if (newLastReviewedDate == null) {
            return oldLastReviewedDate;
        }

        // if the new last reviewed timestamp is the same as the old value
        // then no further validation is required

        if (newLastReviewedDate.equals(oldLastReviewedDate)) {
            return newLastReviewedDate;
        }

        // otherwise we're going to make sure to validate that the date
        // specified is not in the future (we'll allow an offset of 5 minutes
        // in case the client/server times are not in sync) and within the configured
        // offset days from the current time (we don't want admins to specify
        // review date way in the past unless we're dealing with a new object
        // in which case we don't really care much about the strict review
        // date validation and allow a much larger offset).

        long currentTime = System.currentTimeMillis();
        long reviewTime = newLastReviewedDate.millis();
        if (reviewTime > currentTime + 300 * 1000) {
            throw ZMSUtils.requestError("Last reviewed date: " + newLastReviewedDate +
                    " is in the future", caller);
        }
        long maxLastReviewDateOffsetMillis = isNewObject ? maxLastReviewDateOffsetMillisForNewObjects :
                maxLastReviewDateOffsetMillisForUpdatedObjects;
        if (currentTime - reviewTime > maxLastReviewDateOffsetMillis) {
            throw ZMSUtils.requestError("Last reviewed date: " + newLastReviewedDate +
                    " is too far in the past", caller);
        }
        return newLastReviewedDate;
    }

    Group executePutGroup(ResourceContext ctx, final String domainName, final String groupName, Group group,
                          final String auditRef, Boolean returnObj) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                final String principal = getPrincipalName(ctx);

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

                // we need to validate and transfer the last reviewed date if necessary

                boolean isNewGroup = originalGroup == null;
                Timestamp originalLastReviewedTime = isNewGroup ? null : originalGroup.getLastReviewedDate();
                group.setLastReviewedDate(objectLastReviewDate(group.getLastReviewedDate(),
                        originalLastReviewedTime, isNewGroup, ctx.getApiName()));

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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);

                return returnObj == Boolean.TRUE ? getGroup(con, domainName, groupName, true, true) : null;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    ServiceIdentity executePutServiceIdentity(ResourceContext ctx, String domainName, String serviceName,
            ServiceIdentity service, String auditRef, String caller, Boolean returnObj) {

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
                if (!processServiceIdentity(ctx, con, originalService, domainName, serviceName,
                        service, false, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put service: " + service.getName(), caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        serviceName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, serviceName, DomainChangeMessage.ObjectType.SERVICE);

                return returnObj == Boolean.TRUE ? getServiceIdentity(con, domainName, serviceName, false) : null;

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
                            " in service " + ResourceUtils.serviceResourceName(domainName, serviceName), caller);
                }

                // update our service and domain time-stamp and save changes

                con.updateServiceIdentityModTimestamp(domainName, serviceName);
                saveChanges(con, domainName);

                // audit log the request

                auditLogPublicKeyEntry(auditDetails, keyEntry, true);
                auditDetails.append("]}");

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        serviceName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, serviceName, DomainChangeMessage.ObjectType.SERVICE);
                
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
                            " in service " + ResourceUtils.serviceResourceName(domainName, serviceName), caller);
                }

                // update our service and domain time-stamp and save changes

                con.updateServiceIdentityModTimestamp(domainName, serviceName);
                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        serviceName, "{\"deleted-publicKeys\": [{\"id\": \"" + keyId + "\"}]}");

                // add domain change event
                addDomainChangeMessage(ctx, domainName, serviceName, DomainChangeMessage.ObjectType.SERVICE);
                
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

        return !StringUtil.isEmpty(role.getTrust());
    }

    Membership executePutMembership(ResourceContext ctx, String domainName, String roleName,
            RoleMember roleMember, String auditRef, String caller, Boolean returnObj) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                final String principal = getPrincipalName(ctx);

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
                            " is a delegated role", caller);
                }

                // now we need verify our quota check

                quotaCheck.checkRoleMembershipQuota(con, domainName, roleName, roleMember.getMemberName(),
                        originalRole.getMaxMembers(), caller);

                // process our insert role member support. since this is a "single"
                // operation, we are not using any transactions.

                String pendingState = roleMember.getApproved() == Boolean.FALSE ? ZMSConsts.PENDING_REQUEST_ADD_STATE : null;
                if (!con.insertRoleMember(domainName, roleName, roleMember.setPendingState(pendingState), principal, auditRef)) {
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);

                return returnObj == Boolean.TRUE ? con.getRoleMember(domainName, roleName, roleMember.getMemberName(), 0, roleMember.getApproved() == Boolean.FALSE) : null;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    GroupMembership executePutGroupMembership(ResourceContext ctx, final String domainName, Group group,
                                   GroupMember groupMember, final String auditRef, Boolean returnObj) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                final String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, ctx.getApiName(), principal, AUDIT_TYPE_GROUP);

                // make sure the group auditing requirements are met

                checkObjectAuditEnabled(con, group.getAuditEnabled(), group.getName(),
                        auditRef, ctx.getApiName(), principal);

                // now we need verify our quota check

                final String groupName = ZMSUtils.extractGroupName(domainName, group.getName());
                quotaCheck.checkGroupMembershipQuota(con, domainName, groupName, groupMember.getMemberName(),
                        group.getMaxMembers(), ctx.getApiName());

                // process our insert group member support. since this is a "single"
                // operation, we are not using any transactions.

                String pendingState = groupMember.getApproved() == Boolean.FALSE ? ZMSConsts.PENDING_REQUEST_ADD_STATE : null;
                if (!con.insertGroupMember(domainName, groupName, groupMember.setPendingState(pendingState), principal, auditRef)) {
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

                // add domain change event

                addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);

                return returnObj == Boolean.TRUE ? con.getGroupMember(domainName, groupName, groupMember.getMemberName(), 0, groupMember.getApproved() == Boolean.FALSE) : null;

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
                        entityName, JSON.string(entity.getValue()));

                // add domain change event
                addDomainChangeMessage(ctx, domainName, entityName, DomainChangeMessage.ObjectType.ENTITY);
                
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

                final String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal, AUDIT_TYPE_ROLE);

                // process our delete role member operation

                Role role = con.getRole(domainName, roleName);
                boolean pending = (role != null) &&
                        (role.getDeleteProtection() == Boolean.TRUE) &&
                        (role.getReviewEnabled() == Boolean.TRUE || role.getAuditEnabled() == Boolean.TRUE);

                if (pending) {
                    RoleMember roleMember = new RoleMember()
                            .setApproved(Boolean.FALSE)
                            .setMemberName(normalizedMember)
                            .setPendingState(ZMSConsts.PENDING_REQUEST_DELETE_STATE);
                    if (!con.insertRoleMember(domainName, roleName, roleMember, principal, auditRef)) {
                        con.rollbackChanges();
                        throw ZMSUtils.requestError(caller + ": unable to insert role member: " +
                                roleMember.getMemberName() + " to role: " + roleName, caller);
                    }
                } else if (!con.deleteRoleMember(domainName, roleName, normalizedMember, principal, auditRef)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to delete role member: " +
                            normalizedMember + " from role: " + roleName, caller);
                }

                // update our role and domain time-stamps, and invalidate local cache entry

                con.updateRoleModTimestamp(domainName, roleName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request
                auditLogRequest(ctx, domainName, auditRef, caller, pending ? ZMSConsts.HTTP_PUT : ZMSConsts.HTTP_DELETE,
                        roleName, "{\"member\": \"" + normalizedMember + "\"}");

                // add domain change event
                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
                
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

                final String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal, AUDIT_TYPE_ROLE);

                // process our delete role member operation

                if (!con.deletePendingRoleMember(domainName, roleName, normalizedMember, principal, auditRef)) {
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
                
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

                final String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, ctx.getApiName(), principal, AUDIT_TYPE_GROUP);

                // process our delete group member operation

                Group group = con.getGroup(domainName, groupName);
                boolean pending = (group != null) &&
                        (group.getDeleteProtection() == Boolean.TRUE) &&
                        (group.getReviewEnabled() == Boolean.TRUE || group.getAuditEnabled() == Boolean.TRUE);

                if (pending) {
                    GroupMember groupMember = new GroupMember()
                            .setApproved(Boolean.FALSE)
                            .setMemberName(normalizedMember)
                            .setPendingState(ZMSConsts.PENDING_REQUEST_DELETE_STATE);
                    if (!con.insertGroupMember(domainName, groupName, groupMember, principal, auditRef)) {
                        con.rollbackChanges();
                        throw ZMSUtils.requestError("unable to insert group member: " +
                                groupMember.getMemberName() + " to group: " + groupName, ctx.getApiName());
                    }
                } else if (!con.deleteGroupMember(domainName, groupName, normalizedMember, principal, auditRef)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError("unable to delete group member: " +
                            normalizedMember + " from group: " + groupName, ctx.getApiName());
                }

                // update our group and domain time-stamps, and invalidate local cache entry

                con.updateGroupModTimestamp(domainName, groupName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), pending ? ZMSConsts.HTTP_PUT : ZMSConsts.HTTP_DELETE,
                        groupName, "{\"member\": \"" + normalizedMember + "\"}");

                // add domain change event
                addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);
                
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

                final String principal = getPrincipalName(ctx);

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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);
                
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, serviceName, DomainChangeMessage.ObjectType.SERVICE);
                
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, entityName, DomainChangeMessage.ObjectType.ENTITY);
                
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
                
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);
                
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

                // extract the current policy for audit log purposes

                List<String> versions = con.listPolicyVersions(domainName, policyName);
                if (versions == null || versions.isEmpty()) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to get versions for policy: " + policyName, caller);
                }
                List<Policy> policyVersions = new ArrayList<>();
                for (String version : versions) {
                    Policy policy = getPolicy(con, domainName, policyName, version);
                    if (policy == null) {
                        con.rollbackChanges();
                        throw ZMSUtils.notFoundError(caller + ": unable to read policy: " + policyName + ", with version: " + version, caller);
                    }
                    policyVersions.add(policy);
                }
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogPolicy(auditDetails, policyVersions, "deleted-policy-versions");

                // process our delete policy request

                if (!con.deletePolicy(domainName, policyName)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to delete policy: " + policyName, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        policyName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);
                
                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeletePolicyVersion(ResourceContext ctx, String domainName, String policyName, String version,
                             String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // extract the current policy version for audit log purposes

                Policy policy = getPolicy(con, domainName, policyName, version);
                if (policy == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to read policy: " + policyName + ", version: " + version, caller);
                }
                if (policy.getActive()) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError(caller + ": unable to delete active policy version. Policy: " + policyName + ", version: " + version, caller);
                }

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogPolicyVersion(auditDetails, policy, true);

                // process our delete policy request

                if (!con.deletePolicyVersion(domainName, policyName, version)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to delete policy: " + policyName + ", version: " + version, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        policyName + ":" + version, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);
                
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
            if (StringUtil.isEmpty(auditRef)) {
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, domainName, DomainChangeMessage.ObjectType.DOMAIN);
                
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
                    if (principal.indexOf('.', prefixLength) == -1) {
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

    void removePrincipalFromDomainRoles(ResourceContext ctx, ObjectStoreConnection con, String domainName, String principalName,
            String adminUser, String auditRef) {

        // extract all the roles that this principal is member of
        // we have to this here so that there are records of
        // entries in the role member audit logs and the domain
        // entries are properly invalidated

        DomainRoleMember roles = con.getPrincipalRoles(principalName, domainName);

        // we want to check if we had any roles otherwise
        // we don't want to update the domain mod timestamp

        if (roles.getMemberRoles().isEmpty()) {
            return;
        }

        for (MemberRole role : roles.getMemberRoles()) {

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

            // add domain change event

            addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
        }

        con.updateDomainModTimestamp(domainName);
        cacheStore.invalidate(domainName);
    }

    void removePrincipalFromAllRoles(ResourceContext ctx, ObjectStoreConnection con, final String principalName,
            final String adminUser, final String auditRef) {

        // extract all the roles that this principal is member of
        // we have to this here so that there are records of
        // entries in the role member audit logs and the domain
        // entries are properly invalidated

        DomainRoleMember roles;
        try {
            roles = con.getPrincipalRoles(principalName, null);
        } catch (ResourceException ex) {

            // if there is no such principal then we have nothing to do

            if (ex.getCode() == ResourceException.NOT_FOUND) {
                return;
            } else {
                throw ex;
            }
        }

        for (MemberRole role : roles.getMemberRoles()) {

            final String domainName = role.getDomainName();
            final String roleName = role.getRoleName();

            // process our delete role member operation

            LOG.info("Inactive User Cleanup - principal: {} role: {}:role.{}", principalName, domainName, roleName);

            // we are going to ignore all errors here rather than
            // rejecting the full operation. our delete user will
            // eventually remove all these principals

            try {
                con.deleteRoleMember(domainName, roleName, principalName, adminUser, auditRef);
            } catch (ResourceException ex) {
                LOG.error("unable to remove {} from {}:role.{} - error {}",
                        principalName, domainName, roleName, ex.getMessage());
            }

            // update our role and domain time-stamps, and invalidate local cache entry

            con.updateRoleModTimestamp(domainName, roleName);
            con.updateDomainModTimestamp(domainName);
            cacheStore.invalidate(domainName);

            // add domain change event
            addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
        }
    }

    void removePrincipalFromAllGroups(ResourceContext ctx, ObjectStoreConnection con, final String principalName,
            final String adminUser, final String auditRef) {

        // extract all the groups that this principal is member of
        // we have to this here so that there are records of
        // entries in the group member audit logs and the domain
        // entries are properly invalidated

        DomainGroupMember roles;
        try {
            roles = con.getPrincipalGroups(principalName, null);
        } catch (ResourceException ex) {

            // if there is no such principal then we have nothing to do

            if (ex.getCode() == ResourceException.NOT_FOUND) {
                return;
            } else {
                throw ex;
            }
        }

        for (GroupMember group : roles.getMemberGroups()) {

            final String domainName = group.getDomainName();
            final String groupName = group.getGroupName();

            // process our delete group member operation

            LOG.info("Inactive User Cleanup - principal: {} group: {}:group.{}", principalName, domainName, groupName);

            // we are going to ignore all errors here rather than
            // rejecting the full operation. our delete user will
            // eventually remove all these principals

            try {
                con.deleteGroupMember(domainName, groupName, principalName, adminUser, auditRef);
            } catch (ResourceException ex) {
                LOG.error("unable to remove {} from {}:group.{} - error {}",
                        principalName, domainName, groupName, ex.getMessage());
            }

            // update our group and domain time-stamps, and invalidate local cache entry

            con.updateGroupModTimestamp(domainName, groupName);
            con.updateDomainModTimestamp(domainName);
            cacheStore.invalidate(domainName);

            // add domain change event
            addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);
        }
    }

    void removePrincipalDomains(ResourceContext ctx, ObjectStoreConnection con, String principalName) {

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
        addDomainChangeMessage(ctx, principalName, principalName, DomainChangeMessage.ObjectType.DOMAIN);
        
        for (String subDomain : subDomains) {
            con.deleteDomain(subDomain);
            cacheStore.invalidate(subDomain);
            addDomainChangeMessage(ctx, subDomain, subDomain, DomainChangeMessage.ObjectType.DOMAIN);
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

                removePrincipalFromDomainRoles(ctx, con, domainName, memberName, getPrincipalName(ctx), auditRef);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE, memberName, null);
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

                removePrincipalDomains(ctx, con, domainName);

                // extract all principals that this user has - this would
                // include the user self plus all services this user
                // has created in the personal domain + sub-domains

                List<String> userSvcPrincipals = con.listPrincipals(domainName);

                // remove this principal from all roles manually so that we
                // can have an audit log record for each role

                final String adminPrincipal = getPrincipalName(ctx);
                removePrincipalFromAllRoles(ctx, con, userName, adminPrincipal, auditRef);
                for (String userSvcPrincipal : userSvcPrincipals) {
                    removePrincipalFromAllRoles(ctx, con, userSvcPrincipal, adminPrincipal, auditRef);
                }

                // remove this principal from all groups manually so that we
                // can have an audit log record for each group

                removePrincipalFromAllGroups(ctx, con, userName, adminPrincipal, auditRef);
                for (String userSvcPrincipal : userSvcPrincipals) {
                    removePrincipalFromAllGroups(ctx, con, userSvcPrincipal, adminPrincipal, auditRef);
                }

                // finally, delete the principal object. any roles that were
                // left behind will be cleaned up from this operation

                if (!con.deletePrincipal(userName, true)) {
                    throw ZMSUtils.notFoundError(caller + ": unable to delete user: "
                            + userName, caller);
                }

                // automatically update any domain contact record where this user is referenced

                updateDomainContactReferences(con, userName);

                // audit log the request

                auditLogRequest(ctx, userName, auditRef, caller, ZMSConsts.HTTP_DELETE, userName, null);
                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void updateDomainContactReferences(ObjectStoreConnection con, final String userName) {

        // first check what domain is this user referenced in

        Map<String, List<String>> contactDomains;
        try {
            contactDomains = con.listContactDomains(userName);
            if (contactDomains == null || contactDomains.isEmpty()) {
                return;
            }
        } catch (Exception ex) {
            LOG.error("unable to obtain contact references for user: {} - error: {}",
                    userName, ex.getMessage());
            return;
        }

        // find the manager for this user

        final String manager = getUserManager(userName);

        // go through each contact reference and update it. if we get any
        // failures for any of the updates, we're just going to log it
        // and continue - we will not fail the transaction

        for (Map.Entry<String, List<String>> entry : contactDomains.entrySet()) {
            final String domainName = entry.getKey();
            for (String contactType : entry.getValue()) {
                try {
                    if (manager == null) {
                        con.deleteDomainContact(domainName, contactType);
                    } else {
                        con.updateDomainContact(domainName, contactType, manager);
                    }
                } catch (Exception ex) {
                    LOG.error("unable to update contact {} reference for user: {} - error: {}",
                            contactType, userName, ex.getMessage());
                }
            }
        }
    }

    String getUserManager(final String userName) {

        // find the manager for this user

        String manager = null;
        try {
            if (zmsConfig.getUserAuthority() != null) {
                manager = zmsConfig.getUserAuthority().getUserManager(userName);
            }
            if (manager == null) {
                LOG.info("unable to determine manager for user: {}", userName);
            }
        } catch (Exception ex) {
            LOG.error("unable to determine manager for user: {} - error: {}",
                    userName, ex.getMessage());
        }

        return manager;
    }

    public ServiceIdentity getServiceIdentity(String domainName, String serviceName, boolean attrsOnly) {

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
            service.setTags(con.getServiceTags(domainName, serviceName));
            List<String> hosts = con.listServiceHosts(domainName, serviceName);
            if (!ZMSUtils.isCollectionEmpty(hosts)) {
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

        final String fullServiceName = ResourceUtils.serviceResourceName(domainName, serviceName);
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
        // and needs to be optimized. For now, we'll configure it with
        // default timeout of 30 minutes to avoid any issues

        ResourceAccessList accessList;
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            con.setOperationTimeout(1800);
            accessList = con.listResourceAccess(principal, action, zmsConfig.getUserDomain());
        }

        // update the resources accordingly if the action is designed for one
        // of our cloud providers

        if (awsAssumeRoleAction.equals(action)) {
            generateAWSResources(accessList);
        } else if (gcpAssumeRoleAction.equals(action) || gcpAssumeServiceAction.equals(action)) {
            generateGCPResources(accessList);
        }

        return accessList;
    }

    void generateGCPResources(ResourceAccessList accessList) {

        // first we need to get a mapping of our gcp domains

        Map<String, String> gcpDomains;
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            gcpDomains = con.listDomainsByCloudProvider(ObjectStoreConnection.PROVIDER_GCP);
        }

        // if the gcp domain list is empty then we'll be removing all resources

        if (gcpDomains == null || gcpDomains.isEmpty()) {
            accessList.setResources(Collections.emptyList());
            return;
        }

        // we're going to update each assertion and generate the
        // resource in the expected gcp role format. however, we
        // are going to remove any assertions where we do not have a
        // valid syntax or no gcp domain

        List<ResourceAccess> resourceAccessList = accessList.getResources();
        for (ResourceAccess resourceAccess : resourceAccessList) {
            Iterator<Assertion> assertionIterator = resourceAccess.getAssertions().iterator();
            while (assertionIterator.hasNext()) {

                Assertion assertion = assertionIterator.next();

                final String role = assertion.getRole();
                final String resource = assertion.getResource();

                if (LOG.isDebugEnabled()) {
                    LOG.debug("processing assertion: {}/{}", role, resource);
                }

                // verify that role and resource domains match

                final String resourceDomain = assertionDomainCheck(role, resource);
                if (resourceDomain == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("assertion domain check failed, removing assertion");
                    }
                    assertionIterator.remove();
                    continue;
                }

                final String gcpProject = gcpDomains.get(resourceDomain);
                if (gcpProject == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("resource without gcp project: {}", resourceDomain);
                    }
                    assertionIterator.remove();
                    continue;
                }

                final String resourceObject = resource.substring(resourceDomain.length() + 1);
                final String resourceComp = (resourceObject.startsWith("roles/") || resourceObject.startsWith("groups/")
                        || resourceObject.startsWith("services/")) ? "/" : "/roles/";
                assertion.setResource(GCP_ARN_PREFIX + gcpProject + resourceComp + resourceObject);
            }
        }
    }

    void generateAWSResources(ResourceAccessList accessList) {

        // first we need to get a mapping of our aws domains

        Map<String, String> awsDomains;
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            awsDomains = con.listDomainsByCloudProvider(ObjectStoreConnection.PROVIDER_AWS);
        }

        // if aws domain list is empty then we'll be removing all resources

        if (awsDomains == null || awsDomains.isEmpty()) {
            accessList.setResources(Collections.emptyList());
            return;
        }

        // we're going to update each assertion and generate the
        // resource in the expected aws role format. however, we
        // are going to remove any assertions where we do not have a
        // valid syntax or no aws domain

        List<ResourceAccess> resourceAccessList = accessList.getResources();
        for (ResourceAccess resourceAccess : resourceAccessList) {
            Iterator<Assertion> assertionIterator = resourceAccess.getAssertions().iterator();
            while (assertionIterator.hasNext()) {

                Assertion assertion = assertionIterator.next();

                final String role = assertion.getRole();
                final String resource = assertion.getResource();

                if (LOG.isDebugEnabled()) {
                    LOG.debug("processing assertion: {}/{}", role, resource);
                }

                // verify that role and resource domains match

                final String resourceDomain = assertionDomainCheck(role, resource);
                if (resourceDomain == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("assertion domain check failed, removing assertion");
                    }
                    assertionIterator.remove();
                    continue;
                }

                final String awsAccount = awsDomains.get(resourceDomain);
                if (awsAccount == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("resource without aws account: {}", resourceDomain);
                    }
                    assertionIterator.remove();
                    continue;
                }

                assertion.setResource(AWS_ARN_PREFIX + awsAccount + ":role/" + resource.substring(resourceDomain.length() + 1));
            }
        }
    }

    String assertionDomainCheck(final String role, final String resource) {

        // first extract and verify the index values

        int rsrcIdx = resource.indexOf(':');
        if (rsrcIdx == -1 || rsrcIdx == 0) {
            return null;
        }

        int roleIdx = role.indexOf(':');
        if (roleIdx == -1 || roleIdx == 0) {
            return null;
        }

        if (rsrcIdx != roleIdx) {
            return null;
        }

        // now extract and verify actual domain values

        final String resourceDomain = resource.substring(0, rsrcIdx);
        return resourceDomain.equals(role.substring(0, roleIdx)) ? resourceDomain : null;
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

    DomainList lookupDomainByCloudProvider(final String provider, final String value) {

        DomainList domList = new DomainList();
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            final String domain = con.lookupDomainByCloudProvider(provider, value);
            if (domain != null) {
                domList.setNames(Collections.singletonList(domain));
            }
        }
        return domList;
    }

    DomainList lookupDomainByAWSAccount(final String account) {
        return lookupDomainByCloudProvider(ObjectStoreConnection.PROVIDER_AWS, account);
    }

    DomainList lookupDomainByAzureSubscription(final String subscription) {
        return lookupDomainByCloudProvider(ObjectStoreConnection.PROVIDER_AZURE, subscription);
    }

    DomainList lookupDomainByGcpProject(final String project) {
        return lookupDomainByCloudProvider(ObjectStoreConnection.PROVIDER_GCP, project);
    }

    DomainList lookupDomainByProductId(Integer productId) {
        DomainList domList = new DomainList();
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            String domain = con.lookupDomainByProductId(productId);
            if (domain != null) {
                domList.setNames(Collections.singletonList(domain));
            }
        }
        return domList;
    }

    DomainList lookupDomainByProductId(String productId) {
        DomainList domList = new DomainList();
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            String domain = con.lookupDomainByProductId(productId);
            if (domain != null) {
                domList.setNames(Collections.singletonList(domain));
            }
        }
        return domList;
    }

    DomainList lookupDomainByBusinessService(final String businessService) {
        DomainList domList = new DomainList();
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            domList.setNames(con.lookupDomainByBusinessService(businessService));
        }
        return domList;
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

    DomainRoleMember getPrincipalRoles(String principal, String domainName, Boolean expand) {

        DomainRoleMember principalRoles;
        DomainGroupMember principalGroups;

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            if (expand != Boolean.TRUE) {
                return con.getPrincipalRoles(principal, domainName);
            }

            principalRoles = con.getPrincipalRoles(principal, null);

            // if we're asked to return expanded list of roles (including indirect
            // membership through group and delegated roles), we need to get the list
            // of groups that the principal is a member of, and then for each one
            // extract the roles the group is a member of, and add those roles to
            // our return list for further processing

            principalGroups = con.getPrincipalGroups(principal, null);
            for (GroupMember groupMember : principalGroups.getMemberGroups()) {
                final String groupName = ResourceUtils.groupResourceName(groupMember.getDomainName(), groupMember.getGroupName());
                try {
                    DomainRoleMember roleGroupMembers = con.getPrincipalRoles(groupName, null);
                    for (MemberRole memberRole : roleGroupMembers.getMemberRoles()) {
                        memberRole.setMemberName(groupName);
                    }
                    principalRoles.getMemberRoles().addAll(roleGroupMembers.getMemberRoles());
                } catch (ResourceException ex) {
                    if (ex.getCode() == ResourceException.NOT_FOUND) {
                        continue;
                    }
                    throw ex;
                }
            }
        }

        // at this point we have determined the full list of roles that the principal
        // is a member of directly or through group membership. so we only need to
        // process the delegated roles. To determine that list, we need to go
        // through each role in our result set and see if there is a policy
        // assertion with the assume_role role action and the given role.
        // Since there is a highly likely chance the same service might exist in the
        // same domain multiple times, we'll maintain our local cache of
        // athenz domain objects to reduce the number of DB calls when checking
        // the last modified timestamp for the domain

        Map<String, AthenzDomain> localDomainCache = new HashMap<>();
        List<MemberRole> delegatedMemberRoles = new ArrayList<>();
        for (MemberRole memberRole : principalRoles.getMemberRoles()) {
            List<MemberRole> roleList = getDelegatedMemberRole(localDomainCache, memberRole);
            if (!ZMSUtils.isCollectionEmpty(roleList)) {
                delegatedMemberRoles.addAll(roleList);
            }
        }

        // combine our delegated role list to our result set

        principalRoles.getMemberRoles().addAll(delegatedMemberRoles);

        // if we're asked to filter the domain field, then we'll go
        // through the full list and filter out the unwanted domains

        if (!StringUtil.isEmpty(domainName)) {
            principalRoles.getMemberRoles().removeIf(item -> !domainName.equals(item.getDomainName()));
        }

        return principalRoles;
    }

    ReviewObjects getRolesForReview(final String principal) {
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return filterObjectsForReview(con.getRolesForReview(principal));
        }
    }

    ReviewObjects getGroupsForReview(final String principal) {
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return filterObjectsForReview(con.getGroupsForReview(principal));
        }
    }

    ReviewObjects filterObjectsForReview(ReviewObjects reviewObjects) {

        List<ReviewObject> objects = reviewObjects.getList();
        if (objects == null || objects.isEmpty()) {
            return reviewObjects;
        }
        List<ReviewObject> filteredObjects = new ArrayList<>();
        long now = System.currentTimeMillis();
        int reviewDaysPercentage = minReviewDaysPercentage.get();
        if (reviewDaysPercentage >= 100) {
            reviewDaysPercentage = ZMSConsts.ZMS_PROP_REVIEW_DAYS_PERCENTAGE_DEFAULT;
        }
        for (ReviewObject object : objects) {

            // if the role hasn't been reviewed before then we're going to add it
            // to our list unless it was created before the review period. therefore
            // for roles that have not been reviewed before, we're going to use the
            // creation time as the last reviewed date time

            long lastReviewedDate = object.getLastReviewedDate() == null ?
                    object.getCreated().millis() : object.getLastReviewedDate().millis();

            // determine the lowest number of days that is configured for any of the objects in our list

            int minDays = minReviewDays(object);

            // we want to review before configured period (based on the percentage) is left since the
            // last review date. For example, if the percentage is 68% and the min review period is
            // 90 days then we want to review before 28.8 days. If the review period is 30 days, then
            // we want to review before 9.6 days. We should never get a review period of 0 days since
            // the connection store must return only objects where one of the expiry/review dates is not 0.

            if (now - lastReviewedDate >=
                    ((TimeUnit.MILLISECONDS.convert(minDays, TimeUnit.DAYS) * reviewDaysPercentage) / 100)) {
                filteredObjects.add(object);
            }
        }

        reviewObjects.setList(filteredObjects);
        return reviewObjects;
    }

    int minReviewDay(int minDays, int checkDays) {
        return (checkDays != 0 && checkDays < minDays) ? checkDays : minDays;
    }

    int minReviewDays(ReviewObject object) {
        int minDays = Integer.MAX_VALUE;
        minDays = minReviewDay(minDays, object.getMemberExpiryDays());
        minDays = minReviewDay(minDays, object.getServiceExpiryDays());
        minDays = minReviewDay(minDays, object.getGroupExpiryDays());
        minDays = minReviewDay(minDays, object.getMemberReviewDays());
        minDays = minReviewDay(minDays, object.getServiceReviewDays());
        return minReviewDay(minDays, object.getGroupReviewDays());
    }

    AthenzDomain getAthenzDomainFromLocalCache(Map<String, AthenzDomain> domainCache, final String domainName) {

        // first we're going to check our local cache and if we find
        // the domain object, return right away

        AthenzDomain athenzDomain = domainCache.get(domainName);
        if (athenzDomain != null) {
            return athenzDomain;
        }

        // obtain the domain from service cache and from DB if necessary
        // add the domain to our local cache before returning

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            try {
                athenzDomain = getAthenzDomain(con, domainName);
            } catch (ResourceException ex) {
                LOG.debug("unable to fetch role athenz domain {}: {}", domainName, ex.getMessage());
                return null;
            }
        }

        domainCache.put(domainName, athenzDomain);
        return athenzDomain;
    }

    List<MemberRole> getDelegatedMemberRole(Map<String, AthenzDomain> domainCache, MemberRole memberRole) {

        // first get the domain object for this role

        AthenzDomain athenzDomain = getAthenzDomainFromLocalCache(domainCache, memberRole.getDomainName());
        if (athenzDomain == null) {
            return null;
        }

        // let's go through all assertions and look for an assume role
        // action with a given role

        final String trustRoleName = ResourceUtils.roleResourceName(memberRole.getDomainName(), memberRole.getRoleName());
        List<MemberRole> memberRoles = new ArrayList<>();
        for (Policy policy : athenzDomain.getPolicies()) {

            // ignore any inactive/multi-version policies

            if (policy.getActive() == Boolean.FALSE) {
                continue;
            }

            List<Assertion> assertions = policy.getAssertions();
            if (assertions == null) {
                continue;
            }

            for (Assertion assertion : assertions) {

                if (!AuthzHelper.assumeRoleNameMatch(trustRoleName, assertion)) {
                    continue;
                }

                // get the list of all roles in the resource domain that
                // have been delegated to our member role domain

                final String resource = assertion.getResource();
                List<String> trustRoles = getDelegatedRoleNames(domainCache, resource, memberRole.getDomainName());
                if (ZMSUtils.isCollectionEmpty(trustRoles)) {
                    continue;
                }

                // go through the list of trusted role names and see if they
                // match our resource definition which might include wildcards

                final String rolePattern = StringUtils.patternFromGlob(resource);
                for (String trustedRole : trustRoles) {
                    if (trustedRole.matches(rolePattern)) {
                        int idx = trustedRole.indexOf(AuthorityConsts.ROLE_SEP);
                        memberRoles.add(new MemberRole()
                                .setRoleName(trustedRole.substring(idx + AuthorityConsts.ROLE_SEP.length()))
                                .setDomainName(trustedRole.substring(0, idx))
                                .setTrustRoleName(trustRoleName)
                                .setMemberName(memberRole.getMemberName())
                                .setExpiration(memberRole.getExpiration()));
                    }
                }

            }
        }
        return memberRoles;
    }

    List<String> getDelegatedRoleNames(Map<String, AthenzDomain> domainCache, final String resource,
            final String trustDomainName) {

        // determine our resource domain name from the arn

        int idx = resource.indexOf(':');
        if (idx == -1) {
            return null;
        }

        // get the list of all roles in the resource domain that
        // have been delegated to our member role domain

        final String resourceDomainName = resource.substring(0, idx);

        // if our resource domain '*' then we have to carry out
        // a db lookup to get all the domains that have a role
        // with the matching name and trust set to our trustDomainName

        if ("*".equals(resourceDomainName)) {
            final String resourceObject = resource.substring(idx + 1);
            if (!resourceObject.startsWith(ROLE_PREFIX)) {
                return null;
            }
            try (ObjectStoreConnection con = store.getConnection(true, false)) {
                return con.listTrustedRolesWithWildcards(resourceDomainName,
                        resourceObject.substring(ROLE_PREFIX.length()), trustDomainName);
            }
        }

        // first get the domain details for this resource domain name

        AthenzDomain athenzDomain = getAthenzDomainFromLocalCache(domainCache, resourceDomainName);
        if (athenzDomain == null) {
            return null;
        }

        // go through the list of roles and return all with the given
        // domain name set as its trust value

        List<String> roleNames = new ArrayList<>();
        for (Role role : athenzDomain.getRoles()) {
            if (trustDomainName.equals(role.getTrust())) {
                roleNames.add(role.getName());
            }
        }
        return roleNames;
    }

    DomainGroupMember getPrincipalGroups(String principal, String domainName) {
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.getPrincipalGroups(principal, domainName);
        }
    }

    public Group getGroup(final String domainName, final String groupName, Boolean auditLog, Boolean pending) {

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

        Map<String, TagValueList> groupTags = con.getGroupTags(domainName, groupName);
        if (groupTags != null) {
            group.setTags(groupTags);
        }

        return group;
    }

    public Role getRole(String domainName, String roleName, Boolean auditLog, Boolean expand, Boolean pending) {

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

            Map<String, TagValueList> roleTags = con.getRoleTags(domainName, roleName);
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

        String fullRoleName = ResourceUtils.roleResourceName(domainName, roleName);

        // iterate through all policies to see which one has the
        // assume_role assertion for the given role

        for (Policy policy : domain.getPolicies()) {

            // ignore any inactive/multi-version policies
            if (policy.getActive() == Boolean.FALSE) {
                continue;
            }

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

    Policy getPolicy(String domainName, String policyName, String version) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return getPolicy(con, domainName, policyName, version);
        }
    }

    Assertion getAssertion(String domainName, String policyName, Long assertionId) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.getAssertion(domainName, policyName, assertionId);
        }
    }

    void executePutAssertion(ResourceContext ctx, String domainName, String policyName, String version,
            Assertion assertion, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // now we need verify our quota check

                quotaCheck.checkPolicyAssertionQuota(con, domainName, policyName, version, caller);

                // process our insert assertion. since this is a "single"
                // operation, we are not using any transactions.

                if (!con.insertAssertion(domainName, policyName, version, assertion)) {
                    throw ZMSUtils.requestError(caller + ": unable to insert assertion: " +
                            " to policy: " + policyName, caller);
                }

                // update our policy and domain time-stamps, and invalidate local cache entry

                con.updatePolicyModTimestamp(domainName, policyName, version);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogAssertion(auditDetails, assertion, true);

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        policyName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);
                
                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executeDeleteAssertion(ResourceContext ctx, String domainName, String policyName, String version,
            Long assertionId, String auditRef, String caller) {

        String versionForAuditLog = StringUtil.isEmpty(version) ? "active version" : version;
        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // fetch the assertion for our audit log

                Assertion assertion = con.getAssertion(domainName, policyName, assertionId);
                if (assertion == null) {
                    throw ZMSUtils.notFoundError(caller + ": unable to read assertion: " +
                            assertionId + " from policy: " + policyName + " version: " + versionForAuditLog, caller);
                }

                // process our delete assertion. since this is a "single"
                // operation, we are not using any transactions.

                if (!con.deleteAssertion(domainName, policyName, version, assertionId)) {
                    throw ZMSUtils.requestError(caller + ": unable to delete assertion: " +
                            assertionId + " from policy: " + policyName + " version: " + versionForAuditLog, caller);
                }

                // update our policy and domain time-stamps, and invalidate local cache entry

                con.updatePolicyModTimestamp(domainName, policyName, version);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"policy\": \"").append(policyName)
                        .append("\", \"version\": \"").append(versionForAuditLog)
                        .append("\", \"assertionId\": \"").append(assertionId)
                        .append("\", \"deleted-assertions\": [");
                auditLogAssertion(auditDetails, assertion, true);
                auditDetails.append("]}");

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        policyName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);
                
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

    Policy getPolicy(ObjectStoreConnection con, String domainName, String policyName, String version) {

        Policy policy = con.getPolicy(domainName, policyName, version);
        if (policy != null) {
            policy.setAssertions(con.listAssertions(domainName, policyName, version));
            policy.setTags(con.getPolicyTags(domainName, policyName, version));
        }

        return policy;
    }

    List<String> listPolicies(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.listPolicies(domainName, null);
        }
    }

    List<String> listPolicyVersions(String domainName, String policyName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.listPolicyVersions(domainName, policyName);
        }
    }

    List<String> listServiceIdentities(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.listServiceIdentities(domainName);
        }
    }

    void executePutDomainMeta(ResourceContext ctx, Domain domain, DomainMeta meta,
            final String systemAttribute, boolean deleteAllowed, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                final String domainName = domain.getName();

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
                        .setGcpProject(domain.getGcpProject())
                        .setGcpProjectNumber(domain.getGcpProjectNumber())
                        .setYpmId(domain.getYpmId())
                        .setProductId(domain.getProductId())
                        .setCertDnsDomain(domain.getCertDnsDomain())
                        .setMemberExpiryDays(domain.getMemberExpiryDays())
                        .setServiceExpiryDays(domain.getServiceExpiryDays())
                        .setGroupExpiryDays(domain.getGroupExpiryDays())
                        .setTokenExpiryMins(domain.getTokenExpiryMins())
                        .setRoleCertExpiryMins(domain.getRoleCertExpiryMins())
                        .setServiceCertExpiryMins(domain.getServiceCertExpiryMins())
                        .setSignAlgorithm(domain.getSignAlgorithm())
                        .setUserAuthorityFilter(domain.getUserAuthorityFilter())
                        .setBusinessService(domain.getBusinessService())
                        .setTags(domain.getTags())
                        .setBusinessService(domain.getBusinessService())
                        .setMemberPurgeExpiryDays(domain.getMemberPurgeExpiryDays())
                        .setFeatureFlags(domain.getFeatureFlags())
                        .setContacts(domain.getContacts())
                        .setEnvironment(domain.getEnvironment());

                // then we're going to apply the updated fields
                // from the given object

                if (systemAttribute != null) {
                    updateSystemMetaFields(updatedDomain, systemAttribute, deleteAllowed, meta);
                } else {
                    updateDomainMetaFields(updatedDomain, meta);
                }

                con.updateDomain(updatedDomain);

                // if we're only updating our tags then we need to explicitly
                // update our domain last mod timestamp since it won't be
                // updated during the updateDomain call if there are no other
                // changes present in the request

                if (!processDomainTags(con, meta.getTags(), domain, domainName)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError(caller + "Unable to update tags", caller);
                }

                if (!processDomainContacts(con, domainName, meta.getContacts(), domain.getContacts())) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError(caller + "Unable to update contacts", caller);
                }

                con.updateDomainModTimestamp(domainName);
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

                // add domain change event

                addDomainChangeMessage(ctx, domainName, domainName, DomainChangeMessage.ObjectType.DOMAIN);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    boolean processDomainContacts(ObjectStoreConnection con, final String domainName,
            Map<String, String> updatedContacts, Map<String, String> originalContacts) {

        // if our new list is null then we're going to skip updating any
        // of our contacts

        if (updatedContacts == null) {
            return true;
        }

        // if our original list is empty then we're going to insert
        // all of our new contacts if any are present. we'll make
        // sure they all have non-empty values

        if (originalContacts == null || originalContacts.isEmpty()) {
            for (Map.Entry<String, String> entry : updatedContacts.entrySet()) {
                if (!StringUtil.isEmpty(entry.getValue())) {
                    if (!con.insertDomainContact(domainName, entry.getKey(), entry.getValue())) {
                        return false;
                    }
                }
            }
            return true;
        }

        // if our new list is empty then we're going to delete all of our
        // existing contacts

        if (updatedContacts.isEmpty()) {
            for (String contact : originalContacts.keySet()) {
                if (!con.deleteDomainContact(domainName, contact)) {
                    return false;
                }
            }
            return true;
        }

        // process our updated contacts - we're either going to update, insert,
        // or delete our contacts

        for (Map.Entry<String, String> entry : updatedContacts.entrySet()) {
            String type = entry.getKey();
            String name = entry.getValue();
            if (originalContacts.containsKey(type)) {
                if (!originalContacts.get(type).equals(name)) {
                    if (StringUtil.isEmpty(name)) {
                        if (!con.deleteDomainContact(domainName, type)) {
                            return false;
                        }
                    } else {
                        if (!con.updateDomainContact(domainName, type, name)) {
                            return false;
                        }
                    }
                }
            } else {
                if (!StringUtil.isEmpty(entry.getValue())) {
                    if (!con.insertDomainContact(domainName, type, name)) {
                        return false;
                    }
                }
            }
        }

        // now we have process any of our deletes - these are the contacts
        // that were in our original list but not in our updated list

        for (String type : originalContacts.keySet()) {
            if (!updatedContacts.containsKey(type)) {
                if (!con.deleteDomainContact(domainName, type)) {
                    return false;
                }
            }
        }

        return true;
    }

    private boolean processDomainTags(ObjectStoreConnection con, Map<String, TagValueList> domainTags,
            Domain originalDomain, final String domainName) {

        BiFunction<ObjectStoreConnection, Map<String, TagValueList>, Boolean> insertOp =
                (ObjectStoreConnection c, Map<String, TagValueList> tags) -> c.insertDomainTags(domainName, tags);
        BiFunction<ObjectStoreConnection, Set<String>, Boolean> deleteOp =
                (ObjectStoreConnection c, Set<String> tagKeys) -> c.deleteDomainTags(domainName, tagKeys);

        return processTags(con, domainTags, (originalDomain != null ? originalDomain.getTags() : null) , insertOp, deleteOp);
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

            if (!StringUtil.isEmpty(role.getTrust())) {
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
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
        boolean groupMemberExpiryDayReduced = isNumOfDaysReduced(domain.getGroupExpiryDays(),
                updatedDomain.getGroupExpiryDays());

        if (!userMemberExpiryDayReduced && !serviceMemberExpiryDayReduced && !groupMemberExpiryDayReduced) {
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
        long groupExpiryMillis = groupMemberExpiryDayReduced ? System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(updatedDomain.getGroupExpiryDays(), TimeUnit.DAYS) : 0;
        Timestamp userExpiration = Timestamp.fromMillis(userExpiryMillis);
        Timestamp serviceExpiration = Timestamp.fromMillis(serviceExpiryMillis);
        Timestamp groupExpiration = Timestamp.fromMillis(groupExpiryMillis);

        final String principal = getPrincipalName(ctx);
        boolean domainModified = false;
        for (Role role : athenzDomain.getRoles()) {
            // if the role already has a specific expiry date set then we
            // will automatically skip this role

            if (role.getMemberExpiryDays() != null || role.getServiceExpiryDays() != null || role.getGroupExpiryDays() != null) {
                continue;
            }

            // if it's a delegated role then we have nothing to do

            if (!StringUtil.isEmpty(role.getTrust())) {
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
                    groupExpiration, groupExpiryMillis, null, 0,
                    null, 0, null, null, 0);
            if (insertRoleMembers(ctx, con, roleMembersWithUpdatedDueDates, domain.getName(),
                    roleName, principal, auditRef, caller)) {

                // update our role and domain time-stamps, and invalidate local cache entry

                con.updateRoleModTimestamp(domain.getName(), roleName);
                domainModified = true;
            }
        }
        for (Group group : athenzDomain.getGroups()) {

            // if the group already has a specific expiry date set then we
            // will automatically skip this group

            if (group.getMemberExpiryDays() != null || group.getServiceExpiryDays() != null) {
                continue;
            }

            // if no group members, then there is nothing to do

            final List<GroupMember> groupMembers = group.getGroupMembers();
            if (groupMembers == null || groupMembers.isEmpty()) {
                continue;
            }

            // process our group members and if there were any changes processed then update
            // our group and domain time-stamps, and invalidate local cache entry

            final String groupName = AthenzUtils.extractGroupName(group.getName());
            List<GroupMember> groupMembersWithUpdatedDueDates = getGroupMembersWithUpdatedDueDates(groupMembers,
                    userExpiration, userExpiryMillis, serviceExpiration, serviceExpiryMillis, null);
            if (insertGroupMembers(ctx, con, groupMembersWithUpdatedDueDates, domain.getName(),
                    groupName, principal, auditRef, caller)) {

                // update our group and domain time-stamps, and invalidate local cache entry

                con.updateGroupModTimestamp(domain.getName(), groupName);
                domainModified = true;
            }
        }
        if (domainModified) {
            con.updateDomainModTimestamp(domain.getName());
            cacheStore.invalidate(domain.getName());
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
        if (meta.getBusinessService() != null) {
            domain.setBusinessService(meta.getBusinessService());
        }
        if (meta.getTags() != null) {
            domain.setTags(meta.getTags());
        }
        if (meta.getMemberPurgeExpiryDays() != null) {
            domain.setMemberPurgeExpiryDays(meta.getMemberPurgeExpiryDays());
        }
        if (meta.getContacts() != null) {
            domain.setContacts(meta.getContacts());
        }
        if (meta.getEnvironment() != null) {
            domain.setEnvironment(meta.getEnvironment());
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

        return oldValue.equals(newValue);
    }

    boolean isDeleteSystemMetaAllowed(boolean deleteAllowed, Integer oldValue, Integer newValue) {

        // if authorized or old value is not set, then there is
        // no need to check any value

        if (deleteAllowed || oldValue == null || oldValue == 0) {
            return true;
        }

        // since our old value is not null then we will only
        // allow if the new value is identical

        return newValue != null && newValue.intValue() == oldValue.intValue();
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
            case ZMSConsts.SYSTEM_META_GCP_PROJECT:
                if (!isDeleteSystemMetaAllowed(deleteAllowed, domain.getGcpProject(), meta.getGcpProject())) {
                    throw ZMSUtils.forbiddenError("unauthorized to reset system meta attribute: " + attribute, caller);
                }
                domain.setGcpProject(meta.getGcpProject());
                domain.setGcpProjectNumber(meta.getGcpProjectNumber());
                break;
            case ZMSConsts.SYSTEM_META_PRODUCT_ID:
                if (!isDeleteSystemMetaAllowed(deleteAllowed, domain.getYpmId(), meta.getYpmId())) {
                    throw ZMSUtils.forbiddenError("unauthorized to reset system meta attribute: " + attribute, caller);
                }
                domain.setYpmId(meta.getYpmId());
                if (!isDeleteSystemMetaAllowed(deleteAllowed, domain.getProductId(), meta.getProductId())) {
                    throw ZMSUtils.forbiddenError("unauthorized to reset system meta attribute: " + attribute, caller);
                }
                domain.setProductId(meta.getProductId());
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
            case ZMSConsts.SYSTEM_META_BUSINESS_SERVICE:
                domain.setBusinessService(meta.getBusinessService());
                break;
            case ZMSConsts.SYSTEM_META_FEATURE_FLAGS:
                domain.setFeatureFlags(meta.getFeatureFlags());
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
                            zmsConfig.getAddlUserCheckDomainPrefixList(),
                            zmsConfig.getHeadlessUserDomainPrefix()) != Principal.Type.GROUP) {
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

                final String principalName = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principalName, AUDIT_TYPE_TEMPLATE);

                // go through our list of templates and add the specified
                // roles and polices to our domain

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"add-templates\": ");
                boolean firstEntry = true;

                for (String templateName : domainTemplate.getTemplateNames()) {
                    firstEntry = auditLogSeparator(auditDetails, firstEntry);
                    if (!addSolutionTemplate(ctx, con, domainName, templateName, principalName,
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
                deleteSolutionTemplate(ctx, con, domainName, templateName, template, auditDetails);

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

    boolean addSolutionTemplate(ResourceContext ctx, ObjectStoreConnection con, String domainName, String templateName,
            String admin, List<TemplateParam> templateParams, String auditRef, StringBuilder auditDetails) {

        auditDetails.append("{\"name\": \"").append(templateName).append('\"');

        // we have already verified that our template is valid, but
        // we'll just double check to make sure it's not null

        Template template = zmsConfig.getServerSolutionTemplates().get(templateName);
        if (template == null) {
            auditDetails.append("}");
            return true;
        }

        auditDetails.append(",");

        boolean firstEntry = true;

        // iterate through roles in the list.
        // When adding a template, if the role does not exist in our domain
        // then insert it otherwise only apply the changes to the member list.

        List<Role> templateRoles = template.getRoles();
        if (templateRoles != null) {
            for (Role role : templateRoles) {

                Role templateRole = updateTemplateRole(con, role, domainName, templateParams);
                if (templateRole == null) {
                    return false;
                }

                String roleName = ZMSUtils.removeDomainPrefix(templateRole.getName(),
                    domainName, ROLE_PREFIX);

                // retrieve our original role

                Role originalRole = getRole(con, domainName, roleName, false, false, false);

                // Merge original role with template role to handle role meta data
                // if original role is null then it is an insert operation and no need of merging

                if (originalRole != null) {
                    mergeOriginalRoleAndMetaRoleAttributes(originalRole, templateRole);
                }

                // before processing, make sure to validate the role to make
                // sure it's valid after all the substitutions

                ZMSUtils.validateObject(zmsConfig.getValidator(), templateRole, ZMSConsts.TYPE_ROLE, CALLER_TEMPLATE);

                // now process the request

                firstEntry = auditLogSeparator(auditDetails, firstEntry);
                auditDetails.append(" \"add-role\": ");
                if (!processRole(con, originalRole, domainName, roleName, templateRole,
                        admin, auditRef, true, auditDetails)) {
                    return false;
                }

                // add domain change event

                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
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

                Policy originalPolicy = getPolicy(con, domainName, policyName, null);

                // now process the request

                firstEntry = auditLogSeparator(auditDetails, firstEntry);
                auditDetails.append(" \"add-policy\": ");
                if (!processPolicy(con, originalPolicy, domainName, policyName, templatePolicy,
                        true, auditDetails)) {
                    return false;
                }
                
                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);
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
                if (!processServiceIdentity(ctx, con, originalServiceIdentity, domainName,
                        serviceIdentityName, templateServiceIdentity, true, auditDetails)) {
                    return false;
                }

                // add domain change event
                addDomainChangeMessage(ctx, domainName, serviceIdentityName, DomainChangeMessage.ObjectType.SERVICE);
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

    void deleteSolutionTemplate(ResourceContext ctx, ObjectStoreConnection con, String domainName, String templateName,
            Template template, StringBuilder auditDetails) {

        // currently there is no support for dynamic templates since the
        // DELETE request has no payload and we can't pass our parameters

        auditDetails.append("{\"name\": \"").append(templateName).append('\"');

        // we have already verified that our template is valid but
        // we'll just double check to make sure it's not null

        if (template == null) {
            auditDetails.append("}");
            return;
        }

        auditDetails.append(",");

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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
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
                
                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, serviceName, DomainChangeMessage.ObjectType.SERVICE);
            }
        }

        // delete the template from the current list

        con.deleteDomainTemplate(domainName, templateName, null);
        auditDetails.append("}");
    }

    Role updateTemplateRole(ObjectStoreConnection con, Role role, String domainName, List<TemplateParam> params) {

        // first process our given role name and carry out any
        // requested substitutions

        String templateRoleName = role.getName().replace(TEMPLATE_DOMAIN_NAME, domainName);
        String templateRoleTrust = role.getTrust();
        if (params != null) {
            for (TemplateParam param : params) {
                final String paramKey = "_" + param.getName() + "_";
                templateRoleName = templateRoleName.replace(paramKey, param.getValue());
                if (!StringUtil.isEmpty(templateRoleTrust)) {
                    templateRoleTrust = templateRoleTrust.replace(paramKey, param.getValue());
                }
            }
        }

        // if we have a role trust value specified then we want to make
        // sure that domain actually exists and is not pointing to itself

        if (!StringUtil.isEmpty(templateRoleTrust)) {
            if (templateRoleTrust.equals(domainName)) {
                LOG.error("Template role trust domain {} points to itself", templateRoleTrust);
                return null;
            }
            if (con.getDomain(templateRoleTrust) == null) {
                LOG.error("Template role trust domain {} does not exist", templateRoleTrust);
                return null;
            }
        }

        Role templateRole = new Role()
                .setName(templateRoleName)
                .setTrust(templateRoleTrust)
                //adding additional role meta attributes if present in template->roles
                .setCertExpiryMins(role.getCertExpiryMins())
                .setSelfServe(role.getSelfServe())
                .setMemberExpiryDays(role.getMemberExpiryDays())
                .setTokenExpiryMins(role.getTokenExpiryMins())
                .setSignAlgorithm(role.getSignAlgorithm())
                .setServiceExpiryDays(role.getServiceExpiryDays())
                .setGroupExpiryDays(role.getGroupExpiryDays())
                .setGroupReviewDays(role.getGroupReviewDays())
                .setMemberReviewDays(role.getMemberReviewDays())
                .setServiceReviewDays(role.getServiceReviewDays())
                .setReviewEnabled(role.getReviewEnabled())
                .setNotifyRoles(role.getNotifyRoles())
                .setUserAuthorityFilter(role.getUserAuthorityFilter())
                .setDescription(role.getDescription())
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
                newRoleMember.setReviewReminder(roleMember.getReviewReminder());
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
                newAssertion.setEffect(assertion.getEffect());

                // process our assertion resource and role for any requested substitutions

                String action = assertion.getAction().replace(TEMPLATE_DOMAIN_NAME, domainName);
                String resource = assertion.getResource().replace(TEMPLATE_DOMAIN_NAME, domainName);
                String role = assertion.getRole().replace(TEMPLATE_DOMAIN_NAME, domainName);
                if (params != null) {
                    for (TemplateParam param : params) {
                        final String paramKey = "_" + param.getName() + "_";
                        resource = resource.replace(paramKey, param.getValue());
                        role = role.replace(paramKey, param.getValue());
                        action = action.replace(paramKey, param.getValue());
                    }
                }
                newAssertion.setAction(action);
                newAssertion.setResource(resource);
                newAssertion.setRole(role);

                // validate the assertion and add it to the list

                ZMSUtils.validatePolicyAssertion(zmsConfig.getValidator(), newAssertion, true, CALLER_TEMPLATE);
                newAssertions.add(newAssertion);
            }
        }
        templatePolicy.setAssertions(newAssertions);

        // before returning, make sure to validate the policy to make
        // sure it's valid after all the substitutions

        ZMSUtils.validateObject(zmsConfig.getValidator(), templatePolicy, ZMSConsts.TYPE_POLICY, CALLER_TEMPLATE);
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

        // before returning, make sure to validate the policy to make
        // sure it's valid after all the substitutions

        ZMSUtils.validateObject(zmsConfig.getValidator(), templateServiceIdentity,
                ZMSConsts.TYPE_SERVICE_IDENTITY, CALLER_TEMPLATE);
        return templateServiceIdentity;
    }

    void setupTenantAdminPolicy(ResourceContext ctx, String tenantDomain, String provSvcDomain,
            String provSvcName, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, tenantDomain, auditRef, caller, provSvcDomain + "." + provSvcName, AUDIT_TYPE_TENANCY);

                String domainAdminRole = ResourceUtils.roleResourceName(tenantDomain, ZMSConsts.ADMIN_ROLE_NAME);
                String serviceRoleResourceName = ZMSUtils.getTrustedResourceGroupRolePrefix(provSvcDomain,
                        provSvcName, tenantDomain, null) + ZMSConsts.ADMIN_ROLE_NAME;

                // our tenant admin role/policy name

                final String tenancyResource = "tenancy." + provSvcDomain + '.' + provSvcName;

                String adminName = tenancyResource + ".admin";
                String tenantAdminRole = ResourceUtils.roleResourceName(tenantDomain, adminName);

                // tenant admin role - if it already exists then we skip it
                // by default it has no members.

                if (con.getRole(tenantDomain, adminName) == null) {
                    con.insertRole(tenantDomain, new Role().setName(tenantAdminRole));

                    // add domain change event
                    addDomainChangeMessage(ctx, tenantDomain, tenantAdminRole, DomainChangeMessage.ObjectType.ROLE);
                }

                // tenant admin policy - check to see if this already exists. If it does
                // then we don't have anything to do

                if (con.getPolicy(tenantDomain, adminName, null) == null) {

                    Policy adminPolicy = new Policy().setName(ResourceUtils.policyResourceName(tenantDomain, adminName));
                    adminPolicy.setVersion(null);
                    con.insertPolicy(tenantDomain, adminPolicy);

                    // we are going to create 2 assertions - one for the domain admin role
                    // and another for the tenant admin role

                    Assertion assertion = new Assertion().setRole(domainAdminRole)
                            .setResource(serviceRoleResourceName).setAction(ZMSConsts.ACTION_ASSUME_ROLE)
                            .setEffect(AssertionEffect.ALLOW);
                    con.insertAssertion(tenantDomain, adminName, null, assertion);

                    assertion = new Assertion().setRole(tenantAdminRole)
                            .setResource(serviceRoleResourceName).setAction(ZMSConsts.ACTION_ASSUME_ROLE)
                            .setEffect(AssertionEffect.ALLOW);
                    con.insertAssertion(tenantDomain, adminName, null, assertion);

                    // the tenant admin role must have the capability to provision
                    // new resource groups in the domain which requires update
                    // action capability on resource tenancy.<prov_domain>.<prov_svc>

                    String tenantResourceName = tenantDomain + ":" + tenancyResource;
                    assertion = new Assertion().setRole(tenantAdminRole)
                            .setResource(tenantResourceName).setAction(ZMSConsts.ACTION_UPDATE)
                            .setEffect(AssertionEffect.ALLOW);
                    con.insertAssertion(tenantDomain, adminName, null, assertion);

                    // add domain change event
                    addDomainChangeMessage(ctx, tenantDomain, adminPolicy.getName(), DomainChangeMessage.ObjectType.POLICY);
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
            String resourceGroup, List<TenantRoleAction> roles, boolean ignoreDeletes, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                final String principalName = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, provSvcDomain, auditRef, caller, principalName, AUDIT_TYPE_TENANCY);

                // verify tenant domain exists

                if (con.getDomain(tenantDomain) == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": Unknown tenant domain: " + tenantDomain, caller);
                }

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
                        LOG.info("{}: add trusted Role to domain {}: {} -> {}",
                                caller, provSvcDomain, trustedRole, role);
                    }

                    // retrieve our original role in case one exists

                    Role originalRole = getRole(con, provSvcDomain, trustedName, false, false, false);
                    if (originalRole != null) {
                        role.setLastReviewedDate(originalRole.getLastReviewedDate());
                    }

                    // now process the request

                    firstEntry = auditLogSeparator(auditDetails, firstEntry);

                    auditDetails.append("{\"role\": ");
                    if (!processRole(con, originalRole, provSvcDomain, trustedName, role,
                            principalName, auditRef, ignoreDeletes, auditDetails)) {
                        con.rollbackChanges();
                        throw ZMSUtils.internalServerError("unable to put role: " + trustedRole, caller);
                    }

                    // add domain change event
                    addDomainChangeMessage(ctx, provSvcDomain, trustedName, DomainChangeMessage.ObjectType.ROLE);
                    
                    String policyResourceName = ResourceUtils.policyResourceName(provSvcDomain, trustedName);
                    final String resourceName = provSvcDomain + ":service." +
                            ZMSUtils.getTenantResourceGroupRolePrefix(provSvcName, tenantDomain, resourceGroup) + '*';
                    List<Assertion> assertions = Collections.singletonList(
                            new Assertion().setRole(trustedRole)
                                    .setResource(resourceName)
                                    .setAction(tenantAction));

                    Policy policy = new Policy().setName(policyResourceName).setAssertions(assertions);

                    if (LOG.isInfoEnabled()) {
                        LOG.info("{}: add trust policy to domain {}: {} -> {}",
                                caller, provSvcDomain, trustedRole, policy);
                    }

                    // retrieve our original policy

                    Policy originalPolicy = getPolicy(con, provSvcDomain, trustedName, null);

                    // now process the request

                    auditDetails.append(", \"policy\": ");
                    if (!processPolicy(con, originalPolicy, provSvcDomain, trustedName, policy, ignoreDeletes, auditDetails)) {
                        con.rollbackChanges();
                        throw ZMSUtils.internalServerError("unable to put policy: " + policy.getName(), caller);
                    }
                    auditDetails.append('}');

                    // add domain change event
                    addDomainChangeMessage(ctx, provSvcDomain, trustedName, DomainChangeMessage.ObjectType.POLICY);
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

    void addAssumeRolePolicy(ResourceContext ctx, ObjectStoreConnection con, String rolePrefix,
            String trustedRolePrefix, String role, List<RoleMember> roleMembers,
            String tenantDomain, String admin, String auditRef,
            StringBuilder auditDetails, String caller) {

        // first create the role in the domain. We're going to create it
        // only if the role does not already exist

        String roleName = rolePrefix + role;
        String roleResourceName = ResourceUtils.roleResourceName(tenantDomain, roleName);

        // retrieve our original role in case one exists

        Role originalRole = getRole(con, tenantDomain, roleName, false, false, false);

        // we need to add the original role members to the new one

        if (originalRole != null && originalRole.getRoleMembers() != null) {
            roleMembers.addAll(originalRole.getRoleMembers());
        }

        // now process the request

        Role roleObj = new Role().setName(roleResourceName).setRoleMembers(roleMembers);
        if (originalRole != null) {
            roleObj.setLastReviewedDate(originalRole.getLastReviewedDate());
        }

        auditDetails.append("{\"role\": ");
        if (!processRole(con, originalRole, tenantDomain, roleName, roleObj,
                admin, auditRef, false, auditDetails)) {
            con.rollbackChanges();
            throw ZMSUtils.internalServerError("unable to put role: " + roleName, caller);
        }

        // add domain change event
        addDomainChangeMessage(ctx, tenantDomain, roleName, DomainChangeMessage.ObjectType.ROLE);
        
        // now create the corresponding policy. We're going to create it
        // only if the policy does not exist otherwise we'll just
        // add a new assertion

        String policyName = "tenancy." + roleName;
        String policyResourceName = ResourceUtils.policyResourceName(tenantDomain, policyName);
        String serviceRoleResourceName = trustedRolePrefix + role;
        Assertion assertion = new Assertion().setRole(roleResourceName)
                .setResource(serviceRoleResourceName).setAction(ZMSConsts.ACTION_ASSUME_ROLE)
                .setEffect(AssertionEffect.ALLOW);

        if (LOG.isInfoEnabled()) {
            LOG.info("executePutProviderRoles: ---- ASSUME_ROLE policyName is {}", policyName);
        }

        // retrieve our original policy

        Policy originalPolicy = getPolicy(con, tenantDomain, policyName, null);

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

        // add domain change event
        addDomainChangeMessage(ctx, tenantDomain, policyName, DomainChangeMessage.ObjectType.ROLE);
    }

    void executePutProviderRoles(ResourceContext ctx, String tenantDomain, String provSvcDomain,
            String provSvcName, String resourceGroup, List<String> roles, Boolean skipPrincipalMember,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                final String principalName = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, tenantDomain, auditRef, caller, principalName, AUDIT_TYPE_TENANCY);

                // we're going to create a separate role for each one of tenant roles returned
                // based on its action and set the caller as a member in each role
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
                    if (principalName != null && skipPrincipalMember != Boolean.TRUE) {
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

                    addAssumeRolePolicy(ctx, con, rolePrefix, trustedRolePrefix, role, roleMembers,
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
                            LOG.debug("{}: --ignore policy {}", caller, pname);
                        }
                        continue;
                    }

                    if (LOG.isInfoEnabled()) {
                        LOG.info("{}: --delete policy {}", caller, pname);
                    }

                    con.deletePolicy(tenantDomain, pname);

                    // add domain change event
                    addDomainChangeMessage(ctx, tenantDomain, pname, DomainChangeMessage.ObjectType.POLICY);
                }

                // now we're going to find any roles that have the provider prefix as
                // well but we're going to be careful about removing them. We'll check
                // and if we have no more policies referencing them then we'll remove

                List<String> rnames = con.listRoles(tenantDomain);
                for (String rname : rnames) {

                    if (!validResourceGroupObjectToDelete(rname, rnamePrefix)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("{}: --ignore role {}", caller, rname);
                        }
                        continue;
                    }

                    if (!con.listPolicies(tenantDomain, rname).isEmpty()) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("{}: --ignore role {} due to active references", caller, rname);
                        }
                        continue;
                    }

                    if (LOG.isInfoEnabled()) {
                        LOG.info("{}: --delete role {}", caller, rname);
                    }

                    con.deleteRole(tenantDomain, rname);

                    // add domain change event
                    addDomainChangeMessage(ctx, tenantDomain, rname, DomainChangeMessage.ObjectType.POLICY);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, tenantDomain);

                // audit log the request

                auditLogRequest(ctx, tenantDomain, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        ResourceUtils.entityResourceName(provSvcDomain, provSvcName), null);

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

                        // add domain change event
                        addDomainChangeMessage(ctx, provSvcDomain, rname, DomainChangeMessage.ObjectType.ROLE);
                        addDomainChangeMessage(ctx, provSvcDomain, rname, DomainChangeMessage.ObjectType.POLICY);
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

        final String trustDom = role.getTrust();
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
            LOG.debug("isTenantRolePrefixMatch: role-name={}, role-prefix={}, resource-group={}, tenant-domain={}",
                    roleName, rolePrefix, resourceGroup, tenantDomain);
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
                LOG.debug("isTenantRolePrefixMatch: verifying tenant subdomain: {}", subDomain);
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
        athenzDomain.setRoleMemberPrincipalTypes(zmsConfig.getUserDomainPrefix(),
                zmsConfig.getAddlUserCheckDomainPrefixList(), zmsConfig.getHeadlessUserDomainPrefix());

        DataCache dataCache = new DataCache(athenzDomain,
                athenzDomain.getDomain().getModified().millis());
        cacheStore.put(domainName, dataCache);

        return athenzDomain;
    }

    DomainMetaList listModifiedDomains(long modifiedSince, boolean readWrite) {

        // since this is the operation executed by ZTS servers to
        // retrieve latest domain changes, we're going to use
        // the read-write store as opposed to read-only store to
        // get our up-to-date data

        try (ObjectStoreConnection con = store.getConnection(true, readWrite)) {
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
        if (roleMember.getReviewReminder() != null) {
            auditDetails.append(", \"reminder\": \"").append(roleMember.getReviewReminder().toString()).append('"');
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

    boolean auditLogPolicyVersion(StringBuilder auditDetails, Policy policy, boolean firstEntry) {
        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        auditDetails.append("{\"name\": \"").append(policy.getName())
        .append("\", \"version\": \"").append(policy.getVersion())
        .append("\", \"active\": \"").append(policy.getActive())
        .append("\", \"modified\": \"").append(policy.getModified()).append('"');
        if (policy.getAssertions() != null) {
            auditLogAssertions(auditDetails, "deleted-assertions", policy.getAssertions());
        }
        auditDetails.append("}");
        return firstEntry;
    }

    void auditLogPolicy(StringBuilder auditDetails, List<Policy> policyVersions, String label)  {
        auditDetails.append("{\"name\": \"").append(policyVersions.get(0).getName()).append('\"');
        auditDetails.append(", \"").append(label).append("\": [");
        boolean firstEntry = true;
        for (Policy value : policyVersions) {
            firstEntry = auditLogPolicyVersion(auditDetails, value, firstEntry);
        }
        auditDetails.append(']');
        auditDetails.append("}");
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
                .append("\", \"businessService\": \"").append(domain.getBusinessService())
                .append("\", \"productId\": \"").append(domain.getProductId())
                .append("\", \"featureFlags\": \"").append(domain.getFeatureFlags()).append("\"");
        auditLogTags(auditDetails, domain.getTags());
        auditLogDomainContacts(auditDetails, domain.getContacts());
        auditDetails.append("}");
    }

    void auditLogDomainContacts(StringBuilder auditDetails, Map<String, String> contacts) {
        if (contacts != null) {
            auditDetails.append(", \"contacts\": {");
            boolean firstEntry = true;
            for (Map.Entry<String, String> entry: contacts.entrySet()) {
                firstEntry = auditLogSeparator(auditDetails, firstEntry);
                auditDetails.append("\"").append(entry.getKey()).append("\": \"").append(entry.getValue()).append("\"");
            }
            auditDetails.append("}");
        }
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

    void auditLogRoleMeta(StringBuilder auditDetails, Role role, String roleName, boolean close) {
        auditDetails.append("{\"name\": \"").append(roleName)
                .append("\", \"selfServe\": \"").append(role.getSelfServe())
                .append("\", \"memberExpiryDays\": \"").append(role.getMemberExpiryDays())
                .append("\", \"serviceExpiryDays\": \"").append(role.getServiceExpiryDays())
                .append("\", \"groupExpiryDays\": \"").append(role.getGroupExpiryDays())
                .append("\", \"tokenExpiryMins\": \"").append(role.getTokenExpiryMins())
                .append("\", \"certExpiryMins\": \"").append(role.getCertExpiryMins())
                .append("\", \"memberReviewDays\": \"").append(role.getMemberReviewDays())
                .append("\", \"serviceReviewDays\": \"").append(role.getServiceReviewDays())
                .append("\", \"groupReviewDays\": \"").append(role.getGroupReviewDays())
                .append("\", \"reviewEnabled\": \"").append(role.getReviewEnabled())
                .append("\", \"notifyRoles\": \"").append(role.getNotifyRoles())
                .append("\", \"signAlgorithm\": \"").append(role.getSignAlgorithm())
                .append("\", \"userAuthorityFilter\": \"").append(role.getUserAuthorityFilter())
                .append("\", \"userAuthorityExpiration\": \"").append(role.getUserAuthorityExpiration())
                .append("\", \"description\": \"").append(role.getDescription())
                .append("\", \"deleteProtection\": \"").append(role.getDeleteProtection())
                .append("\", \"lastReviewedDate\": \"").append(role.getLastReviewedDate())
                .append("\", \"maxMembers\": \"").append(role.getMembers())
                .append("\", \"selfRenew\": \"").append(role.getSelfRenew())
                .append("\", \"selfRenewMins\": \"").append(role.getSelfRenewMins()).append("\"");
        auditLogTags(auditDetails, role.getTags());
        if (close) {
            auditDetails.append("}");
        }
    }

    void auditLogGroupMeta(StringBuilder auditDetails, Group group, final String groupName, boolean close) {
        auditDetails.append("{\"name\": \"").append(groupName)
                .append("\", \"selfServe\": \"").append(group.getSelfServe())
                .append("\", \"memberExpiryDays\": \"").append(group.getMemberExpiryDays())
                .append("\", \"serviceExpiryDays\": \"").append(group.getServiceExpiryDays())
                .append("\", \"reviewEnabled\": \"").append(group.getReviewEnabled())
                .append("\", \"notifyRoles\": \"").append(group.getNotifyRoles())
                .append("\", \"userAuthorityFilter\": \"").append(group.getUserAuthorityFilter())
                .append("\", \"userAuthorityExpiration\": \"").append(group.getUserAuthorityExpiration())
                .append("\", \"deleteProtection\": \"").append(group.getDeleteProtection())
                .append("\", \"lastReviewedDate\": \"").append(group.getLastReviewedDate())
                .append("\", \"maxMembers\": \"").append(group.getMaxMembers())
                .append("\", \"selfRenew\": \"").append(group.getSelfRenew())
                .append("\", \"selfRenewMins\": \"").append(group.getSelfRenewMins()).append("\"");
        auditLogTags(auditDetails, group.getTags());
        if (close) {
            auditDetails.append("}");
        }
    }

    void auditLogTags(StringBuilder auditDetails, Map<String, TagValueList> tags) {
        if (tags != null) {
            auditDetails.append(", \"tags\": {");
            boolean firstEntry = true;
            for (String key : tags.keySet()) {
                firstEntry = auditLogTag(auditDetails, tags.get(key), key, firstEntry);
            }
            auditDetails.append("}");
        }
    }

    private boolean auditLogTag(StringBuilder auditDetails, TagValueList tagValueList, String key, boolean firstEntry) {
        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        auditDetails.append("\"").append(key).append("\": [");
        boolean innerFirstEntry = true;
        for (String value : tagValueList.getList()) {
            innerFirstEntry = auditLogSeparator(auditDetails, innerFirstEntry);
            auditDetails.append("\"").append(value).append("\"");
        }
        auditDetails.append("]");
        return firstEntry;
    }

    void auditLogAssertionConditions(StringBuilder auditDetails, List<AssertionCondition> assertionConditions, String label)  {
        auditDetails.append("{\"").append(label).append("\": [");
        boolean firstEntry = true;
        for (AssertionCondition value : assertionConditions) {
            firstEntry = auditLogAssertionCondition(auditDetails, value, firstEntry);
        }
        auditDetails.append("]}");
    }

    boolean auditLogAssertionCondition(StringBuilder auditDetails, AssertionCondition assertionCondition, boolean firstEntry) {

        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        auditDetails.append("{\"conditionId\": ").append(assertionCondition.getId())
                .append(", \"conditionsMap\": {");
        boolean innerFirstEntry = true;
        for (String key : assertionCondition.getConditionsMap().keySet()) {
            innerFirstEntry = auditLogAssertionConditionData(auditDetails, assertionCondition.getConditionsMap().get(key),
                    key, innerFirstEntry);
        }
        auditDetails.append("}}");
        return firstEntry;
    }

    boolean auditLogAssertionConditionData(StringBuilder auditDetails, AssertionConditionData assertionConditionData,
            String conditionKey, boolean firstEntry) {

        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        auditDetails.append("\"").append(conditionKey)
                .append("\": {\"operator\": \"").append(assertionConditionData.getOperator().name())
                .append("\", \"value\": \"").append(assertionConditionData.getValue())
                .append("\"}");
        return firstEntry;
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, domainName, DomainChangeMessage.ObjectType.DOMAIN);
                
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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, domainName, DomainChangeMessage.ObjectType.DOMAIN);
                
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

    public Stats getStats(String domainName) {
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.getStats(domainName);
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
                        .setGroupReviewDays(originalRole.getGroupReviewDays())
                        .setTokenExpiryMins(originalRole.getTokenExpiryMins())
                        .setCertExpiryMins(originalRole.getCertExpiryMins())
                        .setMemberReviewDays(originalRole.getMemberReviewDays())
                        .setServiceReviewDays(originalRole.getServiceReviewDays())
                        .setSignAlgorithm(originalRole.getSignAlgorithm())
                        .setReviewEnabled(originalRole.getReviewEnabled())
                        .setDeleteProtection(originalRole.getDeleteProtection())
                        .setNotifyRoles(originalRole.getNotifyRoles())
                        .setLastReviewedDate(originalRole.getLastReviewedDate())
                        .setMaxMembers(originalRole.getMaxMembers())
                        .setSelfRenew(originalRole.getSelfRenew())
                        .setSelfRenewMins(originalRole.getSelfRenewMins());

                // then we're going to apply the updated fields
                // from the given object

                updateRoleSystemMetaFields(con, updatedRole, originalRole, attribute, meta, ctx.getApiName());

                con.updateRole(domainName, updatedRole);
                saveChanges(con, domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogRoleSystemMeta(auditDetails, updatedRole, roleName);

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        roleName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
                
                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    public Group executePutGroupSystemMeta(ResourceContext ctx, final String domainName, final String groupName,
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
                        .setNotifyRoles(originalGroup.getNotifyRoles())
                        .setUserAuthorityFilter(originalGroup.getUserAuthorityFilter())
                        .setUserAuthorityExpiration(originalGroup.getUserAuthorityExpiration())
                        .setMemberExpiryDays(originalGroup.getMemberExpiryDays())
                        .setServiceExpiryDays(originalGroup.getServiceExpiryDays())
                        .setLastReviewedDate(originalGroup.getLastReviewedDate())
                        .setDeleteProtection(originalGroup.getDeleteProtection())
                        .setMaxMembers(originalGroup.getMaxMembers())
                        .setSelfRenew(originalGroup.getSelfRenew())
                        .setSelfRenewMins(originalGroup.getSelfRenewMins());

                // then we're going to apply the updated fields
                // from the given object

                updateGroupSystemMetaFields(updatedGroup, attribute, meta, ctx.getApiName());

                con.updateGroup(domainName, updatedGroup);
                saveChanges(con, domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogGroupSystemMeta(auditDetails, updatedGroup, groupName);

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), ZMSConsts.HTTP_PUT,
                        groupName, auditDetails.toString());

                // add domain change event

                addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);
                
                return updatedGroup;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    public ServiceIdentity executePutServiceIdentitySystemMeta(ResourceContext ctx, String domainName, String serviceName,
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
                if (serviceIdentity == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": Unknown service: " + serviceName, caller);
                }

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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, serviceName, DomainChangeMessage.ObjectType.SERVICE);
                
                return serviceIdentity;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void updateRoleMetaFields(Role role, RoleMeta meta, final String caller) {

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
        if (meta.getGroupReviewDays() != null) {
            role.setGroupReviewDays(meta.getGroupReviewDays());
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
        if (meta.getAuditEnabled() != null) {
            role.setAuditEnabled(meta.getAuditEnabled());
        }
        if (meta.getDeleteProtection() != null) {
            role.setDeleteProtection(meta.getDeleteProtection());
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
        if (meta.getDescription() != null) {
            role.setDescription(meta.getDescription());
        }
        if (meta.getTags() != null) {
            role.setTags(meta.getTags());
        }
        if (meta.getMaxMembers() != null) {
            role.setMaxMembers(meta.getMaxMembers());
        }
        if (meta.getSelfRenew() != null) {
            role.setSelfRenew(meta.getSelfRenew());
        }
        if (meta.getSelfRenewMins() != null) {
            role.setSelfRenewMins(meta.getSelfRenewMins());
        }
        role.setLastReviewedDate(objectLastReviewDate(meta.getLastReviewedDate(),
                role.getLastReviewedDate(), false, caller));
    }

    public Role executePutRoleMeta(ResourceContext ctx, String domainName, String roleName, Role originalRole,
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
                        .setGroupReviewDays(originalRole.getGroupReviewDays())
                        .setTokenExpiryMins(originalRole.getTokenExpiryMins())
                        .setCertExpiryMins(originalRole.getCertExpiryMins())
                        .setMemberReviewDays(originalRole.getMemberReviewDays())
                        .setServiceReviewDays(originalRole.getServiceReviewDays())
                        .setSignAlgorithm(originalRole.getSignAlgorithm())
                        .setReviewEnabled(originalRole.getReviewEnabled())
                        .setDeleteProtection(originalRole.getDeleteProtection())
                        .setNotifyRoles(originalRole.getNotifyRoles())
                        .setUserAuthorityFilter(originalRole.getUserAuthorityFilter())
                        .setUserAuthorityExpiration(originalRole.getUserAuthorityExpiration())
                        .setDescription(originalRole.getDescription())
                        .setTags(originalRole.getTags())
                        .setLastReviewedDate(originalRole.getLastReviewedDate())
                        .setMaxMembers(originalRole.getMaxMembers())
                        .setSelfRenew(originalRole.getSelfRenew())
                        .setSelfRenewMins(originalRole.getSelfRenewMins());

                // then we're going to apply the updated fields
                // from the given object

                updateRoleMetaFields(updatedRole, meta, caller);
                con.updateRole(domainName, updatedRole);

                // create our audit log object

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogRoleMeta(auditDetails, updatedRole, roleName, true);

                processRoleTags(updatedRole, roleName, domainName, originalRole, con);
                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        roleName, auditDetails.toString());

                // if the role member expiry date or review date has changed then we're going
                // process all the members in the role and update the expiration and review
                // date accordingly

                updateRoleMembersDueDates(ctx, con, domainName, roleName, originalRole,
                        updatedRole, auditRef, caller);

                // if there was a change in the role user attribute filter then we need
                // to make the necessary changes as well.

                updateRoleMembersSystemDisabledState(ctx, con, domainName, roleName, originalRole,
                        updatedRole, auditRef, caller);

                // add domain change event
                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
                
                return updatedRole;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void updateGroupMetaFields(Group group, GroupMeta meta, final String caller) {

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
        if (meta.getMemberExpiryDays() != null) {
            group.setMemberExpiryDays(meta.getMemberExpiryDays());
        }
        if (meta.getServiceExpiryDays() != null) {
            group.setServiceExpiryDays(meta.getServiceExpiryDays());
        }
        if (meta.getTags() != null) {
            group.setTags(meta.getTags());
        }
        if (meta.getAuditEnabled() != null) {
            group.setAuditEnabled(meta.getAuditEnabled());
        }
        if (meta.getDeleteProtection() != null) {
            group.setDeleteProtection(meta.getDeleteProtection());
        }
        if (meta.getMaxMembers() != null) {
            group.setMaxMembers(meta.getMaxMembers());
        }
        if (meta.getSelfRenew() != null) {
            group.setSelfRenew(meta.getSelfRenew());
        }
        if (meta.getSelfRenewMins() != null) {
            group.setSelfRenewMins(meta.getSelfRenewMins());
        }
        group.setLastReviewedDate(objectLastReviewDate(meta.getLastReviewedDate(),
                group.getLastReviewedDate(), false, caller));
    }

    public Group executePutGroupMeta(ResourceContext ctx, final String domainName, final String groupName,
                                     Group originalGroup, GroupMeta meta, final String auditRef) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                checkObjectAuditEnabled(con, originalGroup.getAuditEnabled(), originalGroup.getName(),
                        auditRef, ctx.getApiName(), getPrincipalName(ctx));

                // now process the request. first we're going to make a
                // copy of our group

                Group updatedGroup = new Group()
                        .setName(originalGroup.getName())
                        .setAuditEnabled(originalGroup.getAuditEnabled())
                        .setSelfServe(originalGroup.getSelfServe())
                        .setMemberExpiryDays(originalGroup.getMemberExpiryDays())
                        .setServiceExpiryDays(originalGroup.getServiceExpiryDays())
                        .setReviewEnabled(originalGroup.getReviewEnabled())
                        .setNotifyRoles(originalGroup.getNotifyRoles())
                        .setUserAuthorityFilter(originalGroup.getUserAuthorityFilter())
                        .setUserAuthorityExpiration(originalGroup.getUserAuthorityExpiration())
                        .setTags(originalGroup.getTags())
                        .setDeleteProtection(originalGroup.getDeleteProtection())
                        .setLastReviewedDate(originalGroup.getLastReviewedDate())
                        .setMaxMembers(originalGroup.getMaxMembers())
                        .setSelfRenew(originalGroup.getSelfRenew())
                        .setSelfRenewMins(originalGroup.getSelfRenewMins());

                // then we're going to apply the updated fields
                // from the given object

                updateGroupMetaFields(updatedGroup, meta, ctx.getApiName());

                // if either the filter or the expiry has been removed we need to make
                // sure the group is not a member in a role that requires it

                validateGroupUserAuthorityAttrRequirements(con, originalGroup, updatedGroup, ctx.getApiName());

                // update the group in the database

                con.updateGroup(domainName, updatedGroup);

                // create our audit log object

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditLogGroupMeta(auditDetails, updatedGroup, groupName, true);

                // process our tags

                processGroupTags(updatedGroup, groupName, domainName, originalGroup, con);
                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), ZMSConsts.HTTP_PUT,
                        groupName, auditDetails.toString());

                // if the group user authority expiration attribute has changed, we're going
                // process all the members in the group and update the expiration date accordingly

                updateGroupMembersDueDates(ctx, con, domainName, groupName, originalGroup,
                        updatedGroup, auditRef);

                // if there was a change in the role user attribute filter then we need
                // to make the necessary changes as well.

                updateGroupMembersSystemDisabledState(ctx, con, domainName, groupName, originalGroup,
                        updatedGroup, auditRef);

                // add domain change event

                addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);
                
                return updatedGroup;

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
                            + ResourceUtils.roleResourceName(memberRole.getDomainName(), memberRole.getRoleName())
                            + " role filter requirements", caller);
                }
            }

            // now process if the expiry attribute was removed

            if (expiryRemoved) {
                if (ZMSUtils.userAuthorityAttrMissing(role.getUserAuthorityExpiration(), updatedGroup.getUserAuthorityExpiration())) {
                    throw ZMSUtils.requestError("Setting " + updatedGroup.getUserAuthorityExpiration() +
                            " user authority expiration on the group will not satisfy "
                            + ResourceUtils.roleResourceName(memberRole.getDomainName(), memberRole.getRoleName())
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

    <T> boolean updateUserAuthorityExpiry(T member, final String userAuthorityExpiry,
                                          Function<T, Timestamp> expirationGetter,
                                          BiConsumer<T, Timestamp> expirationSetter,
                                          Function<T, String> nameGetter) {

        // if we have a service then there is no processing taking place
        // as the service is not managed by the user authority

        if (!ZMSUtils.isUserDomainPrincipal(nameGetter.apply(member), zmsConfig.getUserDomainPrefix(),
                zmsConfig.getAddlUserCheckDomainPrefixList())) {
            return false;
        }

        Date authorityExpiry = zmsConfig.getUserAuthority().getDateAttribute(nameGetter.apply(member), userAuthorityExpiry);

        // if we don't have a date then we'll expiry the user right away
        // otherwise we'll set the date as imposed by the user authority

        boolean expiryDateUpdated = false;
        Timestamp memberExpiry = expirationGetter.apply(member);

        if (authorityExpiry == null) {

            // we'll update the expiration date to be the current time
            // if the user doesn't have one or it's expires sometime
            // in the future

            if (memberExpiry == null || memberExpiry.millis() > System.currentTimeMillis()) {
                expirationSetter.accept(member, Timestamp.fromCurrentTime());
                expiryDateUpdated = true;
            }
        } else {

            // update the expiration date if it does not match to the
            // value specified by the user authority value

            if (memberExpiry == null || memberExpiry.millis() != authorityExpiry.getTime()) {
                expirationSetter.accept(member, Timestamp.fromDate(authorityExpiry));
                expiryDateUpdated = true;
            }
        }
        return expiryDateUpdated;
    }

    boolean updateUserAuthorityExpiry(RoleMember roleMember, final String userAuthorityExpiry) {
        return updateUserAuthorityExpiry(roleMember,
                userAuthorityExpiry,
                RoleMember::getExpiration,
                RoleMember::setExpiration,
                RoleMember::getMemberName);
    }

    boolean updateUserAuthorityExpiry(GroupMember groupMember, final String userAuthorityExpiry) {
        return updateUserAuthorityExpiry(groupMember,
                userAuthorityExpiry,
                GroupMember::getExpiration,
                GroupMember::setExpiration,
                GroupMember::getMemberName);
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

    List<GroupMember> getGroupMembersWithUpdatedDueDates(List<GroupMember> groupMembers, Timestamp userExpiration,
                                                         long userExpiryMillis, Timestamp serviceExpiration, long serviceExpiryMillis,
                                                         final String userAuthorityExpiry) {

        return getMembersWithUpdatedDueDates(
                groupMembers,
                userExpiration,
                userExpiryMillis,
                serviceExpiration,
                serviceExpiryMillis,
                null,
                0,
                null,
                0,
                null,
                0,
                userAuthorityExpiry,
                null,
                0,
                GroupMember::getExpiration,
                member -> null,
                GroupMember::setExpiration,
                (member, timestamp) -> { },
                GroupMember::getMemberName);
    }

    <T> List<T> getMembersWithUpdatedDueDates(List<T> members, Timestamp userExpiration,
                                          long userExpiryMillis, Timestamp serviceExpiration, long serviceExpiryMillis,
                                          Timestamp groupExpiration, long groupExpiryMillis, Timestamp userReview,
                                          long userReviewMillis, Timestamp serviceReview, long serviceReviewMillis,
                                              final String userAuthorityExpiry, Timestamp groupReview, long groupReviewMillis,
                                              Function<T, Timestamp> expirationGetter,
                                              Function<T, Timestamp> reviewReminderGetter,
                                              BiConsumer<T, Timestamp> expirationSetter,
                                              BiConsumer<T, Timestamp> reviewReminderSetter,
                                              Function<T, String> nameGetter) {
        List<T> membersWithUpdatedDueDates = new ArrayList<>();
        for (T member : members) {
            Timestamp expiration = expirationGetter.apply(member);
            Timestamp reviewDate = reviewReminderGetter.apply(member);
            boolean dueDateUpdated = false;

            switch (ZMSUtils.principalType(nameGetter.apply(member), zmsConfig.getUserDomainPrefix(),
                    zmsConfig.getAddlUserCheckDomainPrefixList(), zmsConfig.getHeadlessUserDomainPrefix())) {

                case USER:

                    if (isEarlierDueDate(userExpiryMillis, expiration)) {
                        expirationSetter.accept(member, userExpiration);
                        dueDateUpdated = true;
                    }
                    if (isEarlierDueDate(userReviewMillis, reviewDate)) {
                        reviewReminderSetter.accept(member, userReview);
                        dueDateUpdated = true;
                    }

                    // if we have a user filter and/or expiry configured we need
                    // to make sure that the user still satisfies the filter
                    // otherwise we'll just expire the user right away

                    if (userAuthorityExpiry != null && updateUserAuthorityExpiry(
                            member,
                            userAuthorityExpiry,
                            expirationGetter,
                            expirationSetter,
                            nameGetter)) {
                        dueDateUpdated = true;
                    }

                    break;

                case GROUP:

                    if (isEarlierDueDate(groupExpiryMillis, expiration)) {
                        expirationSetter.accept(member, groupExpiration);
                        dueDateUpdated = true;
                    }
                    if (isEarlierDueDate(groupReviewMillis, reviewDate)) {
                        reviewReminderSetter.accept(member, groupReview);
                        dueDateUpdated = true;
                    }
                    break;

                case SERVICE:
                case USER_HEADLESS:

                    if (isEarlierDueDate(serviceExpiryMillis, expiration)) {
                        expirationSetter.accept(member, serviceExpiration);
                        dueDateUpdated = true;
                    }
                    if (isEarlierDueDate(serviceReviewMillis, reviewDate)) {
                        reviewReminderSetter.accept(member, serviceReview);
                        dueDateUpdated = true;
                    }
                    break;
            }

            if (dueDateUpdated) {
                membersWithUpdatedDueDates.add(member);
            }
        }

        return membersWithUpdatedDueDates;
    }

    List<RoleMember> getRoleMembersWithUpdatedDueDates(List<RoleMember> roleMembers, Timestamp userExpiration,
            long userExpiryMillis, Timestamp serviceExpiration, long serviceExpiryMillis,
            Timestamp groupExpiration, long groupExpiryMillis, Timestamp userReview,
            long userReviewMillis, Timestamp serviceReview, long serviceReviewMillis,
            final String userAuthorityExpiry, Timestamp groupReview, long groupReviewMillis) {

        return getMembersWithUpdatedDueDates(
                roleMembers,
                userExpiration,
                userExpiryMillis,
                serviceExpiration,
                serviceExpiryMillis,
                groupExpiration,
                groupExpiryMillis,
                userReview,
                userReviewMillis,
                serviceReview,
                serviceReviewMillis,
                userAuthorityExpiry,
                groupReview,
                groupReviewMillis,
                RoleMember::getExpiration,
                RoleMember::getReviewReminder,
                RoleMember::setExpiration,
                RoleMember::setReviewReminder,
                RoleMember::getMemberName);
    }

    private boolean insertRoleMembers(ResourceContext ctx, ObjectStoreConnection con, List<RoleMember> roleMembers,
                                      final String domainName, final String roleName, final String principal,
                                      final String auditRef, final String caller) {

        boolean bDataChanged = false;
        for (RoleMember roleMember : roleMembers) {
            try {
                boolean pendingRequest = (roleMember.getApproved() == Boolean.FALSE);
                if (pendingRequest) {
                    roleMember.setPendingState(ZMSConsts.PENDING_REQUEST_ADD_STATE);
                }
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

            // add domain change event
            addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
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

            // add domain change event
            addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);
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

            // add domain change event
            addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
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

            // add domain change event
            addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);
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

        if (!StringUtil.isEmpty(originalRole.getTrust())) {
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

            // add domain change event
            addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
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

        boolean userAuthorityExpiryChanged = isUserAuthorityExpiryChanged(originalGroup.getUserAuthorityExpiration(), updatedGroup.getUserAuthorityExpiration());

        // we only need to process the group members if the new due date
        // is more restrictive than what we had before

        boolean userMemberExpiryDayReduced = isNumOfDaysReduced(originalGroup.getMemberExpiryDays(),
                updatedGroup.getMemberExpiryDays());
        boolean serviceMemberExpiryDayReduced = isNumOfDaysReduced(originalGroup.getServiceExpiryDays(),
                updatedGroup.getServiceExpiryDays());

        if (!userMemberExpiryDayReduced && !serviceMemberExpiryDayReduced && !userAuthorityExpiryChanged) {
            return;
        }

        // we're only going to process those role members whose
        // due date is either not set or longer than the new limit

        long userExpiryMillis = userMemberExpiryDayReduced ? System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(updatedGroup.getMemberExpiryDays(), TimeUnit.DAYS) : 0;
        long serviceExpiryMillis = serviceMemberExpiryDayReduced ? System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(updatedGroup.getServiceExpiryDays(), TimeUnit.DAYS) : 0;

        Timestamp userExpiration = Timestamp.fromMillis(userExpiryMillis);
        Timestamp serviceExpiration = Timestamp.fromMillis(serviceExpiryMillis);

        final String principal = getPrincipalName(ctx);

        // process our group members and if there were any changes processed then update
        // our group and domain time-stamps, and invalidate local cache entry
        final String userAuthorityExpiry = userAuthorityExpiryChanged ? updatedGroup.getUserAuthorityExpiration() : null;
        List<GroupMember> groupMembersWithUpdatedDueDates = getGroupMembersWithUpdatedDueDates(groupMembers,
                userExpiration, userExpiryMillis, serviceExpiration, serviceExpiryMillis, userAuthorityExpiry);
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

        if (!StringUtil.isEmpty(originalRole.getTrust())) {
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
        boolean groupMemberExpiryDayReduced = isNumOfDaysReduced(originalRole.getGroupExpiryDays(),
                updatedRole.getGroupExpiryDays());

         boolean userMemberReviewDayReduced = isNumOfDaysReduced(originalRole.getMemberReviewDays(),
                 updatedRole.getMemberReviewDays());
         boolean serviceMemberReviewDayReduced = isNumOfDaysReduced(originalRole.getServiceReviewDays(),
                 updatedRole.getServiceReviewDays());
        boolean groupMemberReviewDayReduced = isNumOfDaysReduced(originalRole.getGroupReviewDays(),
                updatedRole.getGroupReviewDays());

        if (!userMemberExpiryDayReduced && !serviceMemberExpiryDayReduced &&
                !groupMemberExpiryDayReduced && !userMemberReviewDayReduced &&
                !serviceMemberReviewDayReduced && !userAuthorityExpiryChanged &&
                !groupMemberReviewDayReduced) {
            return;
        }

        // we're only going to process those role members whose
        // due date is either not set or longer than the new limit

        long userExpiryMillis = userMemberExpiryDayReduced ? System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(updatedRole.getMemberExpiryDays(), TimeUnit.DAYS) : 0;
        long serviceExpiryMillis = serviceMemberExpiryDayReduced ? System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(updatedRole.getServiceExpiryDays(), TimeUnit.DAYS) : 0;
        long groupExpiryMillis = groupMemberExpiryDayReduced ? System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(updatedRole.getGroupExpiryDays(), TimeUnit.DAYS) : 0;

         long userReviewMillis = userMemberReviewDayReduced ? System.currentTimeMillis()
                 + TimeUnit.MILLISECONDS.convert(updatedRole.getMemberReviewDays(), TimeUnit.DAYS) : 0;
         long serviceReviewMillis = serviceMemberReviewDayReduced ? System.currentTimeMillis()
                 + TimeUnit.MILLISECONDS.convert(updatedRole.getServiceReviewDays(), TimeUnit.DAYS) : 0;
        long groupReviewMillis = groupMemberReviewDayReduced ? System.currentTimeMillis()
                + TimeUnit.MILLISECONDS.convert(updatedRole.getGroupReviewDays(), TimeUnit.DAYS) : 0;

        Timestamp userExpiration = Timestamp.fromMillis(userExpiryMillis);
        Timestamp serviceExpiration = Timestamp.fromMillis(serviceExpiryMillis);
        Timestamp groupExpiration = Timestamp.fromMillis(groupExpiryMillis);

        Timestamp userReview = Timestamp.fromMillis(userReviewMillis);
        Timestamp serviceReview = Timestamp.fromMillis(serviceReviewMillis);
        Timestamp groupReview = Timestamp.fromMillis(groupReviewMillis);

        final String principal = getPrincipalName(ctx);

        // process our role members and if there were any changes processed then update
        // our role and domain time-stamps, and invalidate local cache entry

        final String userAuthorityExpiry = userAuthorityExpiryChanged ? updatedRole.getUserAuthorityExpiration() : null;
        List<RoleMember> roleMembersWithUpdatedDueDates = getRoleMembersWithUpdatedDueDates(roleMembers,
                userExpiration, userExpiryMillis, serviceExpiration, serviceExpiryMillis, groupExpiration,
                groupExpiryMillis, userReview, userReviewMillis, serviceReview, serviceReviewMillis,
                userAuthorityExpiry, groupReview, groupReviewMillis);
        if (insertRoleMembers(ctx, con, roleMembersWithUpdatedDueDates, domainName,
                roleName, principal, auditRef, caller)) {

            // update our role and domain time-stamps, and invalidate local cache entry

            con.updateRoleModTimestamp(domainName, roleName);
            con.updateDomainModTimestamp(domainName);
            cacheStore.invalidate(domainName);

            // add domain change event
            addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);
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
            if (StringUtil.isEmpty(auditRef)) {
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

                final String principal = getPrincipalName(ctx);

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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);

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

                final String principal = getPrincipalName(ctx);

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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);

                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    DomainRoleMembership getPendingDomainRoleMembers(final String principal, final String domainName) {

        DomainRoleMembership domainRoleMembership = new DomainRoleMembership();
        List<DomainRoleMembers> domainRoleMembersList = new ArrayList<>();
        boolean emptyDomainName = StringUtil.isEmpty(domainName);

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            // if principal/domain is provided then get pending role members by principal/domain
            // if principal and domain is provided then filter the result to only include role members of given domain name

            if (principal != null) {
                Map<String, List<DomainRoleMember>> domainRoleMembersMap = con.getPendingDomainRoleMembersByPrincipal(principal);
                if (domainRoleMembersMap != null) {
                    for (String domain : domainRoleMembersMap.keySet()) {
                        if (emptyDomainName || domain.equals(domainName) || "*".equals(domainName)) {
                            domainRoleMembersList.add(getDomainRoleMembers(domain, domainRoleMembersMap));
                        }
                    }
                    domainRoleMembership.setDomainRoleMembersList(domainRoleMembersList);
                }
            } else if (!emptyDomainName) {
                Map<String, List<DomainRoleMember>> domainRoleMembersMap = con.getPendingDomainRoleMembersByDomain(domainName);
                if (domainRoleMembersMap != null) {
                    for (String domain : domainRoleMembersMap.keySet()) {
                        domainRoleMembersList.add(getDomainRoleMembers(domain, domainRoleMembersMap));
                    }
                    domainRoleMembership.setDomainRoleMembersList(domainRoleMembersList);
                }
            }
        }
        return domainRoleMembership;
    }

    DomainGroupMembership getPendingDomainGroupMembers(final String principal, final String domainName) {
        DomainGroupMembership domainGroupMembership = new DomainGroupMembership();
        List<DomainGroupMembers> domainGroupMembersList = new ArrayList<>();
        boolean emptyDomainName = StringUtil.isEmpty(domainName);

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            // if principal is provided then get pending group members by principal
            // if domain is also provided then filter the result to only include group members of given domain name

            if (!StringUtil.isEmpty(principal)) {
                Map<String, List<DomainGroupMember>> domainGroupMembersMap = con.getPendingDomainGroupMembersByPrincipal(principal);
                if (domainGroupMembersMap != null) {
                    for (String domain : domainGroupMembersMap.keySet()) {
                        if (emptyDomainName || domain.equals(domainName) || "*".equals(domainName)) {
                                domainGroupMembersList.add(getDomainGroupMembers(domain, domainGroupMembersMap));
                        }
                    }
                    domainGroupMembership.setDomainGroupMembersList(domainGroupMembersList);
                }
            } else if (!emptyDomainName) {
                Map<String, List<DomainGroupMember>> domainGroupMembersMap = con.getPendingDomainGroupMembersByDomain(domainName);
                if (domainGroupMembersMap != null) {
                    for (String domain : domainGroupMembersMap.keySet()) {
                        domainGroupMembersList.add(getDomainGroupMembers(domain, domainGroupMembersMap));
                    }
                    domainGroupMembership.setDomainGroupMembersList(domainGroupMembersList);
                }
            }
        }
        return domainGroupMembership;
    }

    DomainGroupMembers getDomainGroupMembers(String domainName, Map<String, List<DomainGroupMember>> domainGroupMembersMap) {
        DomainGroupMembers domainGroupMembers = new DomainGroupMembers();
        domainGroupMembers.setDomainName(domainName);
        domainGroupMembers.setMembers(domainGroupMembersMap.get(domainName));
        return domainGroupMembers;
    }

    DomainRoleMembers getDomainRoleMembers(String domainName, Map<String, List<DomainRoleMember>> domainRoleMembersMap) {
        DomainRoleMembers domainRoleMembers = new DomainRoleMembers();
        domainRoleMembers.setDomainName(domainName);
        domainRoleMembers.setMembers(domainRoleMembersMap.get(domainName));
        return domainRoleMembers;
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

    Group executePutGroupReview(ResourceContext ctx, final String domainName, final String groupName,
            Group group, MemberDueDays memberExpiryDueDays, final String auditRef, Boolean returnObj) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                final String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, ctx.getApiName(), principal, AUDIT_TYPE_GROUP);

                // retrieve our original group

                Group originalGroup = getGroup(con, domainName, groupName, false, false);

                // now process the request. first we're going to make a copy of our group

                Group updatedGroup = new Group().setName(originalGroup.getName());

                // then we're going to apply the updated expiry and/or active status from the incoming group

                List<GroupMember> noActionMembers = applyGroupMembershipChanges(updatedGroup, originalGroup,
                        group, memberExpiryDueDays, auditRef);

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);

                List<GroupMember> deletedMembers = new ArrayList<>();
                List<GroupMember> extendedMembers = new ArrayList<>();

                auditDetails.append("{\"name\": \"").append(groupName).append('\"')
                        .append(", \"selfServe\": ").append(auditLogBooleanDefault(group.getSelfServe(), Boolean.TRUE))
                        .append(", \"auditEnabled\": ").append(auditLogBooleanDefault(group.getAuditEnabled(), Boolean.TRUE));

                for (GroupMember member : updatedGroup.getGroupMembers()) {

                    // if active flag is coming as false for the member, that means it's flagged for deletion

                    if (member.getActive() == Boolean.FALSE) {
                        if (!con.deleteGroupMember(domainName, groupName, member.getMemberName(), principal, auditRef)) {
                            con.rollbackChanges();
                            throw ZMSUtils.notFoundError("unable to delete group member: " +
                                    member.getMemberName() + " from group: " + groupName, ctx.getApiName());
                        }
                        deletedMembers.add(member);
                    } else {
                        // if not marked for deletion, then we are going to extend the member

                        String pendingState = member.getApproved() == Boolean.FALSE ? ZMSConsts.PENDING_REQUEST_ADD_STATE : null;
                        if (!con.insertGroupMember(domainName, groupName, member.setPendingState(pendingState), principal, auditRef)) {
                            con.rollbackChanges();
                            throw ZMSUtils.notFoundError("unable to extend group member: " +
                                    member.getMemberName() + " for the group: " + groupName, ctx.getApiName());
                        }
                        extendedMembers.add(member);
                    }
                }

                // construct audit log details

                auditLogGroupMembers(auditDetails, "deleted-members", deletedMembers);
                auditLogGroupMembers(auditDetails, "extended-members", extendedMembers);
                auditLogGroupMembers(auditDetails, "no-action-members", noActionMembers);

                auditDetails.append("}");

                if (!deletedMembers.isEmpty() || !extendedMembers.isEmpty()) {
                    // we have one or more changes to the group. We should update
                    // both lastReviewed as well as modified timestamps
                    con.updateGroupModTimestamp(domainName, groupName);
                }

                con.updateGroupReviewTimestamp(domainName, groupName);
                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, ctx.getApiName(), "REVIEW", groupName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);

                return returnObj == Boolean.TRUE ? getGroup(con, domainName, groupName, true, true) : null;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    Role executePutRoleReview(ResourceContext ctx, String domainName, String roleName, Role role,
                              MemberDueDays memberExpiryDueDays, MemberDueDays memberReminderDueDays,
                              String auditRef, String caller, Boolean returnObj) {

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

                if (!StringUtil.isEmpty(originalRole.getTrust())) {
                    throw ZMSUtils.requestError(caller + ": role " + roleName + " is delegated. Review should happen on the trusted role.", caller);
                }

                // now process the request. first we're going to make a copy of our role

                Role updatedRole = new Role().setName(originalRole.getName());

                // then we're going to apply the updated expiry and/or active status from the incoming role

                List<RoleMember> noActionMembers = applyRoleMembershipChanges(updatedRole, originalRole, role,
                        memberExpiryDueDays, memberReminderDueDays, auditRef);

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

                        String pendingState = member.getApproved() == Boolean.FALSE ? ZMSConsts.PENDING_REQUEST_ADD_STATE : null;
                        if (!con.insertRoleMember(domainName, roleName, member.setPendingState(pendingState), principal, auditRef)) {
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
                auditLogRoleMembers(auditDetails, "no-action-members", noActionMembers);

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

                // add domain change event
                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);

                return returnObj == Boolean.TRUE ? getRole(con, domainName, roleName, true, false, true) : null;

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
    List<RoleMember> applyRoleMembershipChanges(Role updatedRole, Role originalRole, Role role,
            MemberDueDays memberExpiryDueDays, MemberDueDays memberReminderDueDays, final String auditRef) {

        Map<String, RoleMember> incomingMemberMap =
                role.getRoleMembers().stream().collect(Collectors.toMap(RoleMember::getMemberName, item -> item));

        List<RoleMember> noActionMembers = new ArrayList<>(originalRole.getRoleMembers().size());

        // updatedMembers size is driven by input

        List<RoleMember> updatedMembers = new ArrayList<>(incomingMemberMap.size());
        updatedRole.setRoleMembers(updatedMembers);
        RoleMember updatedMember;

        // if original role is audit or review enabled then all the extensions
        // should be sent for approval again.

        boolean approvalStatus = originalRole.getAuditEnabled() != Boolean.TRUE &&
                originalRole.getReviewEnabled() != Boolean.TRUE;
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

                // member's new expiration/review reminder date is set by
                // role / domain level expiration setting

                updatedMember.setExpiration(memberDueDateUpdateRequired(memberExpiryDueDays, tempMemberFromMap.getPrincipalType()) ?
                        tempMemberFromMap.getExpiration() : originalMember.getExpiration());

                updatedMember.setReviewReminder(memberDueDateUpdateRequired(memberReminderDueDays, tempMemberFromMap.getPrincipalType()) ?
                        tempMemberFromMap.getReviewReminder() : originalMember.getReviewReminder());

                updatedMember.setAuditRef(auditRef);
                updatedMembers.add(updatedMember);
            } else {
                noActionMembers.add(originalMember);
            }
        }

        return noActionMembers;
    }

    boolean memberDueDateUpdateRequired(MemberDueDays memberDueDays, Integer principalType) {
        long dueDateMills = 0;
        switch (Principal.Type.getType(principalType)) {
            case USER:
                dueDateMills = memberDueDays.getUserDueDateMillis();
                break;
            case SERVICE:
            case USER_HEADLESS:
                dueDateMills = memberDueDays.getServiceDueDateMillis();
                break;
            case GROUP:
                dueDateMills = memberDueDays.getGroupDueDateMillis();
                break;
        }
        return dueDateMills != 0;
    }

    /**
     * This method takes the input group, creates a map using memberName as key,
     * copies members from original group from DB and only adds deleted / extended members to the updatedGroup.
     * @param updatedGroup updated group to be sent to DB to record changes
     * @param originalGroup original group from DB
     * @param group incoming group containing changes from domain admin
     * @param auditRef audit ref for the change
     * @return List of rolemember where no action was taken
     */
    List<GroupMember> applyGroupMembershipChanges(Group updatedGroup, Group originalGroup, Group group,
            MemberDueDays memberExpiryDueDays, final String auditRef) {

        Map<String, GroupMember> incomingMemberMap =
                group.getGroupMembers().stream().collect(Collectors.toMap(GroupMember::getMemberName, item -> item));

        List<GroupMember> noActionMembers = new ArrayList<>(originalGroup.getGroupMembers().size());

        // updatedMembers size is driven by input

        List<GroupMember> updatedMembers = new ArrayList<>(incomingMemberMap.size());
        updatedGroup.setGroupMembers(updatedMembers);
        GroupMember updatedMember;

        // if original group is either audit or review enabled then all the extensions
        // should be sent for approval again.

        boolean approvalStatus = originalGroup.getAuditEnabled() != Boolean.TRUE &&
                originalGroup.getReviewEnabled() != Boolean.TRUE;
        GroupMember tempMemberFromMap;

        for (GroupMember originalMember : originalGroup.getGroupMembers()) {

            // we are only going to update the changed members

            if (incomingMemberMap.containsKey(originalMember.getMemberName())) {

                updatedMember = new GroupMember();
                updatedMember.setMemberName(originalMember.getMemberName());

                tempMemberFromMap = incomingMemberMap.get(updatedMember.getMemberName());

                // member's approval status is determined by auditEnabled flag set on original role

                updatedMember.setApproved(approvalStatus);

                // member's active status is determined by action taken in UI

                updatedMember.setActive(tempMemberFromMap.getActive());

                // member's new expiration is set by role / domain level expiration setting

                updatedMember.setExpiration(memberDueDateUpdateRequired(memberExpiryDueDays, tempMemberFromMap.getPrincipalType()) ?
                        tempMemberFromMap.getExpiration() : originalMember.getExpiration());

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

    void executePutAssertionConditions(ResourceContext ctx, String domainName, String policyName, long assertionId,
                                       AssertionConditions assertionConditions, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // now we need verify our quota check

                quotaCheck.checkAssertionConditionsQuota(con, assertionId, assertionConditions, caller);

                // process our insert assertion condition.

                if (!con.insertAssertionConditions(assertionId, assertionConditions)) {
                    throw ZMSUtils.requestError(String.format("%s: unable to insert assertion conditions for policy=%s assertionId=%d", caller, policyName, assertionId), caller);
                }

                // update our policy and domain time-stamps, and invalidate local cache entry

                con.updatePolicyModTimestamp(domainName, policyName, null);
                saveChanges(con, domainName);


                // audit log the request
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"policy\": \"").append(policyName)
                        .append("\", \"assertionId\": ").append(assertionId)
                        .append(", ");
                auditLogAssertionConditions(auditDetails, assertionConditions.getConditionsList(), "new-assertion-conditions");
                auditDetails.append("}");

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        policyName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);
                
                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutAssertionCondition(ResourceContext ctx, String domainName, String policyName, long assertionId,
                                      AssertionCondition assertionCondition, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // process our insert assertion condition.

                if (assertionCondition.getId() == null) {

                    // now we need verify our quota check
                    quotaCheck.checkAssertionConditionQuota(con, assertionId, assertionCondition, caller);

                    // no condition id in the request. so we are going to generate the next condition id for
                    // the given assertion id and then use it to insert given keys
                    assertionCondition.setId(con.getNextConditionId(assertionId, caller));
                    if (!con.insertAssertionCondition(assertionId, assertionCondition)) {
                        throw ZMSUtils.requestError(String.format("%s: unable to insert new assertion condition for policy=%s assertionId=%d", caller, policyName, assertionId), caller);
                    }
                } else {

                    // existing assertion condition keys found with given condition id. so delete existing keys from DB for the given condition id
                    if (!con.deleteAssertionCondition(assertionId, assertionCondition.getId())) {
                        throw ZMSUtils.notFoundError(String.format("%s: unable to delete assertion condition during putAssertionCondition for policy=%s assertionId=%d conditionId=%d"
                                , caller, policyName, assertionId, assertionCondition.getId()), caller);
                    }
                    // now we need verify our quota check after deleting the old entries
                    quotaCheck.checkAssertionConditionQuota(con, assertionId, assertionCondition, caller);

                    // now insert the new keys against existing condition id
                    if (!con.insertAssertionCondition(assertionId, assertionCondition)) {
                        throw ZMSUtils.requestError(String.format("%s: unable to insert assertion condition for policy=%s assertionId=%d", caller, policyName, assertionId), caller);
                    }
                }

                // update our policy and domain time-stamps, and invalidate local cache entry

                con.updatePolicyModTimestamp(domainName, policyName, null);
                saveChanges(con, domainName);


                // audit log the request
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"policy\": \"").append(policyName)
                        .append("\", \"assertionId\": ").append(assertionId)
                        .append(", \"new-assertion-condition\": ");
                auditLogAssertionCondition(auditDetails, assertionCondition, true);
                auditDetails.append("}");

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        policyName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);
                
                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    public void executeDeleteAssertionConditions(ResourceContext ctx, String domainName, String policyName, Long assertionId, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // fetch the assertion for our audit log

                List<AssertionCondition> assertionConditions = con.getAssertionConditions(assertionId);
                if (assertionConditions == null) {
                    throw ZMSUtils.notFoundError(String.format("%s: unable to read assertion conditions for policy=%s assertionId=%d", caller,
                            policyName, assertionId), caller);
                }

                // process our delete assertion conditions. since this is a "single"
                // operation, we are not using any transactions.

                if (!con.deleteAssertionConditions(assertionId)) {
                    throw ZMSUtils.notFoundError(String.format("%s: unable to delete assertion conditions for policy=%s assertionId=%d", caller,
                            policyName, assertionId), caller);
                }

                // update our policy and domain time-stamps, and invalidate local cache entry

                con.updatePolicyModTimestamp(domainName, policyName, null);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"policy\": \"").append(policyName)
                        .append("\", \"assertionId\": ").append(assertionId)
                        .append(", ");
                auditLogAssertionConditions(auditDetails, assertionConditions, "deleted-assertion-conditions");
                auditDetails.append("}");

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        policyName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);
                
                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    public void executeDeleteAssertionCondition(ResourceContext ctx, String domainName, String policyName, Long assertionId, Integer conditionId, String auditRef, String caller) {
        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // fetch the assertion for our audit log

                AssertionCondition assertionCondition = con.getAssertionCondition(assertionId, conditionId);
                if (assertionCondition == null) {
                    throw ZMSUtils.notFoundError(String.format("%s: unable to read assertion condition for policy=%s assertionId=%d conditionId=%d"
                            , caller, policyName, assertionId, conditionId), caller);
                }

                // process our delete assertion condition. since this is a "single"
                // operation, we are not using any transactions.

                if (!con.deleteAssertionCondition(assertionId, conditionId)) {
                    throw ZMSUtils.notFoundError(String.format("%s: unable to delete assertion condition for policy=%s assertionId=%d conditionId=%d"
                            , caller, policyName, assertionId, conditionId), caller);
                }

                // update our policy and domain time-stamps, and invalidate local cache entry

                con.updatePolicyModTimestamp(domainName, policyName, null);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"policy\": \"").append(policyName)
                        .append("\", \"assertionId\": ").append(assertionId)
                        .append(", \"deleted-assertion-condition\": ");
                auditLogAssertionCondition(auditDetails, assertionCondition, true);
                auditDetails.append("}");

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        policyName, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);
                
                return;

            } catch (ResourceException ex) {

                // otherwise check if we need to retry or return failure

                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    public void putDomainDependency(ResourceContext ctx, String domainName, String service, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                final String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal, AUDIT_TYPE_DOMAIN);

                // verify domain exists

                Domain domain = con.getDomain(domainName);
                if (domain == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": Unknown domain: " + domainName, caller);
                }

                // now process the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                if (!processDomainDependency(con, domainName, service, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put dependency on domain " + domainName + " for service " + service, caller);
                }

                // we only need to commit out changes and no need to update
                // our domain timestamp or invalidate the cache data

                con.commitChanges();

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        service, auditDetails.toString());

                // add domain change event

                addDomainChangeMessage(ctx, domainName, service, DomainChangeMessage.ObjectType.DOMAIN);
                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    public void deleteDomainDependency(ResourceContext ctx, String domainName, String service, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                final String principal = getPrincipalName(ctx);

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal, AUDIT_TYPE_DOMAIN);

                // verify domain exists

                Domain domain = con.getDomain(domainName);
                if (domain == null) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": Unknown domain: " + domainName, caller);
                }

                // now process the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                if (!processDeleteDomainDependency(con, domainName, service, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to delete dependency on domain " + domainName + " for service " + service, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        service, auditDetails.toString());

                // add domain change event
                addDomainChangeMessage(ctx, domainName, service, DomainChangeMessage.ObjectType.DOMAIN);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    private boolean processDomainDependency(ObjectStoreConnection con, String domainName, String service,
                                            StringBuilder auditDetails) {

        boolean requestSuccess = con.insertDomainDependency(domainName, service);

        // if we didn't insert a dependency then we need to return failure

        if (!requestSuccess) {
            return false;
        }

        // open our audit record and log the dependency

        auditDetails.append("{\"domain-dependencies\": ");
        auditDetails.append("{\"domain\": \"").append(domainName)
                .append("\", \"service\": \"").append(service).append("\"}")
                .append('}');

        return true;
    }

    private boolean processDeleteDomainDependency(ObjectStoreConnection con, String domainName, String service,
                                                  StringBuilder auditDetails) {

        boolean requestSuccess = con.deleteDomainDependency(domainName, service);

        // if we didn't delete the dependency then we need to return failure

        if (!requestSuccess) {
            return false;
        }

        // open our audit record and log the dependency

        auditDetails.append("{\"delete-domain-dependencies\": ");
        auditDetails.append("{\"domain\": \"").append(domainName)
                .append("\", \"service\": \"").append(service).append("\"}")
                .append('}');

        return true;
    }

    public ServiceIdentityList listServiceDependencies(String domainName) {
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            ServiceIdentityList serviceIdentityList = new ServiceIdentityList();
            serviceIdentityList.setNames(con.listServiceDependencies(domainName));
            return serviceIdentityList;
        }
    }

    public DomainList listDomainDependencies(String service) {
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            DomainList domainList = new DomainList();
            domainList.setNames(con.listDomainDependencies(service));
            return domainList;
        }
    }

    void executeDeleteExpiredMembership(ResourceContext ctx, ObjectStoreConnection con, String domainName, String roleName,
            String normalizedMember, Timestamp expiration, String auditRef, String caller) {

        final String principal = getPrincipalName(ctx);

        // process our delete role member operation

        if (!con.deleteExpiredRoleMember(domainName, roleName, normalizedMember, principal, expiration, auditRef)) {
            throw ZMSUtils.notFoundError(caller + ": unable to delete role member: " +
                    normalizedMember + " from role: " + roleName + ". this happened either because the" +
                    " member was deleted already or his expiration was updated very recently", caller);
        }
    }

    List<ExpiryMember> executeDeleteDomainExpiredRoleMemberships(ResourceContext ctx, String domainName,
            List<ExpiryMember> members, String auditRef, String caller) {

        List<ExpiryMember> removedList = new ArrayList<>();
        try (ObjectStoreConnection con = store.getConnection(false, true)) {

            // delete all expired domain group members one by one (required due auditLog)
            for (ExpiryMember member : members) {
                try {
                    executeDeleteExpiredMembership(ctx, con, domainName, member.getCollectionName(),
                            member.getPrincipalName(), member.getExpiration(), auditRef, caller);
                    removedList.add(member);
                } catch (Exception ex) {
                    LOG.error("failed to delete expired role member. domain={} role={} member={} expiration={}",
                            domainName, member.getCollectionName(), member.getPrincipalName(),
                            member.getExpiration(), ex);
                }
            }
            purgeTaskSaveDomainChanges(ctx, con, domainName, removedList, auditRef, caller, DomainChangeMessage.ObjectType.ROLE);
            return removedList;
        } catch (Exception ex) {
            LOG.error("failed to delete expired role member of domain={} ({}): ",
                    domainName,
                    members.stream()
                            .map(member -> "role=" + member.getCollectionName() + " member=" + member.getPrincipalName())
                            .collect(Collectors.joining(", ")),
                    ex);
            return null;
        }
    }

    public List<ExpiryMember> executeDeleteAllExpiredRoleMemberships(ResourceContext ctx, String auditRef, String caller) {

        // if our the member expiry days is set to 0, then we'll skip
        // this request and return an empty list

        final int expiryDays = purgeMemberExpiryDays.get();
        if (expiryDays <= 0) {
            return Collections.emptyList();
        }

        final int maxDbCallsPerRun = purgeMembersMaxDbCallsPerRun.get();
        final int limitPerCall = purgeMembersLimitPerCall.get();
        int offset = 0;
        int numOfExpiredMembersRetrieved = 0;
        Map<String, List<ExpiryMember>> allExpiredRoleMembersMap = new HashMap<>();
        List<ExpiryMember> removedList = new ArrayList<>();

        try (ObjectStoreConnection con = store.getConnection(true, false)) {

            // get all expired members from all roles and separate them per domain

            for (int i = 0; i < maxDbCallsPerRun; ++i) {
                List<ExpiryMember> expiredRoleMembers = con.getAllExpiredRoleMembers(limitPerCall, offset, expiryDays);
                if (expiredRoleMembers == null || expiredRoleMembers.isEmpty()) {
                    break;
                }
                numOfExpiredMembersRetrieved += expiredRoleMembers.size();
                for (ExpiryMember member: expiredRoleMembers) {
                    if (allExpiredRoleMembersMap.containsKey(member.getDomainName())) {
                        allExpiredRoleMembersMap.get(member.getDomainName()).add(member);
                    } else {
                        allExpiredRoleMembersMap.put(member.getDomainName(), new ArrayList<>() { { add(member); } });
                    }
                }
                if (expiredRoleMembers.size() < limitPerCall) {
                    break;
                }
                offset += limitPerCall;
            }
        }

        // delete all expired role members. for blocking only one domain at a time, for each domain,
        // its expired members will be deleted in a separate transaction.

        for (Map.Entry<String, List<ExpiryMember>> entry: allExpiredRoleMembersMap.entrySet()) {
            List<ExpiryMember> removedDomainList = executeDeleteDomainExpiredRoleMemberships(ctx, entry.getKey(),
                    entry.getValue(), auditRef, caller);
            if (removedDomainList != null) {
                removedList.addAll(removedDomainList);
            }
        }

        if (numOfExpiredMembersRetrieved == removedList.size()) {
            LOG.info("delete all expired role members done successfully: {} members were deleted", removedList.size());
        } else {
            LOG.info("delete all expired role members done with errors: {} out of {} members were deleted",
                    removedList.size(), numOfExpiredMembersRetrieved);
        }

        return removedList;
    }

    void executeDeleteExpiredGroupMembership(ResourceContext ctx, ObjectStoreConnection con, String domainName,
                                                 String groupName, String normalizedMember, Timestamp expiration, String auditRef) {
        final String principal = getPrincipalName(ctx);
        // process our delete expired group member operation
        if (!con.deleteExpiredGroupMember(domainName, groupName, normalizedMember, principal, expiration, auditRef)) {
            throw ZMSUtils.notFoundError("unable to delete group member: " +
                    normalizedMember + " from group: " + groupName + ". this happened either because the " +
                    "member was deleted already or his expiration was updated very recently", ctx.getApiName());
        }
    }

    List<ExpiryMember> executeDeleteDomainExpiredGroupMemberships(ResourceContext ctx, String domainName,
            List<ExpiryMember> members, String auditRef, String caller) {

        List<ExpiryMember> removedList = new ArrayList<>();
        try (ObjectStoreConnection con = store.getConnection(false, true)) {

            // delete all expired domain group members one by one (required due auditLog)
            for (ExpiryMember member : members) {
                try {
                    executeDeleteExpiredGroupMembership(ctx, con, domainName, member.getCollectionName(),
                            member.getPrincipalName(), member.getExpiration(), auditRef);
                    removedList.add(member);
                } catch (Exception ex) {
                    LOG.error("failed to delete expired group member. domain={} role={} member={} expiration={}",
                            domainName, member.getCollectionName(), member.getPrincipalName(),
                            member.getExpiration(), ex);
                }
            }
            purgeTaskSaveDomainChanges(ctx, con, domainName, removedList, auditRef, caller, DomainChangeMessage.ObjectType.GROUP);
            return removedList;
        } catch (Exception ex) {
            LOG.error("failed to delete expired group member of domain={} ({}): ",
                    domainName,
                    members.stream()
                            .map(member -> "group=" + member.getCollectionName() + " member=" + member.getPrincipalName())
                            .collect(Collectors.joining(", ")),
                    ex);
            return null;
        }
    }

    public List<ExpiryMember> executeDeleteAllExpiredGroupMemberships(ResourceContext ctx, String auditRef, String caller) {

        // if our the member expiry days is set to 0, then we'll skip
        // this request and return an empty list

        final int expiryDays = purgeMemberExpiryDays.get();
        if (expiryDays <= 0) {
            return Collections.emptyList();
        }

        final int maxDbCallsPerRun = purgeMembersMaxDbCallsPerRun.get();
        final int limitPerCall = purgeMembersLimitPerCall.get();
        int offset = 0;
        int numOfExpiredMembersRetrieved = 0;
        Map<String, List<ExpiryMember>> allExpiredGroupMembersMap = new HashMap<>();
        List<ExpiryMember> removedList = new ArrayList<>();

        try (ObjectStoreConnection con = store.getConnection(true, false)) {

            // get all expired members from all groups and separate them per domain

            for (int i = 0; i < maxDbCallsPerRun; ++i) {
                List<ExpiryMember> expiredGroupMembers = con.getAllExpiredGroupMembers(limitPerCall, offset, expiryDays);
                if (expiredGroupMembers == null || expiredGroupMembers.isEmpty()) {
                    break;
                }
                numOfExpiredMembersRetrieved += expiredGroupMembers.size();
                for (ExpiryMember member: expiredGroupMembers) {
                    if (allExpiredGroupMembersMap.containsKey(member.getDomainName())) {
                        allExpiredGroupMembersMap.get(member.getDomainName()).add(member);
                    } else {
                        allExpiredGroupMembersMap.put(member.getDomainName(), new ArrayList<>() { { add(member); } });
                    }
                }
                if (expiredGroupMembers.size() < limitPerCall) {
                    break;
                }
                offset += limitPerCall;
            }
        }

        // delete all expired group members. for blocking only one domain at a time, for each domain,
        // its expired members will be deleted in a separate transaction.

        for (Map.Entry<String, List<ExpiryMember>> entry: allExpiredGroupMembersMap.entrySet()) {
            List<ExpiryMember> removedDomainList = executeDeleteDomainExpiredGroupMemberships(ctx, entry.getKey(),
                    entry.getValue(), auditRef, caller);
            if (removedDomainList != null) {
                removedList.addAll(removedDomainList);
            }
        }

        if (numOfExpiredMembersRetrieved == removedList.size()) {
            LOG.info("delete all expired group members done successfully: {} members were deleted", removedList.size());
        } else {
            LOG.info("delete all expired group members done with errors: {} out of {} members were deleted",
                    removedList.size(), numOfExpiredMembersRetrieved);
        }

        return removedList;
    }

    public AuthHistoryDependencies getAuthHistory(String domain) {
        if (authHistoryStore == null) {
            LOG.warn("Authentication History Store is disabled. getAuthHistory will return empty lists.");
            AuthHistoryDependencies authHistoryDependencies = new AuthHistoryDependencies();
            authHistoryDependencies.setIncomingDependencies(new ArrayList<>());
            authHistoryDependencies.setOutgoingDependencies(new ArrayList<>());
            return authHistoryDependencies;
        }
        try (AuthHistoryStoreConnection con = authHistoryStore.getConnection()) {
            return con.getAuthHistory(domain);
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

    private void addDomainChangeMessage(ResourceContext ctx, String domainName, String objectName, DomainChangeMessage.ObjectType objectType) {
        if (ctx != null) {
            ctx.addDomainChangeMessage(new DomainChangeMessage()
                .setDomainName(domainName)
                .setObjectName(objectName)
                .setObjectType(objectType)
                .setApiName(ctx.getApiName())
                .setPublished(Instant.now().toEpochMilli())
                .setMessageId(java.util.UUID.randomUUID().toString())
            );
        }
    }

    void executePutResourceDomainOwnership(ResourceContext ctx, final String domainName,
            ResourceDomainOwnership resourceOwnership, final String auditRef, final String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(true, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_DOMAIN);

                // now process the request

                if (!con.setResourceDomainOwnership(domainName, resourceOwnership)) {
                    throw ZMSUtils.requestError("unable to put resource domain ownership for domain: "
                            + domainName, caller);
                }

                // invalidate our domain cache

                cacheStore.invalidate(domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT, null,
                        JSON.string(resourceOwnership));

                // add domain change event

                addDomainChangeMessage(ctx, domainName, domainName, DomainChangeMessage.ObjectType.DOMAIN);
                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutResourceRoleOwnership(ResourceContext ctx, final String domainName, final String roleName,
            ResourceRoleOwnership resourceOwnership, final String auditRef, final String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_ROLE);

                // now process the request

                if (!con.setResourceRoleOwnership(domainName, roleName, resourceOwnership)) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError("unable to put resource role ownership for role: "
                            + roleName + " in domain: " + domainName, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        roleName, JSON.string(resourceOwnership));

                // add domain change event

                addDomainChangeMessage(ctx, domainName, roleName, DomainChangeMessage.ObjectType.ROLE);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutResourceGroupOwnership(ResourceContext ctx, final String domainName, final String groupName,
            ResourceGroupOwnership resourceOwnership, final String auditRef, final String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_GROUP);

                // now process the request

                if (!con.setResourceGroupOwnership(domainName, groupName, resourceOwnership)) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError("unable to put resource group ownership for group: "
                            + groupName + " in domain: " + domainName, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        groupName, JSON.string(resourceOwnership));

                // add domain change event

                addDomainChangeMessage(ctx, domainName, groupName, DomainChangeMessage.ObjectType.GROUP);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutResourcePolicyOwnership(ResourceContext ctx, final String domainName, final String policyName,
            ResourcePolicyOwnership resourceOwnership, final String auditRef, final String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_POLICY);

                // now process the request

                if (!con.setResourcePolicyOwnership(domainName, policyName, resourceOwnership)) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError("unable to put resource policy ownership for policy: "
                            + policyName + " in domain: " + domainName, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        policyName, JSON.string(resourceOwnership));

                // add domain change event

                addDomainChangeMessage(ctx, domainName, policyName, DomainChangeMessage.ObjectType.POLICY);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void executePutResourceServiceOwnership(ResourceContext ctx, final String domainName, final String serviceName,
            ResourceServiceIdentityOwnership resourceOwnership, final String auditRef, final String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx), AUDIT_TYPE_SERVICE);

                // now process the request

                if (!con.setResourceServiceOwnership(domainName, serviceName, resourceOwnership)) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError("unable to put resource service ownership for service: "
                            + serviceName + " in domain: " + domainName, caller);
                }

                // update our domain time-stamp and save changes

                saveChanges(con, domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        serviceName, JSON.string(resourceOwnership));

                // add domain change event

                addDomainChangeMessage(ctx, domainName, serviceName, DomainChangeMessage.ObjectType.SERVICE);

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
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
