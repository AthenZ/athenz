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

import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.log.AuditLogMsgBuilder;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.util.StringUtils;
import com.yahoo.athenz.zms.store.AthenzDomain;
import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.ObjectStoreConnection;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Timestamp;
import com.yahoo.rdl.UUID;
import com.yahoo.athenz.common.server.audit.AuditReferenceValidator;


public class DBService {
    
    ObjectStore store;
    final String userDomain;
    AuditLogger auditLogger;
    Cache<String, DataCache> cacheStore;
    QuotaChecker quotaCheck;
    int retrySleepTime;
    int defaultRetryCount;
    int defaultOpTimeout;
    
    private static final Logger LOG = LoggerFactory.getLogger(DBService.class);

    private static final String ROLE_PREFIX = "role.";
    private static final String POLICY_PREFIX = "policy.";
    private static final String TEMPLATE_DOMAIN_NAME = "_domain_";
    AuditReferenceValidator auditReferenceValidator;
    
    public DBService(ObjectStore store, AuditLogger auditLogger, String userDomain, AuditReferenceValidator auditReferenceValidator) {
        
        this.store = store;
        this.userDomain = userDomain;
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
        
        // create our quota checker class
        
        quotaCheck = new QuotaChecker();

        this.auditReferenceValidator = auditReferenceValidator;
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
    
    AthenzDomain getAthenzDomainFromCache(String domainName, boolean masterCopy) {
        
        // if we have a match for a given domain name then we're going
        // to check if the last modified domain timestamp matches to what's
        // in the db: So if there is no match, then we'll take the hit
        // of extra db read, however, in most cases the domain data is not
        // changed that often so we'll satisfy the request with just
        // verifying the last modification time as oppose to reading the
        // full domain data from db
        
        DataCache data = cacheStore.getIfPresent(domainName);
        if (data == null) {
            return null;
        }
        
        long modTime = 0;
        try (ObjectStoreConnection con = store.getConnection(true, masterCopy)) {
            
            // we expect this response to come back immediately from
            // object store so we're going to use a smaller timeout
            // so we should know right away to use our cache
            
            con.setOperationTimeout(10);
            modTime = con.getDomainModTimestamp(domainName);
            
        } catch (ResourceException ex) {
            
            // if the exception is due to timeout or we were not able
            // to get a connection to the object store then we're
            // going to use our cache as is instead of rejecting
            // the operation
            
            if (ex.getCode() == ResourceException.SERVICE_UNAVAILABLE) {
                return data.getAthenzDomain();
            }
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
        
        AuditLogMsgBuilder msgBldr = ZMSUtils.getAuditLogMsgBuilder(ctx, auditLogger,
                domainName, auditRef, caller, operation);
        msgBldr.when(Timestamp.fromCurrentTime().toString()).whatEntity(entityName);
        if (auditDetails != null) {
            msgBldr.whatDetails(auditDetails);
        }
        auditLogger.log(msgBldr);
    }
    
    Domain makeDomain(ResourceContext ctx, String domainName, String description, String org,
            Boolean auditEnabled, List<String> adminUsers, String account, int productId, String applicationId,
            List<String> solutionTemplates, String auditRef) {
        
        final String caller = "makedomain";
        
        Domain domain = new Domain()
                .setName(domainName)
                .setAuditEnabled(auditEnabled)
                .setDescription(description)
                .setOrg(org)
                .setId(UUID.fromCurrentTime())
                .setAccount(account)
                .setYpmId(productId)
                .setModified(Timestamp.fromCurrentTime())
                .setApplicationId(applicationId);
        
        // get our connection object

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

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
                        getPrincipalName(ctx), auditRef, false, auditDetails)) {
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
                        if (!addSolutionTemplate(con, domainName, templateName, getPrincipalName(ctx),
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
            requestSuccess = con.insertRole(domainName, role);
        } else {
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
        
        // support older clients which might send members field
        // at this point, we expect either roleMembers or members,
        // and we can't have both
        
        List<String> members = role.getMembers();
        if (members != null && !members.isEmpty()) {
            roleMembers = ZMSUtils.convertMembersToRoleMembers(members);
        }
        
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
            processUpdateRoleMembers(con, originalRole, roleMembers, ignoreDeletes, 
                    domainName, roleName, admin, auditRef, auditDetails);
        }
        
        auditDetails.append('}');
        return true;
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
        
        ZMSUtils.removeMembers(newMembers, curMembers);
        
        // remove new members from current members
        // which leaves the deleted members.
        
        ZMSUtils.removeMembers(delMembers, roleMembers);
        
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
    
    boolean processServiceIdentity(ObjectStoreConnection con, ServiceIdentity originalService,
            String domainName, String serviceName, ServiceIdentity service,
            boolean ignoreDeletes, StringBuilder auditDetails) {
        
        boolean requestSuccess;
        if (originalService == null) {
            requestSuccess = con.insertServiceIdentity(domainName, service);
        } else {
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
            .append(", \"providerEndpoint\": \"").append(service.getProviderEndpoint()).append('\"')
            .append(", \"description\"L \"").append(service.getDescription()).append('\"');
         
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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal);

                // check that quota is not exceeded

                quotaCheck.checkRoleQuota(con, domainName, role, caller);

                // retrieve our original role

                Role originalRole = getRole(con, domainName, roleName, false, false);

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

    void executePutServiceIdentity(ResourceContext ctx, String domainName, String serviceName,
            ServiceIdentity service, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

                // check that quota is not exceeded

                quotaCheck.checkServiceIdentityQuota(con, domainName, service, caller);

                // retrieve our original service identity object

                ServiceIdentity originalService = getServiceIdentity(con, domainName, serviceName);

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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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

                if (null != ctx) {
                    auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                            serviceName, auditDetails.toString());
                }

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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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

                if (null != ctx) {
                    auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                            serviceName, auditDetails.toString());
                }

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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal);

                // before inserting a member we need to verify that
                // this is a group role and not a delegated one.

                if (isTrustRole(con.getRole(domainName, roleName))) {
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

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        roleName, "{\"member\": \"" + roleMember.getMemberName() + "\"}");

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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, principal);

                // if this is the admin role then we need to make sure
                // the admin is not himself who happens to be the last
                // member in the role

                if (ZMSConsts.ADMIN_ROLE_NAME.equals(roleName)) {
                    List<RoleMember> members = con.listRoleMembers(domainName, roleName);
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
    
    void executeDeleteServiceIdentity(ResourceContext ctx, String domainName, String serviceName,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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
    
    void executeDeletePolicy(ResourceContext ctx, String domainName, String policyName,
            String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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
     * an exception will be thrown. This is the first check before any write
     * operation is carried out so we don't really have anything to roll-back
     **/
    Domain checkDomainAuditEnabled(ObjectStoreConnection con, String domainName, String auditRef, String caller, String principal) {

        Domain domain = con.getDomain(domainName);
        if (domain == null) {
            con.rollbackChanges();
            throw ZMSUtils.notFoundError(caller + ": Unknown domain: " + domainName, caller);
        }

        if (domain.getAuditEnabled()) {
            if (auditRef == null || auditRef.length() == 0) {
                con.rollbackChanges();
                throw ZMSUtils.requestError(caller + ": Audit reference required for domain: " + domainName, caller);
            }

            if (auditReferenceValidator != null && !auditReferenceValidator.validateReference(auditRef, principal, caller)) {
                con.rollbackChanges();
                throw ZMSUtils.requestError(caller + ": Audit reference validation failed for domain: " + domainName + ", auditRef: " + auditRef, caller);
            }
        }
        
        return domain;
    }
    
    Domain executeDeleteDomain(ResourceContext ctx, String domainName, String auditRef, String caller) {

        // our exception handling code does the check for retry count
        // and throws the exception it had received when the retry
        // count reaches 0

        for (int retryCount = defaultRetryCount; ; retryCount--) {

            try (ObjectStoreConnection con = store.getConnection(false, true)) {

                // first verify that auditing requirements are met

                Domain domain = checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

                // now process the request

                con.deleteDomain(domainName);
                con.commitChanges();
                cacheStore.invalidate(domainName);

                // audit log the request

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        domainName, null);

                return domain;

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
    
    ServiceIdentity getServiceIdentity(String domainName, String serviceName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return getServiceIdentity(con, domainName, serviceName);
        }
    }
    
    DomainTemplateList listDomainTemplates(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            DomainTemplateList domainTemplateList = new DomainTemplateList();
            domainTemplateList.setTemplateNames(con.listDomainTemplates(domainName));
            return domainTemplateList;
        }
    }
    
    ServiceIdentity getServiceIdentity(ObjectStoreConnection con, String domainName, String serviceName) {

        ServiceIdentity service = con.getServiceIdentity(domainName, serviceName);
        if (service != null) {
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
            return con.listResourceAccess(principal, action, userDomain);
        }
    }
    
    Domain getDomain(String domainName, boolean masterCopy) {

        try (ObjectStoreConnection con = store.getConnection(true, masterCopy)) {
            return con.getDomain(domainName);
        }
    }
    
    List<String> listDomains(String prefix, long modifiedSince) {
        
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.listDomains(prefix, modifiedSince);
        }
    }

    DomainList lookupDomainById(String account, int productId) {
        
        DomainList domList = new DomainList();
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            String domain = con.lookupDomainById(account, productId);
            if (domain != null) {
                List<String> list = Collections.singletonList(domain);
                domList.setNames(list);
            }
        }
        return domList;
    }
    
    DomainList lookupDomainByAccount(String account) {
        return lookupDomainById(account, 0);
    }

    DomainList lookupDomainByProductId(Integer productId) {
        return lookupDomainById(null, productId);
    }
    
    DomainList lookupDomainByRole(String roleMember, String roleName) {
        
        DomainList domList = new DomainList();
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            List<String> domains = con.lookupDomainByRole(roleMember, roleName);
            if (domains != null) {
                domList.setNames(domains);
            }
        }
        return domList;
    }
    
    List<String> listRoles(String domainName) {
        
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return con.listRoles(domainName);
        }
    }
    
    Membership getMembership(String domainName, String roleName, String principal) {
        
        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            Membership membership = con.getRoleMember(domainName, roleName, principal);
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

    Role getRole(String domainName, String roleName, Boolean auditLog, Boolean expand) {

        try (ObjectStoreConnection con = store.getConnection(true, false)) {
            return getRole(con, domainName, roleName, auditLog, expand);
        }
    }
    
    Role getRole(ObjectStoreConnection con, String domainName, String roleName,
            Boolean auditLog, Boolean expand) {

        Role role = con.getRole(domainName, roleName);
        if (role != null) {
            
            if (role.getTrust() == null) {
                
                // if we have no trust field specified then we need to
                // retrieve our standard group role members
                
                role.setRoleMembers(con.listRoleMembers(domainName, roleName));
                
                // still populate the members for old clients

                role.setMembers(ZMSUtils.convertRoleMembersToMembers(
                        role.getRoleMembers()));

                if (auditLog == Boolean.TRUE) {
                    role.setAuditLog(con.listRoleAuditLogs(domainName, roleName));
                }
                
            } else if (expand == Boolean.TRUE) {

                // otherwise, if asked, let's expand the delegated
                // membership and return the list of members
                
                role.setRoleMembers(getDelegatedRoleMembers(domainName, role.getTrust(), roleName));
                
                // still populate the members for old clients

                role.setMembers(ZMSUtils.convertRoleMembersToMembers(role.getRoleMembers()));
            }
        }
        return role;
    }
    
    List<RoleMember> getDelegatedRoleMembers(String domainName, String trustDomain, String roleName) {
        
        // verify that the domain and trust domain are not the same
        
        if (domainName.equals(trustDomain)) {
            return null;
        }
        
        // retrieve our trust domain
        
        AthenzDomain domain = null;
        try {
            domain = getAthenzDomain(trustDomain, false);
        } catch (ResourceException ignored) {
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
                
                if (!ZMSUtils.assumeRoleResourceMatch(fullRoleName, assertion)) {
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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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

                // first verify that auditing requirements are met

                Domain domain = checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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
                        .setYpmId(domain.getYpmId())
                        .setCertDnsDomain(domain.getCertDnsDomain());

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

                return;

            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
        }
    }

    void updateDomainMetaFields(Domain domain, DomainMeta meta) {

        domain.setApplicationId(meta.getApplicationId());
        domain.setDescription(meta.getDescription());
        domain.setOrg(meta.getOrg());
    }

    boolean isDeleteSystemMetaAllowed(boolean deleteAllowed, Object oldValue, Object newValue) {

        // if authorized or old value is not set, then there is
        // no need to check any value

        if (deleteAllowed || oldValue == null) {
            return true;
        }

        // since our old value is not null then we will only
        // allow if the new value is identical

        return (newValue != null) ? oldValue.equals(newValue) : false;
    }

    void updateSystemMetaFields(Domain domain, final String attribute, boolean deleteAllowed,
            DomainMeta meta) {

        final String caller = "putdomainsystemmeta";

        // system attributes we'll only set if they're available
        // in the given object

        switch (attribute) {
            case ZMSConsts.SYSTEM_META_ACCOUNT:
                if (!isDeleteSystemMetaAllowed(deleteAllowed, domain.getAccount(), meta.getAccount())) {
                    throw ZMSUtils.forbiddenError("unuathorized to reset system meta attribute: " + attribute, caller);
                }
                domain.setAccount(meta.getAccount());
                break;
            case ZMSConsts.SYSTEM_META_PRODUCT_ID:
                if (!isDeleteSystemMetaAllowed(deleteAllowed, domain.getYpmId(), meta.getYpmId())) {
                    throw ZMSUtils.forbiddenError("unuathorized to reset system meta attribute: " + attribute, caller);
                }
                domain.setYpmId(meta.getYpmId());
                break;
            case ZMSConsts.SYSTEM_META_CERT_DNS_DOMAIN:
                if (!isDeleteSystemMetaAllowed(deleteAllowed, domain.getCertDnsDomain(), meta.getCertDnsDomain())) {
                    throw ZMSUtils.forbiddenError("unuathorized to reset system meta attribute: " + attribute, caller);
                }
                domain.setCertDnsDomain(meta.getCertDnsDomain());
                break;
            case ZMSConsts.SYSTEM_META_AUDIT_ENABLED:
                domain.setAuditEnabled(meta.getAuditEnabled());
                break;
            case ZMSConsts.SYSTEM_META_ENABLED:
                domain.setEnabled(meta.getEnabled());
                break;
            default:
                throw ZMSUtils.requestError("unknown system meta attribute: " + attribute, caller);
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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

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

                checkDomainAuditEnabled(con, domainName, auditRef, caller, getPrincipalName(ctx));

                // go through our list of templates and add the specified
                // roles and polices to our domain

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"templates\": ");

                Template template = ZMSImpl.serverSolutionTemplates.get(templateName);
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
        
        Template template = ZMSImpl.serverSolutionTemplates.get(templateName);
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
                
                Role originalRole = getRole(con, domainName, roleName, false, false);

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
                        serviceIdentityName);
                
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
                .setTrust(role.getTrust());
        
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

                checkDomainAuditEnabled(con, tenantDomain, auditRef, caller, provSvcDomain + "." + provSvcName);

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

                checkDomainAuditEnabled(con, provSvcDomain, auditRef, caller, getPrincipalName(ctx));

                String trustedRolePrefix = ZMSUtils.getTrustedResourceGroupRolePrefix(provSvcDomain,
                        provSvcName, tenantDomain, resourceGroup);

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{\"put-tenant-roles\": [");
                boolean firstEntry = true;

                for (TenantRoleAction ra : roles) {

                    String tenantRole = ra.getRole();
                    String tenantAction = ra.getAction();
                    String trustedRole = trustedRolePrefix + tenantRole;
                    String trustedName = trustedRole.substring((provSvcDomain + ":role.").length());

                    Role role = new Role().setName(trustedRole).setTrust(tenantDomain);

                    if (LOG.isInfoEnabled()) {
                        LOG.info(caller + ": add trusted Role to domain " + provSvcDomain +
                                ": " + trustedRole + " -> " + role);
                    }

                    // retrieve our original role in case one exists

                    Role originalRole = getRole(con, provSvcDomain, trustedName, false, false);

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
        
        Role originalRole = getRole(con, tenantDomain, roleName, false, false);

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

                checkDomainAuditEnabled(con, tenantDomain, auditRef, caller, getPrincipalName(ctx));

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

                checkDomainAuditEnabled(con, tenantDomain, auditRef, caller, getPrincipalName(ctx));

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

                checkDomainAuditEnabled(con, provSvcDomain, auditRef, caller, getPrincipalName(ctx));

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
                    rolePrefix + ", reosurce-group=" + resourceGroup + ", tenant-domain=" + tenantDomain);
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
    
    AthenzDomain getAthenzDomain(String domainName, boolean masterCopy) {
        
        // first check to see if we our data is in the cache
        
        AthenzDomain athenzDomain = getAthenzDomainFromCache(domainName, masterCopy);
        if (athenzDomain != null) {
            return athenzDomain;
        }
        
        try (ObjectStoreConnection con = store.getConnection(true, masterCopy)) {
            athenzDomain = con.getAthenzDomain(domainName);
            setMembersInDomain(athenzDomain);
        }

        DataCache dataCache = new DataCache(athenzDomain,
                athenzDomain.getDomain().getModified().millis());
        cacheStore.put(domainName, dataCache);
        
        return athenzDomain;
    }
    
    private void setMembersInDomain(AthenzDomain athenzDomain) {
        List<Role> roleList = athenzDomain.getRoles();
        if (roleList != null) {
            for (Role role: roleList) {
                List<RoleMember> roleMembers = role.getRoleMembers();
                if (roleMembers != null) {
                    List<String> members = role.getMembers();
                    if (members  == null) {
                        members = new ArrayList<>();
                        role.setMembers(members);
                    }
                    for (RoleMember roleMember: roleMembers) {
                        members.add(roleMember.getMemberName());
                    }
                }
            }
        }
    }
    
    DomainModifiedList listModifiedDomains(long modifiedSince) {
        
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
            String entry = value.getMemberName();
            if (value.getExpiration() != null) {
                entry = entry + ":" + value.getExpiration().toString();
            }
            firstEntry = auditLogString(auditDetails, entry, firstEntry);
        }
        auditDetails.append(']');
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
}
