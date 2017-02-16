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
package com.yahoo.athenz.zms;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

public class DBService {
    
    ObjectStore store;
    String userDomain;
    AuditLogger auditLogger;
    Cache<String, DataCache> cacheStore;
    int retrySleepTime = 250;
    int defaultRetryCount = 120;
    
    private static final Logger LOG = LoggerFactory.getLogger(DBService.class);

    private static final String ROLE_PREFIX = "role.";
    private static final String POLICY_PREFIX = "policy.";
    private static final String TEMPLATE_DOMAIN_NAME = "_domain_";
    
    public DBService(ObjectStore store, AuditLogger auditLogger, String userDomain) {
        
        this.store = store;
        this.userDomain = userDomain;
        this.auditLogger = auditLogger;
        cacheStore = CacheBuilder.newBuilder().concurrencyLevel(25).build();

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
    }

    private static class DataCache {
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
    
    AthenzDomain getAthenzDomainFromCache(String domainName) {
        
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
        try (ObjectStoreConnection con = store.getConnection(true)) {
            modTime = con.getDomainModTimestamp(domainName);
        }
        
        if (modTime == data.getModTime()) {
            return data.getAthenzDomain();
        }
        
        cacheStore.invalidate(domainName);
        return null;
    }
    
    String getPrincipalName(ResourceContext ctx) {
        if (ctx == null) {
            return null;
        }
        Principal principal = ((ZMSImpl.RsrcCtxWrapper) ctx).principal();
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
        
        AuditLogMsgBuilder msgBldr = ZMSImpl.getAuditLogMsgBuilder(ctx, domainName, auditRef,
                caller, operation);
        msgBldr.when(Timestamp.fromCurrentTime()).whatEntity(entityName);
        if (auditDetails != null) {
            msgBldr.whatDetails(auditDetails);
        }
        auditLogger.log(msgBldr);
    }
    
    Domain makeDomain(ResourceContext ctx, String domainName, String description, String org,
            Boolean auditEnabled, List<String> adminUsers, String account, int productId,
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
                .setModified(Timestamp.fromCurrentTime());
        
        // get our connection object
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                boolean objectsInserted = con.insertDomain(domain);
                if (!objectsInserted) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError("makeDomain: Cannot create domain: " +
                            domainName + " - already exists", caller);
                }
                
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{domain: ");
                auditLogDomain(auditDetails, domain);
                
                // first create and process the admin role
                
                Role adminRole = ZMSUtils.makeAdminRole(domainName, adminUsers);
                auditDetails.append(", role: ");
                if (!processRole(con, null, domainName, ZMSConsts.ADMIN_ROLE_NAME, adminRole,
                        getPrincipalName(ctx), auditRef, false, auditDetails)) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("makeDomain: Cannot process role: '" +
                            adminRole.getName(), caller);
                }
                
                // now create and process the admin policy
                
                Policy adminPolicy = ZMSUtils.makeAdminPolicy(domainName, adminRole);
                auditDetails.append(", policy: ");
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
                        auditDetails.append(", template: ");
                        Template template = ZMSImpl.serverSolutionTemplates.get(templateName);
                        if (!applySolutionTemplate(con, domainName, templateName, template, true,
                                getPrincipalName(ctx), auditRef, auditDetails)) {
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
            retryCount -= 1;
        } while (retryCount > 0);
        
        return null;
    }
    
    boolean processPolicy(ObjectStoreConnection con, Policy originalPolicy, String domainName,
            String policyName, Policy policy, boolean ignoreDeletes, StringBuilder auditDetails) {

        // check to see if we need to insert the policy or update it
        
        boolean requestSuccess = false;
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
        
        auditDetails.append("{name: \"").append(policyName).append('\"');

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
            
            Assertion checkAssertion = (Assertion) itr.next();
            
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
        
        List<Assertion> matchedAssertions = new ArrayList<Assertion>();
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
        
        boolean requestSuccess = false;
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
        
        auditDetails.append("{name: \"").append(roleName)
            .append("\", trust: \"").append(role.getTrust()).append('\"');
        
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
    
    boolean processServiceIdentity(ObjectStoreConnection con, ServiceIdentity originalService, String domainName,
            String serviceName, ServiceIdentity service, StringBuilder auditDetails) {
        
        boolean requestSuccess = false;
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
        
        auditDetails.append("{name: \"").append(serviceName).append('\"')
            .append(", executable: \"").append(service.getExecutable()).append('\"')
            .append(", user: \"").append(service.getUser()).append('\"')
            .append(", group: \"").append(service.getGroup()).append('\"')
            .append(", providerEndpoint: \"").append(service.getProviderEndpoint()).append('\"');
         
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
            
            for (String publicKey : delPublicKeysSet) {
                if (!con.deletePublicKeyEntry(domainName, serviceName, publicKey)) {
                    return false;
                }
            }
            auditLogPublicKeyEntries(auditDetails, "deleted-publickeys", delPublicKeysSet);
            
            for (String publicKey : newPublicKeysSet) {
                if (!con.insertPublicKeyEntry(domainName, serviceName, publicKeysMap.get(publicKey))) {
                    return false;
                }
            }
            auditLogPublicKeyEntries(auditDetails, "added-publickeys", newPublicKeysSet, publicKeysMap);
        }
        
        // now we need to process the hosts defined for this service
        
        Set<String> curHosts = null;
        if (originalService != null && originalService.getHosts() != null) {
            curHosts = new HashSet<>(originalService.getHosts());
        } else {
            curHosts = new HashSet<>();
        }

        Set<String> newHosts = null;
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

                // this error indicates that the server is reporting is in
                // read-only mode which indicates a fail-over has taken place
                // and we need to clear all connections and start new ones
                
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
            
            try {
                Thread.sleep(retrySleepTime);
            } catch (InterruptedException exc) {
            }
        }
        
        // return our response
        
        return retry;
    }
    
    void executePutPolicy(ResourceContext ctx, String domainName, String policyName, Policy policy,
            String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);

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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executePutRole(ResourceContext ctx, String domainName, String roleName, Role role,
            String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);

                // retrieve our original role
                
                Role originalRole = getRole(con, domainName, roleName, false, false);

                // now process the request
                
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                if (!processRole(con, originalRole, domainName, roleName, role,
                        getPrincipalName(ctx), auditRef, false, auditDetails)) {
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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executePutServiceIdentity(ResourceContext ctx, String domainName, String serviceName,
            ServiceIdentity service, String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);

                // retrieve our original service identity object
                
                ServiceIdentity originalService = getServiceIdentity(con, domainName, serviceName);

                // now process the request
                
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                if (!processServiceIdentity(con, originalService, domainName, serviceName, service, auditDetails)) {
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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executePutPublicKeyEntry(ResourceContext ctx, String domainName, String serviceName,
            PublicKeyEntry keyEntry, String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);

                // check to see if this key already exists or not
                
                PublicKeyEntry originalKeyEntry = con.getPublicKeyEntry(domainName, serviceName, keyEntry.getId());
                
                // now process the request
                
                boolean requestSuccess = false;
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);

                if (originalKeyEntry == null) {
                    requestSuccess = con.insertPublicKeyEntry(domainName, serviceName, keyEntry);
                    auditDetails.append("{added-publicKeys: [");
                } else {
                    requestSuccess = con.updatePublicKeyEntry(domainName, serviceName, keyEntry);
                    auditDetails.append("{updated-publicKeys: [");
                }
                
                if (!requestSuccess) {
                    con.rollbackChanges();
                    throw ZMSUtils.internalServerError("unable to put public key: " + keyEntry.getId() +
                            " in service " + ZMSUtils.serviceResourceName(domainName, serviceName), caller);
                }
                
                // update our domain time-stamp and save changes
                
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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executeDeletePublicKeyEntry(ResourceContext ctx, String domainName, String serviceName,
            String keyId, String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);

                // verify that we don't want to delete the last public key
                
                List<PublicKeyEntry> publicKeys = con.listPublicKeys(domainName, serviceName);
                if (publicKeys.size() == 1 && publicKeys.get(0).getId().equals(keyId)) {
                    throw ZMSUtils.requestError("cannot remove last public key from service", caller);
                }
                
                // now process the request
                
                if (!con.deletePublicKeyEntry(domainName, serviceName, keyId)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError("unable to delete public key: " + keyId +
                            " in service " + ZMSUtils.serviceResourceName(domainName, serviceName), caller);
                }
                
                // update our domain time-stamp and save changes
                
                saveChanges(con, domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{deleted-publicKeys: [{id: \"").append(keyId).append("\"}]}");
                
                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        serviceName, auditDetails.toString());
                
                return;
                
            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    boolean isTrustRole(Role role) {
        
        if (role == null) {
            return false;
        }
        
        if (role.getTrust() == null || role.getTrust().isEmpty()) {
            return false;
        }
        
        return true;
    }
    
    void executePutMembership(ResourceContext ctx, String domainName, String roleName,
            RoleMember roleMember, String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(true)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);

                // before inserting a member we need to verify that
                // this is a group role and not a delegated one.
                
                if (isTrustRole(con.getRole(domainName, roleName))) {
                    con.rollbackChanges();
                    throw ZMSUtils.requestError(caller + ": " + roleName +
                            "is a delegated role", caller);
                }
                
                // process our insert role member support. since this is a "single"
                // operation, we are not using any transactions.
                
                if (!con.insertRoleMember(domainName, roleName, roleMember,
                        getPrincipalName(ctx), auditRef)) {
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
                auditDetails.append("{member: \"").append(roleMember.getMemberName()).append("\"}");
                
                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_PUT,
                        roleName, auditDetails.toString());
                
                return;
                
            } catch (ResourceException ex) {
                
                // otherwise check if we need to retry or return failure
                
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executePutEntity(ResourceContext ctx, String domainName, String entityName,
            Entity entity, String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);

                // check to see if this key already exists or not
                
                Entity originalEntity = con.getEntity(domainName, entityName);
                
                // now process the request
                
                boolean requestSuccess = false;
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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executeDeleteMembership(ResourceContext ctx, String domainName, String roleName,
            String normalizedMember, String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(true)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);

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
                        getPrincipalName(ctx), auditRef)) {
                    con.rollbackChanges();
                    throw ZMSUtils.notFoundError(caller + ": unable to delete role member: " +
                            normalizedMember + " from role: " + roleName, caller);
                }

                // update our role and domain time-stamps, and invalidate local cache entry
                
                con.updateRoleModTimestamp(domainName, roleName);
                con.updateDomainModTimestamp(domainName);
                cacheStore.invalidate(domainName);

                // audit log the request

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{member: \"").append(normalizedMember).append("\"}");

                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        roleName, auditDetails.toString());
                
                return;
                
            } catch (ResourceException ex) {
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executeDeleteServiceIdentity(ResourceContext ctx, String domainName, String serviceName,
            String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);
                
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
            retryCount -= 1;
        } while (retryCount > 0);
    }

    void executeDeleteEntity(ResourceContext ctx, String domainName, String entityName,
            String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);

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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executeDeleteRole(ResourceContext ctx, String domainName, String roleName,
            String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);

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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executeDeletePolicy(ResourceContext ctx, String domainName, String policyName,
            String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);

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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    /**
     * If the domain has audit enabled, and user did not provide the auditRef,
     * an exception will be thrown. This is the first check before any write
     * operation is carried out so we don't really have anything to roll-back
     **/
    Domain checkDomainAuditEnabled(ObjectStoreConnection con, String domainName, String auditRef, String caller) {

        Domain domain = con.getDomain(domainName);
        if (domain == null) {
            con.rollbackChanges();
            throw ZMSUtils.notFoundError(caller + ": Unknown domain: " + domainName, caller);
        }

        if (domain.getAuditEnabled() && (auditRef == null || auditRef.length() == 0)) {
            con.rollbackChanges();
            throw ZMSUtils.requestError(caller + ": Audit reference required for domain: " + domainName, caller);
        }
        
        return domain;
    }
    
    Domain executeDeleteDomain(ResourceContext ctx, String domainName, String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                Domain domain = checkDomainAuditEnabled(con, domainName, auditRef, caller);

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
            retryCount -= 1;
        } while (retryCount > 0);
        
        return null;
    }
    
    ServiceIdentity getServiceIdentity(String domainName, String serviceName) {

        try (ObjectStoreConnection con = store.getConnection(true)) {
            return getServiceIdentity(con, domainName, serviceName);
        }
    }
    
    DomainTemplateList listDomainTemplates(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true)) {
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
    
    PublicKeyEntry getServicePublicKeyEntry(String domainName, String serviceName, String keyId) {

        try (ObjectStoreConnection con = store.getConnection(true)) {
            return con.getPublicKeyEntry(domainName, serviceName, keyId);
        }
    }
    
    public ResourceAccessList getResourceAccessList(String principal, String action) {
        try (ObjectStoreConnection con = store.getConnection(true)) {
            return con.listResourceAccess(principal, action, userDomain);
        }
    }
    
    Domain getDomain(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true)) {
            return con.getDomain(domainName);
        }
    }
    
    List<String> listDomains(String prefix, long modifiedSince) {
        
        try (ObjectStoreConnection con = store.getConnection(true)) {
            return con.listDomains(prefix, modifiedSince);
        }
    }

    DomainList lookupDomainById(String account, int productId) {
        
        DomainList domList = new DomainList();
        try (ObjectStoreConnection con = store.getConnection(true)) {
            String domain = con.lookupDomainById(account, productId);
            if (domain != null) {
                List<String> list = Arrays.asList(domain);
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
        try (ObjectStoreConnection con = store.getConnection(true)) {
            List<String> domains = con.lookupDomainByRole(roleMember, roleName);
            if (domains != null) {
                domList.setNames(domains);
            }
        }
        return domList;
    }
    
    List<String> listRoles(String domainName) {
        
        try (ObjectStoreConnection con = store.getConnection(true)) {
            return con.listRoles(domainName);
        }
    }
    
    Membership getMembership(String domainName, String roleName, String principal) {
        
        try (ObjectStoreConnection con = store.getConnection(true)) {
            Membership membership = con.getRoleMember(domainName, roleName, principal);
            Timestamp expiration = membership.getExpiration();

            //need to check expiration and set isMember if expired

            if (expiration != null && expiration.millis() < System.currentTimeMillis()) {
                membership.setIsMember(false);
            }
            
            return membership;
        }
    }
    
    Role getRole(String domainName, String roleName, Boolean auditLog, Boolean expand) {

        try (ObjectStoreConnection con = store.getConnection(true)) {
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

                if (auditLog != null && auditLog.booleanValue()) {
                    role.setAuditLog(con.listRoleAuditLogs(domainName, roleName));
                }
                
            } else if (expand != null && expand.booleanValue()) {

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
            domain = getAthenzDomain(trustDomain);
        } catch (ResourceException ex) {
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

        return new ArrayList<RoleMember>(roleMembers.values());
    }
    
    Policy getPolicy(String domainName, String policyName) {

        try (ObjectStoreConnection con = store.getConnection(true)) {
            return getPolicy(con, domainName, policyName);
        }
    }
    
    Assertion getAssertion(String domainName, String policyName, Long assertionId) {

        try (ObjectStoreConnection con = store.getConnection(true)) {
            return con.getAssertion(domainName, policyName, assertionId);
        }
    }
    
    public void executePutAssertion(ResourceContext ctx, String domainName, String policyName,
            Assertion assertion, String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(true)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);
                
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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    public void executeDeleteAssertion(ResourceContext ctx, String domainName, String policyName,
            Long assertionId, String auditRef, String caller) {

        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(true)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);
                
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

                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("assertionId=(").append(assertionId).append(')');
                
                auditLogRequest(ctx, domainName, auditRef, caller, ZMSConsts.HTTP_DELETE,
                        policyName, auditDetails.toString());
                
                return;
                
            } catch (ResourceException ex) {
                
                // otherwise check if we need to retry or return failure
                
                if (!shouldRetryOperation(ex, retryCount)) {
                    throw ex;
                }
            }
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    List<String> listEntities(String domainName) {
        
        try (ObjectStoreConnection con = store.getConnection(true)) {
            return con.listEntities(domainName);
        }
    }
    
    Entity getEntity(String domainName, String entityName) {

        try (ObjectStoreConnection con = store.getConnection(true)) {
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

        try (ObjectStoreConnection con = store.getConnection(true)) {
            return con.listPolicies(domainName, null);
        }
    }
    
    List<String> listServiceIdentities(String domainName) {

        try (ObjectStoreConnection con = store.getConnection(true)) {
            return con.listServiceIdentities(domainName);
        }
    }
    
    void executePutDomainMeta(ResourceContext ctx, String domainName, DomainMeta meta,
            String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        Domain domain = null;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                domain = checkDomainAuditEnabled(con, domainName, auditRef, caller);
                
                // now process the request
                
                Domain updatedDomain = new Domain()
                        .setName(domain.getName())
                        .setEnabled(domain.getEnabled())
                        .setId(domain.getId())
                        .setAuditEnabled(meta.getAuditEnabled())
                        .setDescription(meta.getDescription())
                        .setOrg(meta.getOrg());
                
                // we'll only update aws/product ids if the meta
                // object does not contain nulls
                
                if (meta.getAccount() == null && meta.getYpmId() == null) {
                    updatedDomain.setAccount(domain.getAccount());
                    updatedDomain.setYpmId(domain.getYpmId());
                } else {
                    updatedDomain.setYpmId(meta.getYpmId());
                    updatedDomain.setAccount(meta.getAccount());
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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executePutDomainTemplate(ResourceContext ctx, String domainName, List<String> templateNames,
            String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);
                
                // go through our list of templates and add the specified
                // roles and polices to our domain
                
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{add-templates: ");
                boolean firstEntry = true;
                
                for (String templateName : templateNames) {
                    Template template = ZMSImpl.serverSolutionTemplates.get(templateName);
                    firstEntry = auditLogSeparator(auditDetails, firstEntry);
                    if (!applySolutionTemplate(con, domainName, templateName, template, true,
                            getPrincipalName(ctx), auditRef, auditDetails)) {
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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executeDeleteDomainTemplate(ResourceContext ctx, String domainName, String templateName,
            String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, domainName, auditRef, caller);
                
                // go through our list of templates and add the specified
                // roles and polices to our domain
                
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{templates: ");
                
                Template template = ZMSImpl.serverSolutionTemplates.get(templateName);
                if (!applySolutionTemplate(con, domainName, templateName, template, false,
                        getPrincipalName(ctx), auditRef, auditDetails)) {
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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    boolean applySolutionTemplate(ObjectStoreConnection con, String domainName, String templateName,
            Template template, boolean addTemplate, String admin, String auditRef, StringBuilder auditDetails) {
        
        auditDetails.append("{name: \"").append(templateName).append('\"');
        
        // we have already verified that our template is valid but
        // we'll just double check to make sure it's not null
        
        if (template == null) {
            auditDetails.append("}");
            return true;
        }
        
        boolean firstEntry = true;
        
        // iterate through roles in the list.
        // When adding a template, if the role does not exist in our domain
        // then insert it otherwise only apply the changes to the member list.
        // otherwise for delete request, we just the delete role
        
        List<Role> templateRoles = template.getRoles();
        if (templateRoles != null) {
            for (Role role : templateRoles) {
                String roleName = ZMSUtils.removeDomainPrefix(role.getName(),
                    TEMPLATE_DOMAIN_NAME, ROLE_PREFIX);

                if (!addTemplate) {
                    con.deleteRole(domainName, roleName);
                    firstEntry = auditLogSeparator(auditDetails, firstEntry);
                    auditDetails.append(" delete-role: \"").append(roleName).append('\"');
                    continue;
                }

                // retrieve our original role
                
                Role originalRole = getRole(con, domainName, roleName, false, false);

                // now process the request
                
                Role templateRole = updateTemplateRole(role, domainName, roleName);
                firstEntry = auditLogSeparator(auditDetails, firstEntry);
                auditDetails.append(" add-role: ");
                if (!processRole(con, originalRole, domainName, roleName, templateRole,
                        admin, auditRef, true, auditDetails)) {
                    return false;
                }
            }
        }
        
        // iterate through policies in the list.
        // When adding a template, if the policy does not exist in our domain
        // then insert it otherwise only apply the changes to the assertions
        // otherwise for delete requests, we just delete the policy

        List<Policy> templatePolicies = template.getPolicies();
        if (templatePolicies != null) {
            for (Policy policy : templatePolicies) {
                String policyName = ZMSUtils.removeDomainPrefix(policy.getName(),
                    TEMPLATE_DOMAIN_NAME, POLICY_PREFIX);

                if (!addTemplate) {
                    con.deletePolicy(domainName, policyName);
                    firstEntry = auditLogSeparator(auditDetails, firstEntry);
                    auditDetails.append(" delete-policy: \"").append(policyName).append('\"');
                    continue;
                }
                
                // retrieve our original policy
                
                Policy originalPolicy = getPolicy(con, domainName, policyName);
                
                // now process the request
                
                Policy templatePolicy = updateTemplatePolicy(policy, domainName, policyName);
                firstEntry = auditLogSeparator(auditDetails, firstEntry);
                auditDetails.append(" add-policy: ");
                if (!processPolicy(con, originalPolicy, domainName, policyName, templatePolicy,
                        true, auditDetails)) {
                    return false;
                }
            }
        }
        
        // if deleting a template, delete it from the current list
        // if adding a template, only add if it is not in our current list
        
        if (!addTemplate) {
            con.deleteDomainTemplate(domainName, templateName, null);
        } else {
            // check to see if the template is already listed for the domain
            
            List<String> currentTemplateList = con.listDomainTemplates(domainName);
            if (!currentTemplateList.contains(templateName)) {
                con.insertDomainTemplate(domainName, templateName, null);
            }
        }
        
        auditDetails.append("}");
        return true;
    }
    
    Role updateTemplateRole(Role role, String domainName, String roleName) {
        
        Role templateRole = new Role()
                .setName(ZMSUtils.roleResourceName(domainName, roleName))
                .setTrust(role.getTrust());
        List<RoleMember> roleMembers = role.getRoleMembers();
        List<RoleMember> newMembers = new ArrayList<>();
        if (roleMembers != null && !roleMembers.isEmpty()) {
            newMembers.addAll(roleMembers);
        }
        templateRole.setRoleMembers(newMembers);
        return templateRole;
    }
    
    Policy updateTemplatePolicy(Policy policy, String domainName, String policyName) {
        
        Policy templatePolicy = new Policy().setName(ZMSUtils.policyResourceName(domainName, policyName));
        List<Assertion> assertions = policy.getAssertions();
        List<Assertion> newAssertions = new ArrayList<>();
        if (assertions != null && !assertions.isEmpty()) {
            for (Assertion assertion : assertions) {
                Assertion newAssertion = new Assertion();
                newAssertion.setAction(assertion.getAction());
                newAssertion.setEffect(assertion.getEffect());
                newAssertion.setResource(assertion.getResource().replace(TEMPLATE_DOMAIN_NAME, domainName));
                newAssertion.setRole(assertion.getRole().replace(TEMPLATE_DOMAIN_NAME, domainName));
                newAssertions.add(newAssertion);
            }
        }
        templatePolicy.setAssertions(newAssertions);
        return templatePolicy;
    }
    
    void setupTenantAdminPolicy(ResourceContext ctx, String tenantDomain, String provSvcDomain,
            String provSvcName, String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {
                
                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, tenantDomain, auditRef, caller);
                
                String domainAdminRole = ZMSUtils.roleResourceName(tenantDomain, ZMSConsts.ADMIN_ROLE_NAME);
                String serviceRoleResourceName = ZMSUtils.getTrustedResourceGroupRolePrefix(provSvcDomain,
                        provSvcName, tenantDomain, null) + ZMSConsts.ADMIN_ROLE_NAME;

                // our tenant admin role/policy name
                
                StringBuilder tenancyResourceBuilder = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                tenancyResourceBuilder.append("tenancy.").append(provSvcDomain).append('.').append(provSvcName);
                String tenancyResource = tenancyResourceBuilder.toString();
                
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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executePutTenantRoles(ResourceContext ctx, String provSvcDomain, String provSvcName, String tenantDomain,
            String resourceGroup, List<TenantRoleAction> roles, String auditRef, String caller) {
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {

                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, provSvcDomain, auditRef, caller);
                
                String trustedRolePrefix = ZMSUtils.getTrustedResourceGroupRolePrefix(provSvcDomain,
                        provSvcName, tenantDomain, resourceGroup);
                
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{put-tenant-roles: [");
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
                    
                    Role originalRole = getRole(con, provSvcDomain, trustedRole, false, false);

                    // now process the request
                    
                    firstEntry = auditLogSeparator(auditDetails, firstEntry);

                    auditDetails.append("{role: ");
                    if (!processRole(con, originalRole, provSvcDomain, trustedName, role,
                            getPrincipalName(ctx), auditRef, false, auditDetails)) {
                        con.rollbackChanges();
                        throw ZMSUtils.internalServerError("unable to put role: " + trustedRole, caller);
                    }
                    
                    String policyResourceName = ZMSUtils.policyResourceName(provSvcDomain, trustedName);
                    StringBuilder resourceName = new StringBuilder(256);
                    resourceName.append(provSvcDomain).append(":service.")
                        .append(ZMSUtils.getTenantResourceGroupRolePrefix(provSvcName, tenantDomain, resourceGroup))
                        .append('*');
                    List<Assertion> assertions = Arrays.asList(
                        new Assertion().setRole(trustedRole)
                            .setResource(resourceName.toString())
                            .setAction(tenantAction));
                    
                    Policy policy = new Policy().setName(policyResourceName).setAssertions(assertions);
                    
                    if (LOG.isInfoEnabled()) {
                        LOG.info(caller + ": add trust policy to domain " + provSvcDomain +
                                ": " + trustedRole + " -> " + policy);
                    }
                    
                    // retrieve our original policy
                    
                    Policy originalPolicy = getPolicy(con, provSvcDomain, policyResourceName);

                    // now process the request
                    
                    auditDetails.append(", policy: ");
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
            retryCount -= 1;
        } while (retryCount > 0);
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
        auditDetails.append("{role: ");
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
        newAssertions.add(assertion);
        if (originalPolicy != null && originalPolicy.getAssertions() != null) {
            newAssertions.addAll(originalPolicy.getAssertions());
        }
        
        // now process the request
        
        Policy assumeRolePolicy = new Policy().setName(policyResourceName).setAssertions(newAssertions);

        auditDetails.append(", policy: ");
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
            
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {

                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, tenantDomain, auditRef, caller);
                
                // we're going to create a separate role for each one of tenant roles returned
                // based on its action and set the caller as a member in each role
                
                String principalName = getPrincipalName(ctx);
                List<RoleMember> roleMembers = new ArrayList<>();
                if (principalName != null) {
                    RoleMember roleMember = new RoleMember();
                    roleMember.setMemberName(principalName);
                    roleMembers.add(roleMember);
                }
                
                // now set up the roles and policies for all the provider roles returned.
                
                String rolePrefix = ZMSUtils.getProviderResourceGroupRolePrefix(provSvcDomain,
                        provSvcName, resourceGroup);
                String trustedRolePrefix = ZMSUtils.getTrustedResourceGroupRolePrefix(provSvcDomain,
                        provSvcName, tenantDomain, resourceGroup);
                
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{put-provider-roles: [");
                boolean firstEntry = true;
                
                for (String role : roles) {
                    
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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    void executeDeleteTenancy(ResourceContext ctx, String tenantDomain, String provSvcDomain,
            String provSvcName, String resourceGroup, String auditRef, String caller) {
        
        // create list of policies and delete them from the tenant domain
        // have to get all policies that match "tenant.<provider>.*"
        // ex: tenancy.weather.storage.admin
        
        String rnamePrefix = ZMSUtils.getProviderResourceGroupRolePrefix(provSvcDomain, provSvcName,
                resourceGroup);
        
        StringBuilder pnamePrefixBuilder = new StringBuilder(256);
        pnamePrefixBuilder.append("tenancy.").append(rnamePrefix);
        String pnamePrefix = pnamePrefixBuilder.toString();
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {

                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, tenantDomain, auditRef, caller);
                
                // first let's process and remove any policies that start with our
                // provider prefix
                
                List<String> pnames = con.listPolicies(tenantDomain, null);
                for (String pname : pnames) {
                    if (!pname.startsWith(pnamePrefix)) {
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
                    if (!rname.startsWith(rnamePrefix)) {
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
            retryCount -= 1;
        } while (retryCount > 0);
    }

    void executeDeleteTenantRoles(ResourceContext ctx, String provSvcDomain, String provSvcName,
            String tenantDomain, String resourceGroup, String auditRef, String caller) {

        // look for this tenants roles, ex: storage.tenant.sports.reader
        
        String rolePrefix = ZMSUtils.getTenantResourceGroupRolePrefix(provSvcName, tenantDomain, resourceGroup);
        
        int retryCount = defaultRetryCount;
        do {
            try (ObjectStoreConnection con = store.getConnection(false)) {

                // first verify that auditing requirements are met
                
                checkDomainAuditEnabled(con, provSvcDomain, auditRef, caller);
                
                // find roles and policies matching the prefix
                
                List<String> rnames = con.listRoles(provSvcDomain);
                StringBuilder auditDetails = new StringBuilder(ZMSConsts.STRING_BLDR_SIZE_DEFAULT);
                auditDetails.append("{tenant-roles: [");
                boolean firstEntry = true;
                for (String rname: rnames) {
                    if (isTrustRoleForTenant(con, provSvcDomain, rname, rolePrefix, tenantDomain)) {

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
            retryCount -= 1;
        } while (retryCount > 0);
    }
    
    boolean isTrustRoleForTenant(ObjectStoreConnection con, String provSvcDomain, String roleName,
            String rolePrefix, String tenantDomain) {
        
        // first make sure the role name starts with the given prefix
        
        if (!isTenantRolePrefixMatch(con, roleName, rolePrefix, tenantDomain)) {
            return false;
        }
        
        Role role = con.getRole(provSvcDomain, roleName);
        if (role == null) {
            return false;
        }
        
        // ensure it is a trust role for the tenant
        
        String trustDom = role.getTrust();
        if (trustDom != null && trustDom.equals(tenantDomain)) {
            return true;
        }
        
        return false;
    }

    boolean isTrustRoleForTenant(String provSvcDomain, String roleName, String rolePrefix,
            String tenantDomain) {

        try (ObjectStoreConnection con = store.getConnection(true)) {
            return isTrustRoleForTenant(con, provSvcDomain, roleName, rolePrefix, tenantDomain);
        }
    }

    boolean isTenantRolePrefixMatch(String roleName, String rolePrefix, String tenantDomain) {

        try (ObjectStoreConnection con = store.getConnection(true)) {
            return isTenantRolePrefixMatch(con, roleName, rolePrefix, tenantDomain);
        }
    }
    
    boolean isTenantRolePrefixMatch(ObjectStoreConnection con, String roleName, String rolePrefix, String tenantDomain) {
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("isTenantRolePrefixMatch: role-name=" + roleName + ", role-prefix=" +
                    rolePrefix + ", tenant-domain=" + tenantDomain);
        }
        
        // first make sure the role name starts with the given prefix
        
        if (!roleName.startsWith(rolePrefix)) {
            return false;
        }
        
        // also make sure that the last part after the prefix
        // does not include other components which could
        // indicate support for subdomains and resource groups
        // this check is only done if we have no tenantDomain
        // specified since that indicates we're processing a resource
        // group operation
        
        if (tenantDomain == null) {
            if (roleName.indexOf('.', rolePrefix.length()) != -1) {
                return false;
            }
        } else {
            
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
                
                if (con.getDomain(subDomain) != null) {
                    return false;
                }
            } else if (comps.length > 2) {
                
                // if we have more than 2 subcomponents then we're
                // definitely not dealing with resource groups
                
                return false;
            }
        }
        
        return true;
    }
    
    AthenzDomain getAthenzDomain(String domainName) {
        
        // first check to see if we our data is in the cache
        
        AthenzDomain athenzDomain = getAthenzDomainFromCache(domainName);
        if (athenzDomain != null) {
            return athenzDomain;
        }
        
        try (ObjectStoreConnection con = store.getConnection(true)) {
            athenzDomain = con.getAthenzDomain(domainName);
            setMembersInDomain(athenzDomain);
        }
        
        if (athenzDomain != null) {
            DataCache dataCache = new DataCache(athenzDomain,
                    athenzDomain.getDomain().getModified().millis());
            cacheStore.put(domainName, dataCache);
        }
        
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
        
        try (ObjectStoreConnection con = store.getConnection(true)) {
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
        auditDetails.append(", ").append(label).append(": [");
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
        auditDetails.append(", ").append(label).append(": [");
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
        auditDetails.append(", ").append(label).append(": [");
        boolean firstEntry = true;
        for (PublicKeyEntry value : values) {
            firstEntry = auditLogPublicKeyEntry(auditDetails, value, firstEntry);
        }
        auditDetails.append(']');
    }
    
    void auditLogPublicKeyEntries(StringBuilder auditDetails, String label, Set<String> values,
            Map<String, PublicKeyEntry> publicKeysMap) {
        auditDetails.append(", ").append(label).append(": [");
        boolean firstEntry = true;
        for (String value : values) {
            firstEntry = auditLogPublicKeyEntry(auditDetails, publicKeysMap.get(value), firstEntry);
        }
        auditDetails.append(']');
    }
    
    void auditLogPublicKeyEntries(StringBuilder auditDetails, String label, Set<String> values) {
        auditDetails.append(", ").append(label).append(": [");
        boolean firstEntry = true;
        for (String value : values) {
            firstEntry = auditLogPublicKeyEntry(auditDetails, value, firstEntry);
        }
        auditDetails.append(']');
    }
    
    boolean auditLogPublicKeyEntry(StringBuilder auditDetails, PublicKeyEntry publicKey, boolean firstEntry) {
        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        auditDetails.append("{key: \"").append(publicKey.getKey())
            .append("\", id: \"").append(publicKey.getId()).append("\"}");
        return firstEntry;
    }
    
    boolean auditLogPublicKeyEntry(StringBuilder auditDetails, String publicKeyId, boolean firstEntry) {
        firstEntry = auditLogSeparator(auditDetails, firstEntry);
        auditDetails.append("{id: \"").append(publicKeyId).append("\"}");
        return firstEntry;
    }
    
    void auditLogAssertions(StringBuilder auditDetails, String label, Collection<Assertion> values) {
        auditDetails.append(", ").append(label).append(": [");
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
        auditDetails.append("{role: \"").append(assertion.getRole())
            .append("\", action: \"").append(assertion.getAction())
            .append("\", effect: \"").append(assertionEffect)
            .append("\", resource: \"").append(assertion.getResource())
            .append("\"}");
        return firstEntry;
    }
    
    void auditLogDomain(StringBuilder auditDetails, Domain domain) {
        auditDetails.append("{description: \"").append(domain.getDescription())
        .append("\", org: \"").append(domain.getOrg())
        .append("\", auditEnabled: \"").append(domain.getAuditEnabled())
        .append("\", enabled: \"").append(domain.getEnabled())
        .append("\"}");
    }
}
