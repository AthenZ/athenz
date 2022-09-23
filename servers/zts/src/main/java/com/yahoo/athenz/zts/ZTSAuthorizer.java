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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.StringUtils;
import com.yahoo.athenz.common.server.util.AuthzHelper;
import com.yahoo.athenz.zms.GroupMember;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ZTSAuthorizer implements Authorizer {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZTSAuthorizer.class);
    final protected DataStore dataStore;
    final protected ZTSGroupMembersFetcher groupMembersFetcher;
    
    // enum to represent our access response since in some cases we want to
    // handle domain not founds differently instead of just returning failure
    
    enum AccessStatus {
        ALLOWED,
        DENIED,
        DENIED_DOMAIN_NOT_FOUND,
        DENIED_INVALID_ROLE_TOKEN
    }
    
    public ZTSAuthorizer(final DataStore dataStore) {
        this.dataStore = dataStore;
        groupMembersFetcher = new ZTSGroupMembersFetcher(dataStore);
    }

    @Override
    public boolean access(String op, String resource, Principal principal, String trustDomain) {
        
        // for consistent handling of all requests, we're going to convert
        // all incoming object values into lower case (e.g. domain, role,
        // policy, service, etc name)
        
        resource = resource.toLowerCase();
        if (trustDomain != null) {
            trustDomain = trustDomain.toLowerCase();
        }
        op = op.toLowerCase();
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("access:({}, {}, {}, {})", op, resource, principal, trustDomain);
        }
        
        // check to see if the authority is allowed to be processed in
        // authorization checks. If this value is false then the principal
        // must get a usertoken from ZMS first and the submit the request
        // with that token
        
        if (!AuthzHelper.authorityAuthorizationAllowed(principal)) {
            LOGGER.error("Authority is not allowed to support authorization checks");
            return false;
        }
        
        // retrieve our domain based on resource and action/trustDomain pair
        // we want to provider better error reporting to the users so if we get a
        // request where the domain is not found instead of just returning 403
        // forbidden (which is confusing since it assumes the user doesn't have
        // access as oppose to possible mistype of the domain name by the user)
        // we want to return 404 not found. The rest_core has special handling
        // for rest.ResourceExceptions so we'll throw that exception in this
        // special case of not found domains.
        
        String domainName = AuthzHelper.retrieveResourceDomain(resource, op, trustDomain);
        if (domainName == null) {
            throw new ResourceException(ResourceException.NOT_FOUND,
                    new ResourceError().code(ResourceException.NOT_FOUND).message("Domain not found"));
        }
        DataCache domain = dataStore.getDataCache(domainName);
        if (domain == null) {
            throw new ResourceException(ResourceException.NOT_FOUND,
                    new ResourceError().code(ResourceException.NOT_FOUND).message("Domain not found"));
        }
        
        AccessStatus accessStatus = evaluateAccess(domain, principal.getFullName(), op, resource, trustDomain);
        return accessStatus == AccessStatus.ALLOWED;
    }
    
    AccessStatus evaluateAccess(DataCache domain, String identity, String op, String resource,
            String trustDomain) {
        
        AccessStatus accessStatus = AccessStatus.DENIED;

        List<com.yahoo.athenz.zms.Policy> policies = domain.getDomainData().getPolicies().getContents().getPolicies();
        List<Role> roles = domain.getDomainData().getRoles();
        
        for (com.yahoo.athenz.zms.Policy policy : policies) {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("evaluateAccess: processing policy name/version/active: {}/{}/{}",
                        policy.getName(), policy.getVersion(), policy.getActive());
            }

            // ignore any inactive/multi-version policies

            if (policy.getActive() == Boolean.FALSE) {
                continue;
            }
            
            // we are going to process all the assertions defined in this
            // policy. As soon as we get a match for an assertion that
            // denies access, we're going to return that result. If we
            // get a match for an assertion that allows access we're
            // going to remember that result and continue looking at
            // all the assertions in case there is something else that
            // explicitly denies access
            
            List<com.yahoo.athenz.zms.Assertion> assertions = policy.getAssertions();
            if (assertions == null) {
                continue;
            }
            
            for (com.yahoo.athenz.zms.Assertion assertion : assertions) {
                
                // get the effect for the assertion which is set
                // as allowed by default

                com.yahoo.athenz.zms.AssertionEffect effect = assertion.getEffect();
                if (effect == null) {
                    effect = com.yahoo.athenz.zms.AssertionEffect.ALLOW;
                }

                // if we have already matched an allow assertion then
                // we'll automatically skip any assertion that has
                // allow effect since there is no point of matching it
                
                if (accessStatus == AccessStatus.ALLOWED && effect == com.yahoo.athenz.zms.AssertionEffect.ALLOW) {
                    continue;
                }
                
                // if no match then process the next assertion
                
                if (!assertionMatch(assertion, identity, op, resource, roles, trustDomain)) {
                    continue;
                }
                
                // if the assertion has matched and the effect is deny
                // then we're going to return right away otherwise we'll
                // set our return allow matched flag to true and continue
                // processing other assertions
                
                if (effect == com.yahoo.athenz.zms.AssertionEffect.DENY) {
                    return AccessStatus.DENIED;
                }
                
                accessStatus = AccessStatus.ALLOWED;
            }
        }
        
        return accessStatus;
    }
    
    boolean assertionMatch(com.yahoo.athenz.zms.Assertion assertion, String identity, String op,
            String resource, List<Role> roles, String trustDomain) {

        // Lowercase action and resource as it is possible to store them case-sensitive

        String opPattern = StringUtils.patternFromGlob(assertion.getAction().toLowerCase());
        if (!op.matches(opPattern)) {
            return false;
        }
        
        String rezPattern = StringUtils.patternFromGlob(assertion.getResource().toLowerCase());
        if (!resource.matches(rezPattern)) {
            return false;
        }
        
        String rolePattern = StringUtils.patternFromGlob(assertion.getRole());
        boolean matchResult = matchPrincipal(roles, rolePattern, identity, trustDomain);
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("assertionMatch: -> {} (effect: {})", matchResult, assertion.getEffect());
        }

        return matchResult;
    }
    
    boolean matchPrincipal(List<Role> roles, String rolePattern, String fullUser, String trustDomain) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("matchPrincipal: rolePattern: {} user: {} trust: {}", rolePattern, fullUser, trustDomain);
        }

        for (Role role : roles) {
            
            String name = role.getName();
            if (!name.matches(rolePattern)) {
                continue;
            }
            
            if (matchPrincipalInRole(role, name, fullUser, trustDomain)) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("matchPrincipal: assertionMatch: -> OK (by principal)");
                }
                return true;
            }
        }
        return false;
    }
    
    boolean matchPrincipalInRole(Role role, String roleName, String fullUser, String trustDomain) {
        
        // if we have members in the role then we're going to check
        // against that list only
        
        if (role.getRoleMembers() != null) {
            return AuthzHelper.isMemberOfRole(role, fullUser, groupMembersFetcher);
        }
        
        // no members so let's check if this is a trust domain
        
        String trust = role.getTrust();
        if (!AuthzHelper.shouldRunDelegatedTrustCheck(trust, trustDomain)) {
            return false;
        }

        // delegate to another domain.
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("matchPrincipalInRole: [delegated trust. Checking with: {}]", trust);
        }
        
        return delegatedTrust(trust, roleName, fullUser);
    }
    
    boolean delegatedTrust(String domainName, String roleName, String roleMember) {
        
        DataCache domain = dataStore.getDataCache(domainName);
        if (domain == null) {
            return false;
        }
        
        for (com.yahoo.athenz.zms.Policy policy : domain.getDomainData().getPolicies().getContents().getPolicies()) {

            // ignore any inactive/multi-version policies

            if (policy.getActive() == Boolean.FALSE) {
                continue;
            }

            if (AuthzHelper.matchDelegatedTrustPolicy(policy, roleName, roleMember,
                    domain.getDomainData().getRoles(), groupMembersFetcher)) {
                return true;
            }
        }
        
        return false;
    }

    static class ZTSGroupMembersFetcher implements AuthzHelper.GroupMembersFetcher {

        DataStore dataStore;
        ZTSGroupMembersFetcher(DataStore dataStore) {
            this.dataStore = dataStore;
        }

        @Override
        public List<GroupMember> getGroupMembers(String groupName) {
            return dataStore.getGroupMembers(groupName);
        }
    }
}
