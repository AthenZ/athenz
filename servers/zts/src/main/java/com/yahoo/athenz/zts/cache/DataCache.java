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
package com.yahoo.athenz.zts.cache;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.zms.Assertion;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Policy;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.RoleMember;

public class DataCache {

    DomainData domainData = null;

    // member ==> [ role1, role2, ...] complete map
    private final Map<String, Set<MemberRole>> memberRoleCache;
    private final Map<String, Set<String>> trustCache;
    private final Map<String, Set<String>> hostCache;
    private final Map<String, Set<String>> awsRoleCache;
    private final Map<String, String> publicKeyCache;

    public static final String ACTION_ASSUME_ROLE = "assume_role";
    private static final String ACTION_ASSUME_AWS_ROLE = "assume_aws_role";
    
    private static final Logger LOGGER = LoggerFactory.getLogger(DataCache.class);
    
    public DataCache() {
        memberRoleCache = new HashMap<>();
        trustCache = new HashMap<>();
        hostCache = new HashMap<>();
        awsRoleCache = new HashMap<>();
        publicKeyCache = new HashMap<>();
    }
    
    public void setDomainData(DomainData domainData) {
        this.domainData = domainData;
    }
    
    public DomainData getDomainData() {
        return domainData;
    }
    
    /**
     * Update {@code memberRoleCache}
     * @param roleName the new/updated role
     * @param members the list of members of that role
     */
    void processRoleMembers(String roleName, List<RoleMember> members) {
        
        // early out
        
        if (members == null) {
            return;
        }
        
        // memberRoleCache: add members

        long currentTime = System.currentTimeMillis();
        for (RoleMember member : members) {
            
            // if the role member is already expired then there
            // is no point to add it to the cache
            
            long expiration = member.getExpiration() == null ? 0 : member.getExpiration().millis();
            if (expiration != 0 && expiration < currentTime) {
                continue;
            }
            
            final String memberName = member.getMemberName();
            if (!memberRoleCache.containsKey(memberName)) {
                memberRoleCache.put(memberName, new HashSet<>());
            }
            final Set<MemberRole> rolesForMember = memberRoleCache.get(memberName);
            rolesForMember.add(new MemberRole(roleName, expiration));
        }
    }

    void processRoleTrustDomain(String roleName, String trustDomain) {

        if (trustDomain == null) {
            return;
        }
        
        if (!trustCache.containsKey(trustDomain)) {
            trustCache.put(trustDomain, new HashSet<>());
        }
        
        final Set<String> rolesForTrustDomain = trustCache.get(trustDomain);
        rolesForTrustDomain.add(roleName);
    }
    
    public void processRole(Role role) {
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing role: " + role.getName());
        }
        
        /* first process members */
        
        processRoleMembers(role.getName(), role.getRoleMembers());
        
        /* now process trust domains */
        
        processRoleTrustDomain(role.getName(), role.getTrust());
    }
    
    void processAssumeRoleAssertion(Assertion assertion, Map<String, Role> roles) {
        
        final String roleName = assertion.getRole();
        Role role = roles.get(roleName);
        if (role == null) {
            return;
        }
        
        /* add the resource as a role name for all the members */
        
        processRoleMembers(assertion.getResource(), role.getRoleMembers());
    }
    
    void processAWSAssumeRoleAssertion(Assertion assertion) {
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing AWS Assume Role for resource: " + assertion.getResource() +
                    " and role: " + assertion.getRole());
        }

        String role = assertion.getRole();
        if (!awsRoleCache.containsKey(role)) {
            awsRoleCache.put(assertion.getRole(), new HashSet<>());
        }
        
        final Set<String> resourcesForRole = awsRoleCache.get(role);
        resourcesForRole.add(assertion.getResource());
    }
    
    public void processPolicy(String domainName, Policy policy, Map<String, Role> roles) {
        
        String policyName = policy.getName();
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing policy: " + policyName);
        }
        
        List<Assertion> assertions = policy.getAssertions();
        if (assertions == null || assertions.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Policy: {} does not have any assertions, skipping." , policyName);
            }
            return;
        }
        
        for (Assertion assertion : assertions) {
            
            /* we are only interested in assume_role and 
             * assume_aws_role assertions */
            
            switch (assertion.getAction()) {
                case ACTION_ASSUME_AWS_ROLE:
                    processAWSAssumeRoleAssertion(assertion);
                    break;
                case ACTION_ASSUME_ROLE:
                    processAssumeRoleAssertion(assertion, roles);
                    break;
            }
        }
    }

    void processServiceIdentityHosts(String serviceName, List<String> hosts) {

        if (hosts == null || hosts.isEmpty()) {
            return;
        }

        for (String host : hosts) {
            if (!hostCache.containsKey(host)) {
                hostCache.put(host, new HashSet<>());
            }
            
            final Set<String> hostsForService = hostCache.get(host);
            hostsForService.add(serviceName);
        }
    }
    
    String generateServiceKeyName(String service, String keyId) {
        StringBuilder str = new StringBuilder(256);
        str.append(service);
        str.append("_");
        str.append(keyId);
        return str.toString();
    }
    
    void processServiceIdentityPublicKey(String serviceName, String keyId, String publicKey) {
        
        if (publicKey == null) {
            return;
        }
        
        String keyValue = null;
        try {
            keyValue = Crypto.ybase64DecodeString(publicKey);
        } catch (CryptoException ex) {
            LOGGER.error("Invalid public key for " + serviceName + " with id " + keyId
                    + " with value '" + publicKey + "':" + ex.getMessage());
        }
        
        if (keyValue != null) {
            publicKeyCache.put(generateServiceKeyName(serviceName, keyId), keyValue);
        }
    }
    
    void processServiceIdentityPublicKeys(String serviceName, List<PublicKeyEntry> publicKeys) {
        
        if (publicKeys == null || publicKeys.isEmpty()) {
            return;
        }
        
        for (PublicKeyEntry publicKey : publicKeys) {
            processServiceIdentityPublicKey(serviceName, publicKey.getId(),
                publicKey.getKey());
        }
    }
    
    public void processServiceIdentity(com.yahoo.athenz.zms.ServiceIdentity service) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing service identity: " + service.getName());
        }
        
        /* first process the hosts for the service */

        processServiceIdentityHosts(service.getName(), service.getHosts());

        /* now process the public keys */

        processServiceIdentityPublicKeys(service.getName(), service.getPublicKeys());
    }
    
    /**
     * Return roles belonging to a member
     * @param member whose roles we want
     * @return the list of roles
     */
    public Set<MemberRole> getMemberRoleSet(String member) {
        return memberRoleCache.get(member);
    }
    
    /**
     * Return the number of members in the cache
     */
    public int getMemberCount() {
        return memberRoleCache.size();
    }
    
    public Set<String> getAWSResourceRoleSet(String role) {
        return awsRoleCache.get(role);
    }
    
    public Map<String, Set<String>> getTrustMap() {
        return trustCache;
    }
    
    public Map<String, Set<String>> getHostMap() {
        return hostCache;
    }
    
    public Map<String, String> getPublicKeyMap() {
        return publicKeyCache;
    }
}
