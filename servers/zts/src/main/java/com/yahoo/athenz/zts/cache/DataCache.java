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
package com.yahoo.athenz.zts.cache;

import java.util.*;

import com.yahoo.athenz.zts.ZTSConsts;
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
    private final Map<String, Set<MemberRole>> memberPrefixRoleCache;
    private final Set<MemberRole> memberAllRoleCache;
    private final Map<String, Set<String>> trustCache;
    private final Map<String, Set<String>> hostCache;
    private final Map<String, Set<String>> awsRoleCache;
    private final Map<String, String> publicKeyCache;
    private final Map<String, List<String>> providerDnsSuffixCache;

    public static final String ACTION_ASSUME_ROLE = "assume_role";
    private static final String ACTION_ASSUME_AWS_ROLE = "assume_aws_role";
    private static final String ACTION_LAUNCH = "launch";
    private static final String RESOURCE_DNS_PREFIX = "sys.auth:dns.";

    private static final Logger LOGGER = LoggerFactory.getLogger(DataCache.class);
    
    public DataCache() {
        memberRoleCache = new HashMap<>();
        memberPrefixRoleCache = new HashMap<>();
        memberAllRoleCache = new HashSet<>();
        trustCache = new HashMap<>();
        hostCache = new HashMap<>();
        awsRoleCache = new HashMap<>();
        publicKeyCache = new HashMap<>();
        providerDnsSuffixCache = new HashMap<>();
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
            
            // we're going to process 3 types of members
            // * - all members have access to these roles
            // <prefix>* - members with the key name prefix
            // <member> - regular members
            
            final String memberName = member.getMemberName();
            if (memberName.equals("*")) {
                memberAllRoleCache.add(new MemberRole(roleName, expiration));
            } else if (memberName.endsWith("*")) {
                final String keyName = memberName.substring(0, memberName.length() - 1);
                if (!memberPrefixRoleCache.containsKey(keyName)) {
                    memberPrefixRoleCache.put(keyName, new HashSet<>());
                }
                final Set<MemberRole> rolesForMember = memberPrefixRoleCache.get(keyName);
                rolesForMember.add(new MemberRole(roleName, expiration));
            } else {
                if (!memberRoleCache.containsKey(memberName)) {
                    memberRoleCache.put(memberName, new HashSet<>());
                }
                final Set<MemberRole> rolesForMember = memberRoleCache.get(memberName);
                rolesForMember.add(new MemberRole(roleName, expiration));
            }
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
            LOGGER.debug("Processing role: {}", role.getName());
        }
        
        /* first process members */
        
        processRoleMembers(role.getName(), role.getRoleMembers());
        
        /* now process trust domains */
        
        processRoleTrustDomain(role.getName(), role.getTrust());
    }

    void processProviderDNSSuffixAssertion(Assertion assertion, Map<String, Role> roles) {

        // make sure we're processing dns suffix assertion

        final String resource = assertion.getResource();
        if (!resource.startsWith(RESOURCE_DNS_PREFIX)) {
            return;
        }

        Role role = roles.get(assertion.getRole());
        if (role == null || role.getRoleMembers() == null) {
            return;
        }

        final String dnsSuffix = resource.substring(RESOURCE_DNS_PREFIX.length());
        for (RoleMember roleMember : role.getRoleMembers()) {

            final String memberName = roleMember.getMemberName();
            if (!providerDnsSuffixCache.containsKey(memberName)) {
                providerDnsSuffixCache.put(memberName, new ArrayList<>());
            }
            final List<String> dnsSuffixesForProvider = providerDnsSuffixCache.get(memberName);
            dnsSuffixesForProvider.add(dnsSuffix);
        }
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
            LOGGER.debug("Processing AWS Assume Role for resource: {} and role: {}",
                    assertion.getResource(), assertion.getRole());
        }

        final String role = assertion.getRole();
        if (!awsRoleCache.containsKey(role)) {
            awsRoleCache.put(role, new HashSet<>());
        }
        
        final Set<String> resourcesForRole = awsRoleCache.get(role);
        resourcesForRole.add(assertion.getResource());
    }

    void processLaunchAssertion(final String domainName, Assertion assertion, Map<String, Role> roles) {

        // for now we're only processing launch assertion if the
        // domain happens to be the sys.auth domain

        if (!domainName.equals(ZTSConsts.ATHENZ_SYS_DOMAIN)) {
            return;
        }

        processProviderDNSSuffixAssertion(assertion, roles);
    }

    public void processPolicy(String domainName, Policy policy, Map<String, Role> roles) {
        
        final String policyName = policy.getName();
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing policy: {}", policyName);
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
                case ACTION_LAUNCH:
                    processLaunchAssertion(domainName, assertion, roles);
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
        return service + "_" + keyId;
    }
    
    void processServiceIdentityPublicKey(String serviceName, String keyId, String publicKey) {
        
        if (publicKey == null) {
            return;
        }
        
        String keyValue = null;
        try {
            keyValue = Crypto.ybase64DecodeString(publicKey);
        } catch (CryptoException ex) {
            LOGGER.error("Invalid public key for {} with id {} with value '{}': {}",
                    serviceName, keyId, publicKey, ex.getMessage());
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
            LOGGER.debug("Processing service identity: {}", service.getName());
        }
        
        // first process the hosts for the service

        processServiceIdentityHosts(service.getName(), service.getHosts());

        // now process the public keys

        processServiceIdentityPublicKeys(service.getName(), service.getPublicKeys());
    }
    
    /**
     * Return roles belonging to a member
     * @param member whose roles we want
     * @return the list of roles
     */
    public Set<MemberRole> getMemberRoleSet(final String member) {
        return memberRoleCache.get(member);
    }

    /**
     * Returns dns suffix list authorized for a provider
     * @param provider name of the provider for the lookup
     * @return the list of dns suffixes
     */
    public List<String> getProviderDnsSuffixList(final String provider) {
        return providerDnsSuffixCache.get(provider);
    }

    /**
     * Return roles configured for all access
     * @return the list of roles
     */
    public Set<MemberRole> getAllMemberRoleSet() {
        return memberAllRoleCache;
    }
    
    /**
     * Return roles configured for wildcard access
     * @return the list of roles
     */
    public Map<String, Set<MemberRole>> getPrefixMemberRoleSetMap() {
        return memberPrefixRoleCache;
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
