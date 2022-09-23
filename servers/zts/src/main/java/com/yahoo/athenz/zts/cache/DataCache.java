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
package com.yahoo.athenz.zts.cache;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yahoo.athenz.auth.AuthorityConsts;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.common.config.AuthzDetailsEntity;
import com.yahoo.athenz.common.config.AuthzDetailsField;
import com.yahoo.athenz.common.server.util.AuthzHelper;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zts.transportrules.TransportRulesProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

import static com.yahoo.athenz.common.ServerCommonConsts.ATHENZ_SYS_DOMAIN;

public class DataCache {

    DomainData domainData = null;

    // member ==> [ role1, role2, ...] complete map
    private final Map<String, Set<MemberRole>> memberRoleCache;
    private final Map<String, Set<MemberRole>> memberPrefixRoleCache;
    private final Set<MemberRole> memberAllRoleCache;
    private final Map<String, Set<String>> trustCache;
    private final Map<String, Set<String>> hostCache;
    private final Map<String, RoleMeta> roleMetaCache;
    private final Map<String, Set<String>> awsRoleCache;
    private final Map<String, String> publicKeyCache;
    private final Map<String, List<String>> providerDnsSuffixCache;
    private final Map<String, List<String>> providerHostnameAllowedSuffixCache;
    private final Map<String, List<String>> providerHostnameDeniedSuffixCache;
    private final Map<String, List<AuthzDetailsEntity>> authzDetailsCache;
    private final Map<String, Map<String, List<String>>> transportRulesCache;
    private final Set<String> workloadStoreExcludeProvidersCache;

    public static final String ACTION_ASSUME_ROLE = "assume_role";
    public static final String ACTION_ASSUME_AWS_ROLE = "assume_aws_role";
    public static final String ACTION_LAUNCH = "launch";

    public static final String RESOURCE_DNS_PREFIX = "sys.auth:dns.";
    public static final String RESOURCE_HOSTNAME_PREFIX = "sys.auth:hostname.";
    public static final String ROLE_WORKLOAD_STORE_EXCLUDED_PROVIDER_NAME = "sys.auth:role.workload.store.excluded.providers";

    private static final Logger LOGGER = LoggerFactory.getLogger(DataCache.class);
    
    public DataCache() {
        memberRoleCache = new HashMap<>();
        memberPrefixRoleCache = new HashMap<>();
        memberAllRoleCache = new HashSet<>();
        trustCache = new HashMap<>();
        hostCache = new HashMap<>();
        awsRoleCache = new HashMap<>();
        roleMetaCache = new HashMap<>();
        publicKeyCache = new HashMap<>();
        providerDnsSuffixCache = new HashMap<>();
        providerHostnameAllowedSuffixCache = new HashMap<>();
        providerHostnameDeniedSuffixCache = new HashMap<>();
        authzDetailsCache = new HashMap<>();
        transportRulesCache = new HashMap<>();
        workloadStoreExcludeProvidersCache = new HashSet<>();
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
            
            // if the role member is disabled then we'll skip it

            if (AuthzHelper.isMemberDisabled(member.getSystemDisabled())) {
                continue;
            }

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

    void processRoleMeta(Role role) {

        RoleMeta rm = new RoleMeta()
                .setSignAlgorithm(role.getSignAlgorithm())
                .setCertExpiryMins(role.getCertExpiryMins())
                .setTokenExpiryMins(role.getTokenExpiryMins());

        // for the role meta cache we're going to create the map
        // based on the role name without the domain prefix

        String roleName = AthenzUtils.extractRoleName(role.getName());
        if (roleName == null) {
            return;
        }
        roleMetaCache.put(roleName, rm);
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

        // set group type for role members which we need
        // for authorization checks

        setRoleMemberGroupType(role.getRoleMembers());

        // first process members
        
        processRoleMembers(role.getName(), role.getRoleMembers());
        
        // now process trust domains
        
        processRoleTrustDomain(role.getName(), role.getTrust());

        // now process the role meta data

        processRoleMeta(role);
    }

    void setRoleMemberGroupType(List<RoleMember> roleMembers) {

        if (roleMembers == null || roleMembers.isEmpty()) {
            return;
        }

        for (RoleMember roleMember : roleMembers) {
            if (roleMember.getMemberName().contains(AuthorityConsts.GROUP_SEP)) {
                roleMember.setPrincipalType(Principal.Type.GROUP.getValue());
            }
        }
    }

    void processProviderSuffixAssertion(Assertion assertion, AssertionEffect effect, Map<String, Role> roles,
            final String resourceSuffix, Map<String, List<String>> providerSuffixCache) {

        // make sure we have satisfied the effect
        // if effect is null then it defaults to ALLOW

        AssertionEffect assertionEffect = assertion.getEffect() == null ? AssertionEffect.ALLOW : assertion.getEffect();
        if (effect != assertionEffect) {
            return;
        }

        // make sure we're processing dns suffix assertion

        final String resource = assertion.getResource();
        if (!resource.startsWith(resourceSuffix)) {
            return;
        }

        Role role = roles.get(assertion.getRole());
        if (role == null || role.getRoleMembers() == null) {
            return;
        }

        // our dns suffix is in the format sys.auth.dns.<dns-suffix>
        // when storing the value we want must check for sys.auth.dns.
        // but we want to keep the .<dns-suffix> part so later on
        // we don't check to make sure there is . in front of it.
        // so we're going to reduce the length by 1 to get the .

        final String suffix = resource.substring(resourceSuffix.length() - 1);
        for (RoleMember roleMember : role.getRoleMembers()) {

            final String memberName = roleMember.getMemberName();
            if (!providerSuffixCache.containsKey(memberName)) {
                providerSuffixCache.put(memberName, new ArrayList<>());
            }
            final List<String> suffixesForProvider = providerSuffixCache.get(memberName);
            suffixesForProvider.add(suffix);
        }
    }

    void processAssumeRoleAssertion(Assertion assertion, Map<String, Role> roles) {

        if (assertion.getEffect() == AssertionEffect.DENY) {
            return;
        }

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

        if (assertion.getEffect() == AssertionEffect.DENY) {
            return;
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

        if (!domainName.equals(ATHENZ_SYS_DOMAIN)) {
            return;
        }

        processProviderSuffixAssertion(assertion, AssertionEffect.ALLOW, roles,
                RESOURCE_DNS_PREFIX, providerDnsSuffixCache);
        processProviderSuffixAssertion(assertion, AssertionEffect.ALLOW, roles,
                RESOURCE_HOSTNAME_PREFIX, providerHostnameAllowedSuffixCache);
        processProviderSuffixAssertion(assertion, AssertionEffect.DENY, roles,
                RESOURCE_HOSTNAME_PREFIX, providerHostnameDeniedSuffixCache);
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
                default:
                    if (TransportRulesProcessor.isTransportRuleAction(assertion.getAction())) {
                        processTransportRulesAssertion(domainName, assertion, roles);
                    }
            }
        }
    }

    private void processTransportRulesAssertion(String domainName, Assertion assertion, Map<String, Role> roles) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing Transport rules for action={} resource={} and role={}",
                    assertion.getAction(), assertion.getResource(), assertion.getRole());
        }
        String mapKey = assertion.getResource().substring(domainName.length() + 1);
        transportRulesCache.computeIfAbsent(mapKey, k -> new HashMap<>());

        if (roles.containsKey(assertion.getRole()) && roles.get(assertion.getRole()) != null
                && roles.get(assertion.getRole()).getRoleMembers() != null) {
            List<String> serviceMembers = roles.get(assertion.getRole()).getRoleMembers()
                    .stream().map(RoleMember::getMemberName).collect(Collectors.toList());
            transportRulesCache.get(mapKey).put(assertion.getAction(), serviceMembers);
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

    public void processEntity(com.yahoo.athenz.zms.Entity entity, final String domainName) {

        final String entityName = entity.getName();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing entity: {}", entity.getName());
        }

        // at this time we're only support authorization_details entities
        // in ZTS server so we'll ignore any other

        if (!entityName.startsWith(ResourceUtils.entityResourceName(domainName, AuthzDetailsEntity.ENTITY_NAME_PREFIX))) {
            return;
        }

        // we're going to convert our entity into authz object

        AuthzDetailsEntity detailsEntity;
        try {
            detailsEntity = AuthzHelper.convertEntityToAuthzDetailsEntity(entity);
        } catch (JsonProcessingException ex) {
            LOGGER.error("Unable to process entity {}, error {}", entity, ex.getMessage());
            return;
        }

        // go through each role specified in the request add the
        // entity definition to the cache

        for (AuthzDetailsField role : detailsEntity.getRoles()) {

            final String roleName = role.getName();
            if (!authzDetailsCache.containsKey(roleName)) {
                authzDetailsCache.put(roleName, new ArrayList<>());
            }

            final List<AuthzDetailsEntity> entitiesForRole = authzDetailsCache.get(roleName);
            entitiesForRole.add(detailsEntity);
        }
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
     * Returns allowed hostname suffix list authorized for a provider
     * @param provider name of the provider for the lookup
     * @return the list of dns suffixes
     */
    public List<String> getProviderHostnameAllowedSuffixList(final String provider) {
        return providerHostnameAllowedSuffixCache.get(provider);
    }

    /**
     * Returns denied hostname suffix list authorized for a provider
     * @param provider name of the provider for the lookup
     * @return the list of dns suffixes
     */
    public List<String> getProviderHostnameDeniedSuffixList(final String provider) {
        return providerHostnameDeniedSuffixCache.get(provider);
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
     * @return member count
     */
    public int getMemberCount() {
        return memberRoleCache.size();
    }
    
    public Set<String> getAWSResourceRoleSet(String role) {
        return awsRoleCache.get(role);
    }

    public RoleMeta getRoleMeta(String role) {
        return roleMetaCache.get(role);
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

    public Map<String, List<String>> getProviderDnsSuffixCache() {
        return providerDnsSuffixCache;
    }

    public Map<String, List<String>> getProviderHostnameAllowedSuffixCache() {
        return providerHostnameAllowedSuffixCache;
    }

    public Map<String, List<String>> getProviderHostnameDeniedSuffixCache() {
        return providerHostnameDeniedSuffixCache;
    }

    public List<AuthzDetailsEntity> getAuthzDetailsEntities(final String role) {
        return authzDetailsCache.get(role);
    }

    public Map<String, List<String>> getTransportRulesInfoForService(final String service) {
        return transportRulesCache.get(service);
    }

    public boolean isWorkloadStoreExcludedProvider(final String provider) {
        return workloadStoreExcludeProvidersCache.contains(provider);
    }

    /**
     * This method populates relevant cache objects from system configurations via Athenz system domain
     * @param domainData domain object with updates
     */
    public void processSystemBehaviorRoles(DomainData domainData) {
        // only processing system domain
        if (!domainData.getName().equals(ATHENZ_SYS_DOMAIN)) {
            return;
        }
        // if we have a role by name workload.store.excluded.providers then its members will be stored in a set
        // and those providers' workloads will be excluded from workload store
        Set<String> currentExcludedProviders = domainData.getRoles().stream()
                .filter(r -> ROLE_WORKLOAD_STORE_EXCLUDED_PROVIDER_NAME.equals(r.getName()))
                .map(Role::getRoleMembers)
                .flatMap(List::stream)
                .map(RoleMember::getMemberName).collect(Collectors.toSet());
        // first add missing new entries
        if (!workloadStoreExcludeProvidersCache.containsAll(currentExcludedProviders)) {
            workloadStoreExcludeProvidersCache.addAll(currentExcludedProviders);
        }
        // now delete entries which were removed
        workloadStoreExcludeProvidersCache.retainAll(currentExcludedProviders);

    }
}
