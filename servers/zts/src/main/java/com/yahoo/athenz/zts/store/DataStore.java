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
package com.yahoo.athenz.zts.store;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yahoo.rdl.*;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.athenz.common.server.util.StringUtils;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import com.yahoo.athenz.zts.HostServices;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.cache.DataCacheProvider;
import com.yahoo.athenz.zts.cache.MemberRole;
import com.yahoo.athenz.zts.utils.ZTSUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DataStore implements DataCacheProvider {

    ChangeLogStore changeLogStore = null;
    private CloudStore cloudStore = null;
    private final Cache<String, DataCache> cacheStore;
    final Cache<String, PublicKey> zmsPublicKeyCache;
    final Map<String, List<String>> hostCache;
    final Map<String, String> publicKeyCache;
    
    long updDomainRefreshTime = 60;
    long delDomainRefreshTime = 3600;
    long lastDeleteRunTime = 0;

    private static ScheduledExecutorService scheduledThreadPool;
    
    private static final String ROLE_POSTFIX = ":role.";
    
    private final ReentrantReadWriteLock hostRWLock = new ReentrantReadWriteLock();
    private final Lock hostRLock = hostRWLock.readLock();
    private final Lock hostWLock = hostRWLock.writeLock();
    
    private final ReentrantReadWriteLock pkeyRWLock = new ReentrantReadWriteLock();
    private final Lock pkeyRLock = pkeyRWLock.readLock();
    private final Lock pkeyWLock = pkeyRWLock.writeLock();
    
    private static final String ZTS_PROP_DOMAIN_UPDATE_TIMEOUT = "athenz.zts.zms_domain_update_timeout";
    private static final String ZTS_PROP_DOMAIN_DELETE_TIMEOUT = "athenz.zts.zms_domain_delete_timeout";
    
    private static final Logger LOGGER = LoggerFactory.getLogger(DataStore.class);
    
    public DataStore(ChangeLogStore clogStore, CloudStore cloudStore) {

        /* save our store objects */

        this.changeLogStore = clogStore;
        this.setCloudStore(cloudStore);
        
        /* generate our cache stores */

        cacheStore = CacheBuilder.newBuilder().concurrencyLevel(25).build();
        zmsPublicKeyCache = CacheBuilder.newBuilder().concurrencyLevel(25).build();
        
        hostCache = new HashMap<>();
        publicKeyCache = new HashMap<>();

        /* our configured values are going to be in seconds so we need
         * to convert our input in seconds to milliseconds */
        
        updDomainRefreshTime = ZTSUtils.retrieveConfigSetting(ZTS_PROP_DOMAIN_UPDATE_TIMEOUT, 60);
        delDomainRefreshTime = ZTSUtils.retrieveConfigSetting(ZTS_PROP_DOMAIN_DELETE_TIMEOUT, 3600);
        
        /* we will not let our domain delete update time be shorter
         * than the domain update time so if tha't the case we'll
         * set both to be the same value */
        
        if (delDomainRefreshTime < updDomainRefreshTime) {
            delDomainRefreshTime = updDomainRefreshTime;
        }
        
        lastDeleteRunTime = System.currentTimeMillis();
        
        /* load the zms public key from configuration files */
        
        loadZMSPublicKeys();
    }
    
    String generateServiceKeyName(String domain, String service, String keyId) {
        StringBuilder str = new StringBuilder(256);
        str.append(domain);
        str.append(".");
        str.append(service);
        str.append("_");
        str.append(keyId);
        return str.toString();
    }
    
    void loadZMSPublicKeys() {
        
        String rootDir = System.getenv(ZTSConsts.STR_ENV_ROOT);
        if (rootDir == null) {
            rootDir = ZTSConsts.STR_DEF_ROOT;
        }
        
        String confFileName = System.getProperty(ZTSConsts.ZTS_PROP_ATHENZ_CONF,
                rootDir + "/conf/athenz/athenz.conf");
        Path path = Paths.get(confFileName);
        AthenzConfig conf = null;
        try {
            conf = JSON.fromBytes(Files.readAllBytes(path), AthenzConfig.class);
            ArrayList<com.yahoo.athenz.zms.PublicKeyEntry> publicKeys = conf.getZmsPublicKeys();
            if (publicKeys != null) {
                for (com.yahoo.athenz.zms.PublicKeyEntry publicKey : publicKeys) { 
                    String id = publicKey.getId();
                    String key = publicKey.getKey();
                    if (key == null || id == null) {
                        continue;
                    }
                    PublicKey zmsKey = Crypto.loadPublicKey(Crypto.ybase64DecodeString(key));
                    zmsPublicKeyCache.put(id, zmsKey);
                }
            }
        } catch (IOException e) {
            LOGGER.info("Unable to parse conf file " + confFileName);
            return;
        }
    }
    
    boolean processLocalDomains(List<String> localDomainList) {

        /* we can't have a lastModTime set if we have no local
         * domains - in this case we're going to reset */
        
        if (localDomainList.isEmpty()) {
            return false;
        }
        
        /* first we need to retrieve the list of domains from ZMS so we
         * know what domains have been deleted already (if any) */
        
        Set<String> zmsDomainList = changeLogStore.getServerDomainList();
        if (zmsDomainList == null) {
            return false;
        }
        
        for (String domainName : localDomainList) {
            
            /* make sure this domain is still active in ZMS otherwise
             * we'll just remove our local copy */

            if (!zmsDomainList.contains(domainName)) {
                
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Removing local domain: " + domainName + ". Domain not in ZMS anymore.");
                }
                
                deleteDomain(domainName);
                continue;
            }
            
            /* if we get a failure when processing a local domain then it
             * indicates that we had an invalid domain file (possibly
             * corrupted or hacked. In this case we're going to drop
             * everything and request a full refresh from ZMS only if the
             * change log store supports that functionality. Otherwise,
             * we're going to just skip the domain and continue. */

            if (!processLocalDomain(domainName) && changeLogStore.supportsFullRefresh()) {
                return false;
            }
        }
        
        return true;
    }
    
    public boolean init() {
        
        /* now let's retrieve the list of locally saved domains */

        List<String> localDomainList = changeLogStore.getLocalDomainList();

        /* if we are not able to successfully process our local domains
         * then we're going to ask our store to reset the changes
         * and give us the list of all domains from ZMS */

        if (!processLocalDomains(localDomainList)) {
            
            changeLogStore.setLastModificationTimestamp(null);
            
            /* if we have decided that we need to a full refresh
             * we need to clean up and remove any cached domains */

            for (String domainName : localDomainList) {
                deleteDomain(domainName);
            }
        }
        
        /* after our local files have been processed now we need to
         * retrieve the domains that were modified since the last
         * modification time */

        if (!processDomainUpdates()) {
            return false;
        }

        /* Start our monitoring thread to get changes from ZMS */

        scheduledThreadPool = Executors.newScheduledThreadPool(1);
        scheduledThreadPool.scheduleAtFixedRate(new DataUpdater(), updDomainRefreshTime,
                updDomainRefreshTime, TimeUnit.SECONDS);

        return true;
    }

    boolean processLocalDomain(String domainName) {

        boolean result = false;
        try {
            result = processDomain(changeLogStore.getSignedDomain(domainName), false);
        } catch (Exception ex) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Unable to process local domain " + domainName + ": " + ex.getMessage());
            }
        }
        
        if (!result) {
            LOGGER.error("Invalid local domain: " + domainName + ". Full refresh from ZMS required.");
        }
        
        return result;
    }
    
    boolean validateSignedDomain(SignedDomain signedDomain) {
        
        DomainData domainData = signedDomain.getDomain();
        String keyId = signedDomain.getKeyId();
        String signature = signedDomain.getSignature();
        
        PublicKey zmsKey = zmsPublicKeyCache.getIfPresent(keyId == null ? "0" : keyId);
        if (zmsKey == null) {
            
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("ZMS Public Key (id: " + keyId + ") not available");
            }
            
            return false;
        }

        boolean result = Crypto.verify(SignUtils.asCanonicalString(domainData), zmsKey, signature);
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Domain '" + domainData.getName() + "' signature validation: " + result);
        }
        
        return result;
    }
    
    void processDomainRoles(DomainData domainData, DataCache domainCache) {
        
        List<Role> roles = domainData.getRoles();
        if (roles == null) {
            return;
        }

        for (Role role : roles) {
            domainCache.processRole(role);
        }
    }
    
    void processDomainPolicies(DomainData domainData, DataCache domainCache) {
        
        com.yahoo.athenz.zms.SignedPolicies signedPolicies = domainData.getPolicies();
        if (signedPolicies == null) {
            return;
        }
        
        com.yahoo.athenz.zms.DomainPolicies domainPolicies = signedPolicies.getContents();
        if (domainPolicies == null) {
            return;
        }
        
        List<com.yahoo.athenz.zms.Policy> policies = domainPolicies.getPolicies();
        if (policies == null) {
            return;
        }
        
        List<Role> roles = domainData.getRoles();
        HashMap<String, Role> roleMap  = new HashMap<>();
        for (Role role : roles) {
            roleMap.put(role.getName(), role);
        }
        for (com.yahoo.athenz.zms.Policy policy : policies) {
            domainCache.processPolicy(domainData.getName(), policy, roleMap);
        }
    }
    
    void processDomainServiceIdentities(DomainData domainData, DataCache domainCache) {
        
        List<com.yahoo.athenz.zms.ServiceIdentity> services = domainData.getServices();
        if (services == null) {
            return;
        }
        
        for (com.yahoo.athenz.zms.ServiceIdentity service : services) {
            domainCache.processServiceIdentity(service);
        }
    }
    
    public boolean processDomain(SignedDomain signedDomain, boolean saveInStore) {

        DomainData domainData = signedDomain.getDomain();
        String domainName = domainData.getName();
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Processing domain: " + domainName);
        }
        
        /* before doing anything else let's validate our domain */
        
        if (!validateSignedDomain(signedDomain)) {
            return false;
        }

        /* generate our cache object */

        DataCache domainCache = new DataCache();
        
        /* process the roles for this domain */

        processDomainRoles(domainData, domainCache);

        /* process the policies for this domain */
        
        processDomainPolicies(domainData, domainCache);

        /* finally process the service identities */
        
        processDomainServiceIdentities(domainData, domainCache);
        
        /* save the full domain object with the cache entry itself
         * since we need to that information to handle
         * getServiceIdentity and getServiceIdentityList requests */

        domainCache.setDomainData(domainData);
        
        /* add the entry to the cache and struct store */
        
        addDomainToCache(domainName, domainCache);
        
        if (saveInStore) {
            changeLogStore.saveLocalDomain(domainName, signedDomain);
        }
        
        return true;
    }
    
    boolean validDomainListResponse(Set<String> zmsDomainList) {
        
        /* we're doing some basic validation to make sure our
         * retrieved zms domain list is correct. At minimum our
         * list must not be empty and include our sys.auth
         * domain */
        
        if (zmsDomainList.isEmpty()) {
            return false;
        }
        
        if (!zmsDomainList.contains(ZTSConsts.ATHENZ_SYS_DOMAIN)) {
            return false;
        }
        
        return true;
    }
    
    // API
    public boolean processDomainDeletes() {

        /* first let's retrieve the list domains loaded into
         * our local cache */

        ArrayList<String> localDomainList = new ArrayList<>(getCacheStore().asMap().keySet());
        if (localDomainList.isEmpty()) {
            return true;
        }
        
        /* now retrieve the list of domains from ZMS */
        
        Set<String> zmsDomainList = changeLogStore.getServerDomainList();
        if (zmsDomainList == null) {
            return false;
        }
        
        /* make sure we don't have an empty list response
         * from ZMS that would cause all of our domains
         * to be deleted */
        
        if (!validDomainListResponse(zmsDomainList)) {
            return false;
        }
        
        /* go through each local domain and if it doesn't
         * exist in the list returned from ZMS we're going to
         * delete that domain from our cache and change log store */
        
        for (String domainName : localDomainList) {
            
            if (!zmsDomainList.contains(domainName)) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Removing local domain: " + domainName + ". Domain not in ZMS anymore.");
                }
                deleteDomain(domainName);
            }
        }
        
        return true;
    }
    
    // Internal
    void deleteDomain(String domainName) {

        /* first delete our data from the cache */

        deleteDomainFromCache(domainName);

        /* then delete it from the struct store */

        changeLogStore.removeLocalDomain(domainName);
    }
    
    // Internal
    boolean processSignedDomains(SignedDomains signedDomains) {
        
        /* if we have received no data from ZMS server then we're not
         * going to update our last modification time and instead we'll
         * just continue using the old one until we get some updates
         * from ZMS Server */
        
        if (signedDomains == null) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No updates received from ZMS Server");
            }
            return true;
        }
        
        /* now process all of our domains */
        
        List<SignedDomain> domains = signedDomains.getDomains();
        if (domains == null || domains.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No updates received from ZMS Server");
            }
            return true;
        }
        
        for (SignedDomain domain : domains) {
            if (!processDomain(domain, true)) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Poll for new domains and updated domains from the ChangeLogStore (ZMS). 
     * Called by {@code DataUpdater.run()} thread. Deletes are handled separately in {@code processDomainDeletes()}
     * @return true if we have updates, false otherwise
     */
    public boolean processDomainUpdates() {

        StringBuilder lastModTimestamp = new StringBuilder(128);
        SignedDomains signedDomains = changeLogStore.getUpdatedSignedDomains(lastModTimestamp);
        
        /* if our data back was null and the last mod timestamp
         * is also empty then we had a failure */
        
        if (signedDomains == null && lastModTimestamp.length() == 0) {
            return false;
        }
        
        /* process all of our received updated domains */
        
        boolean result = processSignedDomains(signedDomains);
        if (result) {
            changeLogStore.setLastModificationTimestamp(lastModTimestamp.toString());
        }
        
        return result;
    }

    // API
    public DomainData getDomainData(String name) {
        
        DataCache data = getCacheStore().getIfPresent(name);
        if (data == null) {
            return null;
        }
        return data.getDomainData();
    }

    // Internal
    void addHostEntries(Map<String, Set<String>> hostMap) {

        if (hostMap == null || hostMap.isEmpty()) {
            return;
        }
        
        for (Map.Entry<String, Set<String>> entry : hostMap.entrySet()) {
            List<String> services = hostCache.get(entry.getKey());
            if (services == null) {
                services = new ArrayList<String>();
                hostCache.put(entry.getKey(), services);
            }
            services.addAll(entry.getValue());
        }
    }
    
    // Internal
    void removeHostEntries(Map<String, Set<String>> hostMap) {

        if (hostMap == null || hostMap.isEmpty()) {
            return;
        }
        
        for (Map.Entry<String, Set<String>> entry : hostMap.entrySet()) {
            List<String> services = hostCache.get(entry.getKey());
            if (services != null) {
                services.removeAll(entry.getValue());
            }
        }
    }
    
    // Internal
    void addPublicKeys(Map<String, String> publicKeyMap) {
        
        if (publicKeyMap == null || publicKeyMap.isEmpty()) {
            return;
        }
        
        for (Map.Entry<String, String> entry : publicKeyMap.entrySet()) {
            publicKeyCache.put(entry.getKey(), entry.getValue());
        }
    }
    
    // Internal
    void removePublicKeys(Map<String, String> publicKeyMap) {
        
        if (publicKeyMap == null || publicKeyMap.isEmpty()) {
            return;
        }
        
        for (Map.Entry<String, String> entry : publicKeyMap.entrySet()) {
            publicKeyCache.remove(entry.getKey());
        }
    }
    
    // Internal
    public void addDomainToCache(String name, DataCache dataCache) {
        
        /* before update the cache store with our updated data
         * we need to remove the old data host and public key sets */
        
        DataCache oldDataCache = getCacheStore().getIfPresent(name);
        
        try {
            hostWLock.lock();
            if (oldDataCache != null) {
                removeHostEntries(oldDataCache.getHostMap());
            }
            addHostEntries(dataCache.getHostMap());
        } finally {
            hostWLock.unlock();
        }
        
        try {
            pkeyWLock.lock();
            if (oldDataCache != null) {
                removePublicKeys(oldDataCache.getPublicKeyMap());
            }
            addPublicKeys(dataCache.getPublicKeyMap());
        } finally {
            pkeyWLock.unlock();
        }
        
        /* now let's see if we have a cloud account defined
         * and update accordingly */
        
        if (getCloudStore() != null) {
            getCloudStore().updateAccount(name, dataCache.getDomainData().getAccount());
        }
        
        /* update the cache for the given domain */
        
        getCacheStore().put(name, dataCache);
    }

    // Internal
    void deleteDomainFromCache(String name) {
        
        /* before we delete the domain from our cache, we need to
         * remove the old data host and public key sets */
        
        DataCache data = getCacheStore().getIfPresent(name);
        if (data == null) {
            return;
        }
        
        try {
            hostWLock.lock();
            removeHostEntries(data.getHostMap());
        } finally {
            hostWLock.unlock();
        }
        
        try {
            pkeyWLock.lock();
            removePublicKeys(data.getPublicKeyMap());
        } finally {
            pkeyWLock.unlock();
        }
        
        getCacheStore().invalidate(name);
    }
    
    // Internal
    String roleCheckValue(String role, String prefix) {
        
        if (role == null) {
            return null;
        }
        
        String roleCheck = null;
        if (!role.startsWith(prefix)) {
            roleCheck = prefix + role;
        } else {
            roleCheck = role;
        }
        
        return roleCheck;
    }
    
    // Internal
    void processStandardMembership(Set<MemberRole> memberRoles, String rolePrefix,
            String roleName, List<String> accessibleRoles, boolean keepFullName) {
        
        /* if we have no member roles, then we haven't added anything
         * to our return result list */

        if (memberRoles == null) {
            return;
        }
        
        long currentTime = System.currentTimeMillis();
        for (MemberRole memberRole : memberRoles) {
            
            // before adding to the list make sure the user
            // hasn't expired
            
            long expiration = memberRole.getExpiration();
            if (expiration != 0 && expiration < currentTime) {
                continue;
            }
            addRoleToList(memberRole.getRole(), rolePrefix, roleName,
                    accessibleRoles, keepFullName);
        }
    }
    
    // Internal
    void processTrustMembership(DataCache data, String identity, String rolePrefix,
            String roleName, List<String> accessibleRoles, boolean keepFullName) {
        
        Map<String, Set<String>> trustedRolesMap = data.getTrustMap();

        /* iterate through all trusted domains */

        for (Map.Entry<String, Set<String>> trustedRole : trustedRolesMap.entrySet()) {

            processTrustedDomain(getCacheStore().getIfPresent(trustedRole.getKey()),
                    identity, rolePrefix, roleName, trustedRole.getValue(),
                    accessibleRoles, keepFullName);
        }
    }
    
    // API
    @Override
    public DataCache getDataCache(String domainName) {
        return getCacheStore().getIfPresent(domainName);
    }
    
    // API
    public void getAccessibleRoles(DataCache data, String domainName, String identity,
            String roleName, List<String> accessibleRoles, boolean keepFullName) {

        /* if the domain hasn't been processed then we don't have anything to do */
        
        if (data == null) {
            return;
        }

        String rolePrefix = domainName + ROLE_POSTFIX;

        /* first look through the members to see if the given identity is
         * included in the list explicitly */

        processStandardMembership(data.getMemberRoleSet(identity),
                rolePrefix, roleName, accessibleRoles, keepFullName);
        
        /* now process all the roles that have trusted domain specified */

        processTrustMembership(data, identity, rolePrefix, roleName,
                accessibleRoles, keepFullName);
    }

    // Internal
    boolean checkRoleSet(String role, Set<String> checkSet) {
        
        if (checkSet == null) {
            return true;
        }
        
        return checkSet.contains(role);
    }

    // Internal
    void addRoleToList(String role, String rolePrefix, String roleName,
            List<String> accessibleRoles, boolean keepFullName) {

        /* any roles we return must start with the domain role prefix */

        if (!role.startsWith(rolePrefix)) {
            return;
        }

        /* and it must end with the suffix if specified */
        
        if (roleName != null && !role.endsWith(roleName)) {
            return;
        }

        /* when returning the value we're going to skip the prefix */

        if (keepFullName) {
            accessibleRoles.add(role);
        } else {
            accessibleRoles.add(role.substring(rolePrefix.length()));
        }
    }
    
    // Internal
    boolean roleMatchInSet(String role, Set<MemberRole> memberRoles) {
        
        /* since most of the roles will not have wildcards we're
         * going to carry out a simple contains check here and if
         * that's successful then we're done and we don't have to
         * do possibly more expensive regex checks */

        if (memberRoles.contains(role)) {
            return true;
        }
        
        /* no match so let's try the regex pattern check */
        
        String rolePattern = null;
        long currentTime = System.currentTimeMillis();
        for (MemberRole memberRole : memberRoles) {
            
            // before processing make sure the member hasn't
            // expired for this role
            
            long expiration = memberRole.getExpiration();
            if (expiration != 0 && expiration < currentTime) {
                continue;
            }
            rolePattern = StringUtils.patternFromGlob(memberRole.getRole());
            if (role.matches(rolePattern)) {
                return true;
            }
        }
        
        return false;
    }
    
    // Internal
    void processSingleTrustedDomainRole(String roleName, String rolePrefix, String roleSuffix,
            Set<MemberRole> memberRoles, List<String> accessibleRoles, boolean keepFullName) {
        
        /* since our member role set can include wildcard domains we
         * need to match the role as oppose to a direct check if the
         * set contains the name */

        if (!roleMatchInSet(roleName, memberRoles)) {
            return;
        }
        
        /* now check if the role is in the resource list as well */

        addRoleToList(roleName, rolePrefix, roleSuffix, accessibleRoles, keepFullName);
    }
    
    // Internal
    void processTrustedDomain(DataCache trustData, String identity, String rolePrefix,
            String roleSuffix, Set<String> trustedResources, List<String> accessibleRoles,
            boolean keepFullName) {

        /* verify that our data cache and list of trusted resources are valid */
        
        if (trustData == null || trustedResources == null) {
            return;
        }
        
        /* if we have no member roles, then return right away */

        Set<MemberRole> memberRoles = trustData.getMemberRoleSet(identity);
        if (memberRoles == null) {
            return;
        }
        
        for (String resource : trustedResources) {
            
            /* in this case our resource is the role name */
                
            processSingleTrustedDomainRole(resource, rolePrefix, roleSuffix,
                    memberRoles, accessibleRoles, keepFullName);
        }
    }
    
    // API
    public String getPublicKey(String domain, String service, String keyId) {

        String publicKeyName = generateServiceKeyName(domain, service, keyId);
        String publicKey = null;
        
        try {
            pkeyRLock.lock();
            publicKey = publicKeyCache.get(publicKeyName);
        } finally {
            pkeyRLock.unlock();
        }

        if (publicKey == null && LOGGER.isDebugEnabled()) {
            LOGGER.debug("Public key: " + publicKeyName + " not available");
        }
        
        return publicKey;
    }

    // API
    public HostServices getHostServices(String host) {
        
        HostServices result = new HostServices().setHost(host);
        
        try {
            hostRLock.lock();
            
            /* we need to make a copy of our list as oppose to just returning
             * a reference since once we release the host read lock that list
             * can be modified by the updater thread */
            
            List<String> services = hostCache.get(host);
            if (services != null) {
                result.setNames(new ArrayList<>(services));
            }
        } finally {
            hostRLock.unlock();
        }
        
        return result;
    }
    
    public CloudStore getCloudStore() {
        return cloudStore;
    }

    public void setCloudStore(CloudStore cloudStore) {
        this.cloudStore = cloudStore;
    }

    public Cache<String, DataCache> getCacheStore() {
        return cacheStore;
    }

    public Map<String, String> getPublicKeyCache() {
        return publicKeyCache;
    }
    
    class DataUpdater implements Runnable {
        
        @Override
        public void run() {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("DataUpdater: Starting data updater thread...");
            }
            
            try {
                processDomainUpdates();
                
                /* check to see if we need to handle our delete domain list - 
                 * make sure refresh time is converted to millis */
                
                if (System.currentTimeMillis() - lastDeleteRunTime > delDomainRefreshTime * 1000) {
                    
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("DataUpdater: Processing domain delete checks...");
                    }
                    
                    processDomainDeletes();
                    lastDeleteRunTime = System.currentTimeMillis();
                }
                
            } catch (Exception ex) {
                LOGGER.error("DataUpdater: unable to process domain changes: " + ex.getMessage());
            }
        }
    }
}
