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
package com.yahoo.athenz.zts.store;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yahoo.athenz.auth.util.StringUtils;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.util.ConfigProperties;
import com.yahoo.athenz.common.server.util.AuthzHelper;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.Group;
import com.yahoo.athenz.zms.GroupMember;
import com.yahoo.athenz.zms.Role;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import com.yahoo.athenz.zts.*;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.rdl.*;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.cache.DataCacheProvider;
import com.yahoo.athenz.zts.cache.MemberRole;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.yahoo.athenz.common.ServerCommonConsts.ATHENZ_SYS_DOMAIN;
import static com.yahoo.athenz.common.ServerCommonConsts.PROP_ATHENZ_CONF;

public class DataStore implements DataCacheProvider, RolesProvider {

    ChangeLogStore changeLogStore;
    private CloudStore cloudStore;
    private final Cache<String, DataCache> cacheStore;
    final Cache<String, PublicKey> zmsPublicKeyCache;
    final Cache<String, List<GroupMember>> groupMemberCache;
    final Cache<String, List<GroupMember>> principalGroupCache;
    final Map<String, List<String>> hostCache;
    final Map<String, String> publicKeyCache;
    final JWKList ztsJWKList;
    final JWKList ztsJWKListStrictRFC;

    long updDomainRefreshTime;
    long delDomainRefreshTime;
    long checkDomainRefreshTime;
    long lastDeleteRunTime;
    long lastCheckRunTime;

    private static final String ROLE_POSTFIX = ":role.";

    private final ReentrantReadWriteLock hostRWLock = new ReentrantReadWriteLock();
    private final Lock hostRLock = hostRWLock.readLock();
    private final Lock hostWLock = hostRWLock.writeLock();
    
    private final ReentrantReadWriteLock pkeyRWLock = new ReentrantReadWriteLock();
    private final Lock pkeyRLock = pkeyRWLock.readLock();
    private final Lock pkeyWLock = pkeyRWLock.writeLock();
    
    private static final String ZTS_PROP_DOMAIN_UPDATE_TIMEOUT = "athenz.zts.zms_domain_update_timeout";
    private static final String ZTS_PROP_DOMAIN_DELETE_TIMEOUT = "athenz.zts.zms_domain_delete_timeout";
    private static final String ZTS_PROP_DOMAIN_CHECK_TIMEOUT = "athenz.zts.zms_domain_check_timeout";

    private static final Logger LOGGER = LoggerFactory.getLogger(DataStore.class);
    
    public DataStore(ChangeLogStore clogStore, CloudStore cloudStore) {

        /* save our store objects */

        this.changeLogStore = clogStore;
        this.setCloudStore(cloudStore);
        
        /* generate our cache stores */

        cacheStore = CacheBuilder.newBuilder().concurrencyLevel(25).build();
        zmsPublicKeyCache = CacheBuilder.newBuilder().concurrencyLevel(25).build();

        groupMemberCache = CacheBuilder.newBuilder().concurrencyLevel(25).build();
        principalGroupCache = CacheBuilder.newBuilder().concurrencyLevel(25).build();

        ztsJWKList = new JWKList();
        ztsJWKListStrictRFC = new JWKList();

        hostCache = new HashMap<>();
        publicKeyCache = new HashMap<>();

        /* our configured values are going to be in seconds so we need
         * to convert our input in seconds to milliseconds */
        
        updDomainRefreshTime = ConfigProperties.retrieveConfigSetting(ZTS_PROP_DOMAIN_UPDATE_TIMEOUT, 60);
        delDomainRefreshTime = ConfigProperties.retrieveConfigSetting(ZTS_PROP_DOMAIN_DELETE_TIMEOUT, 3600);
        checkDomainRefreshTime = ConfigProperties.retrieveConfigSetting(ZTS_PROP_DOMAIN_CHECK_TIMEOUT, 600);

        /* we will not let our domain delete/check update time be shorter
         * than the domain update time so if that's the case we'll
         * set both to be the same value */
        
        if (delDomainRefreshTime < updDomainRefreshTime) {
            delDomainRefreshTime = updDomainRefreshTime;
        }

        if (checkDomainRefreshTime < updDomainRefreshTime) {
            checkDomainRefreshTime = updDomainRefreshTime;
        }

        lastDeleteRunTime = System.currentTimeMillis();
        lastCheckRunTime = System.currentTimeMillis();

        /* load the zms public key from configuration files */
        
        if (!loadAthenzPublicKeys()) {
            throw new IllegalArgumentException("Unable to initialize public keys");
        }
    }
    
    String generateServiceKeyName(String domain, String service, String keyId) {
        return domain + "." + service + "_" + keyId;
    }

    public JWKList getZtsJWKList(Boolean rfc) {
        return rfc == Boolean.TRUE ? ztsJWKListStrictRFC : ztsJWKList;
    }

    boolean loadAthenzPublicKeys() {

        final String rootDir = ZTSImpl.getRootDir();
        String confFileName = System.getProperty(PROP_ATHENZ_CONF,
                rootDir + "/conf/athenz/athenz.conf");
        Path path = Paths.get(confFileName);
        AthenzConfig conf;
        try {
            conf = JSON.fromBytes(Files.readAllBytes(path), AthenzConfig.class);
            final ArrayList<com.yahoo.athenz.zms.PublicKeyEntry> zmsPublicKeys = conf.getZmsPublicKeys();
            if (zmsPublicKeys == null) {
                LOGGER.error("Conf file {} has no ZMS Public keys", confFileName);
                return false;
            }
            for (com.yahoo.athenz.zms.PublicKeyEntry publicKey : zmsPublicKeys) {
                final String id = publicKey.getId();
                final String key = publicKey.getKey();
                if (key == null || id == null) {
                    LOGGER.error("Missing required zms public key attributes: {}/{}", id, key);
                    continue;
                }
                zmsPublicKeyCache.put(id, Crypto.loadPublicKey(Crypto.ybase64DecodeString(key)));
            }
            if (zmsPublicKeyCache.size() == 0) {
                LOGGER.error("No valid public ZMS keys in conf file: {}", confFileName);
                return false;
            }
            final ArrayList<com.yahoo.athenz.zms.PublicKeyEntry> ztsPublicKeys = conf.getZtsPublicKeys();
            if (ztsPublicKeys == null) {
                LOGGER.error("Conf file {} has no ZTS Public keys", confFileName);
                return false;
            }
            final List<JWK> jwkList = new ArrayList<>();
            final List<JWK> jwkListStrictRFC = new ArrayList<>();
            for (com.yahoo.athenz.zms.PublicKeyEntry publicKey : ztsPublicKeys) {
                final String id = publicKey.getId();
                final String key = publicKey.getKey();
                if (key == null || id == null) {
                    LOGGER.error("Missing required zts public key attributes: {}/{}", id, key);
                    continue;
                }
                final JWK jwk = getJWK(key, id, false);
                if (jwk != null) {
                    jwkList.add(jwk);
                }
                final JWK jwkRfc = getJWK(key, id, true);
                if (jwkRfc != null) {
                    jwkListStrictRFC.add(jwkRfc);
                }
            }
            if (jwkList.isEmpty() || jwkListStrictRFC.isEmpty()) {
                LOGGER.error("No valid public ZTS keys in conf file: {}", confFileName);
                return false;
            }
            ztsJWKList.setKeys(jwkList);
            ztsJWKListStrictRFC.setKeys(jwkListStrictRFC);
        } catch (IOException ex) {
            LOGGER.error("Unable to parse conf file {}, error: {}", confFileName, ex.getMessage());
            return false;
        }
        return true;
    }

    @SuppressWarnings("rawtypes")
    String getCurveName(org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec, boolean rfc) {

        String curveName = null;
        for (Enumeration names = ECNamedCurveTable.getNames(); names.hasMoreElements();) {

            final String name = (String) names.nextElement();
            final X9ECParameters params = ECNamedCurveTable.getByName(name);

            if (params.getN().equals(ecParameterSpec.getN())
                    && params.getH().equals(ecParameterSpec.getH())
                    && params.getCurve().equals(ecParameterSpec.getCurve())
                    && params.getG().equals(ecParameterSpec.getG())) {
                curveName = name;
                break;
            }
        }

        return rfc ? rfcEllipticCurveName(curveName) : curveName;
    }

    JWK getJWK(final String pemKey, final String keyId, boolean rfc) {

        PublicKey publicKey;

        try {
            publicKey = Crypto.loadPublicKey(Crypto.ybase64DecodeString(pemKey));
        } catch (Exception ex) {
            LOGGER.error("Invalid public key: {}", ex.getMessage());
            return null;
        }

        JWK jwk = null;
        final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

        switch (publicKey.getAlgorithm()) {
            case ZTSConsts.RSA:
                jwk = new JWK();
                jwk.setKid(keyId);
                jwk.setUse("sig");
                jwk.setKty("RSA");
                jwk.setAlg("RS256");
                final RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                jwk.setN(new String(encoder.encode(toIntegerBytes(rsaPublicKey.getModulus(), rfc))));
                jwk.setE(new String(encoder.encode(toIntegerBytes(rsaPublicKey.getPublicExponent(), rfc))));
                break;
            case ZTSConsts.ECDSA:
                jwk = new JWK();
                jwk.setKid(keyId);
                jwk.setUse("sig");
                jwk.setKty("EC");
                jwk.setAlg("ES256");
                final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
                final ECPoint ecPoint = ecPublicKey.getW();
                jwk.setX(new String(encoder.encode(toIntegerBytes(ecPoint.getAffineX(), rfc))));
                jwk.setY(new String(encoder.encode(toIntegerBytes(ecPoint.getAffineY(), rfc))));
                jwk.setCrv(getCurveName(EC5Util.convertSpec(ecPublicKey.getParams()), rfc));
                break;
        }

        return jwk;
    }

    /**
     * https://github.com/apache/commons-codec/blob/master/src/main/java/org/apache/commons/codec/binary/Base64.java
     * Licensed Under Apache 2.0 https://github.com/apache/commons-codec/blob/master/LICENSE.txt
     *
     * In apache.commons.code this is a private static function and the wrapper
     * does not generate base64 encoded data that is url safe which is required
     * per jwk spec. So we'll copy the function as is for our use.
     *
     * Returns a byte-array representation of a {@code BigInteger} without sign bit.
     *
     * @param bigInt {@code BigInteger} to be converted
     * @return a byte array representation of the BigInteger parameter
     */

    byte[] toIntegerBytes(final BigInteger bigInt, boolean rfc) {

        // this will be removed once all properties update
        // their code to handle the sign bit correctly
        if (!rfc) {
            return bigInt.toByteArray();
        }

        int bitlen = bigInt.bitLength();
        // round bitlen
        bitlen = ((bitlen + 7) >> 3) << 3;
        final byte[] bigBytes = bigInt.toByteArray();

        if (((bigInt.bitLength() % 8) != 0) && (((bigInt.bitLength() / 8) + 1) == (bitlen / 8))) {
            return bigBytes;
        }
        // set up params for copying everything but sign bit
        int startSrc = 0;
        int len = bigBytes.length;

        ///CLOVER:OFF
        // if bigInt is exactly byte-aligned, just skip signbit in copy
        if ((bigInt.bitLength() % 8) == 0) {
            startSrc = 1;
            len--;
        }
        ///CLOVER:ON
        final int startDst = bitlen / 8 - len; // to pad w/ nulls as per spec
        final byte[] resizedBytes = new byte[bitlen / 8];
        System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len);
        return resizedBytes;
    }

    /**
     * Mapping from curve names used by the crypto libraries
     * to RFC defined values. The valid values for JWKs are defined
     *     https://tools.ietf.org/html/rfc7518
     * and the mapping between alias curve names is taken from
     *     https://tools.ietf.org/html/rfc4492
     *              secp256r1   |  prime256v1   |   NIST P-256
     *              secp384r1   |               |   NIST P-384
     *              secp521r1   |               |   NIST P-521
     * @param curveName curve name used by the crypt library
     * @return rfc defined curve name
     */
    String rfcEllipticCurveName(final String curveName) {

        if (curveName == null) {
            return null;
        }

        String rfcCurveName;
        switch (curveName) {
            case "prime256v1":
            case "secp256r1":
                rfcCurveName = "P-256";
                break;
            case "secp384r1":
                rfcCurveName = "P-384";
                break;
            case "secp521r1":
                rfcCurveName = "P-521";
                break;
            default:
                // if we have no defined rfc curve name
                // then we'll just return the value as is
                rfcCurveName = curveName;
        }

        return rfcCurveName;
    }

    /**
     * This function processes the local domains after comparing the list
     * against the list from ZMS and returns the number of bad domains
     * that it has encountered. If the value is -1 then it indicates to
     * the caller that the full local list was bad so the caller should
     * initiate a full resync.
     * @param localDomainList list of local domain from its storage
     * @return -1 if full resync is needed, 0 if no errors, otherwise
     *  the number of bad domains
     */
    int processLocalDomains(List<String> localDomainList) {

        /* we can't have a lastModTime set if we have no local
         * domains - in this case we're going to reset */
        
        if (localDomainList.isEmpty()) {
            return -1;
        }
        
        /* first we need to retrieve the list of domains from ZMS so we
         * know what domains have been deleted already (if any).
         * If we get no response from ZMS, we're not going to stop
         * ZTS from coming up with its local files */
        
        Set<String> zmsDomainList = changeLogStore.getServerDomainList();

        int badDomains = 0;
        for (String domainName : localDomainList) {
            
            /* make sure this domain is still active in ZMS otherwise
             * we'll just remove our local copy. if we were not able
             * to fetch the domain list from ZMS at this time, we'll
             * just defer the cleanup at the next check */

            if (zmsDomainList != null && !zmsDomainList.contains(domainName)) {
                
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Removing local domain: {}. Domain not in ZMS anymore.", domainName);
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

            if (!processLocalDomain(domainName)) {
                if (changeLogStore.supportsFullRefresh()) {
                    return -1;
                } else {
                    badDomains += 1;
                }
            }
        }

        /* if more than 1/4 of our domains are bad then we have some
         * issue that needs to be addressed so we're going to return failure */

        if (badDomains > localDomainList.size() / 4) {
            LOGGER.error("Too many invalid domains: {} out of {}", badDomains, localDomainList.size());
            return -1;
        }

        return badDomains;
    }
    
    public void init() {
        
        /* now let's retrieve the list of locally saved domains */

        List<String> localDomainList = changeLogStore.getLocalDomainList();

        /* if we are not able to successfully process our local domains
         * then we're going to ask our store to reset the changes
         * and give us the list of all domains from ZMS */

        int badDomains = processLocalDomains(localDomainList);
        if (badDomains == -1) {
            
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
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to initialize storage subsystem");
        }

        /* if we had received any errors when processing local
         * domains then we're going to run a domain check and
         * verify all domains vs their modified timestamp in zms */

        if (badDomains > 0) {
            processDomainChecks();
        }

        /* Start our monitoring thread to get changes from ZMS */

        ScheduledExecutorService scheduledThreadPool = Executors.newScheduledThreadPool(1);
        scheduledThreadPool.scheduleAtFixedRate(new DataUpdater(), updDomainRefreshTime,
                updDomainRefreshTime, TimeUnit.SECONDS);
    }

    boolean processLocalDomain(String domainName) {

        boolean result = false;
        try {
            result = processDomain(changeLogStore.getLocalSignedDomain(domainName), false);
        } catch (Exception ex) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Unable to process local domain {}:{}", domainName, ex.getMessage());
            }
        }
        
        if (!result) {
            LOGGER.error("Invalid local domain: {}. Refresh from ZMS required.", domainName);
        }
        
        return result;
    }
    
    boolean validateSignedDomain(SignedDomain signedDomain) {
        
        DomainData domainData = signedDomain.getDomain();
        String keyId = signedDomain.getKeyId();
        String signature = signedDomain.getSignature();
        
        PublicKey zmsKey = zmsPublicKeyCache.getIfPresent(keyId == null ? "0" : keyId);
        if (zmsKey == null) {
            LOGGER.error("validateSignedDomain: ZMS Public Key id={} not available", keyId);
            return false;
        }

        boolean result = Crypto.verify(SignUtils.asCanonicalString(domainData), zmsKey, signature);
        
        if (!result) {
            LOGGER.error("validateSignedDomain: Domain={} signature validation failed", domainData.getName());
            LOGGER.error("validateSignedDomain: Signed Domain Data: {}", SignUtils.asCanonicalString(domainData));
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

    void processDomainGroups(DomainData domainData) {

        // get the current list of groups so we can determine
        // which groups have been deleted

        List<Group> deletedGroups = null;
        DataCache dataCache = getCacheStore().getIfPresent(domainData.getName());
        if (dataCache != null) {
            deletedGroups = dataCache.getDomainData().getGroups();
        }

        List<Group> groups = domainData.getGroups();
        if (groups != null) {
            for (Group group : groups) {

                // first remove the group from our original list
                // since it's not deleted

                if (deletedGroups != null) {
                    deletedGroups.removeIf(item -> item.getName().equalsIgnoreCase(group.getName()));
                }

                // now process our group

                processGroup(group);
            }
        }

        // before returning we need to process our deleted groups

        if (deletedGroups != null) {
            for (Group group : deletedGroups) {
                processGroupDelete(group);
            }
        }
    }

    void processGroup(Group group) {

        // if the group has null members we'll replace it with an empty set

        if (group.getGroupMembers() == null) {
            group.setGroupMembers(new ArrayList<>());
        }

        // obtain the previous list of members for the group
        // and determine the list of changes between old and new members

        List<GroupMember> originalMembers = groupMemberCache.getIfPresent(group.getName());
        List<GroupMember> curMembers = originalMembers == null ? new ArrayList<>() : new ArrayList<>(originalMembers);
        List<GroupMember> delMembers = new ArrayList<>(curMembers);
        List<GroupMember> newMembers = new ArrayList<>(group.getGroupMembers());
        List<GroupMember> updMembers = new ArrayList<>(group.getGroupMembers());

        // remove current members from new members

        AuthzHelper.removeGroupMembers(newMembers, curMembers);

        // remove new members from current members
        // which leaves the deleted members.

        AuthzHelper.removeGroupMembers(delMembers, group.getGroupMembers());

        // now let's remove our new members from the member list to
        // get the possible list of users that need to be updated

        AuthzHelper.removeGroupMembers(updMembers, newMembers);

        // update the group member cache with the new members

        groupMemberCache.put(group.getName(), group.getGroupMembers());

        // first process the updated entries

        long currentTime = System.currentTimeMillis();
        for (GroupMember member : updMembers) {

            // it's possible that initially we skipped the entry because it was
            // disabled or expired so we might have no entries in the map

            List<GroupMember> groupMembers = principalGroupCache.getIfPresent(member.getMemberName());
            if (groupMembers == null) {

                // make sure we want to process this user

                if (AuthzHelper.shouldSkipGroupMember(member, currentTime)) {
                    continue;
                }

                // otherwise we'll add this member to our new list

                groupMembers = new ArrayList<>();
                groupMembers.add(member);
                principalGroupCache.put(member.getMemberName(), groupMembers);

            } else {

                // if we need to skip the entry then we'll delete the member
                // from our list otherwise we'll just update it

                if (AuthzHelper.shouldSkipGroupMember(member, currentTime)) {
                    groupMembers.removeIf(item -> item.getGroupName().equalsIgnoreCase(group.getName()));
                } else {
                    // we need to find our entry and update details

                    for (GroupMember mbr : groupMembers) {
                        if (mbr.getGroupName().equalsIgnoreCase(group.getName())) {
                            mbr.setExpiration(member.getExpiration());
                            mbr.setSystemDisabled(member.getSystemDisabled());
                            mbr.setActive(member.getActive());
                            mbr.setApproved(member.getApproved());
                            break;
                        }
                    }
                }
            }
        }

        // now let's add our new members

        for (GroupMember member : newMembers) {

            // skip any disabled and expired users

            if (AuthzHelper.shouldSkipGroupMember(member, currentTime)) {
                continue;
            }

            List<GroupMember> groupMembers = principalGroupCache.getIfPresent(member.getMemberName());
            if (groupMembers == null) {
                groupMembers = new ArrayList<>();
                principalGroupCache.put(member.getMemberName(), groupMembers);
            }
            groupMembers.add(member);
        }

        // process deleted members from the group

        processGroupDeletedMembers(group.getName(), delMembers);
    }

    void processGroupDeletedMembers(final String groupName, List<GroupMember> deletedMembers) {

        // if the group has no members then we have nothing to do

        if (deletedMembers == null) {
            return;
        }

        for (GroupMember member : deletedMembers) {
            List<GroupMember> groupMembers = principalGroupCache.getIfPresent(member.getMemberName());
            if (groupMembers == null) {
                continue;
            }
            groupMembers.removeIf(item -> item.getGroupName().equalsIgnoreCase(groupName));
        }
    }

    void processGroupDelete(Group group) {

        // first remove the group from our cache

        groupMemberCache.invalidate(group.getName());

        // delete all the members from our cache objects

        processGroupDeletedMembers(group.getName(), group.getGroupMembers());
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
        
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("Processing domain: {}", domainName);
        }
        
        /* if the domain is disabled we're going to skip
         * processing this domain and just assume success */
        
        if (domainData.getEnabled() == Boolean.FALSE) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Skipping disabled domain domain: {}", domainName);
            }
            return true;
        }
        
        /* before doing anything else let's validate our domain */
        
        if (!validateSignedDomain(signedDomain)) {
            return false;
        }

        /* generate our cache object */

        DataCache domainCache = new DataCache();
        
        /* process the roles for this domain */

        processDomainRoles(domainData, domainCache);

        /* process the groups for this domain */

        processDomainGroups(domainData);

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

        return zmsDomainList.contains(ATHENZ_SYS_DOMAIN);
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

    public void processDomainChecks() {

        /* retrieve the list of domains from ZMS */

        SignedDomains signedDomains = changeLogStore.getServerDomainModifiedList();
        if (signedDomains == null) {
            return;
        }

        /* go through each domain in the list. if it doesn't exist
         * in the local list we need to update it. if it exists
         * but with an older last modified time, then we need
         * to update it. */

        for (SignedDomain zmsDomain : signedDomains.getDomains()) {

            final DomainData domainData = zmsDomain.getDomain();
            DomainData localDomain = getDomainData(domainData.getName());
            if (localDomain == null || localDomain.getModified().millis() < domainData.getModified().millis()) {

                SignedDomain signedDomain = changeLogStore.getServerSignedDomain(domainData.getName());

                if (signedDomain == null) {
                    continue;
                }

                processDomain(signedDomain, true);
            }
        }
    }

    // Internal
    void deleteDomain(final String domainName) {

        /* first delete all groups for this domain */

        processDeleteDomainGroups(domainName);

        /* first delete our data from the cache */

        deleteDomainFromCache(domainName);

        /* then delete it from the struct store */

        changeLogStore.removeLocalDomain(domainName);
    }

    void processDeleteDomainGroups(final String domainName) {

        // get the current list of groups so we can determine
        // which groups have been deleted

        DataCache dataCache = getCacheStore().getIfPresent(domainName);
        if (dataCache == null) {
            return;
        }

        List<Group> deletedGroups = dataCache.getDomainData().getGroups();
        if (deletedGroups == null) {
            return;
        }

        for (Group group : deletedGroups) {
            processGroupDelete(group);
        }
    }

    // Internal
    boolean processSignedDomains(SignedDomains signedDomains) {
        
        /* if we have received no data from ZMS server then we're not
         * going to update our last modification time and instead we'll
         * just continue using the old one until we get some updates
         * from ZMS Server */
        
        if (signedDomains == null) {
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("No updates received from ZMS Server");
            }
            return true;
        }
        
        /* now process all of our domains */
        
        List<SignedDomain> domains = signedDomains.getDomains();
        if (domains == null || domains.isEmpty()) {
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("No updates received from ZMS Server");
            }
            return true;
        }
        
        // we're going to return success as long as one of the
        // domains was successfully processed, otherwise there is
        // no point of retrying all domains over and over again
        
        boolean result = false;
        for (SignedDomain domain : domains) {
            if (processDomain(domain, true)) {
                result = true;
            }
        }
        
        return result;
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
            List<String> services = hostCache.computeIfAbsent(entry.getKey(), k -> new ArrayList<>());
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
    void processStandardMembership(Set<MemberRole> memberRoles, String rolePrefix, Set<String> trustedResources,
                                   String[] requestedRoleList, Set<String> accessibleRoles, boolean keepFullName) {
        
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

            // if we're given trust resource set then make sure
            // the role we're processing is in the set and since
            // since the role set can include wildcard domains we
            // need to match the role as oppose to a direct check if the
            // set contains the name

            if (trustedResources != null && !roleMatchInTrustSet(memberRole.getRole(), trustedResources)) {
                continue;
            }

            addRoleToList(memberRole.getRole(), rolePrefix, requestedRoleList,
                    accessibleRoles, keepFullName);
        }
    }

    void processGroupMembership(DataCache data, final String identity, final String rolePrefix,
                                Set<String> trustedResources, String[] requestedRoleList, Set<String> accessibleRoles,
                                boolean keepFullName) {

        // get the list of groups that a given identity is part of

        List<GroupMember> groupMembers = principalGroupCache.getIfPresent(identity);
        if (groupMembers == null || groupMembers.isEmpty()) {
            return;
        }

        // go through the group list and see if the any of the groups
        // the user is included in the given domain role

        long currentTime = System.currentTimeMillis();
        for (GroupMember member : groupMembers) {

            // skip any members that have already expired

            if (AuthzHelper.isMemberExpired(member.getExpiration(), currentTime)) {
                continue;
            }

            // process the role as a standard identity check

            processStandardMembership(data.getMemberRoleSet(member.getGroupName()),
                    rolePrefix, trustedResources, requestedRoleList, accessibleRoles, keepFullName);
        }
    }

    // Internal
    void processTrustMembership(DataCache data, String identity, String rolePrefix,
            String[] requestedRoleList, Set<String> accessibleRoles, boolean keepFullName) {
        
        Map<String, Set<String>> trustedRolesMap = data.getTrustMap();

        /* iterate through all trusted domains */

        for (Map.Entry<String, Set<String>> trustedRole : trustedRolesMap.entrySet()) {

            processTrustedDomain(getCacheStore().getIfPresent(trustedRole.getKey()),
                    identity, rolePrefix, requestedRoleList, trustedRole.getValue(),
                    accessibleRoles, keepFullName);
        }
    }
    
    // API
    @Override
    public DataCache getDataCache(String domainName) {
        return getCacheStore().getIfPresent(domainName);
    }

    public List<GroupMember> getGroupMembers(final String groupName) {
        return groupMemberCache.getIfPresent(groupName);
    }

    // API
    public void getAccessibleRoles(DataCache data, String domainName, String identity,
            String[] requestedRoleList, Set<String> accessibleRoles, boolean keepFullName) {

        /* if the domain hasn't been processed then we don't have anything to do */
        
        if (data == null) {
            return;
        }
        
        final String rolePrefix = domainName + ROLE_POSTFIX;

        /* first look through the members to see if the given identity is
         * included in the list explicitly */

        processStandardMembership(data.getMemberRoleSet(identity),
                rolePrefix, null, requestedRoleList, accessibleRoles, keepFullName);
        
        /* next look at all * wildcard roles that are configured
         * for all members to access */

        processStandardMembership(data.getAllMemberRoleSet(),
                rolePrefix, null, requestedRoleList, accessibleRoles, keepFullName);
        
        /* then look at the prefix wildcard roles. in this map
         * we only process those where the key in the map is
         * a prefix of our identity */
        
        Map<String, Set<MemberRole>> roleSetMap = data.getPrefixMemberRoleSetMap();
        for (String identityPrefix : roleSetMap.keySet()) {
            if (identity.startsWith(identityPrefix)) {
                processStandardMembership(roleSetMap.get(identityPrefix),
                        rolePrefix, null, requestedRoleList, accessibleRoles, keepFullName);
            }
        }

        // now process our group membership

        processGroupMembership(data, identity, rolePrefix, null, requestedRoleList, accessibleRoles, keepFullName);

        /* finally process all the roles that have trusted domain specified */

        processTrustMembership(data, identity, rolePrefix, requestedRoleList,
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
    void addRoleToList(String role, String rolePrefix, String[] requestedRoleList,
            Set<String> accessibleRoles, boolean keepFullName) {

        /* any roles we return must start with the domain role prefix */

        if (!role.startsWith(rolePrefix)) {
            return;
        }

        /* and it must end with the suffix if requested */
        
        if (requestedRoleList != null) {
            boolean matchFound = false;
            for (String requestedRole : requestedRoleList) {
                if (role.endsWith(requestedRole)) {
                    matchFound = true;
                    break;
                }
            }
            if (!matchFound) {
                return;
            }
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

        String rolePattern;
        long currentTime = System.currentTimeMillis();
        for (MemberRole memberRole : memberRoles) {
            
            // before processing make sure the member hasn't
            // expired for this role
            
            long expiration = memberRole.getExpiration();
            if (expiration != 0 && expiration < currentTime) {
                continue;
            }
            
            // if the role does not contain any of our pattern
            // characters then we can just a regular compare
            
            final String roleName = memberRole.getRole();
            if (StringUtils.containsMatchCharacter(roleName)) {
                rolePattern = StringUtils.patternFromGlob(roleName);
                if (role.matches(rolePattern)) {
                    return true;
                }
            } else {
                if (role.equals(roleName)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    boolean roleMatchInTrustSet(final String role, Set<String> memberRoles) {

        // first we'll do a quick check if the role is included
        // in the set and return if we have a match

        if (memberRoles.contains(role)) {
            return true;
        }

        // we'll look for wildcard characters and try to match

        for (String memberRole : memberRoles) {

            // if the role does not contain any of our pattern
            // then no need to process since we have already
            // verified the contains check above

            if (!StringUtils.containsMatchCharacter(memberRole)) {
                continue;
            }

            final String rolePattern = StringUtils.patternFromGlob(memberRole);
            if (role.matches(rolePattern)) {
                return true;
            }
        }

        return false;
    }

    // Internal
    void processSingleTrustedDomainRole(String roleName, String rolePrefix, String[] requestedRoleList,
            Set<MemberRole> memberRoles, Set<String> accessibleRoles, boolean keepFullName) {
        
        /* since our member role set can include wildcard domains we
         * need to match the role as oppose to a direct check if the
         * set contains the name */

        if (!roleMatchInSet(roleName, memberRoles)) {
            return;
        }
        
        /* now check if the role is in the resource list as well */

        addRoleToList(roleName, rolePrefix, requestedRoleList, accessibleRoles, keepFullName);
    }
    
    // Internal
    void processTrustedDomain(DataCache trustData, String identity, String rolePrefix,
            String[] requestedRoleList, Set<String> trustedResources, Set<String> accessibleRoles,
            boolean keepFullName) {

        /* verify that our data cache and list of trusted resources are valid */
        
        if (trustData == null || trustedResources == null) {
            return;
        }
        
        /* first we need to process our regular roles that include
         * our identity */

        Set<MemberRole> memberRoles = trustData.getMemberRoleSet(identity);
        if (memberRoles != null) {
        
            for (String resource : trustedResources) {
                
                /* in this case our resource is the role name */
                    
                processSingleTrustedDomainRole(resource, rolePrefix, requestedRoleList,
                        memberRoles, accessibleRoles, keepFullName);
            }
        }
        
        /* next we should process all the * wildcard roles */
        
        memberRoles = trustData.getAllMemberRoleSet();
        if (memberRoles != null && !memberRoles.isEmpty()) {
        
            for (String resource : trustedResources) {
                
                /* in this case our resource is the role name */
                    
                processSingleTrustedDomainRole(resource, rolePrefix, requestedRoleList,
                        memberRoles, accessibleRoles, keepFullName);
            }
        }
        
        /* finally we're going to process the wildcard roles
         * but we need to first confirm that our identity
         * matches to member before processing it */
        
        Map<String, Set<MemberRole>> roleSetMap = trustData.getPrefixMemberRoleSetMap();
        for (String identityPrefix : roleSetMap.keySet()) {
            if (identity.startsWith(identityPrefix)) {
                
                memberRoles = roleSetMap.get(identityPrefix);
                for (String resource : trustedResources) {
                    
                    /* in this case our resource is the role name */
                        
                    processSingleTrustedDomainRole(resource, rolePrefix, requestedRoleList,
                            memberRoles, accessibleRoles, keepFullName);
                }
            }
        }

        // process group membership for our delegated roles

        processGroupMembership(trustData, identity, rolePrefix, trustedResources,
                requestedRoleList, accessibleRoles, keepFullName);
    }

    // API
    public String getPublicKey(String domain, String service, String keyId) {

        String publicKeyName = generateServiceKeyName(domain, service, keyId);
        String publicKey;
        
        try {
            pkeyRLock.lock();
            publicKey = publicKeyCache.get(publicKeyName);
        } finally {
            pkeyRLock.unlock();
        }

        ///CLOVER:OFF
        if (publicKey == null && LOGGER.isDebugEnabled()) {
            LOGGER.debug("Public key: " + publicKeyName + " not available");
        }
        ///CLOVER:ON
        
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
        if (this.cloudStore != null) {
            this.cloudStore.close();
        }
        this.cloudStore = cloudStore;
    }

    public Cache<String, DataCache> getCacheStore() {
        return cacheStore;
    }

    public Map<String, String> getPublicKeyCache() {
        return publicKeyCache;
    }

    @Override
    public List<Role> getRolesByDomain(String domain) {
        DomainData domainData = getDomainData(domain);
        if (domainData == null) {
            return new ArrayList<>();
        }

        return domainData.getRoles();
    }

    class DataUpdater implements Runnable {
        
        @Override
        public void run() {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("DataUpdater: Starting data updater thread...");
            }

            try {
                processDomainUpdates();
            } catch (Throwable t) {
                LOGGER.error("DataUpdater: unable to process domain updates", t);
            }

            try {
                // check to see if we need to handle our delete domain list -
                // make sure refresh time is converted to millis
                
                if (System.currentTimeMillis() - lastDeleteRunTime > delDomainRefreshTime * 1000) {
                    
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("DataUpdater: Processing domain delete checks...");
                    }
                    
                    processDomainDeletes();
                    lastDeleteRunTime = System.currentTimeMillis();
                }
            } catch (Throwable t) {
                LOGGER.error("DataUpdater: unable to process domain deletes", t);
            }

            try {
                // check to see if we need to handle our check our domain list -
                //make sure refresh time is converted to millis

                if (System.currentTimeMillis() - lastCheckRunTime > checkDomainRefreshTime * 1000) {

                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("DataUpdater: Processing domain modification timestamp checks...");
                    }

                    processDomainChecks();
                    lastCheckRunTime = System.currentTimeMillis();
                }

            } catch (Throwable t) {
                LOGGER.error("DataUpdater: unable to process domain checks", t);
            }
        }
    }
}
