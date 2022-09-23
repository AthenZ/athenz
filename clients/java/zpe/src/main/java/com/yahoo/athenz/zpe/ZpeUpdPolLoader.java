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
package com.yahoo.athenz.zpe;

import java.io.Closeable;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Function;

import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.zts.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zpe.match.ZpeMatch;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchAll;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchEqual;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchRegex;
import com.yahoo.athenz.zpe.match.impl.ZpeMatchStartsWith;

public class ZpeUpdPolLoader implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(ZpeUpdPolLoader.class);

    static boolean skipPolicyDirCheck;
    static boolean checkPolicyZMSSignature;
    static long sleepTimeMillis = -1;
    static long cleanupTokenInterval = 600000; // 600 secs = 10 minutes
    static long lastRoleTokenCleanup = System.currentTimeMillis();
    static long lastAccessTokenCleanup = System.currentTimeMillis();

    static {

        skipPolicyDirCheck = Boolean.parseBoolean(System.getProperty(ZpeConsts.ZPE_PROP_SKIP_POLICY_DIR_CHECK, "false"));
        checkPolicyZMSSignature = Boolean.parseBoolean(System.getProperty(ZpeConsts.ZPE_PROP_CHECK_POLICY_ZMS_SIGNATURE, "false"));

        // default to 5 minutes / 300 secs
        String timeoutSecs = System.getProperty(ZpeConsts.ZPE_PROP_MON_TIMEOUT, "300");
        try {
            long secs = Long.parseLong(timeoutSecs);
            sleepTimeMillis = TimeUnit.MILLISECONDS.convert(secs, TimeUnit.SECONDS);
        } catch (NumberFormatException exc) {
            LOG.warn("start: WARNING: Failed using system property({}) with value={}, exc: {}",
                    ZpeConsts.ZPE_PROP_MON_TIMEOUT, timeoutSecs, exc);
        }

        // default is 10 minutes / 600 secs
        timeoutSecs = System.getProperty(ZpeConsts.ZPE_PROP_MON_CLEANUP_TOKENS, "600");
        try {
            long secs = Long.parseLong(timeoutSecs);
            cleanupTokenInterval = TimeUnit.MILLISECONDS.convert(secs, TimeUnit.SECONDS);
        } catch (NumberFormatException exc) {
            LOG.warn("start: WARNING: Failed using system property({}) with value={}, exc: {}",
                    ZpeConsts.ZPE_PROP_MON_CLEANUP_TOKENS, timeoutSecs, exc);
        }
    }

    // create thread or event handler to monitor changes to ZpePolFiles
    // find the java7 api for monitoring files
    // see http://docs.oracle.com/javase/tutorial/essential/io/notification.html

    private final ScheduledExecutorService scheduledExecutorSvc = Executors.newScheduledThreadPool(1);
    private ZpeUpdMonitor updMonWorker;

    // key is the domain name, value is a map keyed by role name with list of assertions
    ConcurrentHashMap<String, Map<String, List<Struct>>> domStandardRoleAllowMap = new ConcurrentHashMap<>();

    // wild card role map, keys and values same as domRoleMap above
    ConcurrentHashMap<String, Map<String, List<Struct>>> domWildcardRoleAllowMap = new ConcurrentHashMap<>();

    // key is the domain name, value is a map keyed by role name with list of assertions
    ConcurrentHashMap<String, Map<String, List<Struct>>> domStandardRoleDenyMap = new ConcurrentHashMap<>();

    // wild card role map, keys and values same as domRoleMap above
    ConcurrentHashMap<String, Map<String, List<Struct>>> domWildcardRoleDenyMap = new ConcurrentHashMap<>();

    // cache of active Role Tokens
    static ConcurrentHashMap<String, RoleToken> roleTokenCacheMap = new ConcurrentHashMap<>();

    // cache of active Access Tokens
    static ConcurrentHashMap<String, AccessToken> accessTokenCacheMap = new ConcurrentHashMap<>();

    // array of file status objects
    static class ZpeFileStatus {
        String domain;
        long modifyTimeMillis;
        boolean validPolFile;
        
        ZpeFileStatus(long modTimeMillis) {
            domain = null;
            modifyTimeMillis = modTimeMillis;
            validPolFile = false;
        }
    }

    private final Map<String, ZpeFileStatus> fileStatusRef = new ConcurrentHashMap<>();
    private String polDirName;

    ZpeUpdPolLoader(String dirName) {
    
        if (null != dirName) {
            polDirName = dirName;
            try {
                loadDb();
            } catch (Exception exc) {
                LOG.error("loadDb Failed", exc);
            }
        }
    }
    
    String getDirName() {
        return polDirName;
    }

    Map<String, ZpeFileStatus> getFileStatusMap() {
        return fileStatusRef;
    }

    // return map of wildcard role with assertion list with allow effect
    //
    public Map<String, List<Struct>> getWildcardRoleAllowMap(String domainName) {
        return domWildcardRoleAllowMap.get(domainName);
    }

    // return map of role-name with assertion list with allow effect
    //
    public Map<String, List<Struct>> getStandardRoleAllowMap(String domainName) {
        return domStandardRoleAllowMap.get(domainName);
    }

    // return map of wildcard role with assertion list with deny effect
    //
    public Map<String, List<Struct>> getWildcardRoleDenyMap(String domainName) {
        return domWildcardRoleDenyMap.get(domainName);
    }

    // return map of role-name with assertion list with deny effect
    //
    public Map<String, List<Struct>> getStandardRoleDenyMap(String domainName) {
        return domStandardRoleDenyMap.get(domainName);
    }
    
    static public Map<String, RoleToken> getRoleTokenCacheMap() {
        return roleTokenCacheMap;
    }

    static public Map<String, AccessToken> getAccessTokenCacheMap() {
        return accessTokenCacheMap;
    }

    /**
     * All of our maps must contain the same number of objects since we
     * process and update them at the same time, so we'll just return
     * the number of entries in our allow role map
     * @return number of domains processed
     */
    public int getDomainCount() {
        return domWildcardRoleAllowMap.size();
    }

    public void start() throws Exception {
        if (polDirName == null) {
            throw new Exception("ERROR: start: no policy directory name, can't monitor data files");
        }
        
        if (updMonWorker == null) {
            updMonWorker = new ZpeUpdMonitor(this);
        }
        scheduledExecutorSvc.scheduleAtFixedRate(updMonWorker, 0, sleepTimeMillis, TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        if (updMonWorker != null) {
            updMonWorker.cancel();
        }
        scheduledExecutorSvc.shutdownNow();
    }

    static public void cleanupRoleTokenCache() {
        // is it time to clean up?
        long now = System.currentTimeMillis();
        if (now < (cleanupTokenInterval + lastRoleTokenCleanup)) {
            return;
        }

        long nowSecs = now / 1000;
        roleTokenCacheMap.entrySet().removeIf(entry -> entry.getValue().getExpiryTime() < nowSecs);
        lastRoleTokenCleanup = now; // reset time of last cleanup
    }

    static public void cleanupAccessTokenCache() {
        // is it time to clean up?
        long now = System.currentTimeMillis();
        if (now < (cleanupTokenInterval + lastAccessTokenCleanup)) {
            return;
        }

        long nowSecs = now / 1000;
        accessTokenCacheMap.entrySet().removeIf(entry -> entry.getValue().getExpiryTime() < nowSecs);
        lastAccessTokenCleanup = now; // reset time of last cleanup
    }

    void loadDb() {

        if (updMonWorker == null) {
            updMonWorker = new ZpeUpdMonitor(this);
        }

        if (skipPolicyDirCheck) {
            return;
        }

        loadDb(updMonWorker.loadFileStatus());
    }

    /**
     *  Process the given policy file list and determine if any of the
     *  policy domain files have been updated. New ones will be loaded
     *  into the policy domain map.
     **/
    void loadDb(File []polFileNames) {

        if (polFileNames == null) {
            LOG.error("loadDb: no policy files to load");
            return;
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("loadDb: START thrd={} directory={}", Thread.currentThread().getId(), polDirName);
        }
        for (File polFile: polFileNames) {
            
            String fileName = polFile.getName();
            if (LOG.isDebugEnabled()) {
                LOG.debug("loadDb: START thrd={} file name={}", Thread.currentThread().getId(), fileName);
            }
            long lastModMilliSeconds = polFile.lastModified();
            Map<String, ZpeFileStatus> fsmap = getFileStatusMap();
            ZpeFileStatus fstat = fsmap.get(fileName);
            if (fstat != null) {
                
                if (!polFile.exists()) { // file was deleted
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("loadDb: file({}) was deleted or doesn't exist", fileName);
                    }
                    fsmap.remove(fileName);
                    
                    if (!fstat.validPolFile || fstat.domain == null) {
                        continue;
                    }

                    // replace domain with empty data
                    //
                    domStandardRoleAllowMap.put(fstat.domain, new TreeMap<>());
                    domWildcardRoleAllowMap.put(fstat.domain, new TreeMap<>());
                    domStandardRoleDenyMap.put(fstat.domain, new TreeMap<>());
                    domWildcardRoleDenyMap.put(fstat.domain, new TreeMap<>());
                    continue;
                }
                
                // check if file was modified since last time it was loaded
                //
                if (lastModMilliSeconds <= fstat.modifyTimeMillis) {
                    // if valid and up-to-date return
                    // if not valid, may be due to timing issue for a new
                    // file not completely written - and file system timestamp
                    // only accurate up to the second - not millis
                    String timeMsg = " last-file-mod-time=" + lastModMilliSeconds;
                    if (fstat.validPolFile) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("loadDb: ignore reload file: {} since up to date: {}", fileName, timeMsg);
                        }
                        continue;
                    } else if (LOG.isDebugEnabled()) {
                        LOG.debug("loadDb: retry load file: {} since last load was bad: {}", fileName, timeMsg);
                    }
            
                }
            } else {
                fstat = new ZpeFileStatus(lastModMilliSeconds);
                fsmap.put(fileName, fstat);
            }
            loadFile(polFile);
        }
    }

    ZpeMatch getMatchObject(String value) {
        
        ZpeMatch match;
        if ("*".equals(value)) {
            match = new ZpeMatchAll();
        } else {
            int anyCharMatch = value.indexOf('*');
            int singleCharMatch = value.indexOf('?');

            if (anyCharMatch == -1 && singleCharMatch == -1) {
                match = new ZpeMatchEqual(value);
            } else if (anyCharMatch == value.length() - 1 && singleCharMatch == -1) {
                match = new ZpeMatchStartsWith(value.substring(0, value.length() - 1));
            } else {
                match = new ZpeMatchRegex(value);
            }
        }
        
        return match;
    }

    private PolicyData getJWSPolicyData(JWSPolicyData jwsPolicyData) {

        Function<String, PublicKey> keyGetter = AuthZpeClient::getZtsPublicKey;
        if (!Crypto.validateJWSDocument(jwsPolicyData.getProtectedHeader(), jwsPolicyData.getPayload(),
                jwsPolicyData.getSignature(), keyGetter)) {

            // if our validation failed then it's possible our signature was
            // provided in p1363 format and our BC supports DER format only

            final String derSignature = getDERSignature(jwsPolicyData.getProtectedHeader(), jwsPolicyData.getSignature());
            if (derSignature == null) {
                LOG.error("zts signature validation failed");
                return null;
            }

            if (!Crypto.validateJWSDocument(jwsPolicyData.getProtectedHeader(), jwsPolicyData.getPayload(),
                    derSignature, keyGetter)) {
                LOG.error("zts signature validation failed");
                return null;
            }
        }

        Base64.Decoder base64Decoder = Base64.getUrlDecoder();
        byte[] payload = base64Decoder.decode(jwsPolicyData.getPayload());
        SignedPolicyData signedPolicyData = JSON.fromBytes(payload, SignedPolicyData.class);
        if (signedPolicyData == null) {
            LOG.error("unable to parse jws policy data payload");
            return null;
        }

        return signedPolicyData.getPolicyData();
    }

    boolean isESAlgorithm(final String algorithm) {
        if (algorithm != null) {
            switch (algorithm) {
                case "ES256":
                case "ES384":
                case "ES512":
                    return true;
            }
        }
        return false;
    }

    String getDERSignature(final String protectedHeader, final String signature) {

        Map<String, String> header = Crypto.parseJWSProtectedHeader(protectedHeader);
        if (header == null) {
            return null;
        }
        final String algorithm = header.get("alg");
        if (!isESAlgorithm(algorithm)) {
            return null;
        }
        try {
            Base64.Decoder base64Decoder = Base64.getUrlDecoder();
            final byte[] signatureBytes = base64Decoder.decode(signature);
            final byte[] convertedSignature = Crypto.convertSignatureFromP1363ToDERFormat(signatureBytes,
                    Crypto.getDigestAlgorithm(algorithm));
            Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();
            return base64Encoder.encodeToString(convertedSignature);
        } catch (Exception ex) {
            return null;
        }
    }

    private PolicyData getSignedPolicyData(DomainSignedPolicyData domainSignedPolicyData) {

        // we already verified that the object has policy data present

        SignedPolicyData signedPolicyData = domainSignedPolicyData.getSignedPolicyData();

        final String ztsSignature = domainSignedPolicyData.getSignature();
        final String ztsKeyId = domainSignedPolicyData.getKeyId();

        // first let's verify the ZTS signature for our policy file

        java.security.PublicKey ztsPublicKey = AuthZpeClient.getZtsPublicKey(ztsKeyId);
        if (ztsPublicKey == null) {
            LOG.error("unable to fetch zts public key for id: {}", ztsKeyId);
            return null;
        }

        if (!Crypto.verify(SignUtils.asCanonicalString(signedPolicyData), ztsPublicKey, ztsSignature)) {
            LOG.error("zts signature validation failed");
            return null;
        }

        PolicyData policyData = signedPolicyData.getPolicyData();
        if (policyData == null) {
            LOG.error("missing policy data");
            return null;
        }

        // now let's verify that the ZMS signature for our policy file
        // by default we're skipping this check because with multi-policy
        // support we'll be returning different versions of the policy
        // data from ZTS which cannot be signed by ZMS

        if (checkPolicyZMSSignature) {

            final String zmsSignature = signedPolicyData.getZmsSignature();
            final String zmsKeyId = signedPolicyData.getZmsKeyId();

            java.security.PublicKey zmsPublicKey = AuthZpeClient.getZmsPublicKey(zmsKeyId);
            if (zmsPublicKey == null) {
                LOG.error("unable to fetch zms public key for id: {}", zmsKeyId);
                return null;
            }

            if (!Crypto.verify(SignUtils.asCanonicalString(policyData), zmsPublicKey, zmsSignature)) {
                LOG.error("zms signature validation failed");
                return null;
            }
        }

        return policyData;
    }

    private void markInvalidFile(File polFile) {
        // mark this as an invalid file
        LOG.error("unable to decode domain file={}", polFile.getName());

        Map<String, ZpeFileStatus> fsmap = getFileStatusMap();
        ZpeFileStatus fstat = fsmap.get(polFile.getName());
        if (fstat != null) {
            fstat.validPolFile = false;
        }
    }
    /**
     * Loads and parses the given file. It will create the domain assertion
     * list per role and put it into the domain policy maps(domRoleMap, domWildcardRoleMap).
     **/
    private void loadFile(File polFile) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("loadFile: file({})", polFile.getName());
        }
        
        Path path = Paths.get(polDirName + File.separator + polFile.getName());

        byte[] policyFileData;
        try {
            policyFileData = Files.readAllBytes(path);
        } catch (Exception ex) {
            LOG.error("unable to read policy file={}", polFile.getName(), ex);
            markInvalidFile(polFile);
            return;
        }

        // we're going to assume the old domain signed policy format first
        // and if that fails we'll try jws policy data format

        PolicyData policyData = null;
        DomainSignedPolicyData domainSignedPolicyData = JSON.fromBytes(policyFileData, DomainSignedPolicyData.class);
        if (domainSignedPolicyData != null && domainSignedPolicyData.getSignedPolicyData() != null) {
            policyData = getSignedPolicyData(domainSignedPolicyData);
        } else {
            JWSPolicyData jwsPolicyData = JSON.fromBytes(policyFileData, JWSPolicyData.class);
            if (jwsPolicyData != null) {
                policyData = getJWSPolicyData(jwsPolicyData);
            }
        }

         if (policyData == null) {
             markInvalidFile(polFile);
             return;
         }
         
        // HAVE: valid policy file
        
        String domainName = policyData.getDomain();
        if (LOG.isDebugEnabled()) {
            LOG.debug("loadFile: policy file({}) for domain({}) is valid", polFile.getName(), domainName);
        }
        
        // Process the policies into assertions, process the assertions: action, resource, role
        // If there is a wildcard in the action or resource, compile the
        // regexpr and place it into the assertion Struct.
        // This is a performance enhancement for AuthZpeClient when it 
        // performs the authorization checks.
        Map<String, List<Struct>> roleStandardAllowMap = new TreeMap<>();
        Map<String, List<Struct>> roleWildcardAllowMap = new TreeMap<>();
        Map<String, List<Struct>> roleStandardDenyMap  = new TreeMap<>();
        Map<String, List<Struct>> roleWildcardDenyMap  = new TreeMap<>();
        List<Policy> policies = policyData.getPolicies();
        for (Policy policy : policies) {
            String pname = policy.getName();
            if (LOG.isDebugEnabled()) {
                LOG.debug("loadFile: domain({}) policy({})", domainName, pname);
            }
            List<Assertion> assertions = policy.getAssertions();
            if (assertions == null) {
                continue;
            }
            for (Assertion assertion : assertions) {
                com.yahoo.rdl.Struct strAssert = new Struct();
                strAssert.put(ZpeConsts.ZPE_FIELD_POLICY_NAME, pname);

                // It is possible for action and resource to retain case. Need to lower them both.
                final String passertAction = assertion.getAction().toLowerCase();

                ZpeMatch matchStruct = getMatchObject(passertAction);
                strAssert.put(ZpeConsts.ZPE_ACTION_MATCH_STRUCT, matchStruct);
                
                final String passertResource = assertion.getResource().toLowerCase();
                final String rsrc = AuthZpeClient.stripDomainPrefix(passertResource, domainName, passertResource);
                strAssert.put(ZpeConsts.ZPE_FIELD_RESOURCE, rsrc);
                matchStruct = getMatchObject(rsrc);
                strAssert.put(ZpeConsts.ZPE_RESOURCE_MATCH_STRUCT, matchStruct);

                final String passertRole = assertion.getRole();
                String pRoleName = AuthZpeClient.stripDomainPrefix(passertRole, domainName, passertRole);
                // strip the prefix "role." too
                pRoleName = pRoleName.replaceFirst("^role.", "");
                strAssert.put(ZpeConsts.ZPE_FIELD_ROLE, pRoleName);
                
                // based on the effect and role name determine what
                // map we're going to use
                
                Map<String, List<Struct>> roleMap;
                AssertionEffect passertEffect = assertion.getEffect();
                matchStruct = getMatchObject(pRoleName);
                strAssert.put(ZpeConsts.ZPE_ROLE_MATCH_STRUCT, matchStruct);
                
                if (passertEffect != null && passertEffect.toString().compareTo("DENY") == 0) {
                    if (matchStruct instanceof ZpeMatchEqual) {
                        roleMap = roleStandardDenyMap;
                    } else {
                        roleMap = roleWildcardDenyMap;
                    }
                } else {
                    if (matchStruct instanceof ZpeMatchEqual) {
                        roleMap = roleStandardAllowMap;
                    } else {
                        roleMap = roleWildcardAllowMap;
                    }
                }

                List<Struct> assertList = roleMap.computeIfAbsent(pRoleName, k -> new ArrayList<>());
                assertList.add(strAssert);
            }
        }
 
        Map<String, ZpeFileStatus> fsmap = getFileStatusMap();
        ZpeFileStatus fstat = fsmap.get(polFile.getName());
        if (fstat != null) {
            fstat.validPolFile = true;
            fstat.domain = domainName;
        }
        
        domStandardRoleAllowMap.put(domainName, roleStandardAllowMap);
        domWildcardRoleAllowMap.put(domainName, roleWildcardAllowMap);
        domStandardRoleDenyMap.put(domainName, roleStandardDenyMap);
        domWildcardRoleDenyMap.put(domainName, roleWildcardDenyMap);
    }
}

