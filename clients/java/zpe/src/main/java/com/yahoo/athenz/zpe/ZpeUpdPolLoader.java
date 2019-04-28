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
package com.yahoo.athenz.zpe;

import java.io.Closeable;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import com.yahoo.athenz.auth.token.AccessToken;
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
import com.yahoo.athenz.zts.Assertion;
import com.yahoo.athenz.zts.AssertionEffect;
import com.yahoo.athenz.zts.DomainSignedPolicyData;
import com.yahoo.athenz.zts.Policy;
import com.yahoo.athenz.zts.PolicyData;
import com.yahoo.athenz.zts.SignedPolicyData;

public class ZpeUpdPolLoader implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(ZpeUpdPolLoader.class);
     
    static long sleepTimeMillis = -1;
    static long cleanupTokenInterval = 600000; // 600 secs = 10 minutes
    static long lastRoleTokenCleanup = System.currentTimeMillis();
    static long lastAccessTokenCleanup = System.currentTimeMillis();

    static {
        
        String timeoutSecs = System.getProperty(ZpeConsts.ZPE_PROP_MON_TIMEOUT);
        if (timeoutSecs == null) {
            // default to 5 minutes
            sleepTimeMillis = TimeUnit.MILLISECONDS.convert(5, TimeUnit.MINUTES);
        } else {
            try {
                long secs = Long.parseLong(timeoutSecs);
                sleepTimeMillis = TimeUnit.MILLISECONDS.convert(secs, TimeUnit.SECONDS);
            } catch (NumberFormatException exc) {
                String errMsg = "start: WARNING: Failed using system property("
                        + ZpeConsts.ZPE_PROP_MON_TIMEOUT
                        + ") Got property value=" + timeoutSecs;
                LOG.warn(errMsg + ", exc: " + exc.getMessage());
            }
        }

        timeoutSecs = System.getProperty(ZpeConsts.ZPE_PROP_MON_CLEANUP_TOKENS);
        if (timeoutSecs != null) {
            try {
                long secs = Long.parseLong(timeoutSecs);
                cleanupTokenInterval = TimeUnit.MILLISECONDS.convert(secs, TimeUnit.SECONDS);
            } catch (NumberFormatException exc) {
                String errMsg = "start: WARNING: Failed using system property("
                        + ZpeConsts.ZPE_PROP_MON_CLEANUP_TOKENS
                        + ") Got property value=" + timeoutSecs;
                LOG.warn(errMsg + ", exc: " + exc.getMessage());
            }
        }
    }

    // create thread or event handler to monitor changes to ZpePolFiles
    // see JavaYnetDbWrapper for scheduled thread way to monitor
    // find the java7 api for monitoring files
    // see http://docs.oracle.com/javase/tutorial/essential/io/notification.html
    private ScheduledThreadPoolExecutor scheduledExecutorSvc = new ScheduledThreadPoolExecutor(
            1, new ZpeThreadFactory("ZpeUpdPolLoader"));

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
        String fname;
        String domain;
        long modifyTimeMillis;
        boolean validPolFile;
        
        ZpeFileStatus(String fname, long modTimeMillis) {
            domain = null;
            modifyTimeMillis = modTimeMillis;
            validPolFile = false;
        }
    }

    private Map<String, ZpeFileStatus> fileStatusRef = new ConcurrentHashMap<>();
    private String polDirName;

    ZpeUpdPolLoader(String dirName) {
    
        if (null != dirName) {
            polDirName = dirName;
            try {
                loadDb();
            } catch (Exception exc) {
                LOG.error("loadDb Failed, exc: " + exc.getMessage());
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

    public void start() throws Exception {
        if (polDirName == null) {
            String errMsg = "ERROR: start: no policy directory name, can't monitor data files";
            throw new Exception(errMsg);
        }
        
        if (updMonWorker == null) {
            updMonWorker = new ZpeUpdMonitor(this);
        }
        scheduledExecutorSvc.scheduleAtFixedRate(updMonWorker, 0,
                sleepTimeMillis, TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        if (updMonWorker != null) {
            updMonWorker.cancel();
        }
        scheduledExecutorSvc.shutdownNow();
    }

    static public void cleanupRoleTokenCache() {
        // is it time to cleanup?
        long now = System.currentTimeMillis();
        if (now < (cleanupTokenInterval + lastRoleTokenCleanup)) {
            return;
        }

        long nowSecs = now / 1000;
        roleTokenCacheMap.entrySet().removeIf(entry -> entry.getValue().getExpiryTime() < nowSecs);
        lastRoleTokenCleanup = now; // reset time of last cleanup
    }

    static public void cleanupAccessTokenCache() {
        // is it time to cleanup?
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
        File[] polFileNames = updMonWorker.loadFileStatus();
        loadDb(polFileNames);
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
            LOG.debug("loadDb: START thrd=" + Thread.currentThread().getId() + " directory=" + polDirName);
        }
        for (File polFile: polFileNames) {
            
            String fileName = polFile.getName();
            if (LOG.isDebugEnabled()) {
                LOG.debug("loadDb: START thrd=" + Thread.currentThread().getId() + " file name=" + fileName);
            }
            long lastModMilliSeconds = polFile.lastModified();
            Map<String, ZpeFileStatus> fsmap = getFileStatusMap();
            ZpeFileStatus fstat = fsmap.get(fileName);
            if (fstat != null) {
                
                if (!polFile.exists()) { // file was deleted
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("loadDb: file(" + fileName + " ) was deleted or doesn't exist");
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
                    // if valid and up to date return
                    // if not valid, may be due to timing issue for a new
                    // file not completely written - and file system timestamp
                    // only accurate up to the second - not millis
                    String timeMsg = " last-file-mod-time=" + lastModMilliSeconds;
                    if (fstat.validPolFile) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("loadDb: ignore reload file: " + fileName + " since up to date: " + timeMsg);
                        }
                        continue;
                    } else if (LOG.isDebugEnabled()) {
                        LOG.debug("loadDb: retry load file: " + fileName + " since last load was bad: " + timeMsg);
                    }
            
                }
            } else {
                fstat = new ZpeFileStatus(fileName, lastModMilliSeconds);
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

    /**
     * Loads and parses the given file. It will create the domain assertion
     * list per role and put it into the domain policy maps(domRoleMap, domWildcardRoleMap).
     **/
    private void loadFile(File polFile) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("loadFile: file(" + polFile.getName() + ")");
        }
        
        Path path = Paths.get(polDirName + File.separator + polFile.getName());
        DomainSignedPolicyData spols = null;
        try {
            spols = JSON.fromBytes(Files.readAllBytes(path), DomainSignedPolicyData.class);
        } catch (Exception ex) {
            LOG.error("loadFile: unable to decode policy file=" + polFile.getName() + " error: " + ex.getMessage());
        }
        if (spols == null) {
            LOG.error("loadFile: unable to decode domain file=" + polFile.getName());
            // mark this as an invalid file
            Map<String, ZpeFileStatus> fsmap = getFileStatusMap();
            ZpeFileStatus fstat = fsmap.get(polFile.getName());
            if (fstat != null) {
                fstat.validPolFile = false;
            }
            return;
        }
        
        SignedPolicyData signedPolicyData = spols.getSignedPolicyData();
        String signature = spols.getSignature();
        String keyId = spols.getKeyId();
        
        // first let's verify the ZTS signature for our policy file
        
        boolean verified = false;
        if (signedPolicyData != null) {
            java.security.PublicKey pubKey = AuthZpeClient.getZtsPublicKey(keyId);
            verified = Crypto.verify(SignUtils.asCanonicalString(signedPolicyData), pubKey, signature);
        }
        
        PolicyData policyData = null;
        if (verified) {
            // now let's verify that the ZMS signature for our policy file
            policyData = signedPolicyData.getPolicyData();
            signature = signedPolicyData.getZmsSignature();
            keyId = signedPolicyData.getZmsKeyId();
            
            if (policyData != null) {
                java.security.PublicKey pubKey = AuthZpeClient.getZmsPublicKey(keyId);
                verified = Crypto.verify(SignUtils.asCanonicalString(policyData), pubKey, signature);
            }
        }
        
         if (!verified || policyData == null) {
             LOG.error("loadFile: policy file=" + polFile.getName() + " is invalid");
             // mark this as an invalid file
             Map<String, ZpeFileStatus> fsmap = getFileStatusMap();
             ZpeFileStatus fstat = fsmap.get(polFile.getName());
             if (fstat != null) {
                 fstat.validPolFile = false;
             }
             return;
         }
         
        // HAVE: valid policy file
        
        String domainName = policyData.getDomain();
        if (LOG.isDebugEnabled()) {
            LOG.debug("loadFile: policy file(" + polFile.getName() + ") for domain(" + domainName + ") is valid");
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
                LOG.debug("loadFile: domain(" + domainName + ") policy(" + pname + ")");
            }
            List<Assertion> assertions = policy.getAssertions();
            if (assertions == null) {
                continue;
            }
            for (Assertion assertion : assertions) {
                com.yahoo.rdl.Struct strAssert = new Struct();
                strAssert.put(ZpeConsts.ZPE_FIELD_POLICY_NAME, pname);
                
                String passertAction = assertion.getAction();
                ZpeMatch matchStruct = getMatchObject(passertAction);
                strAssert.put(ZpeConsts.ZPE_ACTION_MATCH_STRUCT, matchStruct);
                
                String passertResource = assertion.getResource();
                String rsrc = AuthZpeClient.stripDomainPrefix(passertResource, domainName, passertResource);
                strAssert.put(ZpeConsts.ZPE_FIELD_RESOURCE, rsrc);
                matchStruct = getMatchObject(rsrc);
                strAssert.put(ZpeConsts.ZPE_RESOURCE_MATCH_STRUCT, matchStruct);

                String passertRole = assertion.getRole();
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

