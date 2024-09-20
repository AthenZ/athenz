/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.store;

import java.util.HashMap;
import java.util.Map;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ConcurrentHashMap;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.util.ConfigProperties;
import io.athenz.server.aws.common.creds.impl.TempCredsProvider;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;

public class CloudStore {
    private static final Logger LOGGER = LoggerFactory.getLogger(CloudStore.class);

    boolean awsEnabled;
    int cacheTimeout;
    int invalidCacheTimeout;
    final private Map<String, String> awsAccountCache;
    final private Map<String, String> azureSubscriptionCache;
    final private Map<String, String> azureTenantCache;
    final private Map<String, String> azureClientCache;

    final private Map<String, String> gcpProjectIdCache;
    final private Map<String, String> gcpProjectNumberCache;
    ConcurrentHashMap<String, AWSTemporaryCredentials> awsCredsCache;
    ConcurrentHashMap<String, Long> awsInvalidCredsCache;
    TempCredsProvider tempCredsProvider;

    private ScheduledExecutorService scheduledThreadPool = null;

    public CloudStore() {

        // initialize our account and cred cache

        awsAccountCache = new HashMap<>();
        awsCredsCache = new ConcurrentHashMap<>();
        awsInvalidCredsCache = new ConcurrentHashMap<>();

        // initialize azure cache

        azureSubscriptionCache = new ConcurrentHashMap<>();
        azureTenantCache = new ConcurrentHashMap<>();
        azureClientCache = new ConcurrentHashMap<>();

        // initialize gcp cache

        gcpProjectIdCache = new ConcurrentHashMap<>();
        gcpProjectNumberCache = new ConcurrentHashMap<>();

        // get the default cache timeout in seconds

        cacheTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT, "600"));

        invalidCacheTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_AWS_CREDS_INVALID_CACHE_TIMEOUT, "120"));

        // initialize aws support

        awsEnabled = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_AWS_ENABLED, "false"));
        initializeAwsSupport();
    }

    public void close() {
        if (scheduledThreadPool != null) {
            scheduledThreadPool.shutdownNow();
        }
    }

    public boolean isAwsEnabled() {
        return awsEnabled;
    }

    void initializeAwsSupport() {

        // these operations require initialization of aws objects so
        // we'll process them only if we have been configured to run in aws

        if (!awsEnabled) {
            return;
        }

        try {
            tempCredsProvider = new TempCredsProvider();
            tempCredsProvider.initialize();
        } catch (ServerResourceException ex) {
            LOGGER.error("unable to initialize aws temporary credentials provider: {}", ex.getMessage());
            throw new ResourceException(ex.getCode(), ex.getMessage());
        }

        // Start our thread to get/update aws temporary credentials

        int credsUpdateTime = ConfigProperties.retrieveConfigSetting(
                ZTSConsts.ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT, 900);

        scheduledThreadPool = Executors.newScheduledThreadPool(1);
        scheduledThreadPool.scheduleAtFixedRate(new AWSCredentialsUpdater(), credsUpdateTime,
                credsUpdateTime, TimeUnit.SECONDS);
    }

    String getCacheKey(final String account, final String roleName, final String principal,
                       Integer durationSeconds, final String externalId) {

        // if our cache is disabled there is no need to generate
        // a cache key since all other operations are no-ops

        if (cacheTimeout == 0) {
            return null;
        }

        StringBuilder cacheKey = new StringBuilder(256);
        cacheKey.append(account).append(':').append(roleName).append(':').append(principal);
        cacheKey.append(':');
        if (durationSeconds != null) {
            cacheKey.append(durationSeconds.intValue());
        }
        cacheKey.append(':');
        if (externalId != null) {
            cacheKey.append(externalId);
        }
        return cacheKey.toString();
    }

    boolean removeExpiredCredentials() {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Checking for expired cached credentials in {} entries", awsCredsCache.size());
        }

        // iterate through all entries in the map and remove any
        // entries that have been expired already

        long now = System.currentTimeMillis();
        return awsCredsCache.entrySet().removeIf(entry -> entry.getValue().getExpiration().millis() < now);
    }

    boolean removeExpiredInvalidCredentials() {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Checking for expired invalid cached credentials in {} entries", awsInvalidCredsCache.size());
        }

        // iterate through all entries in the map and remove any
        // entries that have been expired already

        long checkTime = System.currentTimeMillis() - invalidCacheTimeout * 1000L;
        return awsInvalidCredsCache.entrySet().removeIf(entry -> entry.getValue() <= checkTime);
    }

    boolean isFailedTempCredsRequest(final String cacheKey) {

        // if our cache is disabled there is no need for a lookup

        if (invalidCacheTimeout == 0) {
            return false;
        }

        Long timeStamp = awsInvalidCredsCache.get(cacheKey);
        if (timeStamp == null) {
            return false;
        }

        // we're going to cache any creds for configured number of seconds

        long diffSeconds = (System.currentTimeMillis() - timeStamp) / 1000;
        return diffSeconds < invalidCacheTimeout;
    }

    void putInvalidCacheCreds(final String key) {

        // if our cache is disabled we do nothing

        if (invalidCacheTimeout == 0) {
            return;
        }

        awsInvalidCredsCache.put(key, System.currentTimeMillis());
    }

    AWSTemporaryCredentials getCachedCreds(final String cacheKey, Integer durationSeconds) {

        // if our cache is disabled there is no need for a lookup

        if (cacheTimeout == 0) {
            return null;
        }

        AWSTemporaryCredentials tempCreds = awsCredsCache.get(cacheKey);
        if (tempCreds == null) {
            return null;
        }

        // we're going to cache any creds for 10 mins only

        long diffSeconds = (tempCreds.getExpiration().millis() - System.currentTimeMillis()) / 1000;
        if (durationSeconds == null || durationSeconds <= 0) {
            durationSeconds = 3600; // default 1 hour
        }
        if (durationSeconds - diffSeconds > cacheTimeout) {
            return null;
        }

        return tempCreds;
    }

    void putCacheCreds(final String key, AWSTemporaryCredentials tempCreds) {

        // if our cache is disabled we do nothing

        if (cacheTimeout == 0) {
            return;
        }

        awsCredsCache.put(key, tempCreds);
    }

    public AWSTemporaryCredentials assumeAWSRole(String account, String roleName, String principal,
            Integer durationSeconds, String externalId, StringBuilder errorMessage) {

        if (!awsEnabled) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "AWS Support not enabled");
        }

        // first check to see if we already have the temp creds cached

        final String cacheKey = getCacheKey(account, roleName, principal,
                durationSeconds, externalId);
        AWSTemporaryCredentials tempCreds = getCachedCreds(cacheKey, durationSeconds);
        if (tempCreds != null) {
            return tempCreds;
        }

        // before going to AWS STS, check if we have the request in our failed
        // cache since we don't want to generate too many requests AWS STS
        // and eventually become rate limited

        if (isFailedTempCredsRequest(cacheKey)) {
            errorMessage.append("Cached invalid request. Retry operation after ").append(invalidCacheTimeout)
                    .append(" seconds.");
            return null;
        }

        try {
            tempCreds = tempCredsProvider.getTemporaryCredentials(account, roleName, principal,
                    durationSeconds, externalId, errorMessage);
        } catch (ServerResourceException ex) {

            if (ex.getCode() == ServerResourceException.FORBIDDEN) {
                putInvalidCacheCreds(cacheKey);
            }

            return null;
        }

        putCacheCreds(cacheKey, tempCreds);
        return tempCreds;
    }

    public String getAwsAccount(String domainName) {
        return awsAccountCache.get(domainName);
    }

    public String getAzureSubscription(String domainName) {
        return azureSubscriptionCache.get(domainName);
    }

    public String getAzureTenant(String domainName) {
        return azureTenantCache.get(domainName);
    }

    public String getAzureClient(String domainName) {
        return azureClientCache.get(domainName);
    }

    public String getGCPProjectId(String domainName) {
        return gcpProjectIdCache.get(domainName);
    }

    public String getGCPProjectNumber(String domainName) {
        return gcpProjectNumberCache.get(domainName);
    }

    void updateAwsAccount(final String domainName, final String awsAccount) {

        /* if we have a value specified for the domain, then we're just
         * going to insert it into our map and update the record. If
         * the new value is not present, and we had a value stored before
         * then let's remove it */

        if (!StringUtil.isEmpty(awsAccount)) {
            awsAccountCache.put(domainName, awsAccount);
        } else if (awsAccountCache.get(domainName) != null) {
            awsAccountCache.remove(domainName);
        }
    }

    void updateAzureSubscription(final String domainName, final String azureSubscription, final String azureTenant, final String azureClient) {

        /* if we have a value specified for the domain, then we're just
         * going to insert it into our map and update the record. If
         * the new value is not present, and we had a value stored before
         * then let's remove it */

        if (!StringUtil.isEmpty(azureSubscription)) {
            azureSubscriptionCache.put(domainName, azureSubscription);
            if (!StringUtil.isEmpty(azureTenant)) {
                azureTenantCache.put(domainName, azureTenant);
            }
            if (!StringUtil.isEmpty(azureClient)) {
                azureClientCache.put(domainName, azureClient);
            }
        } else if (azureSubscriptionCache.get(domainName) != null) {
            azureSubscriptionCache.remove(domainName);
            azureTenantCache.remove(domainName);
            azureClientCache.remove(domainName);
        }
    }

    void updateGCPProject(final String domainName, final String gcpProjectId, final String gcpProjectNumber) {

        /* if we have a value specified for the domain, then we're just
         * going to insert it into our map and update the record. If
         * the new value is not present, and we had a value stored before
         * then let's remove it */

        if (!StringUtil.isEmpty(gcpProjectId)) {
            gcpProjectIdCache.put(domainName, gcpProjectId);
            if (!StringUtil.isEmpty(gcpProjectNumber)) {
                gcpProjectNumberCache.put(domainName, gcpProjectNumber);
            }
        } else if (gcpProjectIdCache.get(domainName) != null) {
            gcpProjectIdCache.remove(domainName);
            gcpProjectNumberCache.remove(domainName);
        }
    }

    class AWSCredentialsUpdater implements Runnable {

        @Override
        public void run() {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("AWSCredentialsUpdater: Starting aws credentials updater task...");
            }

            try {
                tempCredsProvider.fetchRoleCredentials();
            } catch (Exception ex) {
                LOGGER.error("AWSCredentialsUpdater: unable to fetch aws role credentials: {}",
                        ex.getMessage());
            }

            try {
                removeExpiredCredentials();
            } catch (Exception ex) {
                LOGGER.error("AWSCredentialsUpdater: unable to remove expired aws credentials: {}",
                        ex.getMessage());
            }

            try {
                removeExpiredInvalidCredentials();
            } catch (Exception ex) {
                LOGGER.error("AWSCredentialsUpdater: unable to remove expired invalid aws credentials: {}",
                        ex.getMessage());
            }
        }
    }

    String getSshKeyReqType(String sshKeyReq) {

        Struct keyReq = JSON.fromString(sshKeyReq, Struct.class);
        if (keyReq == null) {
            LOGGER.error("getSshKeyReqType: Unable to parse ssh key req: {}", sshKeyReq);
            return null;
        }

        String sshType = keyReq.getString(ZTSConsts.ZTS_SSH_TYPE);
        if (sshType == null) {
            LOGGER.error("getSshKeyReqType: SSH Key request does not have certtype: {}", sshKeyReq);
        }
        return sshType;
    }
}
