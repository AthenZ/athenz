/*
 *  Copyright 2020 Verizon Media
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

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.yahoo.athenz.common.server.store.AWSCredentialsRefresher;
import com.yahoo.athenz.common.server.util.ConfigProperties;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT_DEFAULT;
import static com.yahoo.athenz.zts.ZTSConsts.*;

public class CloudStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(CloudStore.class);
    private static final String AWS_ROLE_SESSION_NAME = "athenz-zts-service";

    boolean awsEnabled;
    int cacheTimeout;
    int invalidCacheTimeout;
    private Map<String, String> cloudAccountCache;
    ConcurrentHashMap<String, AWSTemporaryCredentials> awsCredsCache;
    ConcurrentHashMap<String, Long> awsInvalidCredsCache;
    AWSCredentialsRefresher awsCredentialsRefresher = null;


    private ScheduledExecutorService scheduledThreadPool = null;

    public CloudStore() {

        // initialize our account and cred cache

        cloudAccountCache = new HashMap<>();
        awsCredsCache = new ConcurrentHashMap<>();
        awsInvalidCredsCache = new ConcurrentHashMap<>();

        // get the default cache timeout in seconds

        cacheTimeout = Integer.parseInt(
                System.getProperty(ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT, "600"));

        invalidCacheTimeout = Integer.parseInt(
                System.getProperty(ZTS_PROP_AWS_CREDS_INVALID_CACHE_TIMEOUT, "120"));

        // initialize aws support

        awsEnabled = Boolean.parseBoolean(
                System.getProperty(ZTS_PROP_AWS_ENABLED, "false"));
        initializeAwsSupport();
    }

    public void close() {
        if (scheduledThreadPool != null) {
            scheduledThreadPool.shutdownNow();
        }

        if (awsCredentialsRefresher != null) {
            awsCredentialsRefresher.close();
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

        // Instantiate credentials fetcher (null check for tests that override it)
        if (awsCredentialsRefresher == null) {
            awsCredentialsRefresher = new AWSCredentialsRefresher();

        }
        // Start Credentials Cache Cleaner Task

        int credsUpdateTime = ConfigProperties.retrieveConfigSetting(
                ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT, ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT_DEFAULT);

        scheduledThreadPool = Executors.newScheduledThreadPool(1);
        scheduledThreadPool.scheduleAtFixedRate(new AWSCredentialsCacheCleaner(), credsUpdateTime,
                credsUpdateTime, TimeUnit.SECONDS);
    }

    AssumeRoleRequest getAssumeRoleRequest(String account, String roleName,
                                           Integer durationSeconds, String externalId) {

        // assume the target role to get the credentials for the client
        // aws format is arn:aws:iam::<account-id>:role/<role-name>

        final String arn = "arn:aws:iam::" + account + ":role/" + roleName;

        AssumeRoleRequest req = new AssumeRoleRequest();
        req.setRoleArn(arn);

        // for role session name AWS has a limit on length: 64
        // so we need to make sure our session is shorter than that

        req.setRoleSessionName(AWS_ROLE_SESSION_NAME);
        if (durationSeconds != null && durationSeconds > 0) {
            req.setDurationSeconds(durationSeconds);
        }
        if (externalId != null && !externalId.isEmpty()) {
            req.setExternalId(externalId);
        }
        return req;
    }

    public AWSSecurityTokenService getTokenServiceClient() {
        AWSCredentials credentials = awsCredentialsRefresher.getCredentials();
        String awsRegion = awsCredentialsRefresher.getAwsRegion();

        return AWSSecurityTokenServiceClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion(Regions.fromName(awsRegion))
                .build();
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

        long checkTime = System.currentTimeMillis() - invalidCacheTimeout * 1000;
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
                                                 Integer durationSeconds, String externalId) {

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
            LOGGER.error("CloudStore: assumeAWSRole - failed cached request for account {} with role: {}",
                    account, roleName);
            return null;
        }

        AssumeRoleRequest req = getAssumeRoleRequest(account, roleName,
                durationSeconds, externalId);

        try {
            AWSSecurityTokenService client = getTokenServiceClient();
            AssumeRoleResult res = client.assumeRole(req);

            Credentials awsCreds = res.getCredentials();
            tempCreds = new AWSTemporaryCredentials()
                    .setAccessKeyId(awsCreds.getAccessKeyId())
                    .setSecretAccessKey(awsCreds.getSecretAccessKey())
                    .setSessionToken(awsCreds.getSessionToken())
                    .setExpiration(Timestamp.fromMillis(awsCreds.getExpiration().getTime()));

        } catch (AmazonServiceException ex) {

            LOGGER.error("CloudStore: assumeAWSRole - unable to assume role: {}, error: {}, status code: {}",
                    req.getRoleArn(), ex.getMessage(), ex.getStatusCode());

            // if this is access denied then we're going to cache
            // the failed results

            if (ex.getStatusCode() == ResourceException.FORBIDDEN) {
                putInvalidCacheCreds(cacheKey);
            }

            return null;

        } catch (Exception ex) {

            LOGGER.error("CloudStore: assumeAWSRole - unable to assume role: {}, error: {}",
                    req.getRoleArn(), ex.getMessage());

            return null;
        }

        putCacheCreds(cacheKey, tempCreds);
        return tempCreds;
    }

    public String getCloudAccount(String domainName) {
        return cloudAccountCache.get(domainName);
    }

    public void updateAccount(String domainName, String account) {

        /* if we have a value specified for the domain, then we're just
         * going to insert it into our map and update the record. If
         * the new value is not present and we had a value stored before
         * then let's remove it */

        if (account != null && !account.isEmpty()) {
            cloudAccountCache.put(domainName, account);
        } else if (cloudAccountCache.get(domainName) != null) {
            cloudAccountCache.remove(domainName);
        }
    }

    class AWSCredentialsCacheCleaner implements Runnable {

        @Override
        public void run() {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("AWSCredentialsCacheCleaner: Starting aws credentials cache cleaner task...");
            }

            try {
                removeExpiredCredentials();
            } catch (Exception ex) {
                LOGGER.error("AWSCredentialsCacheCleaner: unable to remove expired aws credentials: {}",
                        ex.getMessage());
            }

            try {
                removeExpiredInvalidCredentials();
            } catch (Exception ex) {
                LOGGER.error("AWSCredentialsCacheCleaner: unable to remove expired invalid aws credentials: {}",
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

        String sshType = keyReq.getString(ZTS_SSH_TYPE);
        if (sshType == null) {
            LOGGER.error("getSshKeyReqType: SSH Key request does not have certtype: {}", sshKeyReq);
        }
        return sshType;
    }
}
