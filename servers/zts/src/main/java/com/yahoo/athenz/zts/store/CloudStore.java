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

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.regions.Regions;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import com.yahoo.athenz.zts.OSTKInstanceInformation;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;

public class CloudStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(CloudStore.class);
    private static final String AWS_ROLE_SESSION_NAME = "athenz-zts-service";

    String awsRole = null;
    String awsRegion;
    boolean awsEnabled;
    private int cacheTimeout;
    BasicSessionCredentials credentials;
    private Map<String, String> cloudAccountCache;
    private ConcurrentHashMap<String, AWSTemporaryCredentials> awsCredsCache;
    private HttpClient httpClient;

    private ScheduledExecutorService scheduledThreadPool = null;

    public CloudStore() {

        // initialize our account and cred cache

        cloudAccountCache = new HashMap<>();
        awsCredsCache = new ConcurrentHashMap<>();

        // Instantiate and start our HttpClient

        httpClient = new HttpClient();
        httpClient.setFollowRedirects(false);
        httpClient.setStopTimeout(1000);
        try {
            httpClient.start();
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to start http client", ex);
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Http client not available");
        }

        // check to see if we are given region name

        awsRegion = System.getProperty(ZTSConsts.ZTS_PROP_AWS_REGION_NAME);

        // get the default cache timeout

        cacheTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT, "600"));

        // initialize aws support

        awsEnabled = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_AWS_ENABLED, "false"));
        initializeAwsSupport();
    }

    public void close() {
        if (scheduledThreadPool != null) {
            scheduledThreadPool.shutdownNow();
        }
        stopHttpClient();
    }

    public void setHttpClient(HttpClient client) {
        stopHttpClient();
        httpClient = client;
    }

    private void stopHttpClient() {
        if (httpClient == null) {
            return;
        }
        try {
            httpClient.stop();
        } catch (Exception ignored) {
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

        // initialize and load our bootstrap data

        if (!loadBootMetaData()) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to load boot data");
        }

        // finally fetch the role credentials

        if (!fetchRoleCredentials())  {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to fetch aws role credentials");
        }

        // Start our thread to get/update aws temporary credentials

        int credsUpdateTime = ZTSUtils.retrieveConfigSetting(
                ZTSConsts.ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT, 900);

        scheduledThreadPool = Executors.newScheduledThreadPool(1);
        scheduledThreadPool.scheduleAtFixedRate(new AWSCredentialsUpdater(), credsUpdateTime,
                credsUpdateTime, TimeUnit.SECONDS);
    }

    public AmazonS3 getS3Client() {

        if (!awsEnabled) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "AWS Support not enabled");
        }

        if (credentials == null) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "AWS Role credentials are not available");
        }

        return AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion(Regions.fromName(awsRegion))
                .build();
    }

    boolean loadBootMetaData() {

        // first load the dynamic document

        String document = getMetaData("/dynamic/instance-identity/document");
        if (document == null) {
            return false;
        }

        try {
            if (!parseInstanceInfo(document)) {
                return false;
            }
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to parse instance identity document: {}, error: {}",
                    document, ex.getMessage());
            return false;
        }

        // then the document signature

        String docSignature = getMetaData("/dynamic/instance-identity/pkcs7");
        if (docSignature == null) {
            return false;
        }

        // next the iam profile data

        String iamRole = getMetaData("/meta-data/iam/info");
        if (iamRole == null) {
            return false;
        }

        // now parse and extract the profile details. we'll catch
        // all possible index out of bounds exceptions here and just
        // report the error and return false

        try {
            if (!parseIamRoleInfo(iamRole)) {
                return false;
            }
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to parse iam role data: {}, error: {}",
                    iamRole, ex.getMessage());
            return false;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("CloudStore: service meta information:");
            LOGGER.debug("CloudStore:   role:   {}", awsRole);
            LOGGER.debug("CloudStore:   region: {}", awsRegion);
        }
        return true;
    }

    boolean parseInstanceInfo(String document) {

        Struct instStruct = JSON.fromString(document, Struct.class);
        if (instStruct == null) {
            LOGGER.error("CloudStore: unable to parse instance identity document: {}", document);
            return false;
        }

        // if we're overriding the region name, then we'll
        // extract that value here

        if (awsRegion == null || awsRegion.isEmpty()) {
            awsRegion = instStruct.getString("region");
            if (awsRegion == null || awsRegion.isEmpty()) {
                LOGGER.error("CloudStore: unable to extract region from instance identity document: {}",
                        document);
                return false;
            }
        }

        return true;
    }

    boolean parseIamRoleInfo(String iamRole) {

        Struct iamRoleStruct = JSON.fromString(iamRole, Struct.class);
        if (iamRoleStruct == null) {
            LOGGER.error("CloudStore: unable to parse iam role data: {}", iamRole);
            return false;
        }

        // extract and parse our profile arn
        // "InstanceProfileArn" : "arn:aws:iam::1111111111111:instance-profile/iaas.athenz.zts,athenz",

        String profileArn = iamRoleStruct.getString("InstanceProfileArn");
        if (profileArn == null || profileArn.isEmpty()) {
            LOGGER.error("CloudStore: unable to extract InstanceProfileArn from iam role data: {}", iamRole);
            return false;
        }

        return parseInstanceProfileArn(profileArn);
    }

    boolean parseInstanceProfileArn(String profileArn) {

        // "InstanceProfileArn" : "arn:aws:iam::1111111111111:instance-profile/iaas.athenz.zts,athenz",

        if (!profileArn.startsWith("arn:aws:iam::")) {
            LOGGER.error("CloudStore: InstanceProfileArn does not start with 'arn:aws:iam::' : {}",
                    profileArn);
            return false;
        }

        int idx = profileArn.indexOf(":instance-profile/");
        if (idx == -1) {
            LOGGER.error("CloudStore: unable to parse InstanceProfileArn: {}", profileArn);
            return false;
        }

        final String awsProfile = profileArn.substring(idx + ":instance-profile/".length());

        // make sure we have valid profile and account data

        if (awsProfile.isEmpty()) {
            LOGGER.error("CloudStore: unable to extract profile/account data from InstanceProfileArn: {}",
                    profileArn);
            return false;
        }

        // we need to extract the role from the profile

        idx = awsProfile.indexOf(',');
        if (idx == -1) {
            awsRole = awsProfile;
        } else {
            awsRole = awsProfile.substring(0, idx);
        }

        return true;
    }

    boolean fetchRoleCredentials() {

        // verify that we have a valid awsRole already retrieved

        if (awsRole == null || awsRole.isEmpty()) {
            LOGGER.error("CloudStore: awsRole is not avaialble to fetch role credentials");
            return false;
        }

        final String creds = getMetaData("/meta-data/iam/security-credentials/" + awsRole);
        if (creds == null) {
            return false;
        }

        Struct credsStruct = JSON.fromString(creds, Struct.class);
        if (credsStruct == null) {
            LOGGER.error("CloudStore: unable to parse role credentials data: {}", creds);
            return false;
        }

        String accessKeyId = credsStruct.getString("AccessKeyId");
        String secretAccessKey = credsStruct.getString("SecretAccessKey");
        String token = credsStruct.getString("Token");

        credentials = new BasicSessionCredentials(accessKeyId, secretAccessKey, token);
        return true;
    }

    String getMetaData(String path) {

        final String baseUri = "http://169.254.169.254/latest";
        ContentResponse response;
        try {
            response = httpClient.GET(baseUri + path);
        } catch (InterruptedException | ExecutionException | TimeoutException ex) {
            LOGGER.error("CloudStore: unable to fetch requested uri '{}':{}",
                    path, ex.getMessage());
            return null;
        }
        if (response.getStatus() != 200) {
            LOGGER.error("CloudStore: unable to fetch requested uri '{}' status:{}",
                    path, response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (data == null || data.isEmpty()) {
            LOGGER.error("CloudStore: received empty response from uri '{}' status:{}",
                    path, response.getStatus());
            return null;
        }

        return data;
    }

    AssumeRoleRequest getAssumeRoleRequest(String account, String roleName, String principal,
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

    AWSSecurityTokenService getTokenServiceClient() {

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

        final String cacheKey = getCacheKey(account, roleName, principal,
                durationSeconds, externalId);
        AWSTemporaryCredentials tempCreds = getCachedCreds(cacheKey, durationSeconds);
        if (tempCreds != null) {
            return tempCreds;
        }

        AssumeRoleRequest req = getAssumeRoleRequest(account, roleName, principal,
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

    void updateAccount(String domainName, String account) {

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

    public boolean verifyInstanceDocument(OSTKInstanceInformation info, String publicKey) {

        // for now we're only validating the document signature

        boolean verified = false;
        try {
            final PublicKey pub = Crypto.loadPublicKey(publicKey);
            verified = Crypto.verify(info.getDocument(), pub, info.getSignature());
            if (!verified) {
                LOGGER.error("verifyInstanceDocument: OSTK document signature did not match");
            }
        } catch (Exception ex) {
            LOGGER.error("verifyInstanceDocument: Unable to verify signature: {}",
                    ex.getMessage());
        }
        return verified;
    }

    class AWSCredentialsUpdater implements Runnable {

        @Override
        public void run() {

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("AWSCredentialsUpdater: Starting aws credentials updater task...");
            }

            try {
                fetchRoleCredentials();
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
