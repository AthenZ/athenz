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

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ConcurrentHashMap;

import com.amazonaws.AmazonServiceException;
import com.yahoo.athenz.common.server.util.ConfigProperties;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.ContentResponse;
import org.eclipse.jetty.client.Request;
import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.util.StringUtil;
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
import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import com.yahoo.rdl.Timestamp;

import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_AWS_REGION_NAME;

public class CloudStore {
    private static final Logger LOGGER = LoggerFactory.getLogger(CloudStore.class);

    private static final String AWS_METADATA_BASE_URI = "http://169.254.169.254/latest";
    private static final String AWS_METADATA_TOKEN_URI = "http://169.254.169.254/latest/api/token";
    private static final String AWS_METADATA_TOKEN_HEADER = "X-aws-ec2-metadata-token";
    private static final String AWS_METADATA_TOKEN_TTL_HEADER = "X-aws-ec2-metadata-token-ttl-seconds";

    String awsRole = null;
    String awsRegion;
    String awsRoleSessionName;
    boolean awsEnabled;
    int cacheTimeout;
    int invalidCacheTimeout;
    BasicSessionCredentials credentials;
    final private Map<String, String> awsAccountCache;
    final private Map<String, String> azureSubscriptionCache;
    final private Map<String, String> azureTenantCache;
    final private Map<String, String> azureClientCache;

    final private Map<String, String> gcpProjectIdCache;
    final private Map<String, String> gcpProjectNumberCache;
    ConcurrentHashMap<String, AWSTemporaryCredentials> awsCredsCache;
    ConcurrentHashMap<String, Long> awsInvalidCredsCache;
    private HttpClient httpClient;

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

        // Instantiate and start our HttpClient

        httpClient = new HttpClient();
        setupHttpClient(httpClient);

        // check to see if we are given region name

        awsRegion = System.getProperty(ZTS_PROP_AWS_REGION_NAME);

        // get the default cache timeout in seconds

        cacheTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT, "600"));

        invalidCacheTimeout = Integer.parseInt(
                System.getProperty(ZTSConsts.ZTS_PROP_AWS_CREDS_INVALID_CACHE_TIMEOUT, "120"));

        // fetch the default session name if one is configured

        awsRoleSessionName = System.getProperty(ZTSConsts.ZTS_PROP_AWS_ROLE_SESSION_NAME);

        // initialize aws support

        awsEnabled = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_AWS_ENABLED, "false"));
        initializeAwsSupport();
    }

    void setupHttpClient(HttpClient client) {

        client.setFollowRedirects(false);
        try {
            client.start();
        } catch (Exception ex) {
            LOGGER.error("CloudStore: unable to start http client", ex);
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Http client not available");
        }
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

        int credsUpdateTime = ConfigProperties.retrieveConfigSetting(
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

        final String document = getMetaData("/dynamic/instance-identity/document");
        if (document == null) {
            return false;
        }

        if (!parseInstanceInfo(document)) {
            LOGGER.error("CloudStore: unable to parse instance identity document: {}", document);
            return false;
        }

        // then the document signature

        final String docSignature = getMetaData("/dynamic/instance-identity/pkcs7");
        if (docSignature == null) {
            return false;
        }

        // next the iam profile data

        final String iamRole = getMetaData("/meta-data/iam/info");
        if (iamRole == null) {
            return false;
        }

        // now parse and extract the profile details. we'll catch
        // all possible index out of bounds exceptions here and just
        // report the error and return false

        if (!parseIamRoleInfo(iamRole)) {
            LOGGER.error("CloudStore: unable to parse iam role data: {}", iamRole);
            return false;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("CloudStore: service meta information:");
            LOGGER.debug("CloudStore: role:   {}", awsRole);
            LOGGER.debug("CloudStore: region: {}", awsRegion);
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

        if (StringUtil.isEmpty(awsRegion)) {
            awsRegion = instStruct.getString("region");
            if (StringUtil.isEmpty(awsRegion)) {
                LOGGER.error("CloudStore: unable to extract region from instance identity document: {}", document);
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
        if (StringUtil.isEmpty(profileArn)) {
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

        if (StringUtil.isEmpty(awsRole)) {
            LOGGER.error("CloudStore: awsRole is not available to fetch role credentials");
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

        // first we need to get a token for IMDSv2 support
        // if the token is not available we'll just try without
        // it to see if we can get the data with v1 support

        final String token = processHttpRequest(HttpMethod.PUT, AWS_METADATA_TOKEN_URI, AWS_METADATA_TOKEN_TTL_HEADER, "60");
        if (StringUtil.isEmpty(token)) {
            LOGGER.info("unable to get token for IMDSv2 support");
        }
        return processHttpRequest(HttpMethod.GET, AWS_METADATA_BASE_URI + path, AWS_METADATA_TOKEN_HEADER, token);
    }

    String processHttpRequest(HttpMethod httpMethod, String uri, String headerName, String headerValue) {

        ContentResponse response;
        try {
            Request request = httpClient.newRequest(URI.create(uri)).method(httpMethod);
            if (!StringUtil.isEmpty(headerName) && !StringUtil.isEmpty(headerValue)) {
                request.headers((fields) -> fields.put(headerName, headerValue));
            }
            response = request.send();
        } catch (Exception ex) {
            LOGGER.error("unable to fetch requested uri '{}':{}", uri, ex.getMessage());
            return null;
        }
        if (response.getStatus() != 200) {
            LOGGER.error("unable to fetch requested uri '{}' status:{}", uri, response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (StringUtil.isEmpty(data)) {
            LOGGER.error("received empty response from uri '{}' status:{}", uri, response.getStatus());
            return null;
        }

        return data;
    }

    String getAssumeRoleSessionName(final String principal) {

        // if we're configured to use a specific session name
        // then that's what we'll use and ignore the principal name

        if (!StringUtil.isEmpty(awsRoleSessionName)) {
            return awsRoleSessionName;
        }

        // make sure the role session name is valid and not too long
        // and does not contain any invalid characters. From aws docs:
        //   Length Constraints: Minimum length of 2. Maximum length of 64.
        //   Pattern: [\w+=,.@-]*
        // if the Athenz principal identity is longer than 64 characters,
        // we'll truncate the principal name to 60 and add insert ... in
        // the middle to indicate truncation

        return (principal.length() > 64) ?
                principal.substring(0, 30) + "..." + principal.substring(principal.length() - 30) : principal;
    }

    AssumeRoleRequest getAssumeRoleRequest(final String account, final String roleName, Integer durationSeconds,
            final String externalId, final String principal) {

        // assume the target role to get the credentials for the client
        // aws format is arn:aws:iam::<account-id>:role/<role-name>

        final String arn = "arn:aws:iam::" + account + ":role/" + roleName;

        AssumeRoleRequest req = new AssumeRoleRequest();
        req.setRoleArn(arn);
        req.setRoleSessionName(getAssumeRoleSessionName(principal));
        if (durationSeconds != null && durationSeconds > 0) {
            req.setDurationSeconds(durationSeconds);
        }
        if (!StringUtil.isEmpty(externalId)) {
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

        AssumeRoleRequest req = getAssumeRoleRequest(account, roleName, durationSeconds, externalId, principal);

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

            errorMessage.append(ex.getErrorMessage());
            return null;

        } catch (Exception ex) {

            LOGGER.error("CloudStore: assumeAWSRole - unable to assume role: {}, error: {}",
                    req.getRoleArn(), ex.getMessage());

            errorMessage.append(ex.getMessage());
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
