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

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static com.yahoo.athenz.zts.ZTSConsts.ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

import java.util.Date;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.yahoo.athenz.common.server.store.AWSCredentialsRefresher;
import com.yahoo.athenz.common.server.store.AWSInstanceMetadataFetcher;
import com.yahoo.rdl.Timestamp;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import com.yahoo.athenz.zms.ResourceException;

public class CloudStoreTest {
    public final static String AWS_INSTANCE_DOCUMENT = "{\n"
            + "  \"devpayProductCodes\" : null,\n"
            + "  \"availabilityZone\" : \"us-west-2a\",\n"
            + "  \"privateIp\" : \"10.10.10.10\",\n"
            + "  \"version\" : \"2010-08-31\",\n"
            + "  \"instanceId\" : \"i-056921225f1fbb47a\",\n"
            + "  \"billingProducts\" : null,\n"
            + "  \"instanceType\" : \"t2.micro\",\n"
            + "  \"accountId\" : \"111111111111\",\n"
            + "  \"pendingTime\" : \"2016-04-26T05:37:23Z\",\n"
            + "  \"imageId\" : \"ami-c229c0a2\",\n"
            + "  \"architecture\" : \"x86_64\",\n"
            + "  \"kernelId\" : null,\n"
            + "  \"ramdiskId\" : null,\n"
            + "  \"region\" : \"us-west-2\"\n"
            + "}";

    public final static String AWS_IAM_ROLE_INFO = "{\n"
            + "\"Code\" : \"Success\",\n"
            + "\"LastUpdated\" : \"2016-04-26T05:37:04Z\",\n"
            + "\"InstanceProfileArn\" : \"arn:aws:iam::111111111111:instance-profile/athenz.zts,athenz\",\n"
            + "\"InstanceProfileId\" : \"AIPAJAVNLUGEWFWTIDPRA\"\n"
            + "}";

    @Test
    public void testGetTokenServiceClient() {
        CloudStore store = new CloudStore();
        AWSCredentialsRefresher credentialsRefresher = Mockito.mock(AWSCredentialsRefresher.class);
        when(credentialsRefresher.getCredentials()).thenReturn(new BasicSessionCredentials("accessKey", "secretKey", "token"));
        when(credentialsRefresher.getAwsRegion()).thenReturn("us-west-2");

        store.awsCredentialsRefresher = credentialsRefresher;
        store.awsEnabled = true;
        assertNotNull(store.getTokenServiceClient());
        store.close();
    }

    @Test
    public void testUpdateAccountUpdate() {

        CloudStore store = new CloudStore();
        assertNull(store.getCloudAccount("iaas"));

        // set the account to 1234

        store.updateAccount("iaas", "1234");
        assertEquals("1234", store.getCloudAccount("iaas"));

        // update the account value

        store.updateAccount("iaas", "1235");
        assertEquals("1235", store.getCloudAccount("iaas"));
        store.close();
    }

    @Test
    public void testUpdateAccountDelete() {

        CloudStore store = new CloudStore();

        // set the account to 1234

        store.updateAccount("iaas", "1234");
        assertEquals("1234", store.getCloudAccount("iaas"));

        // delete the account with null

        store.updateAccount("iaas", null);
        assertNull(store.getCloudAccount("iaas"));

        // update the account value

        store.updateAccount("iaas", "1235");
        assertEquals("1235", store.getCloudAccount("iaas"));

        // delete the account with empty string

        store.updateAccount("iaas", "");
        assertNull(store.getCloudAccount("iaas"));
        store.close();
    }

    @Test
    public void testGetAssumeRoleRequest() {

        CloudStore store = new CloudStore();
        AssumeRoleRequest req = store.getAssumeRoleRequest("1234", "admin", null, null);
        assertEquals("arn:aws:iam::1234:role/admin", req.getRoleArn());
        assertEquals("athenz-zts-service", req.getRoleSessionName());
        assertNull(req.getDurationSeconds());
        assertNull(req.getExternalId());

        req = store.getAssumeRoleRequest("12345", "adminuser", 101, "external");
        assertEquals("arn:aws:iam::12345:role/adminuser", req.getRoleArn());
        assertEquals("athenz-zts-service", req.getRoleSessionName());
        assertEquals(Integer.valueOf(101), req.getDurationSeconds());
        assertEquals("external", req.getExternalId());
        store.close();
    }

    @Test
    public void testInitializeAwsSupport()  throws ExecutionException, TimeoutException {

        ContentResponse responseDoc = Mockito.mock(ContentResponse.class);
        Mockito.when(responseDoc.getStatus()).thenReturn(200);
        Mockito.when(responseDoc.getContentAsString()).thenReturn(AWS_INSTANCE_DOCUMENT);

        ContentResponse responseSig = Mockito.mock(ContentResponse.class);
        Mockito.when(responseSig.getStatus()).thenReturn(200);
        Mockito.when(responseSig.getContentAsString()).thenReturn("pkcs7-signature");

        ContentResponse responseInfo = Mockito.mock(ContentResponse.class);
        Mockito.when(responseInfo.getStatus()).thenReturn(200);
        Mockito.when(responseInfo.getContentAsString()).thenReturn(AWS_IAM_ROLE_INFO);

        ContentResponse responseCreds = Mockito.mock(ContentResponse.class);
        Mockito.when(responseCreds.getStatus()).thenReturn(200);
        Mockito.when(responseCreds.getContentAsString()).thenReturn("{\"AccessKeyId\":\"id\",\"SecretAccessKey\":\"key\",\"Token\":\"token\"}");

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        try {
            Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/document")).thenReturn(responseDoc);
        } catch (InterruptedException ignored) {
        }
        try {
            Mockito.when(httpClient.GET("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")).thenReturn(responseSig);
        } catch (InterruptedException ignored) {
        }
        try {
            Mockito.when(httpClient.GET("http://169.254.169.254/latest/meta-data/iam/info")).thenReturn(responseInfo);
        } catch (InterruptedException ignored) {
        }
        try {
            Mockito.when(httpClient.GET("http://169.254.169.254/latest/meta-data/iam/security-credentials/athenz.zts")).thenReturn(responseCreds);
        } catch (InterruptedException ignored) {
        }

        AWSInstanceMetadataFetcher awsInstanceMetadataFetcher = new AWSInstanceMetadataFetcher();
        awsInstanceMetadataFetcher.setHttpClient(httpClient);
        AWSCredentialsRefresher awsCredentialsRefresher = new AWSCredentialsRefresher(awsInstanceMetadataFetcher);
        CloudStore store = new CloudStore();
        store.awsCredentialsRefresher = awsCredentialsRefresher;

        // set creds update time every second

        System.setProperty(ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT, "1");

        store.awsEnabled = true;
        store.initializeAwsSupport();

        // sleep a couple of seconds for the background thread to run
        // before we try to shutting it down

        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }
        store.close();

        System.clearProperty(ZTS_PROP_AWS_CREDS_UPDATE_TIMEOUT);
    }

    @Test
    public void testAssumeAWSRoleAWSNotEnabled() {
        CloudStore cloudStore = new CloudStore();
        try {
            cloudStore.assumeAWSRole("account", "sycner", "athenz.syncer", null, null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        cloudStore.close();
    }

    @Test
    public void testAssumeAWSRole() {
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.awsEnabled = true;
        AssumeRoleResult mockResult = Mockito.mock(AssumeRoleResult.class);
        Credentials creds = Mockito.mock(Credentials.class);
        Mockito.when(creds.getAccessKeyId()).thenReturn("accesskeyid");
        Mockito.when(creds.getSecretAccessKey()).thenReturn("secretaccesskey");
        Mockito.when(creds.getSessionToken()).thenReturn("sessiontoken");
        Mockito.when(creds.getExpiration()).thenReturn(new Date());
        Mockito.when(mockResult.getCredentials()).thenReturn(creds);
        cloudStore.setAssumeRoleResult(mockResult);
        cloudStore.setReturnSuperAWSRole(true);

        AWSTemporaryCredentials awsCreds = cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null);
        assertNotNull(awsCreds);
        assertEquals(awsCreds.getAccessKeyId(), "accesskeyid");
        assertEquals(awsCreds.getSessionToken(), "sessiontoken");
        assertEquals(awsCreds.getSecretAccessKey(), "secretaccesskey");
        cloudStore.close();
    }

    @Test
    public void testAssumeAWSRoleFailedCreds() {
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.awsEnabled = true;
        AssumeRoleResult mockResult = Mockito.mock(AssumeRoleResult.class);
        Credentials creds = Mockito.mock(Credentials.class);
        Mockito.when(creds.getAccessKeyId()).thenReturn("accesskeyid");
        Mockito.when(creds.getSecretAccessKey()).thenReturn("secretaccesskey");
        Mockito.when(creds.getSessionToken()).thenReturn("sessiontoken");
        Mockito.when(creds.getExpiration()).thenReturn(new Date());
        Mockito.when(mockResult.getCredentials()).thenReturn(creds);
        cloudStore.setAssumeRoleResult(mockResult);
        cloudStore.setReturnSuperAWSRole(true);

        // add our key to the invalid cache

        cloudStore.putInvalidCacheCreds(cloudStore.getCacheKey("account", "syncer", "athenz.syncer", null, null));
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null));
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null));

        // now set the timeout to 1 second and sleep that long and after
        // that our test case should work as before

        cloudStore.invalidCacheTimeout = 1;
        try {
            Thread.sleep(1000);
        } catch (InterruptedException ignored) {
        }
        assertNotNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null));
        cloudStore.close();
    }

    @Test
    public void testAssumeAWSRoleFailedCredsCache() {
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.awsEnabled = true;
        cloudStore.setReturnSuperAWSRole(true);
        cloudStore.invalidCacheTimeout = 120;

        // first we're going to return a regular exception
        // in which case we won't cache the failed creds

        cloudStore.setGetServiceException(403, false);
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null));
        assertNull(cloudStore.awsInvalidCredsCache.get(cloudStore.getCacheKey("account", "syncer", "athenz.syncer", null, null)));

        // now we're going to return aamazon service exception
        // but with 401 error code which means against no
        // caching of failed credentials

        cloudStore.setGetServiceException(401, true);
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null));
        assertNull(cloudStore.awsInvalidCredsCache.get(cloudStore.getCacheKey("account", "syncer", "athenz.syncer", null, null)));

        // finally we're going to return access denied - 403
        // amazon exception and we should cache the failed creds

        cloudStore.setGetServiceException(403, true);
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null));
        assertNotNull(cloudStore.awsInvalidCredsCache.get(cloudStore.getCacheKey("account", "syncer", "athenz.syncer", null, null)));

        cloudStore.close();
    }

    @Test
    public void testGetSshKeyReqType() {
        CloudStore cloudStore = new CloudStore();
        final String req = "{\"principals\":[\"localhost\"],\"pubkey\":\"ssh-rsa AAAs\"" +
                ",\"reqip\":\"10.10.10.10\",\"requser\":\"user\",\"certtype\":\"host\",\"transid\":\"0\"}";
        assertEquals(cloudStore.getSshKeyReqType(req), "host");

        final String req2 = "{\"principals\":[\"localhost\"],\"pubkey\":\"ssh-rsa AAAs\"" +
                ",\"reqip\":\"10.10.10.10\",\"requser\":\"user\",\"certtype2\":\"host\",\"transid\":\"0\"}";
        assertNull(cloudStore.getSshKeyReqType(req2));

        final String req3 = "{invalid-json";
        assertNull(cloudStore.getSshKeyReqType(req3));
        cloudStore.close();
    }

    @Test
    public void testGetCacheKey() {
        CloudStore cloudStore = new CloudStore();
        assertEquals(cloudStore.getCacheKey("account", "role", "user", null, null), "account:role:user::");
        assertEquals(cloudStore.getCacheKey("account", "role", "user", 100, null), "account:role:user:100:");
        assertEquals(cloudStore.getCacheKey("account", "role", "user", null, "ext"), "account:role:user::ext");
        assertEquals(cloudStore.getCacheKey("account", "role", "user", null, "100"), "account:role:user::100");
        assertEquals(cloudStore.getCacheKey("account", "role", "user", 100, "ext"), "account:role:user:100:ext");
        cloudStore.close();
    }

    @Test
    public void testGetCachedCreds() {
        CloudStore cloudStore = new CloudStore();
        AWSTemporaryCredentials creds = new AWSTemporaryCredentials();
        creds.setAccessKeyId("keyid");
        creds.setSecretAccessKey("accesskey");
        creds.setSessionToken("token");
        // set the expiration for 1 hour from now
        creds.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3600*1000));
        cloudStore.putCacheCreds("account:role:user::", creds);

        // fetching with a different cache key should not match anything
        assertNull(cloudStore.getCachedCreds("account:role:user:100:", null));
        assertNull(cloudStore.getCachedCreds("account:role:user::ext", null));

        // fetching with null duration should match (default to 3600) and return our object
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", null));

        // fetching with 0 duration should match (default to 3600) and return our object
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", 0));

        // fetching with negative duration should match (default to 3600) and return our object
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", -1));

        // fetching with 1 hour duration should match and return our object
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", 3600));

        // fetching with 45 min duration should match duration
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", 2700));

        // fetching with 1 hour and 5 min duration should match and return our object
        assertNotNull(cloudStore.getCachedCreds("account:role:user::", 3900));

        // fetching with 1 hour and 11 min duration should not match
        assertNull(cloudStore.getCachedCreds("account:role:user::", 4260));

        // fetching with 2 hour duration should not match
        assertNull(cloudStore.getCachedCreds("account:role:user::", 7200));
        cloudStore.close();
    }

    @Test
    public void testGetCachedCredsDisabled() {
        System.setProperty(ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT, "0");
        CloudStore cloudStore = new CloudStore();

        assertNull(cloudStore.getCacheKey("account", "role", "user", null, null));
        assertNull(cloudStore.getCacheKey("account", "role", "user", 100, null));
        assertNull(cloudStore.getCacheKey("account", "role", "user", 100, "ext"));

        AWSTemporaryCredentials creds = new AWSTemporaryCredentials();
        creds.setAccessKeyId("keyid");
        creds.setSecretAccessKey("accesskey");
        creds.setSessionToken("token");
        // set the expiration for 1 hour from now
        creds.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3600*1000));
        cloudStore.putCacheCreds("account:role:user::", creds);

        // with disabled cache there is nothing to match
        assertNull(cloudStore.getCachedCreds("account:role:user::", null));
        cloudStore.close();
        System.clearProperty(ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT);
    }

    @Test
    public void testRemoveExpiredCredentials() {
        CloudStore cloudStore = new CloudStore();

        AWSTemporaryCredentials creds = new AWSTemporaryCredentials();
        creds.setAccessKeyId("keyid");
        creds.setSecretAccessKey("accesskey");
        creds.setSessionToken("token");
        // set the expiration for 1 hour from now
        creds.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3600*1000));
        cloudStore.putCacheCreds("account:role:user::", creds);

        assertFalse(cloudStore.removeExpiredCredentials());

        // now let's add an expired entry
        AWSTemporaryCredentials creds2 = new AWSTemporaryCredentials();
        creds2.setAccessKeyId("keyid");
        creds2.setSecretAccessKey("accesskey");
        creds2.setSessionToken("token");
        // expired credential
        creds2.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() - 1000));
        cloudStore.putCacheCreds("account:role:user2::", creds2);

        assertTrue(cloudStore.removeExpiredCredentials());
        cloudStore.close();
    }

    @Test
    public void testGetCachedAWSCredentials() {
        CloudStore cloudStore = new CloudStore();
        cloudStore.awsEnabled = true;

        AWSTemporaryCredentials creds = new AWSTemporaryCredentials();
        creds.setAccessKeyId("keyid");
        creds.setSecretAccessKey("accesskey");
        creds.setSessionToken("token");
        // set the expiration for 1 hour from now
        creds.setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 3600 * 1000));
        cloudStore.putCacheCreds("account:role:user::ext", creds);

        AWSTemporaryCredentials testCreds = cloudStore.assumeAWSRole("account", "role", "user",
                null, "ext");
        assertNotNull(testCreds);
        assertEquals(testCreds.getAccessKeyId(), "keyid");
        assertEquals(testCreds.getSecretAccessKey(), "accesskey");
        assertEquals(testCreds.getSessionToken(), "token");
        cloudStore.close();
    }

    @Test
    public void testInvalidCacheCreds() {

        CloudStore cloudStore = new CloudStore();
        cloudStore.awsEnabled = true;

        // standard checks

        cloudStore.putInvalidCacheCreds("cacheKey");
        assertTrue(cloudStore.isFailedTempCredsRequest("cacheKey"));
        assertFalse(cloudStore.isFailedTempCredsRequest("unknown-key"));

        // now set the timeout to only 1 second
        // and sleep so our records are expired

        cloudStore.invalidCacheTimeout = 1;
        try {
            Thread.sleep(1000);
        } catch (InterruptedException ignored) {
        }
        // this time our cache key is no longer considered failed

        assertFalse(cloudStore.isFailedTempCredsRequest("cacheKey"));

        // set the timeout to 0 value which should disable
        // cache functionality thus our put does nothing

        cloudStore.invalidCacheTimeout = 0;
        cloudStore.putInvalidCacheCreds("newKey");
        assertFalse(cloudStore.isFailedTempCredsRequest("newKey"));

        // set the timeout back to 2 mins and verify
        // expired check does not remove any entries

        cloudStore.invalidCacheTimeout = 120;
        assertEquals(cloudStore.awsInvalidCredsCache.size(), 1);

        cloudStore.removeExpiredInvalidCredentials();
        assertEquals(cloudStore.awsInvalidCredsCache.size(), 1);

        // now set it to 1 second and it should remove it

        cloudStore.invalidCacheTimeout = 1;
        try {
            Thread.sleep(1000);
        } catch (InterruptedException ignored) {
        }
        cloudStore.removeExpiredInvalidCredentials();
        assertEquals(cloudStore.awsInvalidCredsCache.size(), 0);

        cloudStore.close();
    }

    @Test
    public void testAWSCredentialsCleanerExceptions() {

        CloudStore cloudStore = Mockito.mock(CloudStore.class);

        // we're going to test exceptions from three components
        // and make sure our run does not throw any

        // first operation - all return true
        // second operation - fetchRoleCredentials throws exception
        // third operation - removeExpiredCredentials throws exception
        // forth opreation - removeExpiredInvalidCredentials throws exception

        Mockito.when(cloudStore.removeExpiredCredentials())
                .thenReturn(true)
                .thenReturn(true)
                .thenThrow(new NullPointerException("invalid state"))
                .thenReturn(true);
        Mockito.when(cloudStore.removeExpiredInvalidCredentials())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(true)
                .thenThrow(new NullPointerException("invalid state"));

        CloudStore.AWSCredentialsCacheCleaner updater = cloudStore.new AWSCredentialsCacheCleaner();
        updater.run();
        updater.run();
        updater.run();
        updater.run();
    }
}
