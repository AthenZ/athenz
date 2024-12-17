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

import static org.testng.Assert.*;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.rdl.Timestamp;
import io.athenz.server.aws.common.creds.impl.TempCredsProvider;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.zts.AWSTemporaryCredentials;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;

public class CloudStoreTest {

    @Test
    public void testUpdateAccountUpdate() {

        CloudStore store = new CloudStore();
        assertNull(store.getAwsAccount("iaas"));

        // set the account to 1234

        store.updateAwsAccount("iaas", "1234");
        assertEquals(store.getAwsAccount("iaas"), "1234");

        // update the account value

        store.updateAwsAccount("iaas", "1235");
        assertEquals(store.getAwsAccount("iaas"), "1235");
        store.close();
    }

    @Test
    public void testUpdateAccountDelete() {

        CloudStore store = new CloudStore();

        // set the account to 1234

        store.updateAwsAccount("iaas", "1234");
        assertEquals(store.getAwsAccount("iaas"), "1234");

        // delete the account with null

        store.updateAwsAccount("iaas", null);
        assertNull(store.getAwsAccount("iaas"));

        // update the account value

        store.updateAwsAccount("iaas", "1235");
        assertEquals(store.getAwsAccount("iaas"), "1235");

        // delete the account with empty string

        store.updateAwsAccount("iaas", "");
        assertNull(store.getAwsAccount("iaas"));
        store.close();
    }

    @Test
    public void testAssumeAWSRoleAWSNotEnabled() {
        CloudStore cloudStore = new CloudStore();
        try {
            StringBuilder errorMessage = new StringBuilder();
            cloudStore.assumeAWSRole("account", "sycner", "athenz.syncer", null, null, errorMessage);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
        cloudStore.close();
    }

    @Test
    public void testAssumeAWSRoleFailedCredsCache() throws ServerResourceException {
        MockCloudStore cloudStore = new MockCloudStore();
        cloudStore.awsEnabled = true;
        cloudStore.setReturnSuperAWSRole(true);
        cloudStore.invalidCacheTimeout = 120;

        // first we're going to return a regular exception
        // in which case we won't cache the failed creds

        cloudStore.setGetServiceException(403, false);
        StringBuilder errorMessage = new StringBuilder();
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null, errorMessage));
        assertNull(cloudStore.awsInvalidCredsCache.get(cloudStore.getCacheKey("account", "syncer", "athenz.syncer", null, null)));

        // now we're going to return amazon service exception
        // but with 401 error code which means against no
        // caching of failed credentials

        cloudStore.setGetServiceException(401, true);
        errorMessage.setLength(0);
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null, errorMessage));
        assertNull(cloudStore.awsInvalidCredsCache.get(cloudStore.getCacheKey("account", "syncer", "athenz.syncer", null, null)));

        // finally we're going to return access denied - 403
        // amazon exception, and we should cache the failed creds

        cloudStore.setGetServiceException(403, true);
        errorMessage.setLength(0);
        assertNull(cloudStore.assumeAWSRole("account", "syncer", "athenz.syncer", null, null, errorMessage));
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
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT, "0");
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
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_CREDS_CACHE_TIMEOUT);
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

        StringBuilder errorMessage = new StringBuilder();
        AWSTemporaryCredentials testCreds = cloudStore.assumeAWSRole("account", "role", "user",
                null, "ext", errorMessage);
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

        // now set the timeout to only 1-second
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
    public void testAWSCredentialsUpdaterExceptions () {

        CloudStore cloudStore = Mockito.mock(CloudStore.class);
        cloudStore.tempCredsProvider = Mockito.mock(TempCredsProvider.class);

        // we're going to test exceptions from three components
        // and make sure our run does not throw any

        // first operation - all return true
        // second operation - removeExpiredCredentials throws exception
        // third opreation - removeExpiredInvalidCredentials throws exception

        Mockito.when(cloudStore.removeExpiredCredentials())
                .thenReturn(true)
                .thenThrow(new NullPointerException("invalid state"))
                .thenReturn(true);
        Mockito.when(cloudStore.removeExpiredInvalidCredentials())
                .thenReturn(true)
                .thenReturn(true)
                .thenThrow(new NullPointerException("invalid state"));

        CloudStore.AWSCredentialsUpdater updater = cloudStore.new AWSCredentialsUpdater();
        updater.run();
        updater.run();
        updater.run();
        updater.run();
    }

    @Test
    public void testGetAzureSubscription() {
        CloudStore cloudStore = new CloudStore();
        assertNull(cloudStore.getAzureSubscription("athenz"));

        cloudStore.updateAzureSubscription("athenz", "12345", "321", "999");
        assertEquals(cloudStore.getAzureSubscription("athenz"), "12345");
        assertEquals(cloudStore.getAzureTenant("athenz"), "321");
        assertEquals(cloudStore.getAzureClient("athenz"), "999");

        cloudStore.updateAzureSubscription("athenz", "", "", "");
        assertNull(cloudStore.getAzureSubscription("athenz"));
        assertNull(cloudStore.getAzureTenant("athenz"));
        assertNull(cloudStore.getAzureClient("athenz"));

        cloudStore.updateAzureSubscription("athenz", "12345", null, "888");
        assertEquals(cloudStore.getAzureSubscription("athenz"), "12345");
        assertNull(cloudStore.getAzureTenant("athenz"));
        assertEquals(cloudStore.getAzureClient("athenz"), "888");

        cloudStore.updateAzureSubscription("athenz", "12345", "777", null);
        assertEquals(cloudStore.getAzureSubscription("athenz"), "12345");
        assertEquals(cloudStore.getAzureTenant("athenz"), "777");
        assertEquals(cloudStore.getAzureClient("athenz"), "888");

        cloudStore.close();
    }

    @Test
    public void testGetGcpProject() {
        CloudStore cloudStore = new CloudStore();
        assertNull(cloudStore.getGCPProjectId("athenz"));

        cloudStore.updateGCPProject("athenz", "athenz-gcp-xsdc", "1234");
        assertEquals(cloudStore.getGCPProjectId("athenz"), "athenz-gcp-xsdc");
        assertEquals(cloudStore.getGCPProjectNumber("athenz"), "1234");

        cloudStore.updateGCPProject("athenz", "", "");
        assertNull(cloudStore.getGCPProjectId("athenz"));
        assertNull(cloudStore.getGCPProjectNumber("athenz"));

        cloudStore.updateGCPProject("athenz", "athenz-gcp-xsdc", null);
        assertEquals(cloudStore.getGCPProjectId("athenz"), "athenz-gcp-xsdc");
        assertNull(cloudStore.getGCPProjectNumber("athenz"));

        cloudStore.close();
    }
}
