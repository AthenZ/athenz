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
package io.athenz.server.gcp.common.store.impl;

import com.yahoo.athenz.common.server.store.ChangeLogStore;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.security.PrivateKey;

import static io.athenz.server.gcp.common.Consts.ATHENZ_PROP_GCP_BUCKET_NAME;
import static io.athenz.server.gcp.common.Consts.ATHENZ_PROP_GCP_PROJECT_ID;
import static org.mockito.Mockito.mock;
import static org.testng.Assert.*;

public class GcsChangeLogStoreFactoryTest {

    private GcsChangeLogStoreFactory factory;
    private String originalProjectId;
    private String originalBucketName;

    @BeforeMethod
    public void setUp() {
        factory = new GcsChangeLogStoreFactory();
        // Save original system properties to restore them later
        originalProjectId = System.getProperty(ATHENZ_PROP_GCP_PROJECT_ID);
        originalBucketName = System.getProperty(ATHENZ_PROP_GCP_BUCKET_NAME);
    }

    @AfterMethod
    public void tearDown() {
        // Restore original system properties
        if (originalProjectId != null) {
            System.setProperty(ATHENZ_PROP_GCP_PROJECT_ID, originalProjectId);
        } else {
            System.clearProperty(ATHENZ_PROP_GCP_PROJECT_ID);
        }

        if (originalBucketName != null) {
            System.setProperty(ATHENZ_PROP_GCP_BUCKET_NAME, originalBucketName);
        } else {
            System.clearProperty(ATHENZ_PROP_GCP_BUCKET_NAME);
        }
    }

    @Test
    public void testCreate_Success() {
        // Set required system properties
        System.setProperty(ATHENZ_PROP_GCP_PROJECT_ID, "test-project");
        System.setProperty(ATHENZ_PROP_GCP_BUCKET_NAME, "test-bucket");

        // Mock dependencies
        PrivateKey mockPrivateKey = mock(PrivateKey.class);
        String privateKeyId = "test-key-id";

        // Call method under test
        ChangeLogStore store = factory.create("/home/zts", mockPrivateKey, privateKeyId);

        // Verify
        assertNotNull(store);
        assertTrue(store instanceof GcsChangeLogStore);
        GcsChangeLogStore gcsStore = (GcsChangeLogStore) store;
        // Note: We would need to make these fields accessible or add getters to verify values
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "GCP project id is not specified")
    public void testCreate_MissingProjectId() {
        // Set only bucket name
        System.clearProperty(ATHENZ_PROP_GCP_PROJECT_ID);
        System.setProperty(ATHENZ_PROP_GCP_BUCKET_NAME, "test-bucket");

        // Mock dependencies
        PrivateKey mockPrivateKey = mock(PrivateKey.class);
        String privateKeyId = "test-key-id";

        // Call method under test - should throw exception
        factory.create("/home/zts", mockPrivateKey, privateKeyId);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "GCP project id is not specified")
    public void testCreate_BlankProjectId() {
        // Set empty project ID and valid bucket name
        System.setProperty(ATHENZ_PROP_GCP_PROJECT_ID, "");
        System.setProperty(ATHENZ_PROP_GCP_BUCKET_NAME, "test-bucket");

        // Mock dependencies
        PrivateKey mockPrivateKey = mock(PrivateKey.class);
        String privateKeyId = "test-key-id";

        // Call method under test - should throw exception
        factory.create("/home/zts", mockPrivateKey, privateKeyId);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "GCP bucket name is not specified")
    public void testCreate_MissingBucketName() {
        // Set only project ID
        System.setProperty(ATHENZ_PROP_GCP_PROJECT_ID, "test-project");
        System.clearProperty(ATHENZ_PROP_GCP_BUCKET_NAME);

        // Mock dependencies
        PrivateKey mockPrivateKey = mock(PrivateKey.class);
        String privateKeyId = "test-key-id";

        // Call method under test - should throw exception
        factory.create("/home/zts", mockPrivateKey, privateKeyId);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "GCP bucket name is not specified")
    public void testCreate_BlankBucketName() {
        // Set valid project ID and empty bucket name
        System.setProperty(ATHENZ_PROP_GCP_PROJECT_ID, "test-project");
        System.setProperty(ATHENZ_PROP_GCP_BUCKET_NAME, "");

        // Mock dependencies
        PrivateKey mockPrivateKey = mock(PrivateKey.class);
        String privateKeyId = "test-key-id";

        // Call method under test - should throw exception
        factory.create("/home/zts", mockPrivateKey, privateKeyId);
    }
}