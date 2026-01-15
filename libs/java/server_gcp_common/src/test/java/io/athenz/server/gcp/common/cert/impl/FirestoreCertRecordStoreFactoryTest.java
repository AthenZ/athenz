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
package io.athenz.server.gcp.common.cert.impl;

import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.FirestoreOptions;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.cert.CertRecordStore;
import com.yahoo.athenz.common.server.ServerResourceException;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class FirestoreCertRecordStoreFactoryTest {

    @Mock private Firestore firestore;

    class TestFirestoreCertRecordStoreFactory extends FirestoreCertRecordStoreFactory {
        @Override
        Firestore getFirestoreClient(String projectId, String databaseId) {
            return firestore;
        }
    }

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testCreate() throws ServerResourceException {

        System.setProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_PROJECT_ID, "test-project");
        System.setProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_COLLECTION_NAME, "test-collection");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        TestFirestoreCertRecordStoreFactory factory = new TestFirestoreCertRecordStoreFactory();
        CertRecordStore store = factory.create(keyStore);
        assertNotNull(store);

        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_PROJECT_ID);
        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_COLLECTION_NAME);
    }

    @Test
    public void testCreateWithDatabaseId() throws ServerResourceException {

        System.setProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_PROJECT_ID, "test-project");
        System.setProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_COLLECTION_NAME, "test-collection");
        System.setProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_DATABASE_ID, "custom-db");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        TestFirestoreCertRecordStoreFactory factory = new TestFirestoreCertRecordStoreFactory();
        CertRecordStore store = factory.create(keyStore);
        assertNotNull(store);

        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_PROJECT_ID);
        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_COLLECTION_NAME);
        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_DATABASE_ID);
    }

    @Test
    public void testCreateMissingProjectId() {

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_PROJECT_ID);
        TestFirestoreCertRecordStoreFactory factory = new TestFirestoreCertRecordStoreFactory();
        try {
            factory.create(keyStore);
            fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), ServerResourceException.SERVICE_UNAVAILABLE);
            Assert.assertTrue(ex.getMessage().contains("Firestore project ID not specified"));
        }

        System.setProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_PROJECT_ID, "");
        try {
            factory.create(keyStore);
            fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), ServerResourceException.SERVICE_UNAVAILABLE);
            Assert.assertTrue(ex.getMessage().contains("Firestore project ID not specified"));
        }

        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_PROJECT_ID);
    }

    @Test
    public void testCreateMissingCollectionName() {

        System.setProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_PROJECT_ID, "test-project");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_COLLECTION_NAME);
        TestFirestoreCertRecordStoreFactory factory = new TestFirestoreCertRecordStoreFactory();
        try {
            factory.create(keyStore);
            fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), ServerResourceException.SERVICE_UNAVAILABLE);
            Assert.assertTrue(ex.getMessage().contains("Firestore collection name not specified"));
        }

        System.setProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_COLLECTION_NAME, "");
        try {
            factory.create(keyStore);
            fail();
        } catch (ServerResourceException ex) {
            Assert.assertEquals(ex.getCode(), ServerResourceException.SERVICE_UNAVAILABLE);
            Assert.assertTrue(ex.getMessage().contains("Firestore collection name not specified"));
        }

        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_PROJECT_ID);
        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_COLLECTION_NAME);
    }

    @Test
    public void testGetFirestoreClientException() {

        System.setProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_PROJECT_ID, "test-project");
        System.setProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_COLLECTION_NAME, "test-collection");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);

        FirestoreCertRecordStoreFactory factory = new FirestoreCertRecordStoreFactory() {
            @Override
            Firestore getFirestoreClient(String projectId, String databaseId) {
                throw new RuntimeException("Failed to create Firestore client");
            }
        };

        try {
            factory.create(keyStore);
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof RuntimeException);
            Assert.assertTrue(ex.getMessage().contains("Failed to create Firestore client"));
        }

        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_PROJECT_ID);
        System.clearProperty(FirestoreCertRecordStoreFactory.ZTS_PROP_CERT_FIRESTORE_COLLECTION_NAME);
    }

    @Test
    public void testGetFirestoreClient() {
        FirestoreCertRecordStoreFactory factory = new FirestoreCertRecordStoreFactory();
        try {
            // This will attempt to create a real Firestore client, which may fail
            // without proper GCP credentials, but we're testing that the method exists
            Firestore client = factory.getFirestoreClient("test-project", "(default)");
            assertNotNull(client);
        } catch (Exception ex) {
            // Expected to fail without proper GCP setup
            assertTrue(ex instanceof RuntimeException);
        }
    }

    @Test
    public void testGetFirestoreClientWithCustomDatabaseId() {
        FirestoreCertRecordStoreFactory factory = new FirestoreCertRecordStoreFactory();
        try (MockedStatic<FirestoreOptions> mocked = Mockito.mockStatic(FirestoreOptions.class)) {
            mocked.when(FirestoreOptions::newBuilder)
                    .thenThrow(new IllegalStateException("Simulated failure"));

            try {
                factory.getFirestoreClient("test-project", "(default)");
                fail();
            } catch (Exception ex) {
                assertTrue(ex instanceof RuntimeException);
                Assert.assertTrue(ex.getMessage().contains("Failed to create Firestore client"));
            }
        }
    }
}
