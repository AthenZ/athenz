/*
 * Copyright The Athenz Authors.
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

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import io.athenz.server.aws.common.creds.AwsCredentialsProviderFactory;
import io.athenz.server.aws.common.creds.impl.RolesAnywhereCredentialsProviderFactory;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.utils.SdkAutoCloseable;

import static io.athenz.server.aws.common.creds.impl.TempCredsProvider.ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS;
import static org.testng.Assert.*;

public class CloudStoreFactoryTest {

    private String originalAwsEnabled;
    private String originalFactoryClass;
    private CloudStore store;

    @BeforeMethod
    public void setUp() {
        originalAwsEnabled = System.getProperty(ZTSConsts.ZTS_PROP_AWS_ENABLED);
        originalFactoryClass = System.getProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS);
        RecordingFactory.keyStore = null;
        RecordingFactory.keyStoreSet = false;
        RecordingFactory.createdProvider = null;
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_ENABLED, "true");
        System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, RecordingFactory.class.getName());
    }

    @AfterMethod
    public void tearDown() {
        try {
            if (store != null) {
                store.close();
                store = null;
            }
        } finally {
            restoreProperty(ZTSConsts.ZTS_PROP_AWS_ENABLED, originalAwsEnabled);
            restoreProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, originalFactoryClass);
        }
    }

    private void restoreProperty(String name, String value) {
        if (value == null) {
            System.clearProperty(name);
        } else {
            System.setProperty(name, value);
        }
    }

    @Test
    public void testKeyStoreReachesFactoryAndProviderIsClosed() {
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        store = new CloudStore(keyStore);
        assertTrue(store.isAwsEnabled());
        assertSame(RecordingFactory.keyStore, keyStore);
        assertTrue(RecordingFactory.keyStoreSet);
        assertNotNull(RecordingFactory.createdProvider);
        assertFalse(RecordingFactory.createdProvider.closed);
        store.close();
        assertTrue(RecordingFactory.createdProvider.closed);
        store = null;
    }

    @Test
    public void testLegacyConstructorPassesNullKeyStore() {
        store = new CloudStore();
        assertTrue(RecordingFactory.keyStoreSet);
        assertNull(RecordingFactory.keyStore);
        assertNotNull(RecordingFactory.createdProvider);
    }

    @Test
    public void testDisabledAwsDoesNotInstantiateFactory() {
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_ENABLED, "false");
        System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, "example.missing.CredentialsFactory");
        store = new CloudStore(Mockito.mock(PrivateKeyStore.class));
        assertFalse(store.isAwsEnabled());
        assertNull(store.tempCredsProvider);
        assertFalse(RecordingFactory.keyStoreSet);
    }

    @Test
    public void testDisabledAwsDoesNotCreateRolesAnywhereProvider() {
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_ENABLED, "false");
        System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS,
                RolesAnywhereCredentialsProviderFactory.class.getName());
        store = new CloudStore(Mockito.mock(PrivateKeyStore.class));
        assertFalse(store.isAwsEnabled());
        assertNull(store.tempCredsProvider);
    }

    @Test
    public void testInvalidFactoryFailsWhenAwsIsEnabled() {
        System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, "example.missing.CredentialsFactory");
        try {
            store = new CloudStore(Mockito.mock(PrivateKeyStore.class));
            fail("AWS initialization must fail for an invalid factory");
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
            assertTrue(ex.getMessage().contains("example.missing.CredentialsFactory"));
        }
    }

    public static class RecordingFactory implements AwsCredentialsProviderFactory {
        static PrivateKeyStore keyStore;
        static boolean keyStoreSet;
        static RecordingProvider createdProvider;

        @Override
        public void setPrivateKeyStore(PrivateKeyStore privateKeyStore) {
            keyStore = privateKeyStore;
            keyStoreSet = true;
        }

        @Override
        public AwsCredentialsProvider create() {
            assertTrue(keyStoreSet, "setPrivateKeyStore must precede create");
            createdProvider = new RecordingProvider();
            return createdProvider;
        }
    }

    public static class RecordingProvider implements AwsCredentialsProvider, SdkAutoCloseable {
        boolean closed;

        @Override
        public AwsCredentials resolveCredentials() {
            throw new AssertionError("These tests must not resolve credentials");
        }

        @Override
        public void close() {
            closed = true;
        }
    }
}
