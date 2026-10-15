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

package io.athenz.server.aws.common.creds.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.ServerResourceException;
import io.athenz.server.aws.common.creds.AwsCredentialsProviderFactory;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.utils.SdkAutoCloseable;

import java.lang.reflect.Field;

import static io.athenz.server.aws.common.creds.impl.TempCredsProvider.ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS;
import static org.testng.Assert.*;

public class TempCredsProviderFactoryTest {

    private String originalFactoryClass;
    private TempCredsProvider provider;

    @BeforeMethod
    public void setUp() {
        originalFactoryClass = System.getProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS);
        System.clearProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS);
        RecordingFactory.keyStore = null;
        RecordingFactory.keyStoreSet = false;
        RecordingFactory.createdProvider = null;
    }

    @AfterMethod
    public void tearDown() {
        try {
            if (provider != null) {
                provider.close();
                provider = null;
            }
        } finally {
            if (originalFactoryClass == null) {
                System.clearProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS);
            } else {
                System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, originalFactoryClass);
            }
        }
    }

    @Test
    public void testDefaultFactoryPreservesInstanceProfileCredentials() throws Exception {
        provider = new TempCredsProvider();
        provider.initialize();
        assertTrue(provider.credentialsProvider instanceof InstanceProfileCredentialsProvider);
        // The SDK does not expose a getter for the refresh setting.
        Field asyncUpdate = InstanceProfileCredentialsProvider.class.getDeclaredField("asyncCredentialUpdateEnabled");
        asyncUpdate.setAccessible(true);
        assertEquals(asyncUpdate.get(provider.credentialsProvider), Boolean.TRUE);
    }

    @Test
    public void testConfiguredFactoryReceivesKeyStoreBeforeCreate() throws ServerResourceException {
        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, RecordingFactory.class.getName());
        provider = new TempCredsProvider(keyStore);
        provider.initialize();
        assertSame(RecordingFactory.keyStore, keyStore);
        assertSame(provider.credentialsProvider, RecordingFactory.createdProvider);

        // Exercise the real STS builder without resolving credentials or calling AWS.
        provider.awsRegion = "us-west-2";
        try (StsClient client = provider.getTokenServiceClient()) {
            assertSame(client.serviceClientConfiguration().credentialsProvider(), RecordingFactory.createdProvider);
            assertEquals(client.serviceClientConfiguration().region().id(), "us-west-2");
        }
    }

    @Test
    public void testCloseConfiguredProvider() throws ServerResourceException {
        System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, RecordingFactory.class.getName());
        provider = new TempCredsProvider();
        provider.initialize();
        assertFalse(RecordingFactory.createdProvider.closed);
        provider.close();
        assertTrue(RecordingFactory.createdProvider.closed);
        provider = null;
    }

    @Test
    public void testLegacyConstructorPassesNullKeyStore() throws ServerResourceException {
        System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, RecordingFactory.class.getName());
        provider = new TempCredsProvider();
        provider.initialize();
        assertTrue(RecordingFactory.keyStoreSet);
        assertNull(RecordingFactory.keyStore);
        assertSame(provider.credentialsProvider, RecordingFactory.createdProvider);
    }

    @Test
    public void testFactoryWithoutKeyStoreOverrideAndNonCloseableProvider() throws ServerResourceException {
        System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, SimpleFactory.class.getName());
        provider = new TempCredsProvider(Mockito.mock(PrivateKeyStore.class));
        provider.initialize();
        assertSame(provider.credentialsProvider, SimpleFactory.PROVIDER);
        provider.close();
        provider = null;
    }

    @DataProvider
    public Object[][] invalidFactoryClasses() {
        return new Object[][] {
            {"example.missing.CredentialsFactory"},
            {String.class.getName()},
            {NoDefaultConstructorFactory.class.getName()},
            {ThrowingConstructorFactory.class.getName()},
            {""}
        };
    }

    @Test(dataProvider = "invalidFactoryClasses")
    public void testInvalidFactoryFailsInitialization(String factoryClass) throws ServerResourceException {
        System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, factoryClass);
        provider = new TempCredsProvider();
        try {
            provider.initialize();
            fail("Invalid factory must not fall back to IMDS");
        } catch (ServerResourceException ex) {
            assertEquals(ex.getCode(), ServerResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("Invalid AwsCredentialsProviderFactory class: " + factoryClass));
            assertNull(provider.credentialsProvider);
        }
    }

    @Test
    public void testNullProviderFailsInitialization() throws ServerResourceException {
        System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, NullFactory.class.getName());
        provider = new TempCredsProvider();
        try {
            provider.initialize();
            fail("Factory must return a provider");
        } catch (ServerResourceException ex) {
            assertEquals(ex.getCode(), ServerResourceException.INTERNAL_SERVER_ERROR);
            assertTrue(ex.getMessage().contains("returned null: " + NullFactory.class.getName()));
        }
    }

    @Test
    public void testFactoryCreationFailureIsPropagated() throws ServerResourceException {
        System.setProperty(ZTS_PROP_AWS_CREDS_PROVIDER_FACTORY_CLASS, FailingFactory.class.getName());
        provider = new TempCredsProvider();
        try {
            provider.initialize();
            fail("Factory failure must not fall back to IMDS");
        } catch (ServerResourceException ex) {
            assertSame(ex, FailingFactory.FAILURE);
        }
    }

    @Test
    public void testCloseBeforeInitialization() throws ServerResourceException {
        provider = new TempCredsProvider();
        provider.close();
        provider = null;
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

    public static class SimpleFactory implements AwsCredentialsProviderFactory {
        static final AwsCredentialsProvider PROVIDER = () -> {
            throw new AssertionError("These tests must not resolve credentials");
        };

        @Override
        public AwsCredentialsProvider create() {
            return PROVIDER;
        }
    }

    public static class NoDefaultConstructorFactory extends SimpleFactory {
        public NoDefaultConstructorFactory(String unused) {
        }
    }

    public static class ThrowingConstructorFactory extends SimpleFactory {
        public ThrowingConstructorFactory() {
            throw new IllegalStateException("Factory construction failed");
        }
    }

    public static class NullFactory implements AwsCredentialsProviderFactory {
        @Override
        public AwsCredentialsProvider create() {
            return null;
        }
    }

    public static class FailingFactory implements AwsCredentialsProviderFactory {
        static final ServerResourceException FAILURE = new ServerResourceException(
                ServerResourceException.INTERNAL_SERVER_ERROR, "Factory initialization failed");

        @Override
        public AwsCredentialsProvider create() throws ServerResourceException {
            throw FAILURE;
        }
    }
}
