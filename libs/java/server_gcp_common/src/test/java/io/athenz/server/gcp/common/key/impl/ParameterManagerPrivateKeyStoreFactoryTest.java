package io.athenz.server.gcp.common.key.impl;

import com.google.cloud.parametermanager.v1.ParameterManagerClient;
import com.yahoo.athenz.auth.PrivateKeyStore;
import org.mockito.MockedStatic;
import org.testng.annotations.Test;

import java.io.IOException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.*;

public class ParameterManagerPrivateKeyStoreFactoryTest {
    @Test
    public void testCreate_Success() throws IOException {
        ParameterManagerPrivateKeyStoreFactory factory = new ParameterManagerPrivateKeyStoreFactory();
        try (MockedStatic<ParameterManagerClient> mocked = mockStatic(ParameterManagerClient.class)) {
            ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
            mocked.when(ParameterManagerClient::create).thenReturn(mockClient);

            PrivateKeyStore store = factory.create();
            assertNotNull(store);
            assertTrue(store instanceof ParameterManagerPrivateKeyStore);
        }
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testCreate_Failure() throws IOException {
        ParameterManagerPrivateKeyStoreFactory factory = new ParameterManagerPrivateKeyStoreFactory();
        try (MockedStatic<ParameterManagerClient> mocked = mockStatic(ParameterManagerClient.class)) {
            mocked.when(ParameterManagerClient::create).thenThrow(new IOException("fail"));
            factory.create();
        }
    }
}