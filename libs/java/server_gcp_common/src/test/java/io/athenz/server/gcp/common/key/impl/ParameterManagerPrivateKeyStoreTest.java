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
package io.athenz.server.gcp.common.key.impl;

import com.google.cloud.parametermanager.v1.ListParameterVersionsRequest;
import com.google.cloud.parametermanager.v1.ParameterManagerClient;
import com.google.cloud.parametermanager.v1.ParameterVersion;
import com.google.cloud.parametermanager.v1.ParameterVersionPayload;
import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.util.Crypto;
import io.athenz.server.gcp.common.utils.ParameterManagerClientHelper;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Base64;

import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class ParameterManagerPrivateKeyStoreTest {

    @Test
    public void testGetSecret() {
        // Arrange
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        ParameterManagerPrivateKeyStore keyStore = new ParameterManagerPrivateKeyStore(mockClient, "project-a", "global");

        // Mock getParameter to return a known value
        ParameterManagerPrivateKeyStore spyKeyStore = spy(keyStore);
        doReturn("test-value").when(spyKeyStore).getParameter("test-key");

        // Act
        char[] secret = spyKeyStore.getSecret("app", "group", "test-key");

        // Assert
        assertNotNull(secret);
        assertEquals(new String(secret), "test-value");
    }

    @Test
    public void testGetPrivateKey() throws IOException{
        // Arrange
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        ParameterManagerPrivateKeyStore keyStore = new ParameterManagerPrivateKeyStore(mockClient, "project-a", "global");
        ParameterManagerPrivateKeyStore spyKeyStore = spy(keyStore);

        String service = "zts";
        String serverHostName = "host1";
        String serverRegion = "us-west1";
        String algorithm = "EC";

        String privateKeyPEM = Files.readString(Path.of("src/test/resources/unit_test_ec_private.key"));
        doReturn(privateKeyPEM).when(spyKeyStore).getParameter("service_private_key.ec");
        doReturn("test-key-id").when(spyKeyStore).getParameter("service_private_key_id.ec");

        // Act
        ServerPrivateKey result = spyKeyStore.getPrivateKey(service, serverHostName, serverRegion, algorithm);

        // Assert
        assertNotNull(result);
        assertEquals(result.getAlgorithm(), "ES256");
        assertEquals(result.getId(), "test-key-id");
    }

    @Test
    public void testGetParameter() {
        // Arrange
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        ParameterManagerPrivateKeyStore keyStore = new ParameterManagerPrivateKeyStore(mockClient, "project-a", "global");

        String paramName = "test-param";
        String expectedValue = "expected-value";

        // Mock parameter version
        ParameterVersion mockLatestVersion = mock(ParameterVersion.class);
        ParameterVersion mockParamVersion = mock(ParameterVersion.class);
        ParameterVersionPayload mockPayload = mock(ParameterVersionPayload.class);
        ByteString mockData = ByteString.copyFromUtf8(expectedValue);

        // Define behavior for mocks
        when(mockLatestVersion.getName()).thenReturn("projects/project-a/locations/global/parameters/test-param/versions/1");
        when(mockClient.getParameterVersion(mockLatestVersion.getName())).thenReturn(mockParamVersion);
        when(mockParamVersion.getPayload()).thenReturn(mockPayload);
        when(mockPayload.getData()).thenReturn(mockData);

        // Mock the helper class using PowerMockito
        try (MockedStatic<ParameterManagerClientHelper> mockedHelper = Mockito.mockStatic(ParameterManagerClientHelper.class)) {
            mockedHelper.when(() -> ParameterManagerClientHelper.getLatestParameterVersion(
                            mockClient, "project-a", "global", paramName))
                    .thenReturn(mockLatestVersion);

            // Act
            String result = keyStore.getParameter(paramName);

            // Assert
            assertEquals(expectedValue, result);
        }
    }

    @Test
    public void testGetParameter_ReturnsEmptyStringWhenParameterNotFound() {
        // Arrange
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        ParameterManagerPrivateKeyStore keyStore = new ParameterManagerPrivateKeyStore(mockClient, "project-a", "global");

        String paramName = "non-existent-param";

        // Mock the helper class to return null (parameter not found)
        try (MockedStatic<ParameterManagerClientHelper> mockedHelper = Mockito.mockStatic(ParameterManagerClientHelper.class)) {
            mockedHelper.when(() -> ParameterManagerClientHelper.getLatestParameterVersion(
                            mockClient, "project-a", "global", paramName))
                    .thenReturn(null);

            // Act
            String result = keyStore.getParameter(paramName);

            // Assert
            assertEquals("", result);
        }
    }
}
