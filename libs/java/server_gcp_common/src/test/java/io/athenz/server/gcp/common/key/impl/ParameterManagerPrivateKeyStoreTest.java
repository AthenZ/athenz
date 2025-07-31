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
import org.mockito.Mock;
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
    public void testGetPrivateKey_DelegatesToUtil() throws IOException {
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        ParameterManagerPrivateKeyStore keyStore = spy(new ParameterManagerPrivateKeyStore(mockClient, "project-a", "global"));

        String pemEncoded = Files.readString(Path.of("src/test/resources/unit_test_ec_private.key"));

        // Note: when method references such as "this::getParameter" are used, mocking is not working as expected
        // So, we are mocking the calls made from within getParameter() method

        // Mock "service_private_key.ec" parameter retrieval
        ParameterVersion latestVersion1 = mock(ParameterVersion.class);
        ParameterVersion parameterVersion1 = mock(ParameterVersion.class);
        ParameterVersionPayload parameterVersionPayload1 = mock(ParameterVersionPayload.class);
        ByteString keyByteString = ByteString.copyFrom(pemEncoded, StandardCharsets.UTF_8);

        when(latestVersion1.getName()).thenReturn("projects/sample-project/locations/global/parameters/service_private_key.ec/versions/latest");
        when(mockClient.getParameterVersion("projects/sample-project/locations/global/parameters/service_private_key.ec/versions/latest")).thenReturn(parameterVersion1);
        when(parameterVersion1.getPayload()).thenReturn(parameterVersionPayload1);
        when(parameterVersionPayload1.getData()).thenReturn(keyByteString);

        doReturn(latestVersion1).when(keyStore).getLatestParameterVersion("service_private_key.ec");

        // Mock "service_private_key_id.ec" parameter retrieval
        ParameterVersion latestVersion2 = mock(ParameterVersion.class);
        ParameterVersion parameterVersion2 = mock(ParameterVersion.class);
        ParameterVersionPayload parameterVersionPayload2 = mock(ParameterVersionPayload.class);
        ByteString keyIdByteString = ByteString.copyFrom("test-key-id", StandardCharsets.UTF_8);

        when(latestVersion2.getName()).thenReturn("projects/sample-project/locations/global/parameters/service_private_key_id.ec/versions/latest");
        when(mockClient.getParameterVersion("projects/sample-project/locations/global/parameters/service_private_key_id.ec/versions/latest")).thenReturn(parameterVersion2);
        when(parameterVersion2.getPayload()).thenReturn(parameterVersionPayload2);
        when(parameterVersionPayload2.getData()).thenReturn(keyIdByteString);

        doReturn(latestVersion2).when(keyStore).getLatestParameterVersion("service_private_key_id.ec");

        ServerPrivateKey result = keyStore.getPrivateKey("zts", "host", "region", "EC");

        assertNotNull(result);
        assertEquals(result.getId(), "test-key-id");
        assertEquals(result.getAlgorithm(), "ES256");
    }

    @Test
    public void testGetParameter() {
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        ParameterVersion latestVersion = mock(ParameterVersion.class);
        ParameterVersion parameterVersion = mock(ParameterVersion.class);
        ParameterVersionPayload parameterVersionPayload = mock(ParameterVersionPayload.class);
        ByteString byteString = ByteString.copyFrom("expected-value", StandardCharsets.UTF_8);

        when(latestVersion.getName()).thenReturn("projects/sample-project/locations/global/parameters/param1/versions/latest");
        when(mockClient.getParameterVersion("projects/sample-project/locations/global/parameters/param1/versions/latest")).thenReturn(parameterVersion);
        when(parameterVersion.getPayload()).thenReturn(parameterVersionPayload);
        when(parameterVersionPayload.getData()).thenReturn(byteString);

        ParameterManagerPrivateKeyStore keyStore = spy(new ParameterManagerPrivateKeyStore(mockClient, "project-a", "global"));

        doReturn(latestVersion).when(keyStore).getLatestParameterVersion("param1");

        String result = keyStore.getParameter("param1");
        assertEquals(result, "expected-value");
    }

    @Test
    public void testGetParameter_ReturnsEmptyStringWhenNull() {
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        ParameterManagerPrivateKeyStore keyStore = spy(new ParameterManagerPrivateKeyStore(mockClient, "project-a", "global"));

        doReturn(null).when(keyStore).getLatestParameterVersion("param1");

        String result = keyStore.getParameter("param1");
        assertEquals(result, "");
    }

    @Test
    public void testGetLatestParameterVersion_ReturnsLatest() {
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);

        ParameterVersion version1 = mock(ParameterVersion.class);
        ParameterVersion version2 = mock(ParameterVersion.class);
        ParameterVersion version3 = mock(ParameterVersion.class);

        Timestamp ts1 = Timestamp.newBuilder().setSeconds(1000).setNanos(0).build();
        Timestamp ts2 = Timestamp.newBuilder().setSeconds(2000).setNanos(0).build();
        Timestamp ts3 = Timestamp.newBuilder().setSeconds(1500).setNanos(0).build();

        when(version1.getCreateTime()).thenReturn(ts1);
        when(version2.getCreateTime()).thenReturn(ts2);
        when(version3.getCreateTime()).thenReturn(ts3);

        Iterable<ParameterVersion> versions = java.util.Arrays.asList(version1, version2, version3);

        ParameterManagerClient.ListParameterVersionsPagedResponse pagedResponse = mock(ParameterManagerClient.ListParameterVersionsPagedResponse.class);
        when(pagedResponse.iterateAll()).thenReturn(versions);

        when(mockClient.listParameterVersions(any(ListParameterVersionsRequest.class))).thenReturn(pagedResponse);

        ParameterManagerPrivateKeyStore keyStore = new ParameterManagerPrivateKeyStore(mockClient, "project-a", "global");

        ParameterVersion latest = keyStore.getLatestParameterVersion("param1");
        assertEquals(latest, version2);
    }
}
