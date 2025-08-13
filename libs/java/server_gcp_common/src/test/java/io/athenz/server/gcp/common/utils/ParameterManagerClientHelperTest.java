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
package io.athenz.server.gcp.common.utils;

import com.google.cloud.parametermanager.v1.*;
import com.google.protobuf.Timestamp;
import io.athenz.server.gcp.common.key.impl.ParameterManagerPrivateKeyStoreFactory;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import static io.athenz.server.gcp.common.Consts.GLOBAL_LOCATION;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class ParameterManagerClientHelperTest {

    @Test
    public void ParameterManagerClientHelperTest() {
        // This is just to ensure the class can be instantiated
        assertNotNull(new ParameterManagerClientHelper());
    }

    @Test
    public void testCreateParameterManagerClient_Global() throws IOException {
        try (MockedStatic<ParameterManagerClient> mocked = mockStatic(ParameterManagerClient.class)) {
            ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
            mocked.when(ParameterManagerClient::create).thenReturn(mockClient);

            ParameterManagerClient client = ParameterManagerClientHelper.createParameterManagerClient(GLOBAL_LOCATION);
            assertNotNull(client);
        }
    }

    @Test
    public void testCreateParameterManagerClient_NonGlobal() throws IOException {
        try (MockedStatic<ParameterManagerClient> mocked = mockStatic(ParameterManagerClient.class)) {
            ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
            mocked.when(() -> ParameterManagerClient.create(any(ParameterManagerSettings.class))).thenReturn(mockClient);

            ParameterManagerClient client = ParameterManagerClientHelper.createParameterManagerClient("us-central1");
            assertNotNull(client);
        }
    }

    @Test(expectedExceptions = IOException.class)
    public void testCreateParameterManagerClient_ThrowsIOException() throws IOException {
        try (MockedStatic<ParameterManagerClient> mocked = mockStatic(ParameterManagerClient.class)) {
            mocked.when(ParameterManagerClient::create).thenThrow(new IOException("fail"));
            ParameterManagerClientHelper.createParameterManagerClient(GLOBAL_LOCATION);
        }
    }

    @Test
    public void testIsGlobalLocation_true() {
        assertTrue(ParameterManagerClientHelper.isGlobalLocation("global"));
        assertTrue(ParameterManagerClientHelper.isGlobalLocation("GLOBAL"));
        assertTrue(ParameterManagerClientHelper.isGlobalLocation("GlObAl"));
    }

    @Test
    public void testIsGlobalLocation_false() {
        assertFalse(ParameterManagerClientHelper.isGlobalLocation("us-central1"));
        assertFalse(ParameterManagerClientHelper.isGlobalLocation(""));
        assertFalse(ParameterManagerClientHelper.isGlobalLocation(null));
    }

    @Test
    public void testCreateParameterManagerClient_EndpointConstruction() throws IOException {
        try (MockedStatic<ParameterManagerClient> mocked = mockStatic(ParameterManagerClient.class)) {
            // Capture the settings parameter
            ArgumentCaptor<ParameterManagerSettings> settingsCaptor = ArgumentCaptor.forClass(ParameterManagerSettings.class);
            ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
            mocked.when(() -> ParameterManagerClient.create(settingsCaptor.capture())).thenReturn(mockClient);

            // Test with a specific region
            String testRegion = "us-west1";
            ParameterManagerClient client = ParameterManagerClientHelper.createParameterManagerClient(testRegion);

            // Verify the client was created
            assertNotNull(client);

            // Verify the endpoint was correctly constructed
            ParameterManagerSettings capturedSettings = settingsCaptor.getValue();
            assertEquals("parametermanager.us-west1.rep.googleapis.com:443", capturedSettings.getEndpoint());
        }
    }

    @Test
    public void testGetLatestParameterVersion() {
        // Mock the client and response objects
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        ParameterManagerClient.ListParameterVersionsPagedResponse mockResponse = mock(ParameterManagerClient.ListParameterVersionsPagedResponse.class);

        // Create parameter name
        ParameterName parameterName = ParameterName.of("test-project", "global", "test-parameter");

        // Create parameter versions with different timestamps
        Timestamp oldTime = Timestamp.newBuilder().setSeconds(1000L).setNanos(0).build();
        Timestamp newTime = Timestamp.newBuilder().setSeconds(2000L).setNanos(0).build();

        ParameterVersion oldVersion = ParameterVersion.newBuilder()
                .setName("v1")
                .setCreateTime(oldTime)
                .build();

        ParameterVersion newVersion = ParameterVersion.newBuilder()
                .setName("v2")
                .setCreateTime(newTime)
                .build();

        // Create an Iterable of versions
        Iterable<ParameterVersion> versions = Arrays.asList(oldVersion, newVersion);

        // Set up the mock behavior
        when(mockClient.listParameterVersions(any(ListParameterVersionsRequest.class))).thenReturn(mockResponse);
        when(mockResponse.iterateAll()).thenReturn(versions);

        // Call the method
        ParameterVersion result = ParameterManagerClientHelper.getLatestParameterVersion(mockClient, parameterName);

        // Verify the result
        assertNotNull(result);
        assertEquals("v2", result.getName());
        assertEquals(newTime, result.getCreateTime());
    }

    @Test
    public void testGetLatestParameterVersion_NoVersions() {
        // Mock the client and response objects
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        ParameterManagerClient.ListParameterVersionsPagedResponse mockResponse = mock(ParameterManagerClient.ListParameterVersionsPagedResponse.class);

        // Create parameter name
        ParameterName parameterName = ParameterName.of("test-project", "global", "test-parameter");

        // Create an empty Iterable of versions
        Iterable<ParameterVersion> versions = Collections.emptyList();

        // Set up the mock behavior
        when(mockClient.listParameterVersions(any(ListParameterVersionsRequest.class))).thenReturn(mockResponse);
        when(mockResponse.iterateAll()).thenReturn(versions);

        // Call the method
        ParameterVersion result = ParameterManagerClientHelper.getLatestParameterVersion(mockClient, parameterName);

        // Verify the result
        assertNull(result);
    }

    @Test
    public void testGetLatestParameterVersion_WithStringParameters() {
        // Mock the client and response objects
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        ParameterManagerClient.ListParameterVersionsPagedResponse mockResponse = mock(ParameterManagerClient.ListParameterVersionsPagedResponse.class);

        // Test parameter values
        String projectId = "test-project";
        String location = "global";
        String parameter = "test-parameter";

        // Create parameter versions with different timestamps
        Timestamp oldTime = Timestamp.newBuilder().setSeconds(1000L).setNanos(0).build();
        Timestamp newTime = Timestamp.newBuilder().setSeconds(2000L).setNanos(0).build();

        ParameterVersion oldVersion = ParameterVersion.newBuilder()
                .setName("v1")
                .setCreateTime(oldTime)
                .build();

        ParameterVersion newVersion = ParameterVersion.newBuilder()
                .setName("v2")
                .setCreateTime(newTime)
                .build();

        // Create an Iterable of versions
        Iterable<ParameterVersion> versions = Arrays.asList(oldVersion, newVersion);

        // Set up the mock behavior
        when(mockClient.listParameterVersions(any(ListParameterVersionsRequest.class))).thenReturn(mockResponse);
        when(mockResponse.iterateAll()).thenReturn(versions);

        // Call the method
        ParameterVersion result = ParameterManagerClientHelper.getLatestParameterVersion(mockClient, projectId, location, parameter);

        // Verify the result
        assertNotNull(result);
        assertEquals("v2", result.getName());
        assertEquals(newTime, result.getCreateTime());
    }
}