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
package io.athenz.server.gcp.common.config.impl;

import com.google.cloud.parametermanager.v1.*;
import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import com.yahoo.athenz.common.server.util.config.ConfigEntry;
import io.athenz.server.gcp.common.utils.ParameterManagerClientHelper;
import org.mockito.MockedStatic;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static io.athenz.server.gcp.common.Consts.*;
import static io.athenz.server.gcp.common.config.impl.ConfigProviderParameterManager.PROVIDER_DESCRIPTION_PREFIX;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class ConfigProviderParameterManagerTest {

    @Test
    public void testTryToBuildConfigSource() {
        String sourceDescription = "gcp-param-manager://location--system--";
        // Create a mock client for testing
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);

        // Create a spy of ConfigProviderParameterManager to mock buildClient
        ConfigProviderParameterManager providerSpy = spy(new ConfigProviderParameterManager());
        doReturn(mockClient).when(providerSpy).buildClient(anyString());

        // Test case 1: sourceDescription doesn't start with the prefix
        assertNull(providerSpy.tryToBuildConfigSource("invalid-prefix://something"));

        // Test case 2: sourceDescription has the prefix but no projectId is set
        try {
            System.clearProperty(ATHENZ_PROP_GCP_PROJECT_ID);
            providerSpy.tryToBuildConfigSource(sourceDescription);
            fail("Expected IllegalArgumentException was not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("GCP project ID must be set via system property: " + ATHENZ_PROP_GCP_PROJECT_ID, e.getMessage());
        }

        // Test case 3: sourceDescription has the prefix and projectId is set
        try {
            System.setProperty(ATHENZ_PROP_GCP_PROJECT_ID, "test-project");
            System.setProperty(ATHENZ_PROP_GCP_LOCATION, "test-location");

            ConfigProviderParameterManager.ConfigSourceParameterManager result = providerSpy.tryToBuildConfigSource(sourceDescription);

            assertNotNull(result);
            assertEquals("test-project", result.getProjectId());
            assertEquals("test-location", result.getLocationName().getLocation());
            assertEquals(mockClient, result.getClient());
            assertTrue(result.getParameterFullPrefix().endsWith("location--system--"));
        } finally {
            // Clean up system properties
            System.clearProperty(ATHENZ_PROP_GCP_PROJECT_ID);
            System.clearProperty(ATHENZ_PROP_GCP_LOCATION);
        }

        // Test case 4: using default location
        try {
            System.setProperty(ATHENZ_PROP_GCP_PROJECT_ID, "test-project");
            // Don't set location to test default value

            ConfigProviderParameterManager.ConfigSourceParameterManager result = providerSpy.tryToBuildConfigSource(sourceDescription);

            assertNotNull(result);
            assertEquals(GLOBAL_LOCATION, result.getLocationName().getLocation());
        } finally {
            System.clearProperty(ATHENZ_PROP_GCP_PROJECT_ID);
        }
    }

    @Test
    public void testTryToBuildConfigSourceProjectIdNotSet() {
        // Create a spy of ConfigProviderParameterManager
        ConfigProviderParameterManager providerSpy = spy(new ConfigProviderParameterManager());

        // Make sure the project ID property is cleared
        System.clearProperty(ATHENZ_PROP_GCP_PROJECT_ID);

        // Test with a valid prefix but no project ID
        try {
            providerSpy.tryToBuildConfigSource(PROVIDER_DESCRIPTION_PREFIX + "test-prefix");
            fail("Expected IllegalArgumentException was not thrown");
        } catch (IllegalArgumentException e) {
            assertEquals("GCP project ID must be set via system property: " + ATHENZ_PROP_GCP_PROJECT_ID, e.getMessage());
        } finally {
            // Clean up
            System.clearProperty(ATHENZ_PROP_GCP_PROJECT_ID);
        }
    }

    @Test
    public void testConfigSourceParameterManagerConstructor() {
        // Create mocks
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);

        // Test case 1: redundantPrefix already ends with "--"
        String sourceDescription = "gcp-param-manager://prefix--";
        String redundantPrefix = "prefix--";
        String projectId = "test-project";
        String location = "global";

        ConfigProviderParameterManager.ConfigSourceParameterManager configSource1 = new ConfigProviderParameterManager.ConfigSourceParameterManager(
                sourceDescription, redundantPrefix, projectId, location, mockClient);

        assertEquals(projectId, configSource1.getProjectId());
        assertEquals(LocationName.of(projectId, location).toString(), configSource1.getLocationName().toString());
        assertEquals(mockClient, configSource1.getClient());
        assertEquals(configSource1.getLocationName().toString() + "/parameters/" + redundantPrefix,
                configSource1.getParameterFullPrefix());

        // Test case 2: redundantPrefix doesn't end with "--"
        String redundantPrefix2 = "no-suffix";

        ConfigProviderParameterManager.ConfigSourceParameterManager configSource2 = new ConfigProviderParameterManager.ConfigSourceParameterManager(
                sourceDescription, redundantPrefix2, projectId, location, mockClient);

        assertEquals(configSource2.getLocationName().toString() + "/parameters/" + redundantPrefix2 + "--",
                configSource2.getParameterFullPrefix());
    }


    @Test
    public void testBuildClient() {
        // Test successful client creation
        try (MockedStatic<ParameterManagerClientHelper> helper = mockStatic(ParameterManagerClientHelper.class)) {
            ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
            String location = "test-location";

            helper.when(() -> ParameterManagerClientHelper.createParameterManagerClient(location))
                    .thenReturn(mockClient);

            ConfigProviderParameterManager provider = new ConfigProviderParameterManager();
            ParameterManagerClient result = provider.buildClient(location);

            assertSame(mockClient, result);
            helper.verify(() -> ParameterManagerClientHelper.createParameterManagerClient(location));
        }

        // Test exception handling
        try (MockedStatic<ParameterManagerClientHelper> helper = mockStatic(ParameterManagerClientHelper.class)) {
            String location = "test-location";
            IOException testException = new IOException("Test exception");

            helper.when(() -> ParameterManagerClientHelper.createParameterManagerClient(location))
                    .thenThrow(testException);

            ConfigProviderParameterManager provider = new ConfigProviderParameterManager();

            try {
                provider.buildClient(location);
                fail("Expected RuntimeException was not thrown");
            } catch (RuntimeException e) {
                assertEquals("Failed to create ParameterManagerClient in ConfigProviderParameterManager", e.getMessage());
                assertSame(testException, e.getCause());
            }

            helper.verify(() -> ParameterManagerClientHelper.createParameterManagerClient(location));
        }
    }

    @Test
    public void testTrimPrefixAndReplaceHyphen() {
        // Test basic functionality
        assertEquals(
                ConfigProviderParameterManager.trimPrefixAndReplaceHyphen(
                        "projects/myproject/parameters/athenz-config-key",
                        "projects/myproject/parameters/"),
                "athenz.config.key");

        assertEquals(
                ConfigProviderParameterManager.trimPrefixAndReplaceHyphen(
                        "projects/myproject/locations/global/parameters/athenz/location--system--simple",
                        "projects/myproject/locations/global/parameters/athenz/location--system--"),
                "simple");

        assertEquals(
                ConfigProviderParameterManager.trimPrefixAndReplaceHyphen(
                        "projects/myproject/locations/global/parameters/athenz--system--config-key-name",
                        "projects/myproject/locations/global/parameters/athenz--system--"),
                "config.key.name");

        // Test with no hyphens in the remaining part
        assertEquals(
                ConfigProviderParameterManager.trimPrefixAndReplaceHyphen(
                        "projects/myproject/parameters/athenzconfig",
                        "projects/myproject/parameters/"),
                "athenzconfig");

        // Test with multiple hyphens
        assertEquals(
                ConfigProviderParameterManager.trimPrefixAndReplaceHyphen(
                        "projects/myproject/parameters/athenz-config-key-name",
                        "projects/myproject/parameters/"),
                "athenz.config.key.name");

        // Test with empty remaining string
        assertEquals(
                ConfigProviderParameterManager.trimPrefixAndReplaceHyphen(
                        "projects/myproject/parameters/",
                        "projects/myproject/parameters/"),
                "");
    }

    @Test
    public void testGetConfigEntries() {
        System.out.println("Starting ConfigProviderParameterManagerTest.getConfigEntries");
        // Create mocks
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        ParameterManagerClient.ListParametersPagedResponse mockResponse = mock(ParameterManagerClient.ListParametersPagedResponse.class);

        // Setup test data
        String projectId = "test-project";
        String location = "global";
        String redundantPrefix = "us-west1--system--";
        String sourceDescription = "gcp-param-manager://us-west1--system--";
        LocationName locationName = LocationName.of(projectId, location);
        String parameterFullPrefix = locationName.toString() + "/parameters/" + redundantPrefix;

        String prop1FullName = parameterFullPrefix + "athenz-prop1";
        String prop2FullName = parameterFullPrefix + "athenz-prop2";

        // Create sample parameters
        Parameter param1 = Parameter.newBuilder()
                .setName(prop1FullName)
                .build();
        Parameter param2 = Parameter.newBuilder()
                .setName(prop1FullName)
                .build();
        Parameter param3 = Parameter.newBuilder()
                .setName(locationName.toString() + "/parameters/different-prefix-ignored")
                .build();

        List<Parameter> parameterList = Arrays.asList(param1, param2, param3);

        // Setup mock iterable
        Iterable<Parameter> mockIterable = () -> parameterList.iterator();

        // Configure mocks
        when(mockResponse.iterateAll()).thenReturn(mockIterable);
        when(mockClient.listParameters(locationName.toString())).thenReturn(mockResponse);

        ParameterVersionPayload param1Payload = ParameterVersionPayload.newBuilder()
                .setData(ByteString.copyFromUtf8("prop1value"))
                .build();
        ParameterVersion param1FullVersion = ParameterVersion.newBuilder()
                .setName(prop1FullName)
                .setPayload(param1Payload)
                .build();
        when(mockClient.getParameterVersion(prop1FullName)).thenReturn(param1FullVersion);


        ParameterVersionPayload param2Payload = ParameterVersionPayload.newBuilder()
                .setData(ByteString.copyFromUtf8("prop2value"))
                .build();
        ParameterVersion param2FullVersion = ParameterVersion.newBuilder()
                .setName(prop2FullName)
                .setPayload(param2Payload)
                .build();
        when(mockClient.getParameterVersion(prop2FullName)).thenReturn(param2FullVersion);


        // Mock parameter latest version retrieval
        ParameterVersion prop1LatestVersion = mock(ParameterVersion.class);
        Timestamp ts1 = Timestamp.newBuilder().setSeconds(1000).setNanos(0).build();
        when(prop1LatestVersion.getCreateTime()).thenReturn(ts1);
        when(prop1LatestVersion.getName()).thenReturn(prop1FullName);

        Iterable<ParameterVersion> prop1Versions = java.util.Arrays.asList(prop1LatestVersion);

        ParameterManagerClient.ListParameterVersionsPagedResponse prop1PagedResponse = mock(ParameterManagerClient.ListParameterVersionsPagedResponse.class);
        when(prop1PagedResponse.iterateAll()).thenReturn(prop1Versions).thenReturn(prop1Versions);


        ParameterVersion prop2LatestVersion = mock(ParameterVersion.class);
        Timestamp ts2 = Timestamp.newBuilder().setSeconds(1000).setNanos(0).build();
        when(prop2LatestVersion.getCreateTime()).thenReturn(ts2);
        when(prop2LatestVersion.getName()).thenReturn(prop2FullName);

        Iterable<ParameterVersion> prop2Versions = java.util.Arrays.asList(prop2LatestVersion);

        ParameterManagerClient.ListParameterVersionsPagedResponse prop2PagedResponse = mock(ParameterManagerClient.ListParameterVersionsPagedResponse.class);
        when(prop2PagedResponse.iterateAll()).thenReturn(prop2Versions).thenReturn(prop2Versions);

        when(mockClient.listParameterVersions(any(ListParameterVersionsRequest.class))).thenReturn(prop2PagedResponse);

        // Create the class under test
        ConfigProviderParameterManager.ConfigSourceParameterManager configSource =
                new ConfigProviderParameterManager.ConfigSourceParameterManager(
                        sourceDescription, redundantPrefix, projectId, location, mockClient);

        System.out.println("ConfigSource: " + configSource.toString());

        // Execute the method
        Collection<ConfigEntry> entries = configSource.getConfigEntries();

        // Verify results
        assertEquals(2, entries.size());

        boolean foundDbUser = false;
        boolean foundDbPassword = false;

        entries.stream().anyMatch(e -> e.key.equals("athenz.prop1") && e.value.equals("prop1value"));
        entries.stream().anyMatch(e -> e.key.equals("athenz.prop2") && e.value.equals("prop2value"));
    }


    @Test
    public void testMakeConfigEntry() {
        // Create mocks
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        String projectId = "test-project";
        String location = "global";
        String redundantPrefix = "us-west1--system--";
        String sourceDescription = "gcp-param-manager://us-west1--system--";
        LocationName locationName = LocationName.of(projectId, location);
        String parameterFullPrefix = locationName.toString() + "/parameters/" + redundantPrefix;
        String paramName = parameterFullPrefix + "athenz-test-param";

        // Create the parameter
        Parameter param = Parameter.newBuilder()
                .setName(paramName)
                .build();

        // Create the parameter version
        ParameterName parsedParamName = ParameterName.parse(paramName);
        ParameterVersion latestVersion = ParameterVersion.newBuilder()
                .setName(paramName + "/versions/1")
                .build();

        // Create the payload for the parameter version
        ParameterVersionPayload payload = ParameterVersionPayload.newBuilder()
                .setData(ByteString.copyFromUtf8("test-value"))
                .build();

        ParameterVersion fullVersion = ParameterVersion.newBuilder()
                .setName(paramName + "/versions/1")
                .setPayload(payload)
                .build();

        // Configure mocks
        try (MockedStatic<ParameterManagerClientHelper> helper = mockStatic(ParameterManagerClientHelper.class)) {
            helper.when(() -> ParameterManagerClientHelper.getLatestParameterVersion(mockClient, parsedParamName))
                    .thenReturn(latestVersion);

            when(mockClient.getParameterVersion(latestVersion.getName())).thenReturn(fullVersion);

            // Create the class under test
            ConfigProviderParameterManager.ConfigSourceParameterManager configSource =
                    new ConfigProviderParameterManager.ConfigSourceParameterManager(
                            sourceDescription, redundantPrefix, projectId, location, mockClient);

            // Execute the method
            ConfigEntry entry = configSource.makeConfigEntry(param);

            // Verify results
            assertNotNull(entry);
            assertEquals("athenz.test.param", entry.key);
            assertEquals("test-value", entry.value);
            assertEquals(configSource, entry.sourceSource);
            assertEquals("", entry.sourceDescription);

            // Verify method calls
            helper.verify(() -> ParameterManagerClientHelper.getLatestParameterVersion(mockClient, parsedParamName));
            verify(mockClient).getParameterVersion(latestVersion.getName());
        }
    }

    @Test
    public void testMakeConfigEntryErrorCases() {
        // Create mocks
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);
        String projectId = "test-project";
        String location = "global";
        String redundantPrefix = "us-west1--system--";
        String sourceDescription = "gcp-param-manager://us-west1--system--";
        LocationName locationName = LocationName.of(projectId, location);
        String parameterFullPrefix = locationName.toString() + "/parameters/" + redundantPrefix;
        String paramName = parameterFullPrefix + "athenz-error-param";

        // Create the parameter
        Parameter param = Parameter.newBuilder()
                .setName(paramName)
                .build();

        ParameterName parsedParamName = ParameterName.parse(paramName);

        // Create the class under test
        ConfigProviderParameterManager.ConfigSourceParameterManager configSource =
                new ConfigProviderParameterManager.ConfigSourceParameterManager(
                        sourceDescription, redundantPrefix, projectId, location, mockClient);

        // Test case 1: getLatestParameterVersion returns null
        try (MockedStatic<ParameterManagerClientHelper> helper = mockStatic(ParameterManagerClientHelper.class)) {
            helper.when(() -> ParameterManagerClientHelper.getLatestParameterVersion(mockClient, parsedParamName))
                    .thenReturn(null);

            ConfigEntry entry = configSource.makeConfigEntry(param);
            assertNull(entry, "Entry should be null when latest parameter version is not found");
        }

        // Test case 2: getParameterVersion throws an exception
        try (MockedStatic<ParameterManagerClientHelper> helper = mockStatic(ParameterManagerClientHelper.class)) {
            ParameterVersion latestVersion = ParameterVersion.newBuilder()
                    .setName(paramName + "/versions/1")
                    .build();

            helper.when(() -> ParameterManagerClientHelper.getLatestParameterVersion(mockClient, parsedParamName))
                    .thenReturn(latestVersion);

            when(mockClient.getParameterVersion(latestVersion.getName()))
                    .thenThrow(new RuntimeException("Test exception"));

            ConfigEntry entry = configSource.makeConfigEntry(param);
            assertNull(entry, "Entry should be null when an exception occurs");
        }
    }

    @Test
    public void testToString() {
        // Create mocks
        ParameterManagerClient mockClient = mock(ParameterManagerClient.class);

        // Setup test data
        String projectId = "test-project";
        String location = "global";
        String redundantPrefix = "us-west1--system--";
        String sourceDescription = "gcp-param-manager://us-west1--system--";
        LocationName locationName = LocationName.of(projectId, location);
        String parameterFullPrefix = locationName.toString() + "/parameters/" + redundantPrefix;

        // Create the class under test
        ConfigProviderParameterManager.ConfigSourceParameterManager configSource =
                new ConfigProviderParameterManager.ConfigSourceParameterManager(
                        sourceDescription, redundantPrefix, projectId, location, mockClient);

        // Execute the method
        String result = configSource.toString();

        // Verify results
        assertEquals("GCP-Parameters-Manager projectId: " + projectId +
                ", location: " + location +
                ", parameterFullPrefix: " + parameterFullPrefix, result);
    }



}