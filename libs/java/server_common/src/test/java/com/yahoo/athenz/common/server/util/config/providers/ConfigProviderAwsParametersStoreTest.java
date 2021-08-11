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
package com.yahoo.athenz.common.server.util.config.providers;

import com.yahoo.athenz.common.server.util.Utils;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParametersByPathRequest;
import software.amazon.awssdk.services.ssm.model.GetParametersByPathResponse;
import software.amazon.awssdk.services.ssm.model.Parameter;

import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static org.testng.Assert.*;

public class ConfigProviderAwsParametersStoreTest {

    @Test
    public void testConfigProviderAwsParametersStore() {
        ConfigProviderAwsParametersStore provider = new ConfigProviderAwsParametersStore() {
            @Override
            protected SsmClient buildSsmClient() {
                SsmClient mockSsmClient = Mockito.mock(SsmClient.class);
                Mockito.when(mockSsmClient.getParametersByPath(Mockito.any(GetParametersByPathRequest.class))).thenAnswer(invocation -> {
                    GetParametersByPathRequest request = invocation.getArgument(0);
                    assertEquals(request.path(), "/test/prefix");
                    assertTrue(request.recursive());

                    // Mock 3 response pages.
                    GetParametersByPathResponse response = Mockito.mock(GetParametersByPathResponse.class);
                    String nextToken = request.nextToken();
                    if (nextToken == null) {
                        Mockito.when(response.parameters()).thenAnswer(invocation2 -> Arrays.asList(
                                buildParameter("/test/prefix/01", "value-01"),
                                buildParameter("02", "value-02")));
                        Mockito.when(response.nextToken()).thenReturn("A");
                    } else if (nextToken.equals("A")) {
                        Mockito.when(response.parameters()).thenAnswer(invocation2 -> Arrays.asList(
                                buildParameter("/test/prefix/11", "value-11"),
                                buildParameter("12", "value-12")));
                        Mockito.when(response.nextToken()).thenReturn("B");
                    } else if (nextToken.equals("B")) {
                        Mockito.when(response.parameters()).thenAnswer(invocation2 -> Arrays.asList(
                                buildParameter("/test/prefix/21", "value-21"),
                                buildParameter("22", "value-22")));
                        Mockito.when(response.nextToken()).thenReturn(null);
                    } else {
                        fail("Unexpected nextToken()");
                    }
                    return response;
                });
                return mockSsmClient;
            }
        };

        assertNull(provider.tryToBuildConfigSource("non-relevant"));

        ConfigProviderAwsParametersStore.ConfigSourceAwsParametersStore source = provider.tryToBuildConfigSource("aws-param-store://test/prefix");
        assertNotNull(source);
        assertEquals(source.toString(), "AWS-Parameters-Store path \"/test/prefix\"");
        assertEquals(source.path, "/test/prefix");
        assertEquals(source.parameterNamesRedundantPrefix, "/test/prefix/");

        Map<String, String> unsortedEntries = source.getConfigEntries().stream().collect(Collectors.toMap(entry -> entry.key, entry -> entry.value));
        Map<String, String> sortedEntries = new TreeMap<>(unsortedEntries);
        assertEquals("{\"01\":\"value-01\",\"02\":\"value-02\",\"11\":\"value-11\",\"12\":\"value-12\",\"21\":\"value-21\",\"22\":\"value-22\"}", Utils.jsonSerializeForLog(sortedEntries));
    }

    private static Parameter buildParameter(String name, String value) {
        Parameter parameter = Mockito.mock(Parameter.class);
        Mockito.when(parameter.name()).thenReturn(name);
        Mockito.when(parameter.value()).thenReturn(value);
        return parameter;
    }
}