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
package com.yahoo.athenz.auth.util;

import static org.testng.Assert.*;
import org.testng.annotations.Test;
import org.mockito.Mockito;

import com.yahoo.athenz.auth.ServerPrivateKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.BiFunction;
import java.util.function.Function;

public class PrivateKeyStoreUtilTest {

    @Test
    public void testGetParameterNameProcessorFn() {
        BiFunction<String, String, String> fn = PrivateKeyStoreUtil.getParameterNameProcessorFn("aws", "zms", "RSA");
        // No system property set, should use default and append algorithm
        String paramName = fn.apply("athenz.%s.%s.key_name", "service_private_key");
        assertEquals(paramName, "service_private_key.rsa");

        // Set system property and verify override
        System.setProperty("athenz.aws.zms.key_name", "custom_key_name");
        paramName = fn.apply("athenz.%s.%s.key_name", "service_private_key");
        assertEquals(paramName, "custom_key_name.rsa");
        System.clearProperty("athenz.aws.zms.key_name");
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterNullRegion() {
        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "aws", "zms", null, "rsa", param -> "value");
        assertNull(privateKey);

        privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "aws", "zms", "", "rsa", param -> "value");
        assertNull(privateKey);
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterUnknownService() {
        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "aws", "unknown", "us-west-2", "rsa", param -> "value");
        assertNull(privateKey);
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterZmsService() throws IOException {
        String pemEncoded = Files.readString(Path.of("src/test/resources/unit_test_ec_private.key"));

        // Mock the function to return valid private key data
        Function<String, String> mockFn = param -> {
            if (param.contains("custom_key_id")) {
                return "test-key-id";
            } else {
                return pemEncoded;
            }
        };

        System.setProperty("athenz.aws.zms.key_name", "custom_key_name");
        System.setProperty("athenz.aws.zms.key_id_name", "custom_key_id");

        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "aws", "zms", "us-west-2", "ec", mockFn);
        assertNotNull(privateKey);
        assertEquals(privateKey.getId(), "test-key-id");

        System.clearProperty("athenz.aws.zms.key_name");
        System.clearProperty("athenz.aws.zms.key_id_name");
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterZtsService() throws IOException {
        String pemEncoded = Files.readString(Path.of("src/test/resources/unit_test_ec_private.key"));
        // Similar test for ZTS service
        Function<String, String> mockFn = Mockito.mock(Function.class);
        Mockito.when(mockFn.apply("service_private_key.rsa")).thenReturn(pemEncoded);
        Mockito.when(mockFn.apply("service_private_key_id.rsa")).thenReturn("zts-key-id");

        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "aws", "zts", "us-west-2", "rsa", mockFn);
        assertNotNull(privateKey);
        assertEquals(privateKey.getId(), "zts-key-id");
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterZtsServiceException() {
        Function<String, String> mockFn = Mockito.mock(Function.class);
        Mockito.when(mockFn.apply("service_private_key.rsa")).thenThrow(new RuntimeException("getParameter failure"));

        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "aws", "zts", "us-west-2", "rsa", mockFn);
        assertNull(privateKey);
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterMsdService() throws IOException {
        String pemEncoded = Files.readString(Path.of("src/test/resources/unit_test_ec_private.key"));
        // Similar test for MSD service
        Function<String, String> mockFn = param -> {
            if (param.contains("key_id")) {
                return "msd-key-id";
            } else {
                return pemEncoded;
            }
        };

        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "aws", "msd", "us-west-2", "rsa", mockFn);
        assertNotNull(privateKey);
        assertEquals(privateKey.getId(), "msd-key-id");
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterFailedToLoad() {
        // Test case when loading private key fails
        Function<String, String> mockFn = param -> "invalid-key-data";

        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "aws", "zms", "us-west-2", "rsa", mockFn);
        assertNull(privateKey);
    }
}