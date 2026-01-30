/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package io.athenz.syncer.aws.common.impl;

import com.yahoo.athenz.auth.util.Crypto;
import io.athenz.syncer.common.zms.Config;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;

import software.amazon.awssdk.http.TlsTrustManagersProvider;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.core.checksums.RequestChecksumCalculation;
import software.amazon.awssdk.core.checksums.ResponseChecksumValidation;

import java.net.URI;
import java.security.cert.X509Certificate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class S3ClientFactoryTest {

    @Test
    public void testCreateS3Factory() throws Exception {
        assertNotNull(new S3ClientFactory());
    }

    @Test
    public void testGetS3ClientWithCustomEndpointAndCaCert() throws Exception {
        // Setup configuration
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, "test-bucket");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_ENDPOINT, "https://custom.s3.endpoint");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_CA_CERT, "src/test/resources/dummy_ca.pem");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, "test-key");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "test-secret");

        Config.getInstance().loadProperties();

        // Mocks
        try (MockedStatic<ApacheHttpClient> mockHttpClientStatic = mockStatic(ApacheHttpClient.class);
             MockedStatic<S3Client> mockS3ClientStatic = mockStatic(S3Client.class);
             MockedStatic<Crypto> mockCryptoStatic = mockStatic(Crypto.class)) {

            // Mock Crypto
            mockCryptoStatic.when(() -> Crypto.loadX509Certificates(anyString())).thenReturn(new X509Certificate[]{mock(X509Certificate.class)});

            // Mock ApacheHttpClient builder
            ApacheHttpClient.Builder mockHttpBuilder = mock(ApacheHttpClient.Builder.class);
            SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);

            mockHttpClientStatic.when(ApacheHttpClient::builder).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.connectionTimeout(any())).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.socketTimeout(any())).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.tlsTrustManagersProvider(any())).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.build()).thenReturn(mockHttpClient);

            // Mock S3Client builder
            S3ClientBuilder mockS3Builder = mock(S3ClientBuilder.class);
            S3Client mockS3Client = mock(S3Client.class);

            mockS3ClientStatic.when(S3Client::builder).thenReturn(mockS3Builder);
            when(mockS3Builder.httpClient(any(SdkHttpClient.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.region(any(Region.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.endpointOverride(any(URI.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.credentialsProvider(any())).thenReturn(mockS3Builder);
            when(mockS3Builder.build()).thenReturn(mockS3Client);

            // Mock HeadBucket to pass verification
            when(mockS3Client.headBucket(any(HeadBucketRequest.class))).thenReturn(HeadBucketResponse.builder().build());

            // Execute
            S3Client client = S3ClientFactory.getS3Client();

            // Verify
            assertNotNull(client);

            // Verify ApacheHttpClient configured with TrustManager
            verify(mockHttpBuilder).tlsTrustManagersProvider(any(TlsTrustManagersProvider.class));

            // Verify S3Client configured with Endpoint Override
            ArgumentCaptor<URI> uriCaptor = ArgumentCaptor.forClass(URI.class);
            verify(mockS3Builder).endpointOverride(uriCaptor.capture());
            assertEquals(uriCaptor.getValue().toString(), "https://custom.s3.endpoint");
        } finally {
            // Cleanup
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_ENDPOINT);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_CA_CERT);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        }
    }

    @Test
    public void testGetS3ClientEmptyBucket() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, "");
        Config.getInstance().loadProperties();

        try {
            S3ClientFactory.getS3Client();
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("required bucket name not configured"));
        }

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
    }

    @Test
    public void testGetS3ClientWithTimeoutValuesDefaultBuilderFailure() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, "aws-bucket-name");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT, "1000");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT, "2000");

        Config.getInstance().loadProperties();

        try {
            S3ClientFactory.getS3Client();
            fail();
        } catch (Exception ignored) {
        }

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
    }

    @Test
    public void testGetS3ClientWithInvalidTimeoutValuesDefaultBuilderFailure() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, "aws-bucket-name");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT, "a");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT, "b");

        Config.getInstance().loadProperties();

        try {
            S3ClientFactory.getS3Client();
            fail();
        } catch (Exception ignored) {
        }

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
    }

    @Test
    public void testGetS3ClientInvalidCredsSpecified() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, "some-unknown-aws-bucket-name");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT, "");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT, "");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, TestConsts.TEST_AWS_KEY_ID);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, TestConsts.TEST_AWS_ACCESS_KEY);

        Config.getInstance().loadProperties();

        try {
            S3ClientFactory.getS3Client();
            fail();
        } catch (Exception ex) {
            assertTrue(ex instanceof AwsServiceException);
        }

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
    }

    @Test
    public void testGetRegionFromConfiguration() {
        // Setup configuration with a specific region
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION, "us-east-1");
        Config.getInstance().loadProperties();

        try {
            // Execute
            Region region = S3ClientFactory.getRegion();

            // Verify
            assertEquals(Region.US_EAST_1, region);
        } finally {
            // Cleanup
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        }
    }

    @Test
    public void testGetRegionFromDefaultProvider() {
        // Setup configuration with no region specified
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        Config.getInstance().loadProperties();

        try {
            // Execute
            Region region = S3ClientFactory.getRegion();

            // Verify - since we can't predict what the DefaultAwsRegionProviderChain will return,
            // we just verify it's not null and we got some region
            assertNotNull(region);
        } finally {
            // Cleanup
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        }
    }

    @Test
    public void testGetRegionDefaultsToUsWest2OnError() throws Exception {
        // Setup configuration with no region specified
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        Config.getInstance().loadProperties();

        try (MockedStatic<DefaultAwsRegionProviderChain> mockedChain = mockStatic(DefaultAwsRegionProviderChain.class)) {
            // Mock the chain builder to return a chain that throws exception
            DefaultAwsRegionProviderChain mockProvider = mock(DefaultAwsRegionProviderChain.class);
            when(mockProvider.getRegion()).thenThrow(new RuntimeException("Test exception"));

            // Mock the builder
            DefaultAwsRegionProviderChain.Builder mockBuilder = mock(DefaultAwsRegionProviderChain.Builder.class);
            when(mockBuilder.build()).thenReturn(mockProvider);

            // Mock the static builder() method
            mockedChain.when(DefaultAwsRegionProviderChain::builder).thenReturn(mockBuilder);

            // Execute
            Region region = S3ClientFactory.getRegion();

            // Verify we get the default US_WEST_2
            assertEquals(Region.US_WEST_2, region);
        } finally {
            // Cleanup
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        }
    }

    @Test
    public void testVerifyBucketExistSuccess() {
        // Mock the S3Client
        S3Client mockS3Client = mock(S3Client.class);

        // Setup successful response
        HeadBucketResponse response = HeadBucketResponse.builder().build();
        when(mockS3Client.headBucket(any(HeadBucketRequest.class))).thenReturn(response);

        // Method should complete without exception
        S3ClientFactory.verifyBucketExist(mockS3Client, "test-bucket");

        // Verify headBucket was called with the correct bucket name
        ArgumentCaptor<HeadBucketRequest> requestCaptor = ArgumentCaptor.forClass(HeadBucketRequest.class);
        verify(mockS3Client).headBucket(requestCaptor.capture());
        assertEquals("test-bucket", requestCaptor.getValue().bucket());
    }

    @Test(expectedExceptions = Exception.class)
    public void testVerifyBucketExistFailure() {
        // Mock the S3Client
        S3Client mockS3Client = mock(S3Client.class);

        when(mockS3Client.headBucket(any(HeadBucketRequest.class))).thenThrow(new RuntimeException("The specified bucket does not exist"));

        S3ClientFactory.verifyBucketExist(mockS3Client, "nonexistent-bucket");
    }

    @Test
    public void testGetS3ClientWithChecksumValidationEnabled() throws Exception {
        // Setup configuration
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, "test-bucket");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_CHECKSUM_VALIDATION, "true");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, "test-key");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "test-secret");

        Config.getInstance().loadProperties();

        // Mocks
        try (MockedStatic<ApacheHttpClient> mockHttpClientStatic = mockStatic(ApacheHttpClient.class);
             MockedStatic<S3Client> mockS3ClientStatic = mockStatic(S3Client.class)) {

            // Mock ApacheHttpClient builder
            ApacheHttpClient.Builder mockHttpBuilder = mock(ApacheHttpClient.Builder.class);
            SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);

            mockHttpClientStatic.when(ApacheHttpClient::builder).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.connectionTimeout(any())).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.socketTimeout(any())).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.build()).thenReturn(mockHttpClient);

            // Mock S3Client builder
            S3ClientBuilder mockS3Builder = mock(S3ClientBuilder.class);
            S3Client mockS3Client = mock(S3Client.class);

            mockS3ClientStatic.when(S3Client::builder).thenReturn(mockS3Builder);
            when(mockS3Builder.httpClient(any(SdkHttpClient.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.region(any(Region.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.requestChecksumCalculation(any(RequestChecksumCalculation.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.responseChecksumValidation(any(ResponseChecksumValidation.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.credentialsProvider(any())).thenReturn(mockS3Builder);
            when(mockS3Builder.build()).thenReturn(mockS3Client);

            // Mock HeadBucket to pass verification
            when(mockS3Client.headBucket(any(HeadBucketRequest.class))).thenReturn(HeadBucketResponse.builder().build());

            // Execute
            S3Client client = S3ClientFactory.getS3Client();

            // Verify
            assertNotNull(client);

            // Verify checksum calculation and validation were enabled
            verify(mockS3Builder).requestChecksumCalculation(RequestChecksumCalculation.WHEN_REQUIRED);
            verify(mockS3Builder).responseChecksumValidation(ResponseChecksumValidation.WHEN_REQUIRED);
        } finally {
            // Cleanup
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_CHECKSUM_VALIDATION);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        }
    }

    @Test
    public void testGetS3ClientWithChecksumValidationDisabled() throws Exception {
        // Setup configuration
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, "test-bucket");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_CHECKSUM_VALIDATION, "false");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, "test-key");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "test-secret");

        Config.getInstance().loadProperties();

        // Mocks
        try (MockedStatic<ApacheHttpClient> mockHttpClientStatic = mockStatic(ApacheHttpClient.class);
             MockedStatic<S3Client> mockS3ClientStatic = mockStatic(S3Client.class)) {

            // Mock ApacheHttpClient builder
            ApacheHttpClient.Builder mockHttpBuilder = mock(ApacheHttpClient.Builder.class);
            SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);

            mockHttpClientStatic.when(ApacheHttpClient::builder).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.connectionTimeout(any())).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.socketTimeout(any())).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.build()).thenReturn(mockHttpClient);

            // Mock S3Client builder
            S3ClientBuilder mockS3Builder = mock(S3ClientBuilder.class);
            S3Client mockS3Client = mock(S3Client.class);

            mockS3ClientStatic.when(S3Client::builder).thenReturn(mockS3Builder);
            when(mockS3Builder.httpClient(any(SdkHttpClient.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.region(any(Region.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.credentialsProvider(any())).thenReturn(mockS3Builder);
            when(mockS3Builder.build()).thenReturn(mockS3Client);

            // Mock HeadBucket to pass verification
            when(mockS3Client.headBucket(any(HeadBucketRequest.class))).thenReturn(HeadBucketResponse.builder().build());

            // Execute
            S3Client client = S3ClientFactory.getS3Client();

            // Verify
            assertNotNull(client);

            // Verify checksum calculation and validation were NOT called
            verify(mockS3Builder, never()).requestChecksumCalculation(any());
            verify(mockS3Builder, never()).responseChecksumValidation(any());
        } finally {
            // Cleanup
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_CHECKSUM_VALIDATION);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        }
    }

    @Test
    public void testGetS3ClientWithChecksumValidationNotConfigured() throws Exception {
        // Setup configuration without checksum validation parameter
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, "test-bucket");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, "test-key");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "test-secret");

        Config.getInstance().loadProperties();

        // Mocks
        try (MockedStatic<ApacheHttpClient> mockHttpClientStatic = mockStatic(ApacheHttpClient.class);
             MockedStatic<S3Client> mockS3ClientStatic = mockStatic(S3Client.class)) {

            // Mock ApacheHttpClient builder
            ApacheHttpClient.Builder mockHttpBuilder = mock(ApacheHttpClient.Builder.class);
            SdkHttpClient mockHttpClient = mock(SdkHttpClient.class);

            mockHttpClientStatic.when(ApacheHttpClient::builder).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.connectionTimeout(any())).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.socketTimeout(any())).thenReturn(mockHttpBuilder);
            when(mockHttpBuilder.build()).thenReturn(mockHttpClient);

            // Mock S3Client builder
            S3ClientBuilder mockS3Builder = mock(S3ClientBuilder.class);
            S3Client mockS3Client = mock(S3Client.class);

            mockS3ClientStatic.when(S3Client::builder).thenReturn(mockS3Builder);
            when(mockS3Builder.httpClient(any(SdkHttpClient.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.region(any(Region.class))).thenReturn(mockS3Builder);
            when(mockS3Builder.credentialsProvider(any())).thenReturn(mockS3Builder);
            when(mockS3Builder.build()).thenReturn(mockS3Client);

            // Mock HeadBucket to pass verification
            when(mockS3Client.headBucket(any(HeadBucketRequest.class))).thenReturn(HeadBucketResponse.builder().build());

            // Execute
            S3Client client = S3ClientFactory.getS3Client();

            // Verify
            assertNotNull(client);

            // Verify checksum calculation and validation were NOT called (default behavior)
            verify(mockS3Builder, never()).requestChecksumCalculation(any());
            verify(mockS3Builder, never()).responseChecksumValidation(any());
        } finally {
            // Cleanup
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        }
    }
}
