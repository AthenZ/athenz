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

import io.athenz.syncer.common.zms.Config;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class AwsDomainStoreTest {

    @Test
    public void testAwsSyncerInitBadRegion() {
        System.out.println("testAwsSyncerInitBadRegion");

        // set props for bucket, clear aws secrets
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION, TestConsts.TEST_AWS_S3_REGION);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, TestConsts.TEST_AWS_KEY_ID);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, TestConsts.TEST_AWS_ACCESS_KEY);
        Config.getInstance().loadConfigParams();

        try {
            new AwsDomainStore();
        } catch (Exception exc) {
            System.out.println("testCloudInitBadRegion: AwsSyncer throws=" + exc);
            assertTrue(exc instanceof SdkClientException);
        }

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION);
    }

    @Test
    public void testAwsSyncerInitBadBucket() {
        System.out.println("testAwsSyncerInitBadBucket");

        // set property for bucket and for aws secrets
        String bucket = "no_such_bucket";

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, bucket);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, "abcd");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "xyz");
        Config.getInstance().loadConfigParams();

        try {
            new AwsDomainStore();
        } catch (Exception ex) {
            assertTrue(ex instanceof AwsServiceException);
        }

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
    }

    @Test
    public void testAwsDomainStoreConstructorSuccess() {
        System.out.println("testAwsDomainStoreConstructorSuccess");

        // Set required properties for successful initialization
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, "test-bucket");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, "test-key-id");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "test-access-key");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION, "us-west-2");

        Config.getInstance().loadConfigParams();

        try {
            // Mock S3ClientFactory to return a mock S3Client
            S3Client mockS3Client = Mockito.mock(S3Client.class);
            try (MockedStatic<S3ClientFactory> mockedFactory = Mockito.mockStatic(S3ClientFactory.class)) {
                mockedFactory.when(S3ClientFactory::getS3Client).thenReturn(mockS3Client);

                // Test constructor - should not throw exception
                AwsDomainStore store = new AwsDomainStore();
                // Verify the store was created successfully
                assertNotNull(store);
            }
        } catch (Exception ex) {
            fail("Constructor should not throw exception: " + ex.getMessage());
        } finally {
            // Clean up properties
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION);
        }
    }


    @Test
    public void testUploadDomain() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_SSE_ALGORITHM, "sse");

        Config.getInstance().loadConfigParams();

        S3Client s3Client = Mockito.mock(S3Client.class);
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());

        AwsDomainStore awsDomainStore = new AwsDomainStore(s3Client);
        awsDomainStore.uploadDomain("coretech", "{\"domainName\":\"coretech\"}");

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_SSE_ALGORITHM);
    }

    @Test
    public void testUploadDomainFailure() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        Config.getInstance().loadConfigParams();

        S3Client s3Client = Mockito.mock(S3Client.class);
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenThrow(AwsServiceException.builder()
                        .awsErrorDetails(AwsErrorDetails.builder().errorMessage("failure").build()).build());

        AwsDomainStore awsDomainStore = new AwsDomainStore(s3Client);
        try {
            awsDomainStore.uploadDomain("coretech", "{\"domainName\":\"coretech\"}");
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("failure"));
        }

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
    }

    @Test
    public void testDeleteDomain() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        Config.getInstance().loadConfigParams();

        S3Client s3Client = Mockito.mock(S3Client.class);

        AwsDomainStore awsDomainStore = new AwsDomainStore(s3Client);
        awsDomainStore.deleteDomain("coretech");
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
    }

    @Test
    public void testDeleteDomainFailure() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        Config.getInstance().loadConfigParams();

        S3Client s3Client = Mockito.mock(S3Client.class);
        doThrow(AwsServiceException.builder()
                .awsErrorDetails(AwsErrorDetails.builder().errorMessage("failure").build()).build())
                .when(s3Client).deleteObject(any(DeleteObjectRequest.class));

        AwsDomainStore awsDomainStore = new AwsDomainStore(s3Client);
        try {
            awsDomainStore.deleteDomain("coretech");
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("failure"));
        }
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
    }
}
