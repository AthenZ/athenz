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

package com.yahoo.athenz.zms_aws_domain_syncer;

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
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class AwsSyncerTest {

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
            new AwsSyncer();
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
            new AwsSyncer();
        } catch (Exception ex) {
            assertTrue(ex instanceof AwsServiceException);
        }

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
    }

    @Test
    public void testUploadDomain() {

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_SSE_ALGORITHM, "sse");

        Config.getInstance().loadConfigParams();

        S3Client s3Client = Mockito.mock(S3Client.class);
        when(s3Client.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
                .thenReturn(PutObjectResponse.builder().build());

        AwsSyncer awsSyncer = new AwsSyncer(s3Client);
        awsSyncer.uploadDomain("coretech", "{\"domainName\":\"coretech\"}");

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

        AwsSyncer awsSyncer = new AwsSyncer(s3Client);
        try {
            awsSyncer.uploadDomain("coretech", "{\"domainName\":\"coretech\"}");
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

        AwsSyncer awsSyncer = new AwsSyncer(s3Client);
        awsSyncer.deleteDomain("coretech");
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

        AwsSyncer awsSyncer = new AwsSyncer(s3Client);
        try {
            awsSyncer.deleteDomain("coretech");
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("failure"));
        }
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
    }
}
