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

package io.athenz.syncer.aws.common.impl;

import io.athenz.syncer.common.zms.CloudDomainStore;
import io.athenz.syncer.common.zms.Config;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.s3.S3Client;

import static org.testng.Assert.*;

public class AwsDomainStoreFactoryTest {

    @Test
    public void testCreateSuccess() {
        // Mock S3ClientFactory to return a mock S3Client
        S3Client mockS3Client = Mockito.mock(S3Client.class);

        try (MockedStatic<S3ClientFactory> mockedFactory = Mockito.mockStatic(S3ClientFactory.class)) {
            mockedFactory.when(S3ClientFactory::getS3Client).thenReturn(mockS3Client);

            // Required properties for AwsDomainStore creation
            System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
            System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, "test-bucket");
            System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, "test-key-id");
            System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, "test-access-key");
            System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION, "us-west-2");

            Config.getInstance().loadConfigParams();

            // Create the factory and test create() method
            AwsDomainStoreFactory factory = new AwsDomainStoreFactory();
            CloudDomainStore store = factory.create();

            // Verify success
            assertNotNull(store);
            assertTrue(store instanceof AwsDomainStore);
        } finally {
            // Clean up properties
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION);
        }
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testCreateFailure() {
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT + "_invalid");
        AwsDomainStoreFactory factory = new AwsDomainStoreFactory();
        factory.create();
    }
}