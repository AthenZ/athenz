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

import com.amazonaws.services.s3.model.AmazonS3Exception;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class S3ClientFactoryTest {

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
            assertTrue(ex instanceof AmazonS3Exception);
        }

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
    }
}
