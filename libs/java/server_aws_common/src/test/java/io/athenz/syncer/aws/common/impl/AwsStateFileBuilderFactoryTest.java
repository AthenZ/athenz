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

import io.athenz.syncer.common.zms.Config;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.s3.S3Client;

import static org.mockito.Mockito.mockConstruction;
import static org.testng.Assert.*;

public class AwsStateFileBuilderFactoryTest {

    private String originalRootPath;

    @BeforeMethod
    public void setUp() {
        // Save original system properties to restore later
        originalRootPath = System.getProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
    }

    @AfterMethod
    public void tearDown() {
        // Restore original system properties
        if (originalRootPath != null) {
            System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, originalRootPath);
        } else {
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        }
    }

    // Note: The following tests are commented out because mocking S3ClientFactory::getS3Client is leaking into other tests

//    @Test(expectedExceptions = RuntimeException.class)
//    public void testCreateNoBucket() {
//        AwsStateFileBuilderFactory factory = new AwsStateFileBuilderFactory();
//        AwsStateFileBuilder builder = factory.create();
//        assertNotNull(builder, "The factory should return a non-null AwsStateFileBuilder instance");
//    }

//    @Test
//    public void testCreate() {
//        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
//
//        // Create mock objects
//        S3Client mockS3Client = Mockito.mock(S3Client.class);
//        S3ClientFactory s3ClientFactory = Mockito.mock(S3ClientFactory.class);
//
//        // Set up the S3ClientFactory to return our mock client
//        try (MockedStatic<S3ClientFactory> mockedFactory = Mockito.mockStatic(S3ClientFactory.class)) {
//            mockedFactory.when(S3ClientFactory::getS3Client).thenReturn(mockS3Client);
//
//            // Arrange
//            AwsStateFileBuilderFactory factory = new AwsStateFileBuilderFactory();
//
//            // Act
//            AwsStateFileBuilder builder = factory.create();
//
//            // Assert
//            assertNotNull(builder, "The factory should return a non-null AwsStateFileBuilder instance");
//            assertTrue(builder instanceof AwsStateFileBuilder, "The returned object should be an instance of AwsStateFileBuilder");
//
//        } finally {
//            System.clearProperty(Config.SYNC_CFG_PARAM_ROOT_PATH);
//        }
//    }
//
//
//    @Test
//    public void testCreateFailure() {
//        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TestUtils.TESTROOT);
//
//        // Create mock objects
//        S3Client mockS3Client = Mockito.mock(S3Client.class);
//        S3ClientFactory s3ClientFactory = Mockito.mock(S3ClientFactory.class);
//
//        // Set up the S3ClientFactory to return our mock client
//        try (MockedStatic<S3ClientFactory> mockedFactory = Mockito.mockStatic(S3ClientFactory.class)) {
//            mockedFactory.when(S3ClientFactory::getS3Client).thenThrow(new RuntimeException("Connection error"));
//
//            // Arrange
//            AwsStateFileBuilderFactory factory = new AwsStateFileBuilderFactory();
//
//            // Act
//            AwsStateFileBuilder builder = factory.create();
//            fail();
//        } catch (RuntimeException e) {
//            // expected
//        } finally {
//            System.clearProperty(Config.SYNC_CFG_PARAM_ROOT_PATH);
//        }
//    }



}