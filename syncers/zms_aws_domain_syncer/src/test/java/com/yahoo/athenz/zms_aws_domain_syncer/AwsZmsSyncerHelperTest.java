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

import io.athenz.syncer.aws.common.impl.AwsDomainStoreFactory;
import io.athenz.syncer.aws.common.impl.AwsStateFileBuilderFactory;
import io.athenz.syncer.common.zms.CloudZmsSyncer;
import io.athenz.syncer.common.zms.Config;
import org.testng.annotations.Test;

import java.util.Objects;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class AwsZmsSyncerHelperTest {
    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @Test(expectedExceptions = Exception.class)
    public void testCreateCloudZmsSyncerFailure() throws Exception {
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, "/invalid-path");
        System.setProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS, "io.athenz.syncer.common.zms.impl.IdontExist");
        try {
            assertNotNull(new AwsZmsSyncerHelper().createCloudZmsSyncer());
        } finally {
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS);
        }
    }

    @Test
    public void testCreateCloudZmsSyncer() throws Exception {
        final String certFile = Objects.requireNonNull(classLoader.getResource("unit_test_x509.pem")).getFile();
        final String keyFile = Objects.requireNonNull(classLoader.getResource("unit_test_private.pem")).getFile();
        final String caFile = Objects.requireNonNull(classLoader.getResource("unit_test_truststore.jks")).getFile();

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, "src/test/resources");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH, ".");
        System.setProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL, "https://athenz.com:4443/");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION,"us-west-2");
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE, keyFile);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_CERT, certFile);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PATH, caFile);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PASSWORD, "secret");
        System.setProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL, "https://athenz.io");

        Config.getInstance().loadConfigParams();

        try {
            assertNotNull(new AwsZmsSyncerHelper().createCloudZmsSyncer());
        } finally {
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH);
            System.clearProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_CERT);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PATH);
            System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PASSWORD);
            System.clearProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL);
        }
    }

    @Test
    public void testRunSuccess() throws Exception {
        CloudZmsSyncer cloudZmsSyncer = mock(CloudZmsSyncer.class);
        when(cloudZmsSyncer.processDomains()).thenReturn(true);

        // Create a test subclass that overrides createCloudZmsSyncer
        AwsZmsSyncerHelper helper = new AwsZmsSyncerHelper() {
            @Override
            protected CloudZmsSyncer createCloudZmsSyncer() throws Exception {
                return cloudZmsSyncer;
            }
        };

        assertTrue(helper.run());
    }

    @Test
    public void testRunFailure() throws Exception {
        CloudZmsSyncer cloudZmsSyncer = mock(CloudZmsSyncer.class);
        when(cloudZmsSyncer.processDomains()).thenReturn(false);
        AwsZmsSyncerHelper helper = new AwsZmsSyncerHelper() {
            @Override
            protected CloudZmsSyncer createCloudZmsSyncer() throws Exception {
                return cloudZmsSyncer;
            }
        };

        // Test the run method
        assertFalse(helper.run());
    }

    @Test
    public void testRunException() {
        // Create a test subclass that overrides createCloudZmsSyncer
        AwsZmsSyncerHelper helper = new AwsZmsSyncerHelper() {
            @Override
            protected CloudZmsSyncer createCloudZmsSyncer() {
                throw new RuntimeException("Test exception");
            }
        };

        // Test the run method
        assertFalse(helper.run());
    }


    @Test
    public void testSetRequiredPropertiesWhenNull() {
        // Clear any existing properties
        System.clearProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS);
        System.clearProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS);

        // Call the method
        AwsZmsSyncerHelper helper = new AwsZmsSyncerHelper();
        try {
            helper.setRequiredProperties();
            // Verify properties were set correctly
            assertEquals(
                    System.getProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS),
                    AwsDomainStoreFactory.class.getName()
            );
            assertEquals(
                    System.getProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS),
                    AwsStateFileBuilderFactory.class.getName()
            );
        } finally {
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS);
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS);
        }
    }

    @Test
    public void testSetRequiredPropertiesWhenAlreadySet() {
        // Set custom values
        String customDomainStore = "custom.domain.store.Factory";
        String customStateFileBuilder = "custom.state.file.Builder";

        System.setProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS, customDomainStore);
        System.setProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS, customStateFileBuilder);

        // Call the method
        AwsZmsSyncerHelper helper = new AwsZmsSyncerHelper();
        try {
            helper.setRequiredProperties();

            // Verify original properties were preserved
            assertEquals(
                    System.getProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS),
                    customDomainStore
            );
            assertEquals(
                    System.getProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS),
                    customStateFileBuilder
            );
        } finally {
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS);
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS);
        }
    }
}