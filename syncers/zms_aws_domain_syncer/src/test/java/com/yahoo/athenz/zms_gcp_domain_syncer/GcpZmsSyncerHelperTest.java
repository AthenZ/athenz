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
package com.yahoo.athenz.zms_gcp_domain_syncer;

import io.athenz.syncer.common.zms.CloudZmsSyncer;
import io.athenz.syncer.common.zms.Config;
import io.athenz.syncer.gcp.common.impl.GcsDomainStoreFactory;
import io.athenz.syncer.gcp.common.impl.GcsStateFileBuilderFactory;
import org.testng.annotations.Test;

import java.util.Objects;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class GcpZmsSyncerHelperTest {
    private final ClassLoader classLoader = this.getClass().getClassLoader();

    @Test(expectedExceptions = Exception.class)
    public void testCreateCloudZmsSyncerFailure() throws Exception {
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, "/invalid-path");
        System.setProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS, "io.athenz.syncer.common.zms.impl.IdontExist");
        try {
            assertNotNull(new GcpZmsSyncerHelper().createCloudZmsSyncer());
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
            assertNotNull(new GcpZmsSyncerHelper().createCloudZmsSyncer());
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
        GcpZmsSyncerHelper helper = new GcpZmsSyncerHelper() {
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
        GcpZmsSyncerHelper helper = new GcpZmsSyncerHelper() {
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
        GcpZmsSyncerHelper helper = new GcpZmsSyncerHelper() {
            @Override
            protected CloudZmsSyncer createCloudZmsSyncer() {
                throw new RuntimeException("Test exception");
            }
        };

        // Test the run method
        assertFalse(helper.run());
    }

    @Test
    public void testSetRequiredProperties() {
        final String domainStoreProp = CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS;
        final String stateFileProp = CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS;
        String originalDomainStoreProp = System.getProperty(domainStoreProp);
        String originalStateFileProp = System.getProperty(stateFileProp);

        try {
            // Clear properties first to ensure a clean state
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS);
            System.clearProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS);

            // Test when properties are not set
            GcpZmsSyncerHelper helper = new GcpZmsSyncerHelper();
            helper.setRequiredProperties();

            // Verify properties were set correctly
            assertEquals(System.getProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS),
                    GcsDomainStoreFactory.class.getName());
            assertEquals(System.getProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS),
                    GcsStateFileBuilderFactory.class.getName());

            // Test when properties are already set
            System.setProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS, "custom.factory.class");
            System.setProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS, "custom.builder.class");

            helper.setRequiredProperties();

            // Verify properties remain unchanged
            assertEquals(System.getProperty(CloudZmsSyncer.SYNC_PROP_CLOUD_DOMAIN_STORE_FACTORY_CLASS),
                    "custom.factory.class");
            assertEquals(System.getProperty(CloudZmsSyncer.SYNC_PROP_STATEFILE_BUILDER_FACTORY_CLASS),
                    "custom.builder.class");
        } finally {
            // Clean up and restore original properties
            if (originalDomainStoreProp != null) {
                System.setProperty(domainStoreProp, originalDomainStoreProp);
            } else {
                System.clearProperty(domainStoreProp);
            }
            if (originalStateFileProp != null) {
                System.setProperty(stateFileProp, originalStateFileProp);
            } else {
                System.clearProperty(stateFileProp);
            }
        }
    }
}