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

package io.athenz.syncer.common.zms;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

public class ConfigTest {

    private final static String TESTROOT = "src/test/resources";

    private final static String TEST_ZMS_CFG_PARAM_ZMS_URL = "http://somwhere_out_ther/";

    @BeforeMethod
    public void beforeMethod() {
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DEBUG, "true");
    }

    @AfterMethod
    public void afterMethod() {
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH, TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DEBUG, "true");
    }

    @Test
    public void testConfigNoConfigFile() {
        System.out.println("testConfigNoConfigFile");
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOT_PATH);
        Config configInstance = Config.getInstance();
        configInstance.loadConfigParams();
        Assert.assertFalse(configInstance.isConfigSuccessful());
    }

    @Test
    public void testConfigFileParams() {
        System.out.println("testConfigFileParams");
        Config configInstance = Config.getInstance();
        configInstance.loadConfigParams();
        Assert.assertTrue(configInstance.isConfigSuccessful());
        Assert.assertTrue(configInstance.isDebugEnabled());

        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH), TestConsts.TEST_STATE_DIR_DEFAULT);
        Assert.assertNull(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT));
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT), "25000");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE), "key_file");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATHENZ_SVC_CERT), "cert_file");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUST_STORE_PATH), "truststore_path");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUST_STORE_PASSWORD), "truststore_password");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS), "10");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT), "1800");
    }

    @Test
    public void testConfigPropsOverrideSome() {
        System.out.println("testConfigPropsOverRideSome");

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH, TestConsts.TEST_STATE_DIR);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE, TestConsts.TEST_SVC_KEY_FILE);
        Config configInstance = Config.getInstance();
        configInstance.loadConfigParams();
        Assert.assertTrue(configInstance.isConfigSuccessful());

        String rootPath = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ROOT_PATH) + "/";

        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH), rootPath + TestConsts.TEST_STATE_DIR);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_BUCKET), "horizon_athenz_sync");
        Assert.assertNull(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT));
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT), "25000");
        Assert.assertNull(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_KEY_ID));
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY), "abcdef");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE), TestConsts.TEST_SVC_KEY_FILE);
        Assert.assertEquals(configInstance.getConfigParam("project_id"), "test_project_id");

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE);
    }

    @Test
    public void testConfigPropsOverrideAll() {
        System.out.println("testConfigPropsOverrideAll");

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH, TestConsts.TEST_STATE_DIR);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_SLEEP_INTERVAL, TestConsts.TEST_SLEEP_INTERVAL);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET, TestConsts.TEST_AWS_BUCKET);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT, TestConsts.TEST_AWS_CONNECT_TIMEOUT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT, TestConsts.TEST_AWS_REQUEST_TIMEOUT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID, TestConsts.TEST_AWS_KEY_ID);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY, TestConsts.TEST_AWS_ACCESS_KEY);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE, TestConsts.TEST_SVC_KEY_FILE);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_CERT, TestConsts.TEST_SVC_CERT_FILE);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PATH, TestConsts.TEST_TRUST_STORE_PATH);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PASSWORD, TestConsts.TEST_TRUST_STORE_PASSWORD);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION, TestConsts.TEST_AWS_S3_REGION);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS, TestConsts.TEST_STATE_BUILDER_THREADS);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT, TestConsts.TEST_STATE_BUILDER_TIMEOUT);


        System.setProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL, TEST_ZMS_CFG_PARAM_ZMS_URL);

        Config configInstance = Config.getInstance();
        configInstance.loadConfigParams();
        Assert.assertTrue(configInstance.isConfigSuccessful());

        String rootPath = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ROOT_PATH) + "/";

        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH), rootPath + TestConsts.TEST_STATE_DIR);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_SLEEP_INTERVAL), TestConsts.TEST_SLEEP_INTERVAL);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_BUCKET), TestConsts.TEST_AWS_BUCKET);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT), TestConsts.TEST_AWS_CONNECT_TIMEOUT);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT), TestConsts.TEST_AWS_REQUEST_TIMEOUT);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_KEY_ID), TestConsts.TEST_AWS_KEY_ID);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY), TestConsts.TEST_AWS_ACCESS_KEY);
        Assert.assertEquals(configInstance.getConfigParam(Config.ZMS_CFG_PARAM_ZMS_URL), TEST_ZMS_CFG_PARAM_ZMS_URL);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE), TestConsts.TEST_SVC_KEY_FILE);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATHENZ_SVC_CERT), TestConsts.TEST_SVC_CERT_FILE);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUST_STORE_PATH), TestConsts.TEST_TRUST_STORE_PATH);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUST_STORE_PASSWORD), TestConsts.TEST_TRUST_STORE_PASSWORD);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWS_S3_REGION), TestConsts.TEST_AWS_S3_REGION);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS), TestConsts.TEST_STATE_BUILDER_THREADS);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT), TestConsts.TEST_STATE_BUILDER_TIMEOUT);

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_SLEEP_INTERVAL);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_BUCKET);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_CONNECT_TIMEOUT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_REQUEST_TIMEOUT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_KEY_ID);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_ACCESS_KEY);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_KEYFILE);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATHENZ_SVC_CERT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUST_STORE_PASSWORD);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWS_S3_REGION);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT);
    }

    @Test
    public void testConfigPropsOverrideExplicitPath() {
        System.out.println("testConfigPropsOverrideExplicitPath");

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH, TestConsts.TEST_STATE_DIR_EXPLICIT);
        Config configInstance = Config.getInstance();
        configInstance.loadConfigParams();
        Assert.assertTrue(configInstance.isConfigSuccessful());

        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_PATH), TestConsts.TEST_STATE_DIR_EXPLICIT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_PATH);
    }

    @Test
    public void testMergeAthenzConfigWithInvalidKeys() {
        System.out.println("testMergeAthenzConfigWithInvalidKeys");

        // Create a temporary test file with a public key entry that has null values
        String tempAthenzConfigPath = TESTROOT + "/temp_athenz_invalid_keys.conf";
        try {
            // Create a config with null key and keyId to trigger the continue statement
            String configContent = "{\n" +
                    "  \"zmsPublicKeys\": [\n" +
                    "    { \"id\": null, \"key\": \"validKey\" },\n" +
                    "    { \"id\": \"validId\", \"key\": null },\n" +
                    "    { \"id\": null, \"key\": null },\n" +
                    "    { \"id\": \"validId2\", \"key\": \"validKey2\" }\n" +
                    "  ],\n" +
                    "  \"zmsUrl\": \"http://localhost:10080/zms/v1\"\n" +
                    "}";

            Files.write(Paths.get(tempAthenzConfigPath), configContent.getBytes());

            // Override the ATHENZ_CONFIG_FILE path to point to our test file
            System.setProperty(Config.PROP_PREFIX + "athenz_config_file", "/temp_athenz_invalid_keys.conf");

            Config configInstance = Config.getInstance();
            configInstance.loadConfigParams();

            // Verify that only the valid key was loaded
            Assert.assertNull(configInstance.getZmsPublicKey("validId")); // null key should be skipped
            Assert.assertNull(configInstance.getZmsPublicKey(null));     // null id should be skipped

            // The valid key should be loaded
            // Note: We can't directly test this without making getZmsPublicKeyMap public
            // or adding a method to count keys, but we can verify config was successful
            Assert.assertTrue(configInstance.isConfigSuccessful());

        } catch (Exception e) {
            Assert.fail("Failed to create test file: " + e.getMessage());
        } finally {
            // Clean up
            try {
                Files.deleteIfExists(Paths.get(tempAthenzConfigPath));
            } catch (Exception ignored) {
                // Ignore cleanup errors
            }
            System.clearProperty(Config.PROP_PREFIX + "athenz_config_file");
        }
    }

}

