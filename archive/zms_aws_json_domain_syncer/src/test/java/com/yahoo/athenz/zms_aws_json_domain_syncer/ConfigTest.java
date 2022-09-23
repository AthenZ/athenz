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
package com.yahoo.athenz.zms_aws_json_domain_syncer;

import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class ConfigTest {

    private final static String TESTROOT = "src/test/resources";

    private final static String TEST_ZMS_CFG_PARAM_ZMS_URL = "http://somwhere_out_there/";

    @BeforeMethod
    public void beforeMethod() {
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOTPATH, TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DEBUG, "true");
    }

    @AfterMethod
    public void afterMethod() {
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOTPATH, TESTROOT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DEBUG, "true");
    }

    @Test
    public void testConfigNoConfigFile() {
        System.out.println("testConfigNoConfigFile");
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ROOTPATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_DEBUG);
        Config configInstance = Config.getInstance();
        configInstance.loadConfigParams();
        Assert.assertEquals(configInstance.isConfigSuccessful(), false);
        Assert.assertEquals(configInstance.isDebugEnabled(), false);
    }

    @Test(dependsOnMethods = {"testConfigNoConfigFile"})
    public void testConfigFileParams() {
        System.out.println("testConfigFileParams");
        Config configInstance = Config.getInstance();
        configInstance.loadConfigParams();
        Assert.assertEquals(configInstance.isConfigSuccessful(), true);
        Assert.assertEquals(configInstance.isDebugEnabled(), true);

        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATEPATH), TestConsts.TEST_STATE_DIR_DEFAULT);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSCONTO), null);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSREQTO), "25000");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATH_SVC_KEYFILE), "key_file");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATH_SVC_CERT), "cert_file");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUSTSOURCE_PATH), "truststore_path");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUSTSOURCE_PASSWORD), "truststore_password");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS), "10");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT), "1800");
    }

    @Test(dependsOnMethods = {"testConfigFileParams"})
    public void testConfigPropsOverideSome() {
        System.out.println("testConfigPropsOverideSome");

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATEPATH, TestConsts.TEST_STATE_DIR);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATH_SVC_KEYFILE, TestConsts.TEST_SVCKEYFILE);
        Config configInstance = Config.getInstance();
        configInstance.loadConfigParams();
        Assert.assertEquals(configInstance.isConfigSuccessful(), true);

        String rootPath = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ROOTPATH) + "/";

        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATEPATH), rootPath + TestConsts.TEST_STATE_DIR);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSBUCK), "horizon_athenz_sync");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSCONTO), null);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSREQTO), "25000");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSKEYID), null);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSACCKEY), "abcdef");
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATH_SVC_KEYFILE), TestConsts.TEST_SVCKEYFILE);

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATEPATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATH_SVC_KEYFILE);
    }

    @Test(dependsOnMethods = {"testConfigPropsOverideSome"})
    public void testConfigPropsOverideAll() {
        System.out.println("testConfigPropsOverideAll");

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATEPATH, TestConsts.TEST_STATE_DIR);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_SLEEPINT, TestConsts.TEST_SLEEPINT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_IGNDOMS, TestConsts.TEST_IGNDOMS);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSBUCK, TestConsts.TEST_AWSBUCK);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSCONTO, TestConsts.TEST_AWSCONTO);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSREQTO, TestConsts.TEST_AWSREQTO);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSKEYID, TestConsts.TEST_AWSKEYID);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSACCKEY, TestConsts.TEST_AWSACCKEY);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ZMSCLTFACT, TestConsts.TEST_ZMSCLTFACT);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATH_SVC_KEYFILE, TestConsts.TEST_SVCKEYFILE);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATH_SVC_CERT, TestConsts.TEST_SVCCERTFILE);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUSTSOURCE_PATH, TestConsts.TEST_TRUSTSOURCEPATH);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUSTSOURCE_PASSWORD, TestConsts.TEST_TRUSTSOURCEPASSWORD);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSREGION, TestConsts.TEST_AWSREGION);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS, TestConsts.TEST_STATEBUILDERTHREADS);
        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT, TestConsts.TEST_STATEBUILDERTIMEOUT);


        System.setProperty(Config.PROP_PREFIX + Config.ZMS_CFG_PARAM_ZMS_URL, TEST_ZMS_CFG_PARAM_ZMS_URL);

        Config configInstance = Config.getInstance();
        configInstance.loadConfigParams();
        Assert.assertEquals(configInstance.isConfigSuccessful(), true);

        String rootPath = configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ROOTPATH) + "/";

        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATEPATH), rootPath + TestConsts.TEST_STATE_DIR);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_SLEEPINT), TestConsts.TEST_SLEEPINT);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_IGNDOMS), TestConsts.TEST_IGNDOMS);
        String[] ignDoms = configInstance.getIgnoredDomains();
        Assert.assertEquals(ignDoms.length, 5);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSBUCK), TestConsts.TEST_AWSBUCK);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSCONTO), TestConsts.TEST_AWSCONTO);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSREQTO), TestConsts.TEST_AWSREQTO);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSKEYID), TestConsts.TEST_AWSKEYID);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSACCKEY), TestConsts.TEST_AWSACCKEY);
        Assert.assertEquals(configInstance.getConfigParam(Config.ZMS_CFG_PARAM_ZMS_URL), TEST_ZMS_CFG_PARAM_ZMS_URL);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ZMSCLTFACT), TestConsts.TEST_ZMSCLTFACT);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATH_SVC_KEYFILE), TestConsts.TEST_SVCKEYFILE);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_ATH_SVC_CERT), TestConsts.TEST_SVCCERTFILE);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUSTSOURCE_PATH), TestConsts.TEST_TRUSTSOURCEPATH);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_TRUSTSOURCE_PASSWORD), TestConsts.TEST_TRUSTSOURCEPASSWORD);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_AWSREGION), TestConsts.TEST_AWSREGION);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS), TestConsts.TEST_STATEBUILDERTHREADS);
        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT), TestConsts.TEST_STATEBUILDERTIMEOUT);

        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATEPATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_SLEEPINT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_IGNDOMS);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSBUCK);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSCONTO);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSREQTO);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSKEYID);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSACCKEY);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ZMSCLTFACT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATH_SVC_KEYFILE);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_ATH_SVC_CERT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUSTSOURCE_PATH);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_TRUSTSOURCE_PASSWORD);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_AWSREGION);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_BUILDER_THREADS);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATE_BUILDER_TIMEOUT);
    }

    @Test(dependsOnMethods = {"testConfigPropsOverideAll"})
    public void testConfigPropsOverideExplicitPath() {
        System.out.println("testConfigPropsOverideExplicitPath");

        System.setProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATEPATH, TestConsts.TEST_STATE_DIR_EXPLICIT);
        Config configInstance = Config.getInstance();
        configInstance.loadConfigParams();
        Assert.assertEquals(configInstance.isConfigSuccessful(), true);

        Assert.assertEquals(configInstance.getConfigParam(Config.SYNC_CFG_PARAM_STATEPATH), TestConsts.TEST_STATE_DIR_EXPLICIT);
        System.clearProperty(Config.PROP_PREFIX + Config.SYNC_CFG_PARAM_STATEPATH);
    }

}

