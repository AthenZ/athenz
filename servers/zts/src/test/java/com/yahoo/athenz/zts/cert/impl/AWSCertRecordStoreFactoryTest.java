/*
 * Copyright 2018 Oath Inc.
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
package com.yahoo.athenz.zts.cert.impl;

import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.services.rds.auth.RdsIamAuthTokenGenerator;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.CertRecordStore;

import static org.testng.Assert.*;

public class AWSCertRecordStoreFactoryTest {

    class TestAWSCertRecordStoreFactory extends AWSCertRecordStoreFactory {

        RdsIamAuthTokenGenerator generator = Mockito.mock(RdsIamAuthTokenGenerator.class);

        @Override
        RdsIamAuthTokenGenerator getTokenGenerator(InstanceProfileCredentialsProvider awsCredProvider) {

            Mockito.when(generator.getAuthToken(ArgumentMatchers.any())).thenReturn("token");
            return generator;
        }

        @Override
        String getInstanceRegion() {
            return "us-west-2";
        }
    }

    class TestAWSCertRecordStoreFactory2 extends AWSCertRecordStoreFactory {

        @Override
        String getAuthToken(String hostname, int port, String rdsUser, String rdsIamRole) {
            if (rdsUser.equals("rds-user")) {
                return "token";
            }
            throw new IllegalArgumentException("Unable to get token");
        }
    }

    @Test
    public void testCreate() {
        
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_MASTER_INSTANCE, "instance");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_IAM_ROLE, "role");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "1");
        
        AWSCertRecordStoreFactory factory = new TestAWSCertRecordStoreFactory();
        CertRecordStore store = factory.create(null);
        
        // sleep a couple of seconds for the updater to run
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }
        assertNotNull(store);

        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_MASTER_INSTANCE);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_USER);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_IAM_ROLE);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
    }

    @Test
    public void testGetTokenGenerator() {

        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_MASTER_INSTANCE, "instance");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_IAM_ROLE, "role");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "1");

        AWSCertRecordStoreFactory factory = new TestAWSCertRecordStoreFactory2();
        CertRecordStore store = factory.create(null);
        assertNotNull(store);

        // unless we're running this test in an AWS instance
        // we'll get an exception back from aws client library

        try {
            factory.getInstanceRegion();
            fail();
        } catch (Exception ignored) {
        }

        InstanceProfileCredentialsProvider provider = Mockito.mock(InstanceProfileCredentialsProvider.class);
        try {
            factory.getTokenGenerator(provider);
            fail();
        } catch (Exception ignored) {
        }

        // sleep a couple of seconds for the updater to run
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_MASTER_INSTANCE);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_USER);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_IAM_ROLE);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
    }

    @Test
    public void testUpdaterException() {

        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_MASTER_INSTANCE, "instance");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_USER, "rds-user2");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_IAM_ROLE, "role");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "1");

        AWSCertRecordStoreFactory factory = new TestAWSCertRecordStoreFactory();
        CertRecordStore store = factory.create(null);
        assertNotNull(store);

        // sleep a couple of seconds for the updater to run
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_MASTER_INSTANCE);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_USER);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_IAM_ROLE);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
    }
}
