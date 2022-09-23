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
package com.yahoo.athenz.zts.cert.impl;

import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.services.rds.auth.RdsIamAuthTokenGenerator;
import com.yahoo.athenz.common.server.cert.CertRecordStore;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.zts.ZTSConsts;

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

        boolean throwGetTokenExc = false;

        void setThrowGetTokenExc(boolean value) {
            throwGetTokenExc = value;
        }

        @Override
        String getAuthToken(String hostname, int port, String rdsUser, String rdsIamRole) {
            if (throwGetTokenExc) {
                throw new IllegalArgumentException("Unable to get token");
            } else {
                return "token";
            }
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
    public void testGetTokenException() {

        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_MASTER_INSTANCE, "instance");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_IAM_ROLE, "role");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "1");

        AWSCertRecordStoreFactory factory = new TestAWSCertRecordStoreFactory2();
        CertRecordStore store = factory.create(null);
        assertNotNull(store);

        ((TestAWSCertRecordStoreFactory2) factory).setThrowGetTokenExc(true);

        // we should not get any exceptions even though the get token
        // call will throw exceptions

        AWSCertRecordStoreFactory.CredentialsUpdater updater = factory.new CredentialsUpdater();
        updater.run();
        updater.run();

        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_MASTER_INSTANCE);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_USER);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_IAM_ROLE);
        System.clearProperty(ZTSConsts.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
    }

    @Test
    public void testCredentialsUpdater() {

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
