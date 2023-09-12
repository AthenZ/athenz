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
package com.yahoo.athenz.zms.store.impl;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.InstanceProfileCredentialsProvider;
import com.amazonaws.services.rds.auth.RdsIamAuthTokenGenerator;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.ObjectStore;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.assertNotNull;

public class AWSObjectStoreFactoryTest {

    static class TestAWSObjectStoreFactory extends AWSObjectStoreFactory {

        @Override
        InstanceProfileCredentialsProvider getNewInstanceCredentialsProvider() {
            InstanceProfileCredentialsProvider provider = Mockito.mock(InstanceProfileCredentialsProvider.class);
            AWSCredentials awsCredentials = Mockito.mock(AWSCredentials.class);
            Mockito.when(provider.getCredentials()).thenReturn(awsCredentials);
            Mockito.when(awsCredentials.getAWSAccessKeyId()).thenReturn("id");
            return provider;
        }

        @Override
        String getRegion() {
            return "us-west-2";
        }

        @Override
        String getGeneratorAuthToken(RdsIamAuthTokenGenerator generator, final String hostname,
                                     int port, final String rdsUser) {
            if (rdsUser.equals("rds-user")) {
                return "token";
            }
            return null;
        }
    }
    
    @Test
    public void testCreate() {

        System.setProperty(ZMSConsts.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(ZMSConsts.ZMS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(ZMSConsts.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "1");

        System.clearProperty(ZMSConsts.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);

        AWSObjectStoreFactory factory = new TestAWSObjectStoreFactory();
        ObjectStore store = factory.create(null);
        
        // sleep a couple of seconds for the updater to run
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }
        assertNotNull(store);
    }

    @Test
    public void testOriginalMethods() {

        System.setProperty(ZMSConsts.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(ZMSConsts.ZMS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(ZMSConsts.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "30000");

        System.clearProperty(ZMSConsts.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE);

        AWSObjectStoreFactory factory = new AWSObjectStoreFactory();

        try {
            factory.getNewInstanceCredentialsProvider();
        } catch (Exception ignored) {
        }

        try {
            factory.getRegion();
        } catch (Exception ignored) {
        }

        try {
            factory.getGeneratorAuthToken(null, "localhost", 40888, "rdsUser");
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testCreateWithReplica() {

        System.setProperty(ZMSConsts.ZMS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(ZMSConsts.ZMS_PROP_AWS_RDS_REPLICA_INSTANCE, "replica");
        System.setProperty(ZMSConsts.ZMS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(ZMSConsts.ZMS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "30000");

        AWSObjectStoreFactory factory = new TestAWSObjectStoreFactory();
        ObjectStore store = factory.create(null);

        // sleep a couple of seconds for the updater to run
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }
        assertNotNull(store);
    }
}
