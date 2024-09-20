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
package io.athenz.server.aws.common.cert.impl;

import com.yahoo.athenz.common.server.cert.CertRecordStore;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class AWSCertRecordStoreFactoryTest {

    static class TestAWSCertRecordStoreFactory extends AWSCertRecordStoreFactory {

        @Override
        String getAuthToken(String hostname, int port, String rdsUser) {
            return "token";
        }
    }

    static class TestAWSCertRecordStoreFactory2 extends AWSCertRecordStoreFactory {

        boolean throwGetTokenExc = false;

        void setThrowGetTokenExc(boolean value) {
            throwGetTokenExc = value;
        }

        @Override
        String getAuthToken(String hostname, int port, String rdsUser) {
            if (throwGetTokenExc) {
                throw new IllegalArgumentException("Unable to get token");
            } else {
                return "token";
            }
        }
    }

    @Test
    public void testCreate() {
        
        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "1");
        
        AWSCertRecordStoreFactory factory = new TestAWSCertRecordStoreFactory();
        CertRecordStore store = factory.create(null);
        
        // sleep a couple of seconds for the updater to run
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }
        assertNotNull(store);

        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_USER);
        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
    }

    @Test
    public void testGetTokenException() {

        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "1");

        TestAWSCertRecordStoreFactory2 factory = new TestAWSCertRecordStoreFactory2();
        CertRecordStore store = factory.create(null);
        assertNotNull(store);

        factory.setThrowGetTokenExc(true);

        // we should not get any exceptions even though the get token
        // call will throw exceptions

        AWSCertRecordStoreFactory.CredentialsUpdater updater = factory.new CredentialsUpdater();
        updater.run();
        updater.run();

        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_USER);
        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
    }

    @Test
    public void testCredentialsUpdater() {

        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_USER, "rds-user2");
        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "1");

        AWSCertRecordStoreFactory factory = new TestAWSCertRecordStoreFactory();
        CertRecordStore store = factory.create(null);
        assertNotNull(store);

        // sleep a couple of seconds for the updater to run
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ignored) {
        }

        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_USER);
        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
    }

    @Test
    public void testOriginalMethods() {

        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_PRIMARY_INSTANCE, "instance");
        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "30000");

        AWSCertRecordStoreFactory factory = new AWSCertRecordStoreFactory();

        try {
            factory.getAuthToken("host", 3306, "user");
        } catch (Exception ignored) {
        }

        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_PRIMARY_INSTANCE);
        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_USER);
        System.clearProperty(AWSCertRecordStoreFactory.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME);
    }
}
