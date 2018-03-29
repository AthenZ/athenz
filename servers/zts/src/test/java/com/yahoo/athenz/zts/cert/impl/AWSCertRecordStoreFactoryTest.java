/**
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

import java.sql.SQLException;

import org.testng.annotations.Test;

import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.CertRecordStore;

import static org.testng.Assert.*;

public class AWSCertRecordStoreFactoryTest {

    class TestAWSCertRecordStoreFactory extends AWSCertRecordStoreFactory {
        
        @Override
        String getAuthToken(String hostname, int port, String rdsUser, String rdsIamRole) {
            if (rdsUser.equals("rds-user")) {
                return "token";
            }
            return null;
        }
    }
    
    @Test
    public void testCreate() throws SQLException {
        
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_MASTER_INSTANCE, "instance");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_USER, "rds-user");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_IAM_ROLE, "role");
        System.setProperty(ZTSConsts.ZTS_PROP_AWS_RDS_CREDS_REFRESH_TIME, "1");
        
        AWSCertRecordStoreFactory factory = new TestAWSCertRecordStoreFactory();
        CertRecordStore store = factory.create(null);
        
        // sleep a couple of seconds for the updater to run
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
        }
        assertNotNull(store);
    }
}
