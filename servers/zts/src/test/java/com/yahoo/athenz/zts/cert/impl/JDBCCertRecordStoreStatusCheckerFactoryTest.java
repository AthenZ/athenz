/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.common.server.status.StatusChecker;
import com.yahoo.athenz.zts.ZTSConsts;
import org.testng.annotations.Test;

import static org.testng.AssertJUnit.*;

public class JDBCCertRecordStoreStatusCheckerFactoryTest {

    @Test
    public void testCreate() {
        System.getProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZTSConsts.ZTS_PKEY_STORE_FACTORY_CLASS);
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_STORE, "jdbc:mysql://localhost");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_USER, "user");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_PASSWORD, "password");

        JDBCCertRecordStoreStatusCheckerFactory jdbcCertRecordStoreStatusCheckerFactory =
                new JDBCCertRecordStoreStatusCheckerFactory();
        StatusChecker statusChecker = jdbcCertRecordStoreStatusCheckerFactory.create();
        assertNotNull(statusChecker);

        System.clearProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_STORE);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_USER);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_PASSWORD);
    }

    @Test
    public void testBadKeyStoreClass() {
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS, "unknownClassName");
        try {
            new JDBCCertRecordStoreStatusCheckerFactory();

            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid private key store");
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);
    }
}
