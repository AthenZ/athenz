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

package com.yahoo.athenz.common.server.cert.impl;

import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.status.StatusChecker;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class JDBCCertRecordStoreStatusCheckerFactoryTest {

    @Test
    public void testCreate() throws ServerResourceException {
        System.getProperty(JDBCCertRecordStoreStatusCheckerFactory.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                JDBCCertRecordStoreStatusCheckerFactory.ZTS_PKEY_STORE_FACTORY_CLASS);
        System.setProperty(JDBCCertRecordStoreFactory.ZTS_PROP_CERT_JDBC_STORE, "jdbc:mysql://localhost");
        System.setProperty(JDBCCertRecordStoreFactory.ZTS_PROP_CERT_JDBC_USER, "user");
        System.setProperty(JDBCCertRecordStoreFactory.ZTS_PROP_CERT_JDBC_PASSWORD, "password");

        JDBCCertRecordStoreStatusCheckerFactory jdbcCertRecordStoreStatusCheckerFactory =
                new JDBCCertRecordStoreStatusCheckerFactory();
        StatusChecker statusChecker = jdbcCertRecordStoreStatusCheckerFactory.create();
        assertNotNull(statusChecker);

        System.clearProperty(JDBCCertRecordStoreStatusCheckerFactory.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);
        System.clearProperty(JDBCCertRecordStoreFactory.ZTS_PROP_CERT_JDBC_STORE);
        System.clearProperty(JDBCCertRecordStoreFactory.ZTS_PROP_CERT_JDBC_USER);
        System.clearProperty(JDBCCertRecordStoreFactory.ZTS_PROP_CERT_JDBC_PASSWORD);
    }

    @Test
    public void testBadKeyStoreClass() {
        System.setProperty(JDBCCertRecordStoreStatusCheckerFactory.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS, "unknownClassName");
        try {
            new JDBCCertRecordStoreStatusCheckerFactory();

            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid private key store");
        }

        System.clearProperty(JDBCCertRecordStoreStatusCheckerFactory.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);
    }
}
