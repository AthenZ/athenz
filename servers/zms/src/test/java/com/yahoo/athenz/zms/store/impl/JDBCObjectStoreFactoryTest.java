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

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.ObjectStore;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import static org.testng.Assert.assertNotNull;

public class JDBCObjectStoreFactoryTest {

    @Test
    public void testCreateWriteOnly() {
        
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_STORE, "jdbc:mysql://localhost");
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_USER, "user");
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_PASSWORD, "password");

        System.clearProperty(ZMSConsts.ZMS_PROP_JDBC_RO_STORE);
        System.clearProperty(ZMSConsts.ZMS_PROP_JDBC_RO_USER);
        System.clearProperty(ZMSConsts.ZMS_PROP_JDBC_RO_PASSWORD);

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        Mockito.doReturn("password".toCharArray()).when(keyStore).getSecret("jdbc", "password");

        JDBCObjectStoreFactory factory = new JDBCObjectStoreFactory();
        ObjectStore store = factory.create(keyStore);
        assertNotNull(store);
    }

    @Test
    public void testCreateReadWrite() {

        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_STORE, "jdbc:mysql://localhost");
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_USER, "user");
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RW_PASSWORD, "password");

        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RO_STORE, "jdbc:mysql://localhost");
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RO_USER, "user");
        System.setProperty(ZMSConsts.ZMS_PROP_JDBC_RO_PASSWORD, "password");

        PrivateKeyStore keyStore = Mockito.mock(PrivateKeyStore.class);
        char[] passwordMock = new char[]{'p','a','s','s','w','o','r','d'};
        Mockito.doReturn(passwordMock).when(keyStore).getSecret("jdbc", "password");

        JDBCObjectStoreFactory factory = new JDBCObjectStoreFactory();
        ObjectStore store = factory.create(keyStore);
        assertNotNull(store);
    }
}
