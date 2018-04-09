/*
 * Copyright 2017 Yahoo Holdings, Inc.
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

import java.util.Properties;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.ObjectStoreFactory;
import com.yahoo.athenz.zms.store.jdbc.JDBCObjectStore;

public class JDBCObjectStoreFactory implements ObjectStoreFactory {

    private static final String JDBC               = "jdbc";
    private static final String ATHENZ_DB_USER     = "user";
    private static final String ATHENZ_DB_PASSWORD = "password";
    
    @Override
    public ObjectStore create(PrivateKeyStore keyStore) {
        String jdbcStore = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RW_STORE);
        String jdbcUser = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RW_USER);
        String password = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RW_PASSWORD, "");
        String jdbcPassword = keyStore.getApplicationSecret(JDBC, password);
        
        Properties readWriteProperties = new Properties();
        readWriteProperties.setProperty(ATHENZ_DB_USER, jdbcUser);
        readWriteProperties.setProperty(ATHENZ_DB_PASSWORD, jdbcPassword);
        
        PoolableDataSource readWriteSrc = DataSourceFactory.create(jdbcStore, readWriteProperties);
        
        // now check to see if we also have a read-only jdbc store configured
        // if no username and password are specified then we'll use the
        // read-write store credentials
        
        PoolableDataSource readOnlySrc = null;
        String jdbcReadOnlyStore = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RO_STORE);
        if (jdbcReadOnlyStore != null && jdbcReadOnlyStore.startsWith("jdbc:")) {
            String jdbcReadOnlyUser = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RO_USER, jdbcUser);
            String readOnlyPassword = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RO_PASSWORD, password);
            String jdbcReadOnlyPassword = keyStore.getApplicationSecret(JDBC, readOnlyPassword);
            
            Properties readOnlyProperties = new Properties();
            readOnlyProperties.setProperty(ATHENZ_DB_USER, jdbcReadOnlyUser);
            readOnlyProperties.setProperty(ATHENZ_DB_PASSWORD, jdbcReadOnlyPassword);
            
            readOnlySrc = DataSourceFactory.create(jdbcReadOnlyStore, readOnlyProperties);
        }
        
        return new JDBCObjectStore(readWriteSrc, readOnlySrc);
    }
}
