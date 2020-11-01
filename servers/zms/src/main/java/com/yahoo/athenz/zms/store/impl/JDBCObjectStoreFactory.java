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
import com.yahoo.athenz.zms.store.impl.jdbc.JDBCObjectStore;

public class JDBCObjectStoreFactory implements ObjectStoreFactory {

    private static final String JDBC               = "jdbc";
    
    @Override
    public ObjectStore create(PrivateKeyStore keyStore) {
        final String jdbcStore = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RW_STORE);
        final String jdbcUser = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RW_USER);
        final String password = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RW_PASSWORD, "");
        final String jdbcAppName = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_APP_NAME, JDBC);
        String jdbcPassword = keyStore.getApplicationSecret(jdbcAppName, password);
        
        Properties readWriteProperties = new Properties();
        readWriteProperties.setProperty(ZMSConsts.DB_PROP_USER, jdbcUser);
        readWriteProperties.setProperty(ZMSConsts.DB_PROP_PASSWORD, jdbcPassword);
        readWriteProperties.setProperty(ZMSConsts.DB_PROP_VERIFY_SERVER_CERT,
                System.getProperty(ZMSConsts.ZMS_PROP_JDBC_VERIFY_SERVER_CERT, "false"));
        readWriteProperties.setProperty(ZMSConsts.DB_PROP_USE_SSL,
                System.getProperty(ZMSConsts.ZMS_PROP_JDBC_USE_SSL, "false"));
        readWriteProperties.setProperty(ZMSConsts.DB_PROP_TLS_PROTOCOLS,
                System.getProperty(ZMSConsts.ZMS_PROP_JDBC_TLS_VERSIONS, "TLSv1.2,TLSv1.3"));

        PoolableDataSource readWriteSrc = DataSourceFactory.create(jdbcStore, readWriteProperties);
        
        // now check to see if we also have a read-only jdbc store configured
        // if no username and password are specified then we'll use the
        // read-write store credentials
        
        PoolableDataSource readOnlySrc = null;
        String jdbcReadOnlyStore = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RO_STORE);
        if (jdbcReadOnlyStore != null && jdbcReadOnlyStore.startsWith("jdbc:")) {
            final String jdbcReadOnlyUser = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RO_USER, jdbcUser);
            final String readOnlyPassword = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_RO_PASSWORD, password);
            final String jdbcReadOnlyPassword = keyStore.getApplicationSecret(jdbcAppName, readOnlyPassword);
            
            Properties readOnlyProperties = new Properties();
            readOnlyProperties.setProperty(ZMSConsts.DB_PROP_USER, jdbcReadOnlyUser);
            readOnlyProperties.setProperty(ZMSConsts.DB_PROP_PASSWORD, jdbcReadOnlyPassword);
            readOnlyProperties.setProperty(ZMSConsts.DB_PROP_VERIFY_SERVER_CERT,
                    System.getProperty(ZMSConsts.ZMS_PROP_JDBC_VERIFY_SERVER_CERT, "false"));
            readOnlyProperties.setProperty(ZMSConsts.DB_PROP_USE_SSL,
                    System.getProperty(ZMSConsts.ZMS_PROP_JDBC_USE_SSL, "false"));
            readOnlyProperties.setProperty(ZMSConsts.DB_PROP_TLS_PROTOCOLS,
                    System.getProperty(ZMSConsts.ZMS_PROP_JDBC_TLS_VERSIONS, "TLSv1.2,TLSv1.3"));
            readOnlySrc = DataSourceFactory.create(jdbcReadOnlyStore, readOnlyProperties);
        }
        
        return new JDBCObjectStore(readWriteSrc, readOnlySrc);
    }
}
