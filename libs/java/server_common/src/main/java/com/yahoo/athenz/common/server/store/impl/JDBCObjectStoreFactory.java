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
package com.yahoo.athenz.common.server.store.impl;

import java.util.Properties;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.common.server.store.ObjectStore;
import com.yahoo.athenz.common.server.store.ObjectStoreFactory;
import org.eclipse.jetty.util.StringUtil;

public class JDBCObjectStoreFactory implements ObjectStoreFactory {

    private static final String JDBC_APP_NAME     = "jdbc";
    private static final String JDBC_TIME_ZONE    = "SERVER";
    private static final String JDBC_TLS_VERSIONS = "TLSv1.2,TLSv1.3";

    @Override
    public ObjectStore create(PrivateKeyStore keyStore) {
        final String jdbcStore = System.getProperty(JDBCConsts.ZMS_PROP_JDBC_RW_STORE);
        final String jdbcUser = System.getProperty(JDBCConsts.ZMS_PROP_JDBC_RW_USER);
        final String password = System.getProperty(JDBCConsts.ZMS_PROP_JDBC_RW_PASSWORD, "");
        final String jdbcAppName = System.getProperty(JDBCConsts.ZMS_PROP_JDBC_APP_NAME, JDBC_APP_NAME);
        final String jdbcKeygroupName = System.getProperty(JDBCConsts.ZMS_PROP_JDBC_KEYGROUP_NAME, "");
        Properties readWriteProperties = getProperties(jdbcUser, keyStore.getSecret(jdbcAppName, jdbcKeygroupName, password));
        PoolableDataSource readWriteSrc = DataSourceFactory.create(jdbcStore, readWriteProperties);
        
        // now check to see if we also have a read-only jdbc store configured
        // if no username and password are specified then we'll use the
        // read-write store credentials
        
        PoolableDataSource readOnlySrc = null;
        String jdbcReadOnlyStore = System.getProperty(JDBCConsts.ZMS_PROP_JDBC_RO_STORE);
        if (jdbcReadOnlyStore != null && jdbcReadOnlyStore.startsWith(JDBC_APP_NAME)) {
            final String jdbcReadOnlyUser = getDefaultSetting(JDBCConsts.ZMS_PROP_JDBC_RO_USER, jdbcUser);
            final String readOnlyPassword = getDefaultSetting(JDBCConsts.ZMS_PROP_JDBC_RO_PASSWORD, password);
            Properties readOnlyProperties = getProperties(jdbcReadOnlyUser, keyStore.getSecret(jdbcAppName, jdbcKeygroupName, readOnlyPassword));
            readOnlySrc = DataSourceFactory.create(jdbcReadOnlyStore, readOnlyProperties);
        }
        return new JDBCObjectStore(readWriteSrc, readOnlySrc);
    }

    String getDefaultSetting(final String propName, final String defaultValue) {
        final String value = System.getProperty(propName);
        return (StringUtil.isEmpty(value)) ? defaultValue : value;
    }

    Properties getProperties(final String dbUser, final char[] dbPassword) {
        Properties properties = new Properties();
        properties.setProperty(ServerCommonConsts.DB_PROP_USER, dbUser);
        properties.setProperty(ServerCommonConsts.DB_PROP_PASSWORD, String.valueOf(dbPassword));
        properties.setProperty(ServerCommonConsts.DB_PROP_VERIFY_SERVER_CERT,
                System.getProperty(JDBCConsts.ZMS_PROP_JDBC_VERIFY_SERVER_CERT, "false"));
        properties.setProperty(ServerCommonConsts.DB_PROP_USE_SSL,
                System.getProperty(JDBCConsts.ZMS_PROP_JDBC_USE_SSL, "false"));
        properties.setProperty(ServerCommonConsts.DB_PROP_TLS_PROTOCOLS,
                System.getProperty(JDBCConsts.ZMS_PROP_JDBC_TLS_VERSIONS, JDBC_TLS_VERSIONS));
        properties.setProperty(ServerCommonConsts.DB_PROP_CONN_TIME_ZONE, JDBC_TIME_ZONE);
        return properties;
    }
}
