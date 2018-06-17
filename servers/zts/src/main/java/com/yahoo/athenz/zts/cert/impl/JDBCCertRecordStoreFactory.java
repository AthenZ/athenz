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
package com.yahoo.athenz.zts.cert.impl;

import java.util.Properties;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.CertRecordStore;
import com.yahoo.athenz.zts.cert.CertRecordStoreFactory;

public class JDBCCertRecordStoreFactory implements CertRecordStoreFactory {

    private static final String JDBC               = "jdbc";
    
    @Override
    public CertRecordStore create(PrivateKeyStore keyStore) {
        
        final String jdbcStore = System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_STORE);
        final String jdbcUser = System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_USER);
        final String password = System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_PASSWORD, "");
        final String jdbcAppName = System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_APP_NAME, JDBC);

        String jdbcPassword = keyStore.getApplicationSecret(jdbcAppName, password);
            
        Properties props = new Properties();
        props.setProperty(ZTSConsts.DB_PROP_USER, jdbcUser);
        props.setProperty(ZTSConsts.DB_PROP_PASSWORD, jdbcPassword);
        props.setProperty(ZTSConsts.DB_PROP_VERIFY_SERVER_CERT,
                System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_VERIFY_SERVER_CERT, "false"));
        props.setProperty(ZTSConsts.DB_PROP_USE_SSL,
                System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_USE_SSL, "false"));

        PoolableDataSource src = DataSourceFactory.create(jdbcStore, props);
        return new JDBCCertRecordStore(src);
    }
}
