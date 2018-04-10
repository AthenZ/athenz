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
    private static final String ATHENZ_DB_USER     = "user";
    private static final String ATHENZ_DB_PASSWORD = "password";
    
    @Override
    public CertRecordStore create(PrivateKeyStore keyStore) {
        
        String jdbcStore = System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_STORE);
        String jdbcUser = System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_USER);
        String password = System.getProperty(ZTSConsts.ZTS_PROP_CERT_JDBC_PASSWORD, "");
        String jdbcPassword = keyStore.getApplicationSecret(JDBC, password);
            
        Properties props = new Properties();
        props.setProperty(ATHENZ_DB_USER, jdbcUser);
        props.setProperty(ATHENZ_DB_PASSWORD, jdbcPassword);
        
        PoolableDataSource src = DataSourceFactory.create(jdbcStore, props);
        return new JDBCCertRecordStore(src);
    }
}
