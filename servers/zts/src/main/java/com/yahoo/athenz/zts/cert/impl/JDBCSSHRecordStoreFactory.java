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
package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.ssh.SSHRecordStore;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreFactory;
import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zts.ZTSConsts;

import java.util.Properties;

public class JDBCSSHRecordStoreFactory implements SSHRecordStoreFactory {

    private static final String JDBC = "jdbc";
    
    @Override
    public SSHRecordStore create(PrivateKeyStore keyStore) {
        
        final String jdbcStore = System.getProperty(ZTSConsts.ZTS_PROP_SSH_JDBC_STORE);
        final String jdbcUser = System.getProperty(ZTSConsts.ZTS_PROP_SSH_JDBC_USER);
        final String password = System.getProperty(ZTSConsts.ZTS_PROP_SSH_JDBC_PASSWORD, "");
        final String jdbcAppName = System.getProperty(ZTSConsts.ZTS_PROP_SSH_JDBC_APP_NAME, JDBC);

        Properties props = new Properties();
        props.setProperty(ZTSConsts.DB_PROP_USER, jdbcUser);
        props.setProperty(ZTSConsts.DB_PROP_PASSWORD, String.valueOf(keyStore.getSecret(jdbcAppName, password)));
        props.setProperty(ZTSConsts.DB_PROP_VERIFY_SERVER_CERT,
                System.getProperty(ZTSConsts.ZTS_PROP_SSH_JDBC_VERIFY_SERVER_CERT, "false"));
        props.setProperty(ZTSConsts.DB_PROP_USE_SSL,
                System.getProperty(ZTSConsts.ZTS_PROP_SSH_JDBC_USE_SSL, "false"));

        PoolableDataSource src = DataSourceFactory.create(jdbcStore, props);

        // set default timeout for our connections

        JDBCSSHRecordStore certStore = new JDBCSSHRecordStore(src);
        int opTimeout = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_SSH_OP_TIMEOUT, "10"));
        certStore.setOperationTimeout(opTimeout);

        return certStore;
    }
}
