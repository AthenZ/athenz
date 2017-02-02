/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zms;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.AuthorityKeyStore;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.MetricFactory;
import com.yahoo.athenz.common.server.db.DataSourceFactory;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.common.server.log.AuditLogger;
import com.yahoo.athenz.common.server.rest.Http.AuthorityList;
import com.yahoo.athenz.zms.store.ObjectStore;
import com.yahoo.athenz.zms.store.file.FileObjectStore;
import com.yahoo.athenz.zms.store.jdbc.JDBCObjectStore;

import java.io.File;
import java.security.PrivateKey;

public class ZMSServerImpl {

    ZMSImpl instance = null;

    AuditLogger auditLogger             = null;
    String      auditLoggerMsgBldrClass = null;

    public ZMSServerImpl(String serverHostName, PrivateKeyStoreFactory pkeyStoreFactory,
            MetricFactory metricFactory, AuditLogger auditLog, String auditLogMsgBldrClass,
            AuthorityList authList) {

        auditLogger             = auditLog;
        auditLoggerMsgBldrClass = auditLogMsgBldrClass;
        
        // extract the private key and public keys for our service
        
        StringBuilder privKeyId = new StringBuilder(256);
        PrivateKeyStore keyStore = pkeyStoreFactory.create();
        PrivateKey pkey = keyStore.getPrivateKey(ZMSConsts.ZMS_SERVICE, serverHostName, privKeyId);
        
        // create our metric and increment our startup count
        
        Metric metric = metricFactory.create();
        metric.increment("zms_sa_startup");
        
        ObjectStore store = null;
        String jdbcStore = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_STORE);
        if (jdbcStore != null && jdbcStore.startsWith("jdbc:")) {
            String userName = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_USER);
            String password = System.getProperty(ZMSConsts.ZMS_PROP_JDBC_PASSWORD, "");
            PoolableDataSource src = DataSourceFactory.create(jdbcStore, userName, password);
            store = new JDBCObjectStore(src);
        } else {
            String homeDir = System.getProperty(ZMSConsts.ZMS_PROP_HOME,
                    ZMS.getRootDir() + "/var/zms_server");
            String fileDirName = System.getProperty(ZMSConsts.ZMS_PROP_FILE_STORE, "zms_root");
            String path = getFileStructPath(homeDir, fileDirName);
            store = new FileObjectStore(new File(path));
        }
        
        try {
            instance = new ZMSImpl(serverHostName, store, metric, pkey, privKeyId.toString(),
                    auditLogger, auditLoggerMsgBldrClass);
            instance.putAuthorityList(authList);
        } catch (Exception ex) {
            metric.increment("zms_startup_fail_sum");
            throw ex;
        }
        
        // make sure to set the keystore for any instance that requires it
        
        for (Authority authority : authList.getAuthorities()) {
            if (AuthorityKeyStore.class.isInstance(authority)) {
                ((AuthorityKeyStore) authority).setKeyStore(instance);
            }
        }
    }

    String getFileStructPath(String db_context, String name) {
        
        String path = db_context;
        if (path == null) {
            path = name;
        } else if (name != null) {
            path = path + File.separator + name;
        }
        
        return path;
    }
    
    public Authorizer getAuthorizer() {
        return instance;
    }

    public ZMSHandler getInstance() {
        return instance;
    }
}
