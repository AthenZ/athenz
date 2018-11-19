/*
 * Copyright 2017 Yahoo Inc.
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

import java.security.cert.X509Certificate;
import java.sql.SQLException;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.zts.cert.X509CertUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.cert.CertRecordStore;
import com.yahoo.athenz.zts.cert.CertRecordStoreConnection;


public class JDBCCertRecordStore implements CertRecordStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(JDBCCertRecordStore.class);
    private static final Logger CERTLOGGER = LoggerFactory.getLogger("X509CertLogger");

    PoolableDataSource src;
    private int opTimeout = 10; //in seconds

    public JDBCCertRecordStore(PoolableDataSource src) {
        this.src = src;
    }

    @Override
    public CertRecordStoreConnection getConnection() {
        try {
            JDBCCertRecordStoreConnection jdbcConn = new JDBCCertRecordStoreConnection(src.getConnection());
            jdbcConn.setOperationTimeout(opTimeout);
            return jdbcConn;
        } catch (SQLException ex) {
            LOGGER.error("getConnection: {}", ex.getMessage());
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE, ex.getMessage());
        }
    }
    
    @Override
    public void setOperationTimeout(int opTimeout) {
        this.opTimeout = opTimeout;
    }
    
    @Override
    public void clearConnections() {
        src.clearPoolConnections();
    }

    @Override
    public void log(final Principal principal, final String ip, final String provider,
                    final String instanceId, final X509Certificate x509Cert) {
        X509CertUtils.logCert(CERTLOGGER, principal, ip, provider, instanceId, x509Cert);
    }
}
