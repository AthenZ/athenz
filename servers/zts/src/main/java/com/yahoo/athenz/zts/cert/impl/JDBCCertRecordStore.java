/**
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

import java.sql.SQLException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.cert.CertRecordStore;
import com.yahoo.athenz.zts.cert.CertRecordStoreConnection;

public class JDBCCertRecordStore implements CertRecordStore {

    private static final Logger LOG = LoggerFactory.getLogger(JDBCCertRecordStore.class);

    PoolableDataSource src;
    
    public JDBCCertRecordStore(PoolableDataSource src) {
        this.src = src;
    }

    @Override
    public CertRecordStoreConnection getConnection(boolean autoCommit) {
        try {
            return new JDBCCertRecordStoreConnection(src.getConnection(), autoCommit);
        } catch (SQLException ex) {
            LOG.error("getConnection: {}", ex.getMessage());
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR, ex.getMessage());
        }
    }
    
    @Override
    public void clearConnections() {
        src.clearPoolConnections();
    }
}
