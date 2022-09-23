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

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.server.ssh.SSHRecordStore;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreConnection;
import com.yahoo.athenz.common.server.db.PoolableDataSource;
import com.yahoo.athenz.common.utils.X509CertUtils;
import com.yahoo.athenz.zts.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.SQLException;

public class JDBCSSHRecordStore implements SSHRecordStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(JDBCSSHRecordStore.class);
    private static final Logger SSHLOGGER = LoggerFactory.getLogger("SSHCertLogger");

    PoolableDataSource src;
    private int opTimeout = 10; //in seconds

    public JDBCSSHRecordStore(PoolableDataSource src) {
        this.src = src;
    }

    @Override
    public SSHRecordStoreConnection getConnection() {
        try {
            JDBCSSHRecordStoreConnection jdbcConn = new JDBCSSHRecordStoreConnection(src.getConnection());
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
    public void log(final Principal principal, final String ip, final String service,
                    final String instanceId) {
        X509CertUtils.logSSH(SSHLOGGER, principal, ip, service, instanceId);
    }

    @Override
    public boolean enableNotifications(NotificationManager notificationManager, RolesProvider rolesProvider, final String serverName) {
        LOGGER.warn("Notifications not supported");
        return false;
    }
}
