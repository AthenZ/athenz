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
import com.yahoo.athenz.common.utils.X509CertUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class FileSSHRecordStore implements SSHRecordStore {

    private static final Logger SSHLOGGER = LoggerFactory.getLogger("SSHCertLogger");

    File rootDir;

    public FileSSHRecordStore(File rootDirectory) {
        if (!rootDirectory.exists()) {
            if (!rootDirectory.mkdirs()) {
                error("cannot create specified root: " + rootDirectory);
            }
        } else {
            if (!rootDirectory.isDirectory()) {
                error("specified root is not a directory: " + rootDirectory);
            }
        }
        this.rootDir = rootDirectory;
    }

    @Override
    public SSHRecordStoreConnection getConnection() {
        return new FileSSHRecordStoreConnection(rootDir);
    }
    
    @Override
    public void setOperationTimeout(int opTimeout) {
    }
    
    @Override
    public void clearConnections() {
    }

    static void error(String msg) {
        throw new RuntimeException("FileObjectStore: " + msg);
    }

    @Override
    public void log(final Principal principal, final String ip, final String service,
                    final String instanceId) {
        X509CertUtils.logSSH(SSHLOGGER, principal, ip, service, instanceId);
    }

    @Override
    public boolean enableNotifications(NotificationManager notificationManager, RolesProvider rolesProvider, final String serverName) {
        return false;
    }
}
