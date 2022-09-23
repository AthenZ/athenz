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

import java.io.File;
import java.security.cert.X509Certificate;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.cert.CertRecordStore;
import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.utils.X509CertUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileCertRecordStore implements CertRecordStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileCertRecordStore.class);
    private static final Logger CERTLOGGER = LoggerFactory.getLogger("X509CertLogger");

    File rootDir;
    
    public FileCertRecordStore(File rootDirectory) {
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
    public CertRecordStoreConnection getConnection() {
        return new FileCertRecordStoreConnection(rootDir);
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
    public void log(final Principal principal, final String ip, final String provider,
                    final String instanceId, final X509Certificate x509Cert) {
        X509CertUtils.logCert(CERTLOGGER, principal, ip, provider, instanceId, x509Cert);
    }

    @Override
    public boolean enableNotifications(NotificationManager notificationManager, RolesProvider rolesProvider, final String serverName) {
        LOGGER.warn("Notifications not supported");
        return false;
    }
}
