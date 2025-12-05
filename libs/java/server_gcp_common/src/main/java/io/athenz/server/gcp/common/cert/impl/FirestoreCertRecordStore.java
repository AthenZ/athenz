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
package io.athenz.server.gcp.common.cert.impl;

import com.google.cloud.firestore.Firestore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.server.cert.CertRecordStore;
import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.db.RolesProvider;
import com.yahoo.athenz.common.server.notification.NotificationManager;
import com.yahoo.athenz.common.utils.X509CertUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;

public class FirestoreCertRecordStore implements CertRecordStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(FirestoreCertRecordStore.class);
    private static final Logger CERTLOGGER = LoggerFactory.getLogger("X509CertLogger");

    private final Firestore firestore;
    private final String collectionName;

    public FirestoreCertRecordStore(Firestore firestore, final String collectionName) {
        this.firestore = firestore;
        this.collectionName = collectionName;
    }

    @Override
    public CertRecordStoreConnection getConnection() {
        return new FirestoreCertRecordStoreConnection(firestore, collectionName);
    }

    @Override
    public void setOperationTimeout(int opTimeout) {
        // Firestore client handles timeouts internally
    }

    @Override
    public void clearConnections() {
        // No connection pooling required for Firestore
    }

    @Override
    public void log(final Principal principal, final String ip, final String provider,
            final String instanceId, final X509Certificate x509Cert) {
        X509CertUtils.logCert(CERTLOGGER, principal, ip, provider, instanceId, x509Cert);
    }

    @Override
    public boolean enableNotifications(NotificationManager notificationManager, RolesProvider rolesProvider,
            final String serverName) {
        // Notification support can be added in the future if needed
        LOGGER.info("Notification support not yet implemented for FirestoreCertRecordStore");
        return false;
    }
}
