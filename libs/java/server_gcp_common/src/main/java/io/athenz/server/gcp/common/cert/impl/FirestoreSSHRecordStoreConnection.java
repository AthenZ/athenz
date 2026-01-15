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

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteResult;
import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.common.server.ssh.SSHRecordStoreConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class FirestoreSSHRecordStoreConnection implements SSHRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(FirestoreSSHRecordStoreConnection.class);

    public static final String ZTS_PROP_SSH_FIRESTORE_ITEM_TTL_HOURS = "athenz.zts.ssh_firestore_item_ttl_hours";

    private static final String KEY_PRIMARY = "primaryKey";
    private static final String KEY_INSTANCE_ID = "instanceId";
    private static final String KEY_SERVICE = "service";
    private static final String KEY_PRINCIPALS = "principals";
    private static final String KEY_CLIENT_IP = "clientIP";
    private static final String KEY_PRIVATE_IP = "privateIP";
    private static final String KEY_TTL_TIMESTAMP = "ttlTimestamp";

    // Configuration setting in hours - defaults to 720 hours (30 days)
    private static final Long EXPIRY_HOURS = Long.parseLong(
            System.getProperty(ZTS_PROP_SSH_FIRESTORE_ITEM_TTL_HOURS, "720"));

    private final Firestore firestore;
    private final String collectionName;

    public FirestoreSSHRecordStoreConnection(Firestore firestore, final String collectionName) {
        this.firestore = firestore;
        this.collectionName = collectionName;
    }

    @Override
    public void setOperationTimeout(int queryTimeout) {
        // Firestore client handles timeouts internally
    }

    @Override
    public void close() {
        // Firestore client is managed at the store level, not connection level
    }

    @Override
    public SSHCertRecord getSSHCertRecord(String instanceId, String service) {

        final String primaryKey = getPrimaryKey(instanceId, service);

        try {
            DocumentReference docRef = firestore.collection(collectionName).document(primaryKey);
            ApiFuture<DocumentSnapshot> future = docRef.get();
            DocumentSnapshot document = future.get();

            if (!document.exists()) {
                LOGGER.error("Firestore Get Error for {}: document not found", primaryKey);
                return null;
            }

            SSHCertRecord certRecord = new SSHCertRecord();
            certRecord.setInstanceId(document.getString(KEY_INSTANCE_ID));
            certRecord.setService(document.getString(KEY_SERVICE));
            certRecord.setPrincipals(document.getString(KEY_PRINCIPALS));
            certRecord.setClientIP(document.getString(KEY_CLIENT_IP));
            certRecord.setPrivateIP(document.getString(KEY_PRIVATE_IP));
            return certRecord;

        } catch (Exception ex) {
            LOGGER.error("Firestore Get Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
    }

    @Override
    public boolean updateSSHCertRecord(SSHCertRecord certRecord) {

        final String primaryKey = getPrimaryKey(certRecord.getInstanceId(), certRecord.getService());

        try {
            DocumentReference docRef = firestore.collection(collectionName).document(primaryKey);

            Map<String, Object> updates = new HashMap<>();
            updates.put(KEY_INSTANCE_ID, certRecord.getInstanceId());
            updates.put(KEY_SERVICE, certRecord.getService());
            updates.put(KEY_CLIENT_IP, certRecord.getClientIP());
            updates.put(KEY_PRINCIPALS, certRecord.getPrincipals());
            updates.put(KEY_PRIVATE_IP, certRecord.getPrivateIP());

            // Calculate TTL timestamp (current time + expiry hours)
            long ttlMillis = System.currentTimeMillis() + TimeUnit.HOURS.toMillis(EXPIRY_HOURS);
            updates.put(KEY_TTL_TIMESTAMP, Timestamp.of(new java.sql.Timestamp(ttlMillis)));

            ApiFuture<WriteResult> future = docRef.update(updates);
            future.get();
            return true;
        } catch (Exception ex) {
            LOGGER.error("Firestore Update Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return false;
        }
    }

    @Override
    public boolean insertSSHCertRecord(SSHCertRecord certRecord) {

        final String primaryKey = getPrimaryKey(certRecord.getInstanceId(), certRecord.getService());

        try {
            DocumentReference docRef = firestore.collection(collectionName).document(primaryKey);

            Map<String, Object> data = new HashMap<>();
            data.put(KEY_PRIMARY, primaryKey);
            data.put(KEY_INSTANCE_ID, certRecord.getInstanceId());
            data.put(KEY_SERVICE, certRecord.getService());
            data.put(KEY_CLIENT_IP, certRecord.getClientIP());
            data.put(KEY_PRINCIPALS, certRecord.getPrincipals());
            data.put(KEY_PRIVATE_IP, certRecord.getPrivateIP());

            // Calculate TTL timestamp (current time + expiry hours)
            long ttlMillis = System.currentTimeMillis() + TimeUnit.HOURS.toMillis(EXPIRY_HOURS);
            data.put(KEY_TTL_TIMESTAMP, Timestamp.of(new java.sql.Timestamp(ttlMillis)));

            ApiFuture<WriteResult> future = docRef.set(data);
            future.get();
            return true;
        } catch (Exception ex) {
            LOGGER.error("Firestore Insert Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return false;
        }
    }

    @Override
    public boolean deleteSSHCertRecord(String instanceId, String service) {

        final String primaryKey = getPrimaryKey(instanceId, service);

        try {
            DocumentReference docRef = firestore.collection(collectionName).document(primaryKey);
            ApiFuture<WriteResult> future = docRef.delete();
            future.get();
            return true;
        } catch (Exception ex) {
            LOGGER.error("Firestore Delete Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return false;
        }
    }

    @Override
    public int deleteExpiredSSHCertRecords(int expiryTimeMins, int limit) {
        // with Firestore there is no need to manually expunge expired
        // record since we have the TTL option enabled for our table,
        // and we just need to make sure the attribute is updated with
        // the epoch time + timeout seconds when it should retire

        return 0;
    }

    private String getPrimaryKey(final String instanceId, final String service) {
        return service + ":" + instanceId;
    }
}
