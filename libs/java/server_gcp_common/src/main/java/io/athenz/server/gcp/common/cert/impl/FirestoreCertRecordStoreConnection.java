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
import com.google.cloud.firestore.*;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.cert.CertRecordStoreConnection;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class FirestoreCertRecordStoreConnection implements CertRecordStoreConnection {

    private static final Logger LOGGER = LoggerFactory.getLogger(FirestoreCertRecordStoreConnection.class);

    public static final String ZTS_PROP_CERT_FIRESTORE_ITEM_TTL_HOURS = "athenz.zts.cert_firestore_item_ttl_hours";
    public static final String ZTS_PROP_NOTIFICATION_GRACE_PERIOD_HOURS = "athenz.zts.notification_cert_fail_grace_hours";

    private static final String KEY_PRIMARY = "primaryKey";
    private static final String KEY_PROVIDER = "provider";
    private static final String KEY_INSTANCE_ID = "instanceId";
    private static final String KEY_SERVICE = "service";
    private static final String KEY_CURRENT_SERIAL = "currentSerial";
    private static final String KEY_CURRENT_TIME = "currentTime";
    private static final String KEY_CURRENT_IP = "currentIP";
    private static final String KEY_PREV_SERIAL = "prevSerial";
    private static final String KEY_PREV_TIME = "prevTime";
    private static final String KEY_PREV_IP = "prevIP";
    private static final String KEY_CLIENT_CERT = "clientCert";
    private static final String KEY_LAST_NOTIFIED_TIME = "lastNotifiedTime";
    private static final String KEY_LAST_NOTIFIED_SERVER = "lastNotifiedServer";
    private static final String KEY_EXPIRY_TIME = "expiryTime";
    private static final String KEY_HOSTNAME = "hostName";
    private static final String KEY_TTL_TIMESTAMP = "ttlTimestamp";
    private static final String KEY_REGISTER_TIME = "registerTime";
    private static final String KEY_SVC_DATA_UPDATE_TIME = "svcDataUpdateTime";
    private static final String KEY_SIA_PROVIDER = "siaProvider";

    private static final String UNKNOWN_SIA_PROVIDER = "N/A";

    // Configuration settings in hours
    private static final Long EXPIRY_HOURS = Long.parseLong(
            System.getProperty(ZTS_PROP_CERT_FIRESTORE_ITEM_TTL_HOURS, "720"));

    // Default grace period - 2 weeks (336 hours)
    private static final Long EXPIRY_HOURS_GRACE = Long.parseLong(
            System.getProperty(ZTS_PROP_NOTIFICATION_GRACE_PERIOD_HOURS, "336"));

    private final Firestore firestore;
    private final String collectionName;

    public FirestoreCertRecordStoreConnection(Firestore firestore, final String collectionName) {
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
    public X509CertRecord getX509CertRecord(String provider, String instanceId, String service) throws ServerResourceException {

        final String primaryKey = getPrimaryKey(provider, instanceId, service);

        try {
            DocumentReference docRef = firestore.collection(collectionName).document(primaryKey);
            ApiFuture<DocumentSnapshot> future = docRef.get();
            DocumentSnapshot document = future.get();

            if (!document.exists()) {
                LOGGER.error("Firestore Get Error for {}: document not found", primaryKey);
                return null;
            }

            return documentToX509CertRecord(document);
        } catch (Exception ex) {
            LOGGER.error("Firestore Get Error for {}: {}/{}", primaryKey, ex.getClass(), ex.getMessage());
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
    }

    private X509CertRecord documentToX509CertRecord(DocumentSnapshot document) {

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider(document.getString(KEY_PROVIDER));
        certRecord.setInstanceId(document.getString(KEY_INSTANCE_ID));
        certRecord.setService(document.getString(KEY_SERVICE));
        certRecord.setCurrentSerial(document.getString(KEY_CURRENT_SERIAL));
        certRecord.setCurrentIP(document.getString(KEY_CURRENT_IP));
        certRecord.setCurrentTime(getDateFromTimestamp(document.getTimestamp(KEY_CURRENT_TIME)));
        certRecord.setPrevSerial(document.getString(KEY_PREV_SERIAL));
        certRecord.setPrevIP(document.getString(KEY_PREV_IP));
        certRecord.setPrevTime(getDateFromTimestamp(document.getTimestamp(KEY_PREV_TIME)));
        certRecord.setClientCert(document.getBoolean(KEY_CLIENT_CERT));
        certRecord.setLastNotifiedTime(getDateFromTimestamp(document.getTimestamp(KEY_LAST_NOTIFIED_TIME)));
        certRecord.setLastNotifiedServer(document.getString(KEY_LAST_NOTIFIED_SERVER));
        certRecord.setExpiryTime(getDateFromTimestamp(document.getTimestamp(KEY_EXPIRY_TIME)));
        certRecord.setHostName(document.getString(KEY_HOSTNAME));
        certRecord.setSvcDataUpdateTime(getDateFromTimestamp(document.getTimestamp(KEY_SVC_DATA_UPDATE_TIME)));
        certRecord.setSiaProvider(document.getString(KEY_SIA_PROVIDER));
        return certRecord;
    }

    private Date getDateFromTimestamp(Timestamp timestamp) {
        if (timestamp == null) {
            return null;
        }
        return timestamp.toDate();
    }

    private Timestamp getTimestampFromDate(Date date) {
        if (date == null) {
            return null;
        }
        return Timestamp.of(new java.sql.Timestamp(date.getTime()));
    }

    String getDefaultValueIfEmpty(final String value, final String defaultValue) {
        return StringUtil.isEmpty(value) ? defaultValue : value;
    }

    @Override
    public boolean updateX509CertRecord(X509CertRecord certRecord) {

        final String primaryKey = getPrimaryKey(certRecord.getProvider(), certRecord.getInstanceId(),
                certRecord.getService());

        // if we don't have a svc update time we'll default to the current time
        if (certRecord.getSvcDataUpdateTime() == null) {
            certRecord.setSvcDataUpdateTime(new Date());
        }

        // Prevent inserting null values in hostName
        final String hostName = getDefaultValueIfEmpty(certRecord.getHostName(), primaryKey);

        // if we have null value for the SIA provider, we'll default to "N/A"
        final String siaProvider = getDefaultValueIfEmpty(certRecord.getSiaProvider(), UNKNOWN_SIA_PROVIDER);

        try {
            DocumentReference docRef = firestore.collection(collectionName).document(primaryKey);

            Map<String, Object> updates = new HashMap<>();
            updates.put(KEY_INSTANCE_ID, certRecord.getInstanceId());
            updates.put(KEY_PROVIDER, certRecord.getProvider());
            updates.put(KEY_SERVICE, certRecord.getService());
            updates.put(KEY_CURRENT_SERIAL, certRecord.getCurrentSerial());
            updates.put(KEY_CURRENT_IP, certRecord.getCurrentIP());
            updates.put(KEY_CURRENT_TIME, getTimestampFromDate(certRecord.getCurrentTime()));
            updates.put(KEY_PREV_SERIAL, certRecord.getPrevSerial());
            updates.put(KEY_PREV_IP, certRecord.getPrevIP());
            updates.put(KEY_PREV_TIME, getTimestampFromDate(certRecord.getPrevTime()));
            updates.put(KEY_CLIENT_CERT, certRecord.getClientCert());
            updates.put(KEY_SVC_DATA_UPDATE_TIME, getTimestampFromDate(certRecord.getSvcDataUpdateTime()));
            updates.put(KEY_EXPIRY_TIME, getTimestampFromDate(certRecord.getExpiryTime()));
            updates.put(KEY_HOSTNAME, hostName);
            updates.put(KEY_SIA_PROVIDER, siaProvider);

            // Calculate TTL timestamp (current time + expiry hours)
            if (certRecord.getCurrentTime() != null) {
                long ttlMillis = certRecord.getCurrentTime().getTime() + TimeUnit.HOURS.toMillis(EXPIRY_HOURS);
                updates.put(KEY_TTL_TIMESTAMP, Timestamp.of(new java.sql.Timestamp(ttlMillis)));
            }

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
    public boolean insertX509CertRecord(X509CertRecord certRecord) {

        final String primaryKey = getPrimaryKey(certRecord.getProvider(), certRecord.getInstanceId(),
                certRecord.getService());

        // Prevent inserting null values in hostName
        final String hostName = getDefaultValueIfEmpty(certRecord.getHostName(), primaryKey);

        // if we have null value for the SIA provider, we'll default to "N/A"
        final String siaProvider = getDefaultValueIfEmpty(certRecord.getSiaProvider(), UNKNOWN_SIA_PROVIDER);

        try {
            DocumentReference docRef = firestore.collection(collectionName).document(primaryKey);

            Map<String, Object> data = new HashMap<>();
            data.put(KEY_PRIMARY, primaryKey);
            data.put(KEY_INSTANCE_ID, certRecord.getInstanceId());
            data.put(KEY_PROVIDER, certRecord.getProvider());
            data.put(KEY_SERVICE, certRecord.getService());
            data.put(KEY_CURRENT_SERIAL, certRecord.getCurrentSerial());
            data.put(KEY_CURRENT_IP, certRecord.getCurrentIP());
            data.put(KEY_CURRENT_TIME, getTimestampFromDate(certRecord.getCurrentTime()));
            data.put(KEY_PREV_SERIAL, certRecord.getPrevSerial());
            data.put(KEY_PREV_IP, certRecord.getPrevIP());
            data.put(KEY_PREV_TIME, getTimestampFromDate(certRecord.getPrevTime()));
            data.put(KEY_CLIENT_CERT, certRecord.getClientCert());
            data.put(KEY_EXPIRY_TIME, getTimestampFromDate(certRecord.getExpiryTime()));
            data.put(KEY_SVC_DATA_UPDATE_TIME, getTimestampFromDate(certRecord.getSvcDataUpdateTime()));
            data.put(KEY_REGISTER_TIME, Timestamp.now());
            data.put(KEY_HOSTNAME, hostName);
            data.put(KEY_SIA_PROVIDER, siaProvider);

            // Calculate TTL timestamp (current time + expiry hours)
            if (certRecord.getCurrentTime() != null) {
                long ttlMillis = certRecord.getCurrentTime().getTime() + TimeUnit.HOURS.toMillis(EXPIRY_HOURS);
                data.put(KEY_TTL_TIMESTAMP, Timestamp.of(new java.sql.Timestamp(ttlMillis)));
            }

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
    public boolean deleteX509CertRecord(String provider, String instanceId, String service) {

        final String primaryKey = getPrimaryKey(provider, instanceId, service);

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
    public int deleteExpiredX509CertRecords(int expiryTimeMins, int limit) {
        // with Firestore there is no need to manually expunge expired
        // record since we have the TTL option enabled for our table,
        // and we just need to make sure the attribute is updated with
        // the epoch time + timeout seconds when it should retire

        return 0;
    }

    @Override
    public List<X509CertRecord> updateUnrefreshedCertificatesNotificationTimestamp(final String lastNotifiedServer,
            long lastNotifiedTime, final String provider) {

        List<DocumentSnapshot> documents = getUnrefreshedCertsRecords(lastNotifiedTime, provider);
        return updateLastNotified(lastNotifiedServer, lastNotifiedTime, documents);
    }

    private String getPrimaryKey(final String provider, final String instanceId, final String service) {
        return provider + ":" + service + ":" + instanceId;
    }

    private List<X509CertRecord> updateLastNotified(String lastNotifiedServer, long lastNotifiedTime,
            List<DocumentSnapshot> documents) {

        Date yesterday = Date.from(
                Instant.ofEpochMilli(lastNotifiedTime).minus(1, ChronoUnit.DAYS)
        );

        List<X509CertRecord> updatedRecords = new ArrayList<>();
        WriteBatch batch = firestore.batch();
        int updateCount = 0;

        for (DocumentSnapshot document : documents) {
            Date docLastNotifiedDate = getDateFromTimestamp(document.getTimestamp(KEY_LAST_NOTIFIED_TIME));

            // Update if never notified or last notified before yesterday
            if (docLastNotifiedDate == null || docLastNotifiedDate.before(yesterday)) {
                Timestamp expectedTimestamp = Timestamp.of(new java.sql.Timestamp(lastNotifiedTime));

                Map<String, Object> updates = new HashMap<>();
                updates.put(KEY_LAST_NOTIFIED_TIME, expectedTimestamp);
                updates.put(KEY_LAST_NOTIFIED_SERVER, lastNotifiedServer);

                batch.update(document.getReference(), updates);
                updateCount++;

                // Build updated record from existing document + updates
                X509CertRecord certRecord = documentToX509CertRecord(document);
                certRecord.setLastNotifiedTime(new Date(lastNotifiedTime));
                certRecord.setLastNotifiedServer(lastNotifiedServer);
                updatedRecords.add(certRecord);
            }
        }

        if (updateCount > 0) {
            try {
                batch.commit().get();
            } catch (Exception ex) {
                LOGGER.error("Firestore batch updateLastNotified failed: {}/{}", ex.getClass(), ex.getMessage());
                if (ex instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                // If the batch fails, we should not return any records as updated.
                return Collections.emptyList();
            }
        }

        return updatedRecords;
    }

    private List<DocumentSnapshot> getUnrefreshedCertsRecords(long lastNotifiedTime, String provider) {

        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);
        long unrefreshedCertsRangeBegin = lastNotifiedTime - TimeUnit.HOURS.toMillis(EXPIRY_HOURS);
        long unrefreshedCertsRangeEnd = lastNotifiedTime - TimeUnit.HOURS.toMillis(EXPIRY_HOURS_GRACE);

        Timestamp rangeBeginTs = Timestamp.of(new java.sql.Timestamp(unrefreshedCertsRangeBegin));
        Timestamp rangeEndTs = Timestamp.of(new java.sql.Timestamp(unrefreshedCertsRangeEnd));
        Timestamp yesterdayTs = Timestamp.of(new java.sql.Timestamp(yesterday));

        try {
            // Query for unrefreshed certificates
            // Note: This query may require a composite index in Firestore
            Query query = firestore.collection(collectionName)
                    .whereEqualTo(KEY_PROVIDER, provider)
                    .whereGreaterThanOrEqualTo(KEY_CURRENT_TIME, rangeEndTs)
                    .whereLessThanOrEqualTo(KEY_CURRENT_TIME, rangeBeginTs);

            ApiFuture<QuerySnapshot> future = query.get();
            QuerySnapshot querySnapshot = future.get();

            // Filter documents that need notification (never notified or notified before yesterday)
            // and have hostName set
            List<DocumentSnapshot> candidateDocuments = querySnapshot.getDocuments().stream()
                    .filter(doc -> doc.contains(KEY_HOSTNAME) && !StringUtil.isEmpty(doc.getString(KEY_HOSTNAME)))
                    .filter(doc -> {
                        Timestamp lastNotifiedTs = doc.getTimestamp(KEY_LAST_NOTIFIED_TIME);
                        return lastNotifiedTs == null || lastNotifiedTs.compareTo(yesterdayTs) < 0;
                    })
                    .collect(Collectors.toList());

            // fetch all related records in bulk and filter in memory
            return filterMostUpdatedHostRecords(candidateDocuments, provider);

        } catch (Exception ex) {
            LOGGER.error("Firestore getUnrefreshedCertsRecords Error: {}/{}", ex.getClass(), ex.getMessage());
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return Collections.emptyList();
        }
    }

    /**
     * Filters candidate documents to only include the most updated record for each (hostname, provider, service) combination.
     * implementation note: currently not optimizing for N+1 query problem, since the usage of getUnrefreshedCertsRecords may not materialize in GCP.
     */
    private List<DocumentSnapshot> filterMostUpdatedHostRecords(List<DocumentSnapshot> candidateDocuments, String provider) {
        if (candidateDocuments.isEmpty()) {
            return candidateDocuments;
        }

        try {
            // Group candidates by (hostname, provider, service) to identify unique combinations
            Map<String, List<DocumentSnapshot>> groupedCandidates = candidateDocuments.stream()
                    .filter(doc -> !StringUtil.isEmpty(doc.getString(KEY_HOSTNAME))
                            && !StringUtil.isEmpty(doc.getString(KEY_SERVICE)))
                    .collect(Collectors.groupingBy(doc ->
                            doc.getString(KEY_HOSTNAME) + ":" +
                            doc.getString(KEY_PROVIDER) + ":" +
                            doc.getString(KEY_SERVICE)
                    ));

            // For each unique combination, query all records and find the most recent one
            // Store most recent record IDs for quick lookup
            Set<String> mostRecentRecordIds = new HashSet<>();

            for (Map.Entry<String, List<DocumentSnapshot>> entry : groupedCandidates.entrySet()) {
                List<DocumentSnapshot> groupDocs = entry.getValue();

                // Extract hostname, provider, service from any document in the group
                DocumentSnapshot sampleDoc = groupDocs.get(0);
                String hostName = sampleDoc.getString(KEY_HOSTNAME);
                String service = sampleDoc.getString(KEY_SERVICE);

                // Query all records with same hostname, provider, and service
                Query query = firestore.collection(collectionName)
                        .whereEqualTo(KEY_HOSTNAME, hostName)
                        .whereEqualTo(KEY_PROVIDER, provider)
                        .whereEqualTo(KEY_SERVICE, service);

                ApiFuture<QuerySnapshot> future = query.get();
                QuerySnapshot querySnapshot = future.get();
                List<QueryDocumentSnapshot> allRecords = querySnapshot.getDocuments();

                // Find the most recent record (highest currentTime)
                DocumentSnapshot mostRecentRecord = allRecords.stream()
                        .filter(doc -> doc.getTimestamp(KEY_CURRENT_TIME) != null)
                        .max(Comparator.comparing(doc -> doc.getTimestamp(KEY_CURRENT_TIME)))
                        .orElse(null);

                if (mostRecentRecord != null) {
                    mostRecentRecordIds.add(mostRecentRecord.getId());
                }
            }

            // Filter candidates to only include most recent records
            return candidateDocuments.stream()
                    .filter(doc -> mostRecentRecordIds.contains(doc.getId()))
                    .collect(Collectors.toList());

        } catch (Exception ex) {
            LOGGER.error("Firestore filterMostUpdatedHostRecords Error: {}/{}", ex.getClass(), ex.getMessage());
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            // Return empty list on error to avoid potentially incorrect notifications
            return Collections.emptyList();
        }
    }
}
