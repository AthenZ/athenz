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
import com.google.api.core.ApiFutures;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.*;
import java.util.concurrent.ExecutionException;

import static io.athenz.server.gcp.common.cert.impl.FirestoreCertRecordStoreConnection.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class FirestoreCertRecordStoreConnectionTest {

    private final String collectionName = "cert-collection";

    @Mock private Firestore firestore;
    @Mock private CollectionReference collectionReference;
    @Mock private DocumentReference documentReference;
    @Mock private ApiFuture<DocumentSnapshot> futureGet;
    @Mock private ApiFuture<WriteResult> futureWrite;
    @Mock private ApiFuture<List<WriteResult>> futureWriteBatch;
    @Mock private ApiFuture<QuerySnapshot> futureQuery;
    @Mock private DocumentSnapshot documentSnapshot;
    @Mock private QuerySnapshot querySnapshot;
    @Mock private WriteResult writeResult;
    @Mock private WriteBatch writeBatch;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        when(firestore.collection(collectionName)).thenReturn(collectionReference);
        when(collectionReference.document(any())).thenReturn(documentReference);
    }

    private FirestoreCertRecordStoreConnection getDBConnection() {
        return new FirestoreCertRecordStoreConnection(firestore, collectionName);
    }

    @Test
    public void testGetX509CertRecord() throws Exception {

        when(documentReference.get()).thenReturn(futureGet);
        when(futureGet.get()).thenReturn(documentSnapshot);
        when(documentSnapshot.exists()).thenReturn(true);

        Date now = new Date();
        Timestamp timestamp = Timestamp.of(new java.sql.Timestamp(now.getTime()));

        when(documentSnapshot.getString("provider")).thenReturn("athenz.provider");
        when(documentSnapshot.getString("instanceId")).thenReturn("1234");
        when(documentSnapshot.getString("service")).thenReturn("cn");
        when(documentSnapshot.getString("currentSerial")).thenReturn("current-serial");
        when(documentSnapshot.getString("currentIP")).thenReturn("current-ip");
        when(documentSnapshot.getTimestamp("currentTime")).thenReturn(timestamp);
        when(documentSnapshot.getString("prevSerial")).thenReturn("prev-serial");
        when(documentSnapshot.getString("prevIP")).thenReturn("prev-ip");
        when(documentSnapshot.getTimestamp("prevTime")).thenReturn(timestamp);
        when(documentSnapshot.getBoolean("clientCert")).thenReturn(false);
        when(documentSnapshot.getTimestamp("lastNotifiedTime")).thenReturn(timestamp);
        when(documentSnapshot.getString("lastNotifiedServer")).thenReturn("last-notified-server");
        when(documentSnapshot.getTimestamp("expiryTime")).thenReturn(timestamp);
        when(documentSnapshot.getString("hostName")).thenReturn("hostname");
        when(documentSnapshot.getTimestamp("svcDataUpdateTime")).thenReturn(timestamp);
        when(documentSnapshot.getString("siaProvider")).thenReturn("sia-provider");

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();
        dbConn.setOperationTimeout(10);
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");

        assertNotNull(certRecord);
        assertEquals(certRecord.getProvider(), "athenz.provider");
        assertEquals(certRecord.getInstanceId(), "1234");
        assertEquals(certRecord.getService(), "cn");
        assertEquals(certRecord.getCurrentSerial(), "current-serial");
        assertEquals(certRecord.getCurrentIP(), "current-ip");
        assertEquals(certRecord.getPrevSerial(), "prev-serial");
        assertEquals(certRecord.getPrevIP(), "prev-ip");
        assertFalse(certRecord.getClientCert());
        assertEquals(certRecord.getLastNotifiedServer(), "last-notified-server");
        assertEquals(certRecord.getHostName(), "hostname");
        assertEquals(certRecord.getSiaProvider(), "sia-provider");

        dbConn.close();
    }

    @Test
    public void testGetX509CertRecordNotFound() throws Exception {

        when(documentReference.get()).thenReturn(futureGet);
        when(futureGet.get()).thenReturn(documentSnapshot);
        when(documentSnapshot.exists()).thenReturn(false);

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testGetX509CertRecordExecutionException() throws Exception {

        when(documentReference.get()).thenReturn(futureGet);
        when(futureGet.get()).thenThrow(new ExecutionException("error", new Throwable("error")));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testGetX509CertRecordException() throws Exception {
        when(documentReference.get()).thenThrow(new RuntimeException("unknown exception"));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testGetX509CertRecordInterruptedException() throws Exception {

        when(documentReference.get()).thenReturn(futureGet);
        when(futureGet.get()).thenThrow(new InterruptedException("interrupted"));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testInsertX509CertRecord() throws Exception {

        when(documentReference.set(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenReturn(writeResult);

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider("athenz.provider");
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentTime(new Date());
        certRecord.setPrevSerial("prev-serial");
        certRecord.setPrevIP("prev-ip");
        certRecord.setPrevTime(new Date());
        certRecord.setClientCert(false);
        certRecord.setExpiryTime(new Date());
        certRecord.setSvcDataUpdateTime(new Date());
        certRecord.setHostName("hostname");
        certRecord.setSiaProvider("sia-provider");

        boolean result = dbConn.insertX509CertRecord(certRecord);
        assertTrue(result);

        dbConn.close();
    }

    @Test
    public void testInsertX509CertRecordNullHostName() throws Exception {

        when(documentReference.set(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenReturn(writeResult);

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider("athenz.provider");
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentTime(new Date());
        certRecord.setHostName(null);

        boolean result = dbConn.insertX509CertRecord(certRecord);
        assertTrue(result);

        dbConn.close();
    }

    @Test
    public void testInsertX509CertRecordNullSiaProvider() throws Exception {

        when(documentReference.set(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenReturn(writeResult);

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider("athenz.provider");
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentTime(new Date());
        certRecord.setSiaProvider(null);

        boolean result = dbConn.insertX509CertRecord(certRecord);
        assertTrue(result);

        dbConn.close();
    }

    @Test
    public void testInsertX509CertRecordException() throws Exception {

        when(documentReference.set(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new ExecutionException("error", new Throwable("error")));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider("athenz.provider");
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");

        boolean result = dbConn.insertX509CertRecord(certRecord);
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testInsertX509CertRecordInterruptedException() throws Exception {

        when(documentReference.set(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new InterruptedException("interrupted"));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider("athenz.provider");
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");

        boolean result = dbConn.insertX509CertRecord(certRecord);
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testUpdateX509CertRecord() throws Exception {

        when(documentReference.update(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenReturn(writeResult);

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider("athenz.provider");
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentTime(new Date());
        certRecord.setPrevSerial("prev-serial");
        certRecord.setPrevIP("prev-ip");
        certRecord.setPrevTime(new Date());
        certRecord.setClientCert(false);
        certRecord.setExpiryTime(new Date());
        certRecord.setHostName("hostname");
        certRecord.setSiaProvider("sia-provider");

        boolean result = dbConn.updateX509CertRecord(certRecord);
        assertTrue(result);

        dbConn.close();
    }

    @Test
    public void testUpdateX509CertRecordNullSvcDataUpdateTime() throws Exception {

        when(documentReference.update(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenReturn(writeResult);

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider("athenz.provider");
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentTime(new Date());
        certRecord.setSvcDataUpdateTime(null);

        boolean result = dbConn.updateX509CertRecord(certRecord);
        assertTrue(result);
        assertNotNull(certRecord.getSvcDataUpdateTime());

        dbConn.close();
    }

    @Test
    public void testUpdateX509CertRecordException() throws Exception {

        when(documentReference.update(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new ExecutionException("error", new Throwable("error")));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider("athenz.provider");
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");

        boolean result = dbConn.updateX509CertRecord(certRecord);
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testUpdateX509CertRecordInterruptedException() throws Exception {

        when(documentReference.update(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new InterruptedException("interrupted"));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setProvider("athenz.provider");
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");

        boolean result = dbConn.updateX509CertRecord(certRecord);
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testDeleteX509CertRecord() throws Exception {

        when(documentReference.delete()).thenReturn(futureWrite);
        when(futureWrite.get()).thenReturn(writeResult);

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        boolean result = dbConn.deleteX509CertRecord("athenz.provider", "1234", "cn");
        assertTrue(result);

        dbConn.close();
    }

    @Test
    public void testDeleteX509CertRecordException() throws Exception {

        when(documentReference.delete()).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new ExecutionException("error", new Throwable("error")));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        boolean result = dbConn.deleteX509CertRecord("athenz.provider", "1234", "cn");
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testDeleteX509CertRecordInterruptedException() throws Exception {

        when(documentReference.delete()).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new InterruptedException("interrupted"));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        boolean result = dbConn.deleteX509CertRecord("athenz.provider", "1234", "cn");
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testDeleteExpiredX509CertRecords() {
        // Firestore uses native TTL, so this method always returns 0
        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        int deletedCount = dbConn.deleteExpiredX509CertRecords(100, 10);
        assertEquals(deletedCount, 0);

        dbConn.close();
    }

    @Test
    public void testGetDefaultValueIfEmpty() {
        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        assertEquals(dbConn.getDefaultValueIfEmpty("value", "default"), "value");
        assertEquals(dbConn.getDefaultValueIfEmpty("", "default"), "default");
        assertEquals(dbConn.getDefaultValueIfEmpty(null, "default"), "default");

        dbConn.close();
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestamp() throws Exception {

        // Setup mocks for getUnrefreshedCertsRecords
        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        DocumentReference ref = Mockito.mock(DocumentReference.class);

        when(doc.getReference()).thenReturn(ref);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn("hostname");
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);
        when(doc.getString("provider")).thenReturn("athenz.provider");
        when(doc.getString("service")).thenReturn("service");
        when(doc.getTimestamp("currentTime")).thenReturn(Timestamp.now());
        when(doc.getId()).thenReturn("doc-id");
        // Add all fields required by documentToX509CertRecord
        when(doc.getString("instanceId")).thenReturn("instance-id");
        when(doc.getString("currentSerial")).thenReturn("current-serial");
        when(doc.getString("currentIP")).thenReturn("10.0.0.1");
        when(doc.getString("prevSerial")).thenReturn("prev-serial");
        when(doc.getString("prevIP")).thenReturn("10.0.0.2");
        when(doc.getTimestamp("prevTime")).thenReturn(null);
        when(doc.getBoolean("clientCert")).thenReturn(false);
        when(doc.getString("lastNotifiedServer")).thenReturn(null);
        when(doc.getTimestamp("expiryTime")).thenReturn(null);
        when(doc.getTimestamp("svcDataUpdateTime")).thenReturn(null);
        when(doc.getString("siaProvider")).thenReturn(null);

        List<QueryDocumentSnapshot> documents = Collections.singletonList(doc);
        when(querySnapshot.getDocuments()).thenReturn(documents);

        // Setup for mostUpdatedHostRecord check
        Query hostQuery = Mockito.mock(Query.class);
        QuerySnapshot hostQuerySnapshot = Mockito.mock(QuerySnapshot.class);
        ApiFuture<QuerySnapshot> hostFutureQuery = Mockito.mock(ApiFuture.class);

        when(collectionReference.whereEqualTo("hostName", "hostname")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("provider", "athenz.provider")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("service", "service")).thenReturn(hostQuery);
        when(hostQuery.get()).thenReturn(hostFutureQuery);
        when(hostFutureQuery.get()).thenReturn(hostQuerySnapshot);
        when(hostQuerySnapshot.getDocuments()).thenReturn(documents);

        // Setup batch operation
        when(firestore.batch()).thenReturn(writeBatch);
        when(writeBatch.update(any(DocumentReference.class), any(Map.class))).thenReturn(writeBatch);
        when(writeBatch.commit()).thenReturn(futureWriteBatch);
        when(futureWriteBatch.get()).thenReturn(Collections.emptyList());

        long now = System.currentTimeMillis();

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", now, "athenz.provider");

        assertNotNull(records);
        assertEquals(records.size(), 1);

        dbConn.close();
    }

    @Test
    public void testUpdateUnrefreshedCertRecordsException() throws Exception {

        // Setup mocks for getUnrefreshedCertsRecords
        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenThrow(new InterruptedException("interrupted"));


        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        DocumentReference ref = Mockito.mock(DocumentReference.class);

        List<QueryDocumentSnapshot> documents = Collections.singletonList(doc);
        when(querySnapshot.getDocuments()).thenReturn(documents);

        long now = System.currentTimeMillis();

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", now, "athenz.provider");

        assertNotNull(records);
        assertEquals(records.size(), 0);

        dbConn.close();
    }

    @Test
    public void testUpdateUnrefreshedCertificatesException() throws Exception {

        // Setup mocks for getUnrefreshedCertsRecords
        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        DocumentReference ref = Mockito.mock(DocumentReference.class);

        when(doc.getReference()).thenReturn(ref);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn("hostname");
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);
        when(doc.getString("provider")).thenReturn("athenz.provider");
        when(doc.getString("service")).thenReturn("service");
        when(doc.getTimestamp("currentTime")).thenReturn(Timestamp.now());
        when(doc.getId()).thenReturn("doc-id");
        // Add all fields required by documentToX509CertRecord
        when(doc.getString("instanceId")).thenReturn("instance-id");
        when(doc.getString("currentSerial")).thenReturn("current-serial");
        when(doc.getString("currentIP")).thenReturn("10.0.0.1");
        when(doc.getString("prevSerial")).thenReturn("prev-serial");
        when(doc.getString("prevIP")).thenReturn("10.0.0.2");
        when(doc.getTimestamp("prevTime")).thenReturn(null);
        when(doc.getBoolean("clientCert")).thenReturn(false);
        when(doc.getString("lastNotifiedServer")).thenReturn(null);
        when(doc.getTimestamp("expiryTime")).thenReturn(null);
        when(doc.getTimestamp("svcDataUpdateTime")).thenReturn(null);
        when(doc.getString("siaProvider")).thenReturn(null);

        List<QueryDocumentSnapshot> documents = Collections.singletonList(doc);
        when(querySnapshot.getDocuments()).thenReturn(documents);

        // Setup for mostUpdatedHostRecord check
        Query hostQuery = Mockito.mock(Query.class);
        QuerySnapshot hostQuerySnapshot = Mockito.mock(QuerySnapshot.class);
        ApiFuture<QuerySnapshot> hostFutureQuery = Mockito.mock(ApiFuture.class);

        when(collectionReference.whereEqualTo("hostName", "hostname")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("provider", "athenz.provider")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("service", "service")).thenReturn(hostQuery);
        when(hostQuery.get()).thenReturn(hostFutureQuery);
        when(hostFutureQuery.get()).thenReturn(hostQuerySnapshot);
        when(hostQuerySnapshot.getDocuments()).thenReturn(documents);

        // Setup batch operation to fail
        when(firestore.batch()).thenReturn(writeBatch);
        when(writeBatch.update(any(DocumentReference.class), any(Map.class))).thenReturn(writeBatch);
        when(writeBatch.commit()).thenReturn(futureWriteBatch);
        when(futureWriteBatch.get()).thenThrow(new RuntimeException("batch commit failed"));

        long now = System.currentTimeMillis();

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", now, "athenz.provider");

        assertNotNull(records);
        assertEquals(records.size(), 0);

        dbConn.close();
    }

    @Test
    public void testUpdateUnrefreshedCertificatesInterruptedException() throws Exception {

        // Setup mocks for getUnrefreshedCertsRecords
        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        DocumentReference ref = Mockito.mock(DocumentReference.class);

        when(doc.getReference()).thenReturn(ref);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn("hostname");
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);
        when(doc.getString("provider")).thenReturn("athenz.provider");
        when(doc.getString("service")).thenReturn("service");
        when(doc.getTimestamp("currentTime")).thenReturn(Timestamp.now());
        when(doc.getId()).thenReturn("doc-id");
        // Add all fields required by documentToX509CertRecord
        when(doc.getString("instanceId")).thenReturn("instance-id");
        when(doc.getString("currentSerial")).thenReturn("current-serial");
        when(doc.getString("currentIP")).thenReturn("10.0.0.1");
        when(doc.getString("prevSerial")).thenReturn("prev-serial");
        when(doc.getString("prevIP")).thenReturn("10.0.0.2");
        when(doc.getTimestamp("prevTime")).thenReturn(null);
        when(doc.getBoolean("clientCert")).thenReturn(false);
        when(doc.getString("lastNotifiedServer")).thenReturn(null);
        when(doc.getTimestamp("expiryTime")).thenReturn(null);
        when(doc.getTimestamp("svcDataUpdateTime")).thenReturn(null);
        when(doc.getString("siaProvider")).thenReturn(null);

        List<QueryDocumentSnapshot> documents = Collections.singletonList(doc);
        when(querySnapshot.getDocuments()).thenReturn(documents);

        // Setup for mostUpdatedHostRecord check
        Query hostQuery = Mockito.mock(Query.class);
        QuerySnapshot hostQuerySnapshot = Mockito.mock(QuerySnapshot.class);
        ApiFuture<QuerySnapshot> hostFutureQuery = Mockito.mock(ApiFuture.class);

        when(collectionReference.whereEqualTo("hostName", "hostname")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("provider", "athenz.provider")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("service", "service")).thenReturn(hostQuery);
        when(hostQuery.get()).thenReturn(hostFutureQuery);
        when(hostFutureQuery.get()).thenReturn(hostQuerySnapshot);
        when(hostQuerySnapshot.getDocuments()).thenReturn(documents);

        // Setup batch operation to throw InterruptedException
        when(firestore.batch()).thenReturn(writeBatch);
        when(writeBatch.update(any(DocumentReference.class), any(Map.class))).thenReturn(writeBatch);
        when(writeBatch.commit()).thenReturn(futureWriteBatch);
        when(futureWriteBatch.get()).thenThrow(new InterruptedException("interrupted"));

        long now = System.currentTimeMillis();

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", now, "athenz.provider");

        assertNotNull(records);
        assertEquals(records.size(), 0);

        dbConn.close();
    }

    @Test
    public void testMostUpdatedHostRecordNullCurrentTime() throws Exception {
        // Test case: recordCurrentTime is null, should be filtered out

        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        DocumentReference ref = Mockito.mock(DocumentReference.class);

        when(doc.getReference()).thenReturn(ref);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn("hostname");
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);
        when(doc.getString("provider")).thenReturn("athenz.provider");
        when(doc.getString("service")).thenReturn("service");
        when(doc.getTimestamp("currentTime")).thenReturn(null); // NULL current time
        when(doc.getId()).thenReturn("doc-id");

        List<QueryDocumentSnapshot> documents = Collections.singletonList(doc);
        when(querySnapshot.getDocuments()).thenReturn(documents);

        // Setup for mostUpdatedHostRecord check
        Query hostQuery = Mockito.mock(Query.class);
        QuerySnapshot hostQuerySnapshot = Mockito.mock(QuerySnapshot.class);
        ApiFuture<QuerySnapshot> hostFutureQuery = Mockito.mock(ApiFuture.class);

        when(collectionReference.whereEqualTo("hostName", "hostname")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("provider", "athenz.provider")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("service", "service")).thenReturn(hostQuery);
        when(hostQuery.get()).thenReturn(hostFutureQuery);
        when(hostFutureQuery.get()).thenReturn(hostQuerySnapshot);
        when(hostQuerySnapshot.getDocuments()).thenReturn(documents);

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", System.currentTimeMillis(), "athenz.provider");

        // Should return empty list because record has null currentTime
        assertNotNull(records);
        assertEquals(records.size(), 0);

        dbConn.close();
    }

    @Test
    public void testMostUpdatedHostRecordNewerRecordExists() throws Exception {
        // Test case: Another record with same hostname has newer currentTime

        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot oldDoc = Mockito.mock(QueryDocumentSnapshot.class);
        DocumentReference ref = Mockito.mock(DocumentReference.class);

        Timestamp oldTime = Timestamp.of(new java.sql.Timestamp(System.currentTimeMillis() - 1000000));
        Timestamp newerTime = Timestamp.of(new java.sql.Timestamp(System.currentTimeMillis()));

        when(oldDoc.getReference()).thenReturn(ref);
        when(oldDoc.contains("hostName")).thenReturn(true);
        when(oldDoc.getString("hostName")).thenReturn("hostname");
        when(oldDoc.getTimestamp("lastNotifiedTime")).thenReturn(null);
        when(oldDoc.getString("provider")).thenReturn("athenz.provider");
        when(oldDoc.getString("service")).thenReturn("service");
        when(oldDoc.getTimestamp("currentTime")).thenReturn(oldTime);
        when(oldDoc.getId()).thenReturn("old-doc-id");

        List<QueryDocumentSnapshot> documents = Collections.singletonList(oldDoc);
        when(querySnapshot.getDocuments()).thenReturn(documents);

        // Setup for mostUpdatedHostRecord check - return TWO documents (old and new)
        QueryDocumentSnapshot newDoc = Mockito.mock(QueryDocumentSnapshot.class);
        when(newDoc.getTimestamp("currentTime")).thenReturn(newerTime);
        when(newDoc.getId()).thenReturn("new-doc-id"); // Different ID

        Query hostQuery = Mockito.mock(Query.class);
        QuerySnapshot hostQuerySnapshot = Mockito.mock(QuerySnapshot.class);
        ApiFuture<QuerySnapshot> hostFutureQuery = Mockito.mock(ApiFuture.class);

        when(collectionReference.whereEqualTo("hostName", "hostname")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("provider", "athenz.provider")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("service", "service")).thenReturn(hostQuery);
        when(hostQuery.get()).thenReturn(hostFutureQuery);
        when(hostFutureQuery.get()).thenReturn(hostQuerySnapshot);
        when(hostQuerySnapshot.getDocuments()).thenReturn(Arrays.asList(oldDoc, newDoc)); // Return both

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", System.currentTimeMillis(), "athenz.provider");

        // Should return empty list because a newer record exists
        assertNotNull(records);
        assertEquals(records.size(), 0);

        dbConn.close();
    }

    @Test
    public void testMostUpdatedHostRecordEmptyHostname() throws Exception {
        // Test case: hostname is empty, should be filtered out

        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        DocumentReference ref = Mockito.mock(DocumentReference.class);

        when(doc.getReference()).thenReturn(ref);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn(""); // EMPTY hostname
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);
        when(doc.getString("provider")).thenReturn("athenz.provider");
        when(doc.getString("service")).thenReturn("service");
        when(doc.getTimestamp("currentTime")).thenReturn(Timestamp.now());
        when(doc.getId()).thenReturn("doc-id");

        List<QueryDocumentSnapshot> documents = Collections.singletonList(doc);
        when(querySnapshot.getDocuments()).thenReturn(documents);

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", System.currentTimeMillis(), "athenz.provider");

        // Should return empty list because hostname is empty (filtered by getUnrefreshedCertsRecords)
        assertNotNull(records);
        assertEquals(records.size(), 0);

        dbConn.close();
    }

    @Test
    public void testMostUpdatedHostRecordEmptyProvider() throws Exception {
        // Test case: provider is empty, should be filtered out by mostUpdatedHostRecord

        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        DocumentReference ref = Mockito.mock(DocumentReference.class);

        when(doc.getReference()).thenReturn(ref);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn("hostname");
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);
        when(doc.getString("provider")).thenReturn(""); // EMPTY provider
        when(doc.getString("service")).thenReturn("service");
        when(doc.getTimestamp("currentTime")).thenReturn(Timestamp.now());
        when(doc.getId()).thenReturn("doc-id");

        List<QueryDocumentSnapshot> documents = Collections.singletonList(doc);
        when(querySnapshot.getDocuments()).thenReturn(documents);

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", System.currentTimeMillis(), "athenz.provider");

        // Should return empty list because provider is empty (filtered by mostUpdatedHostRecord)
        assertNotNull(records);
        assertEquals(records.size(), 0);

        dbConn.close();
    }

    @Test
    public void testFilterMostUpdatedHostRecordsSuccess() throws Exception {
        // Test successful filtering with a valid most recent record
        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        Timestamp currentTime = Timestamp.now();
        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        DocumentReference ref = Mockito.mock(DocumentReference.class);

        when(doc.getReference()).thenReturn(ref);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn("hostname");
        when(doc.getString("provider")).thenReturn("athenz.provider");
        when(doc.getString("service")).thenReturn("service");
        when(doc.getTimestamp("currentTime")).thenReturn(currentTime);
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);
        when(doc.getId()).thenReturn("doc-id-1");
        when(doc.getString("instanceId")).thenReturn("instance-1");
        when(doc.getString("currentSerial")).thenReturn("serial-1");
        when(doc.getString("currentIP")).thenReturn("10.0.0.1");
        when(doc.getString("prevSerial")).thenReturn(null);
        when(doc.getString("prevIP")).thenReturn(null);
        when(doc.getTimestamp("prevTime")).thenReturn(null);
        when(doc.getBoolean("clientCert")).thenReturn(false);
        when(doc.getString("lastNotifiedServer")).thenReturn(null);
        when(doc.getTimestamp("expiryTime")).thenReturn(null);
        when(doc.getTimestamp("svcDataUpdateTime")).thenReturn(null);
        when(doc.getString("siaProvider")).thenReturn(null);

        when(querySnapshot.getDocuments()).thenReturn(Collections.singletonList(doc));

        // Setup bulk query
        Query hostQuery = Mockito.mock(Query.class);
        QuerySnapshot hostQuerySnapshot = Mockito.mock(QuerySnapshot.class);
        ApiFuture<QuerySnapshot> hostFutureQuery = Mockito.mock(ApiFuture.class);

        when(collectionReference.whereEqualTo("hostName", "hostname")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("provider", "athenz.provider")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("service", "service")).thenReturn(hostQuery);
        when(hostQuery.get()).thenReturn(hostFutureQuery);
        when(hostFutureQuery.get()).thenReturn(hostQuerySnapshot);
        when(hostQuerySnapshot.getDocuments()).thenReturn(Collections.singletonList(doc));

        // Setup batch operation
        when(firestore.batch()).thenReturn(writeBatch);
        when(writeBatch.update(any(DocumentReference.class), any(Map.class))).thenReturn(writeBatch);
        when(writeBatch.commit()).thenReturn(futureWriteBatch);
        when(futureWriteBatch.get()).thenReturn(Collections.emptyList());

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", System.currentTimeMillis(), "athenz.provider");

        assertNotNull(records);
        assertEquals(records.size(), 1);

        dbConn.close();
    }

    @Test
    public void testFilterMostUpdatedHostRecordsNullHostname() throws Exception {
        // Test filtering documents with null hostname
        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn(null); // NULL hostname
        when(doc.getString("provider")).thenReturn("athenz.provider");
        when(doc.getString("service")).thenReturn("service");
        when(doc.getTimestamp("currentTime")).thenReturn(Timestamp.now());
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);

        when(querySnapshot.getDocuments()).thenReturn(Collections.singletonList(doc));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", System.currentTimeMillis(), "athenz.provider");

        assertNotNull(records);
        assertEquals(records.size(), 0); // Should be filtered out

        dbConn.close();
    }

    @Test
    public void testFilterMostUpdatedHostRecordsNullService() throws Exception {
        // Test filtering documents with null service
        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn("hostname");
        when(doc.getString("provider")).thenReturn("athenz.provider");
        when(doc.getString("service")).thenReturn(null); // NULL service
        when(doc.getTimestamp("currentTime")).thenReturn(Timestamp.now());
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);

        when(querySnapshot.getDocuments()).thenReturn(Collections.singletonList(doc));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", System.currentTimeMillis(), "athenz.provider");

        assertNotNull(records);
        assertEquals(records.size(), 0); // Should be filtered out

        dbConn.close();
    }

    @Test
    public void testFilterMostUpdatedHostRecordsAllNullCurrentTime() throws Exception {
        // Test when all records in a group have null currentTime - no record should be selected
        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn("hostname");
        when(doc.getString("provider")).thenReturn("athenz.provider");
        when(doc.getString("service")).thenReturn("service");
        when(doc.getTimestamp("currentTime")).thenReturn(null); // NULL currentTime
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);
        when(doc.getId()).thenReturn("doc-id");

        when(querySnapshot.getDocuments()).thenReturn(Collections.singletonList(doc));

        // Setup bulk query - returns the same document with null currentTime
        Query hostQuery = Mockito.mock(Query.class);
        QuerySnapshot hostQuerySnapshot = Mockito.mock(QuerySnapshot.class);
        ApiFuture<QuerySnapshot> hostFutureQuery = Mockito.mock(ApiFuture.class);

        when(collectionReference.whereEqualTo("hostName", "hostname")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("provider", "athenz.provider")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("service", "service")).thenReturn(hostQuery);
        when(hostQuery.get()).thenReturn(hostFutureQuery);
        when(hostFutureQuery.get()).thenReturn(hostQuerySnapshot);
        when(hostQuerySnapshot.getDocuments()).thenReturn(Collections.singletonList(doc));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", System.currentTimeMillis(), "athenz.provider");

        assertNotNull(records);
        assertEquals(records.size(), 0); // No record with valid currentTime

        dbConn.close();
    }

    @Test
    public void testFilterMostUpdatedHostRecordsOlderRecordFiltered() throws Exception {
        // Test that older records are filtered out when a newer record exists
        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        Timestamp oldTime = Timestamp.of(new java.sql.Timestamp(System.currentTimeMillis() - 100000));
        Timestamp newTime = Timestamp.of(new java.sql.Timestamp(System.currentTimeMillis()));

        // Old document (candidate from initial query)
        QueryDocumentSnapshot oldDoc = Mockito.mock(QueryDocumentSnapshot.class);
        when(oldDoc.contains("hostName")).thenReturn(true);
        when(oldDoc.getString("hostName")).thenReturn("hostname");
        when(oldDoc.getString("provider")).thenReturn("athenz.provider");
        when(oldDoc.getString("service")).thenReturn("service");
        when(oldDoc.getTimestamp("currentTime")).thenReturn(oldTime);
        when(oldDoc.getTimestamp("lastNotifiedTime")).thenReturn(null);
        when(oldDoc.getId()).thenReturn("old-doc-id");

        when(querySnapshot.getDocuments()).thenReturn(Collections.singletonList(oldDoc));

        // New document (returned by bulk query)
        QueryDocumentSnapshot newDoc = Mockito.mock(QueryDocumentSnapshot.class);
        when(newDoc.getTimestamp("currentTime")).thenReturn(newTime);
        when(newDoc.getId()).thenReturn("new-doc-id");

        // Setup bulk query - returns both old and new documents
        Query hostQuery = Mockito.mock(Query.class);
        QuerySnapshot hostQuerySnapshot = Mockito.mock(QuerySnapshot.class);
        ApiFuture<QuerySnapshot> hostFutureQuery = Mockito.mock(ApiFuture.class);

        when(collectionReference.whereEqualTo("hostName", "hostname")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("provider", "athenz.provider")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("service", "service")).thenReturn(hostQuery);
        when(hostQuery.get()).thenReturn(hostFutureQuery);
        when(hostFutureQuery.get()).thenReturn(hostQuerySnapshot);
        when(hostQuerySnapshot.getDocuments()).thenReturn(Arrays.asList(oldDoc, newDoc));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", System.currentTimeMillis(), "athenz.provider");

        assertNotNull(records);
        assertEquals(records.size(), 0); // Old doc filtered out, new doc not in candidates

        dbConn.close();
    }

    @Test
    public void testFilterMostUpdatedHostRecordsExecutionException() throws Exception {
        // Test exception handling during bulk query
        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn("hostname");
        when(doc.getString("provider")).thenReturn("athenz.provider");
        when(doc.getString("service")).thenReturn("service");
        when(doc.getTimestamp("currentTime")).thenReturn(Timestamp.now());
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);

        when(querySnapshot.getDocuments()).thenReturn(Collections.singletonList(doc));

        // Setup bulk query to throw ExecutionException
        Query hostQuery = Mockito.mock(Query.class);
        ApiFuture<QuerySnapshot> hostFutureQuery = Mockito.mock(ApiFuture.class);

        when(collectionReference.whereEqualTo("hostName", "hostname")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("provider", "athenz.provider")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("service", "service")).thenReturn(hostQuery);
        when(hostQuery.get()).thenReturn(hostFutureQuery);
        when(hostFutureQuery.get()).thenThrow(new ExecutionException("Query failed", new Throwable("error")));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", System.currentTimeMillis(), "athenz.provider");

        assertNotNull(records);
        assertEquals(records.size(), 0); // Exception returns empty list

        dbConn.close();
    }

    @Test
    public void testFilterMostUpdatedHostRecordsInterruptedException() throws Exception {
        // Test InterruptedException handling during bulk query
        Query query = Mockito.mock(Query.class);
        when(collectionReference.whereEqualTo(eq("provider"), anyString())).thenReturn(query);
        when(query.whereGreaterThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.whereLessThanOrEqualTo(eq("currentTime"), any(Timestamp.class))).thenReturn(query);
        when(query.get()).thenReturn(futureQuery);
        when(futureQuery.get()).thenReturn(querySnapshot);

        QueryDocumentSnapshot doc = Mockito.mock(QueryDocumentSnapshot.class);
        when(doc.contains("hostName")).thenReturn(true);
        when(doc.getString("hostName")).thenReturn("hostname");
        when(doc.getString("provider")).thenReturn("athenz.provider");
        when(doc.getString("service")).thenReturn("service");
        when(doc.getTimestamp("currentTime")).thenReturn(Timestamp.now());
        when(doc.getTimestamp("lastNotifiedTime")).thenReturn(null);

        when(querySnapshot.getDocuments()).thenReturn(Collections.singletonList(doc));

        // Setup bulk query to throw InterruptedException
        Query hostQuery = Mockito.mock(Query.class);
        ApiFuture<QuerySnapshot> hostFutureQuery = Mockito.mock(ApiFuture.class);

        when(collectionReference.whereEqualTo("hostName", "hostname")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("provider", "athenz.provider")).thenReturn(hostQuery);
        when(hostQuery.whereEqualTo("service", "service")).thenReturn(hostQuery);
        when(hostQuery.get()).thenReturn(hostFutureQuery);
        when(hostFutureQuery.get()).thenThrow(new InterruptedException("interrupted"));

        FirestoreCertRecordStoreConnection dbConn = getDBConnection();

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "server", System.currentTimeMillis(), "athenz.provider");

        assertNotNull(records);
        assertEquals(records.size(), 0); // InterruptedException returns empty list

        dbConn.close();
    }


}
