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
import com.google.cloud.firestore.CollectionReference;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteResult;
import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Map;
import java.util.concurrent.ExecutionException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class FirestoreSSHRecordStoreConnectionTest {

    private final String collectionName = "ssh-collection";

    @Mock private Firestore firestore;
    @Mock private CollectionReference collectionReference;
    @Mock private DocumentReference documentReference;
    @Mock private ApiFuture<DocumentSnapshot> futureGet;
    @Mock private ApiFuture<WriteResult> futureWrite;
    @Mock private DocumentSnapshot documentSnapshot;
    @Mock private WriteResult writeResult;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        when(firestore.collection(collectionName)).thenReturn(collectionReference);
        when(collectionReference.document(any())).thenReturn(documentReference);
    }

    private FirestoreSSHRecordStoreConnection getDBConnection() {
        return new FirestoreSSHRecordStoreConnection(firestore, collectionName);
    }

    @Test
    public void testGetSSHCertRecord() throws Exception {

        when(documentReference.get()).thenReturn(futureGet);
        when(futureGet.get()).thenReturn(documentSnapshot);
        when(documentSnapshot.exists()).thenReturn(true);

        when(documentSnapshot.getString("instanceId")).thenReturn("1234");
        when(documentSnapshot.getString("service")).thenReturn("cn");
        when(documentSnapshot.getString("principals")).thenReturn("host1,host2");
        when(documentSnapshot.getString("clientIP")).thenReturn("10.10.10.11");
        when(documentSnapshot.getString("privateIP")).thenReturn("10.10.10.12");

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();
        dbConn.setOperationTimeout(10);
        SSHCertRecord certRecord = dbConn.getSSHCertRecord("1234", "cn");

        assertNotNull(certRecord);
        assertEquals(certRecord.getInstanceId(), "1234");
        assertEquals(certRecord.getService(), "cn");
        assertEquals(certRecord.getPrincipals(), "host1,host2");
        assertEquals(certRecord.getClientIP(), "10.10.10.11");
        assertEquals(certRecord.getPrivateIP(), "10.10.10.12");

        dbConn.close();
    }

    @Test
    public void testGetSSHCertRecordNotFound() throws Exception {

        when(documentReference.get()).thenReturn(futureGet);
        when(futureGet.get()).thenReturn(documentSnapshot);
        when(documentSnapshot.exists()).thenReturn(false);

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();
        SSHCertRecord certRecord = dbConn.getSSHCertRecord("1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testGetSSHCertRecordException() throws Exception {

        when(documentReference.get()).thenReturn(futureGet);
        when(futureGet.get()).thenThrow(new ExecutionException("error", new Throwable("error")));

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();
        SSHCertRecord certRecord = dbConn.getSSHCertRecord("1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testGetSSHCertRecordInterruptedException() throws Exception {

        when(documentReference.get()).thenReturn(futureGet);
        when(futureGet.get()).thenThrow(new InterruptedException("interrupted"));

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();
        SSHCertRecord certRecord = dbConn.getSSHCertRecord("1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testInsertSSHCertRecord() throws Exception {

        when(documentReference.set(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenReturn(writeResult);

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");
        certRecord.setPrincipals("host1,host2");
        certRecord.setClientIP("10.10.10.11");
        certRecord.setPrivateIP("10.10.10.12");

        boolean result = dbConn.insertSSHCertRecord(certRecord);
        assertTrue(result);

        // Verify that set was called with a map containing the expected fields
        verify(documentReference).set(ArgumentMatchers.argThat(map -> {
            Map<String, Object> m = (Map<String, Object>) map;
            return m.containsKey("primaryKey") &&
                   m.containsKey("instanceId") &&
                   m.containsKey("service") &&
                   m.containsKey("principals") &&
                   m.containsKey("clientIP") &&
                   m.containsKey("privateIP") &&
                   m.containsKey("ttlTimestamp");
        }));

        dbConn.close();
    }

    @Test
    public void testInsertSSHCertRecordException() throws Exception {

        when(documentReference.set(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new ExecutionException("error", new Throwable("error")));

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");

        boolean result = dbConn.insertSSHCertRecord(certRecord);
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testInsertSSHCertRecordInterruptedException() throws Exception {

        when(documentReference.set(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new InterruptedException("interrupted"));

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");

        boolean result = dbConn.insertSSHCertRecord(certRecord);
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testUpdateSSHCertRecord() throws Exception {

        when(documentReference.update(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenReturn(writeResult);

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");
        certRecord.setPrincipals("host1,host2");
        certRecord.setClientIP("10.10.10.11");
        certRecord.setPrivateIP("10.10.10.12");

        boolean result = dbConn.updateSSHCertRecord(certRecord);
        assertTrue(result);

        // Verify that update was called with a map containing the expected fields
        verify(documentReference).update(ArgumentMatchers.argThat(map -> {
            Map<String, Object> m = (Map<String, Object>) map;
            return m.containsKey("instanceId") &&
                   m.containsKey("service") &&
                   m.containsKey("principals") &&
                   m.containsKey("clientIP") &&
                   m.containsKey("privateIP") &&
                   m.containsKey("ttlTimestamp");
        }));

        dbConn.close();
    }

    @Test
    public void testUpdateSSHCertRecordException() throws Exception {

        when(documentReference.update(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new ExecutionException("error", new Throwable("error")));

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");

        boolean result = dbConn.updateSSHCertRecord(certRecord);
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testUpdateSSHCertRecordInterruptedException() throws Exception {

        when(documentReference.update(any(Map.class))).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new InterruptedException("interrupted"));

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");

        boolean result = dbConn.updateSSHCertRecord(certRecord);
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testDeleteSSHCertRecord() throws Exception {

        when(documentReference.delete()).thenReturn(futureWrite);
        when(futureWrite.get()).thenReturn(writeResult);

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();

        boolean result = dbConn.deleteSSHCertRecord("1234", "cn");
        assertTrue(result);

        dbConn.close();
    }

    @Test
    public void testDeleteSSHCertRecordException() throws Exception {

        when(documentReference.delete()).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new ExecutionException("error", new Throwable("error")));

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();

        boolean result = dbConn.deleteSSHCertRecord("1234", "cn");
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testDeleteSSHCertRecordInterruptedException() throws Exception {

        when(documentReference.delete()).thenReturn(futureWrite);
        when(futureWrite.get()).thenThrow(new InterruptedException("interrupted"));

        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();

        boolean result = dbConn.deleteSSHCertRecord("1234", "cn");
        assertFalse(result);

        dbConn.close();
    }

    @Test
    public void testDeleteExpiredSSHCertRecords() {
        // Firestore uses native TTL, so this method always returns 0
        FirestoreSSHRecordStoreConnection dbConn = getDBConnection();

        int deletedCount = dbConn.deleteExpiredSSHCertRecords(100, 10);
        assertEquals(deletedCount, 0);

        dbConn.close();
    }
}
