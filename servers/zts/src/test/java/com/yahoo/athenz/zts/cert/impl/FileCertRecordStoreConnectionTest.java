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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import com.yahoo.athenz.zts.ZTSTestUtils;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

import com.yahoo.athenz.common.server.cert.X509CertRecord;

public class FileCertRecordStoreConnectionTest {

    class FileCertRecordStoreConnectionExt extends FileCertRecordStoreConnection {


        public FileCertRecordStoreConnectionExt(File rootDir) {
            super(rootDir);
        }

        @Override
        boolean notExpired(long currentTime, long lastModified, long expiryTimeMins) {
            return true;
        }
    }

    @Test
    public void testX509CertOperations() {
        
        // make sure the directory does not exist

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts-cert-tests"));

        FileCertRecordStore store = new FileCertRecordStore(new File("/tmp/zts-cert-tests"));
        FileCertRecordStoreConnection con = (FileCertRecordStoreConnection) store.getConnection();
        assertNotNull(con);
        con.setOperationTimeout(10);
        
        // first verify that we don't have the entry
        
        X509CertRecord certRecordCheck = con.getX509CertRecord("ostk", "instance-id", "cn");
        assertNull(certRecordCheck);

        // now write the entry
        
        X509CertRecord certRecord = new X509CertRecord();
        Date now = new Date();

        certRecord.setService("cn");
        certRecord.setProvider("ostk");
        certRecord.setInstanceId("instance-id");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentTime(now);
        certRecord.setPrevIP("prev-ip");
        certRecord.setPrevSerial("prev-serial");
        certRecord.setPrevTime(now);
        
        boolean result = con.insertX509CertRecord(certRecord);
        assertTrue(result);
        
        // now read the entry again
        
        certRecordCheck = con.getX509CertRecord("ostk", "instance-id", "cn");
        assertNotNull(certRecordCheck);
        
        assertEquals(certRecordCheck.getCurrentIP(), "current-ip");
        assertEquals(certRecordCheck.getCurrentSerial(), "current-serial");
        assertEquals(certRecordCheck.getCurrentTime(), now);
        assertEquals(certRecordCheck.getInstanceId(), "instance-id");
        assertEquals(certRecordCheck.getPrevIP(), "prev-ip");
        assertEquals(certRecordCheck.getPrevSerial(), "prev-serial");
        assertEquals(certRecordCheck.getPrevTime(), now);
        assertEquals(certRecordCheck.getProvider(), "ostk");
        assertEquals(certRecordCheck.getService(), "cn");
        
        // now update the entry
        
        certRecord.setCurrentIP("updated-ip");
        certRecord.setCurrentSerial("updated-serial");
        
        result = con.updateX509CertRecord(certRecord);
        assertTrue(result);
        
        certRecordCheck = con.getX509CertRecord("ostk", "instance-id", "cn");
        assertNotNull(certRecordCheck);
        
        assertEquals(certRecordCheck.getCurrentIP(), "updated-ip");
        assertEquals(certRecordCheck.getCurrentSerial(), "updated-serial");
        assertEquals(certRecordCheck.getCurrentTime(), now);
        assertEquals(certRecordCheck.getInstanceId(), "instance-id");
        assertEquals(certRecordCheck.getPrevIP(), "prev-ip");
        assertEquals(certRecordCheck.getPrevSerial(), "prev-serial");
        assertEquals(certRecordCheck.getPrevTime(), now);
        assertEquals(certRecordCheck.getProvider(), "ostk");
        assertEquals(certRecordCheck.getService(), "cn");
        
        // now delete the entry
        
        con.deleteX509CertRecord("ostk", "instance-id", "cn");
        certRecordCheck = con.getX509CertRecord("ostk", "instance-id", "cn");
        assertNull(certRecordCheck);
        
        con.close();
    }
    
    @Test
    public void testX509CertOperationsNullValues() {
        
        // make sure the directory does not exist

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts-cert-tests"));

        FileCertRecordStore store = new FileCertRecordStore(new File("/tmp/zts-cert-tests"));
        FileCertRecordStoreConnection con = (FileCertRecordStoreConnection) store.getConnection();
        assertNotNull(con);
        
        boolean result = con.insertX509CertRecord(null);
        assertTrue(result);
        
        result = con.updateX509CertRecord(null);
        assertTrue(result);
        
        con.deleteX509CertRecord("unknown", "instance-id", "cn");
        con.close();
    }
    
    @Test
    public void testdeleteExpiredX509CertRecords() throws Exception {
        
        // make sure the directory does not exist

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts-cert-tests"));

        FileCertRecordStore store = new FileCertRecordStore(new File("/tmp/zts-cert-tests"));
        FileCertRecordStoreConnection con = (FileCertRecordStoreConnection) store.getConnection();
        assertNotNull(con);
        
        X509CertRecord certRecord = new X509CertRecord();
        Date now = new Date();

        certRecord.setService("cn");
        certRecord.setProvider("ostk");
        certRecord.setInstanceId("instance-id");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentTime(now);
        certRecord.setPrevIP("prev-ip");
        certRecord.setPrevSerial("prev-serial");
        certRecord.setPrevTime(now);
        
        boolean result = con.insertX509CertRecord(certRecord);
        assertTrue(result);
        
        X509CertRecord certRecordCheck = con.getX509CertRecord("ostk", "instance-id", "cn");
        assertNotNull(certRecordCheck);

        // Verify that certificates are not expired immediately
        con.deleteExpiredX509CertRecords(43200); //30 days
        certRecordCheck = con.getX509CertRecord("ostk", "instance-id", "cn");
        assertNotNull(certRecordCheck);

        Thread.sleep(1000);
        con.deleteExpiredX509CertRecords(0);

        certRecordCheck = con.getX509CertRecord("ostk", "instance-id", "cn");
        assertNull(certRecordCheck);
        con.close();
    }

    @Test
    public void testDeleteExpiredX509CertRecords() {

        // make sure the directory does not exist

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts-cert-tests"));

        FileCertRecordStore store = new FileCertRecordStore(new File("/tmp/zts-cert-tests"));
        FileCertRecordStoreConnection con = (FileCertRecordStoreConnection) store.getConnection();
        assertNotNull(con);

        File dir = Mockito.spy(con.rootDir);
        Mockito.when(dir.list()).thenReturn(null);
        con.rootDir = dir;

        assertEquals(con.deleteExpiredX509CertRecords(0), 0);
    }

    @Test
    public void testdeleteExpiredX509CertRecordsDelete() throws Exception {

        // make sure the directory does not exist

        File rootDir = new File("/tmp/zts-cert-tests");
        ZTSTestUtils.deleteDirectory(rootDir);
        rootDir.mkdirs();

        FileCertRecordStoreConnectionExt store = new FileCertRecordStoreConnectionExt(rootDir);

        X509CertRecord certRecord = new X509CertRecord();
        Date now = new Date();

        certRecord.setService("cn");
        certRecord.setProvider("ostk");
        certRecord.setInstanceId("instance-id");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentTime(now);
        certRecord.setPrevIP("prev-ip");
        certRecord.setPrevSerial("prev-serial");
        certRecord.setPrevTime(now);

        boolean result = store.insertX509CertRecord(certRecord);
        assertTrue(result);

        X509CertRecord certRecordCheck = store.getX509CertRecord("ostk", "instance-id", "cn");
        assertNotNull(certRecordCheck);

        Thread.sleep(1000);
        store.deleteExpiredX509CertRecords(0);

        certRecordCheck = store.getX509CertRecord("ostk", "instance-id", "cn");
        assertNotNull(certRecordCheck);
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestamp() {
        ZTSTestUtils.deleteDirectory(new File("/tmp/zts-cert-tests"));

        FileCertRecordStore store = new FileCertRecordStore(new File("/tmp/zts-cert-tests"));
        FileCertRecordStoreConnection con = (FileCertRecordStoreConnection) store.getConnection();
        assertNotNull(con);
        long timestamp = System.currentTimeMillis();
        List<X509CertRecord> records = con.updateUnrefreshedCertificatesNotificationTimestamp(
                "localhost",
                timestamp,
                "provider");

        // For File store, unrefreshed certs unimplemented. Assert empty collection
        assertEquals(records, new ArrayList<>());
    }
}
