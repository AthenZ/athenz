package com.yahoo.athenz.zts.cert.impl;

import java.io.File;
import java.util.Date;

import org.testng.annotations.Test;
import static org.testng.Assert.*;

import com.yahoo.athenz.zts.cert.X509CertRecord;
import com.yahoo.athenz.zts.store.file.ZMSFileChangeLogStore;

public class FileCertRecordStoreConnectionTest {

    @Test
    public void testX509CertOperations() {
        
        // make sure the directory does not exist
        
        ZMSFileChangeLogStore.deleteDirectory(new File("/tmp/zts-cert-tests"));

        FileCertRecordStore store = new FileCertRecordStore(new File("/tmp/zts-cert-tests"));
        FileCertRecordStoreConnection con = (FileCertRecordStoreConnection) store.getConnection();
        assertNotNull(con);
        con.setOperationTimeout(10);
        
        // first verify that we don't have the entry
        
        X509CertRecord certRecordCheck = con.getX509CertRecord("ostk", "instance-id");
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
        
        certRecordCheck = con.getX509CertRecord("ostk", "instance-id");
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
        
        certRecordCheck = con.getX509CertRecord("ostk", "instance-id");
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
        
        con.deleteX509CertRecord("ostk", "instance-id");
        certRecordCheck = con.getX509CertRecord("ostk", "instance-id");
        assertNull(certRecordCheck);
        
        con.close();
    }
    
    @Test
    public void testX509CertOperationsNullValues() {
        
        // make sure the directory does not exist
        
        ZMSFileChangeLogStore.deleteDirectory(new File("/tmp/zts-cert-tests"));

        FileCertRecordStore store = new FileCertRecordStore(new File("/tmp/zts-cert-tests"));
        FileCertRecordStoreConnection con = (FileCertRecordStoreConnection) store.getConnection();
        assertNotNull(con);
        
        boolean result = con.insertX509CertRecord(null);
        assertTrue(result);
        
        result = con.updateX509CertRecord(null);
        assertTrue(result);
        
        con.deleteX509CertRecord("unknown", "instance-id");
    }
}
