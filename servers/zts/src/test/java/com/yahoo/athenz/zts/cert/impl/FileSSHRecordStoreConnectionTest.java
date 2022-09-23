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

import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.zts.ZTSTestUtils;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.File;

import static org.testng.Assert.*;

public class FileSSHRecordStoreConnectionTest {

    class FileSSHRecordStoreConnectionExt extends FileSSHRecordStoreConnection {

        public FileSSHRecordStoreConnectionExt(File rootDir) {
            super(rootDir);
        }

        @Override
        boolean notExpired(long currentTime, long lastModified, int expiryTimeMins) {
            return true;
        }
    }

    @Test
    public void testSSHCertOperationsNullObjects() {

        // make sure the directory does not exist

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts-ssh-tests"));

        FileSSHRecordStore store = new FileSSHRecordStore(new File("/tmp/zts-ssh-tests"));
        FileSSHRecordStoreConnection con = (FileSSHRecordStoreConnection) store.getConnection();
        assertNotNull(con);
        con.setOperationTimeout(10);

        // no exception when passing null objects

        assertTrue(con.insertSSHCertRecord(null));
        assertTrue(con.updateSSHCertRecord(null));
    }

    @Test
    public void testSSHCertOperations() {
        
        // make sure the directory does not exist

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts-ssh-tests"));

        FileSSHRecordStore store = new FileSSHRecordStore(new File("/tmp/zts-ssh-tests"));
        FileSSHRecordStoreConnection con = (FileSSHRecordStoreConnection) store.getConnection();
        assertNotNull(con);
        con.setOperationTimeout(10);
        
        // first verify that we don't have the entry
        
        SSHCertRecord certRecordCheck = con.getSSHCertRecord("instance-id", "cn");
        assertNull(certRecordCheck);

        // now write the entry
        
        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("instance-id");
        certRecord.setService("cn");
        certRecord.setPrincipals("host1,host2");
        certRecord.setClientIP("10.10.10.11");
        certRecord.setPrivateIP("10.10.10.12");

        assertTrue(con.insertSSHCertRecord(certRecord));

        // now read the entry again
        
        certRecordCheck = con.getSSHCertRecord("instance-id", "cn");
        assertNotNull(certRecordCheck);

        assertEquals(certRecordCheck.getInstanceId(), "instance-id");
        assertEquals(certRecordCheck.getService(), "cn");
        assertEquals(certRecordCheck.getPrincipals(), "host1,host2");
        assertEquals(certRecordCheck.getClientIP(), "10.10.10.11");
        assertEquals(certRecordCheck.getPrivateIP(), "10.10.10.12");
        
        // now update the entry

        certRecord.setPrincipals("host1,host2,host3");
        certRecord.setClientIP("10.10.10.13");

        assertTrue(con.updateSSHCertRecord(certRecord));

        certRecordCheck = con.getSSHCertRecord("instance-id", "cn");
        assertNotNull(certRecordCheck);

        assertEquals(certRecordCheck.getInstanceId(), "instance-id");
        assertEquals(certRecordCheck.getService(), "cn");
        assertEquals(certRecordCheck.getPrincipals(), "host1,host2,host3");
        assertEquals(certRecordCheck.getClientIP(), "10.10.10.13");
        assertEquals(certRecordCheck.getPrivateIP(), "10.10.10.12");
        
        // now delete the entry
        
        con.deleteSSHCertRecord("instance-id", "cn");
        certRecordCheck = con.getSSHCertRecord("instance-id", "cn");
        assertNull(certRecordCheck);
        
        con.close();
    }
    
    @Test
    public void testDeleteExpiredSSHCertRecords() throws Exception {
        
        // make sure the directory does not exist

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts-ssh-tests"));

        FileSSHRecordStore store = new FileSSHRecordStore(new File("/tmp/zts-ssh-tests"));
        FileSSHRecordStoreConnection con = (FileSSHRecordStoreConnection) store.getConnection();
        assertNotNull(con);
        
        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("instance-id");
        certRecord.setService("cn");
        certRecord.setPrincipals("host1,host2");
        certRecord.setClientIP("10.10.10.11");
        certRecord.setPrivateIP("10.10.10.12");

        assertTrue(con.insertSSHCertRecord(certRecord));

        SSHCertRecord certRecordCheck = con.getSSHCertRecord("instance-id", "cn");
        assertNotNull(certRecordCheck);
        
        Thread.sleep(1000);
        con.deleteExpiredSSHCertRecords(0);

        certRecordCheck = con.getSSHCertRecord("instance-id", "cn");
        assertNull(certRecordCheck);
        con.close();
    }

    @Test
    public void testDeleteExpiredSSHCertRecordsDelete() throws Exception {

        // make sure the directory does not exist

        File rootDir = new File("/tmp/zts-ssh-tests");
        ZTSTestUtils.deleteDirectory(rootDir);
        rootDir.mkdirs();

        FileSSHRecordStoreConnectionTest.FileSSHRecordStoreConnectionExt store = new FileSSHRecordStoreConnectionTest.FileSSHRecordStoreConnectionExt(rootDir);

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("instance-id");
        certRecord.setService("cn");
        certRecord.setPrincipals("host1,host2");
        certRecord.setClientIP("10.10.10.11");
        certRecord.setPrivateIP("10.10.10.12");

        assertTrue(store.insertSSHCertRecord(certRecord));

        SSHCertRecord certRecordCheck = store.getSSHCertRecord("instance-id", "cn");
        assertNotNull(certRecordCheck);

        Thread.sleep(1000);
        store.deleteExpiredSSHCertRecords(0);

        certRecordCheck = store.getSSHCertRecord("instance-id", "cn");
        assertNotNull(certRecordCheck);
    }

    @Test
    public void testDeleteExpiredSSHCertRecordsNoDir() {

        // make sure the directory does not exist

        ZTSTestUtils.deleteDirectory(new File("/tmp/zts-ssh-tests"));

        FileSSHRecordStore store = new FileSSHRecordStore(new File("/tmp/zts-ssh-tests"));
        FileSSHRecordStoreConnection con = (FileSSHRecordStoreConnection) store.getConnection();
        assertNotNull(con);

        File dir = Mockito.spy(con.rootDir);
        Mockito.when(dir.list()).thenReturn(null);
        con.rootDir = dir;

        assertEquals(con.deleteExpiredSSHCertRecords(0), 0);
    }
}
