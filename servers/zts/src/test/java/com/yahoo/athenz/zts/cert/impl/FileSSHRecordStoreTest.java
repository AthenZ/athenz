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
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.common.server.ssh.SSHRecordStore;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.ZTSImpl;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import static org.testng.Assert.*;

public class FileSSHRecordStoreTest {

    @Test
    public void testFileSSHRecordStoreFactory() {

        System.setProperty(ZTSConsts.ZTS_PROP_SSH_FILE_STORE_PATH, "/tmp");

        FileSSHRecordStoreFactory factory = new FileSSHRecordStoreFactory();
        SSHRecordStore store = factory.create(null);
        assertNotNull(store);

        System.clearProperty(ZTSConsts.ZTS_PROP_SSH_FILE_STORE_PATH);
    }

    @Test
    public void testGetConnection() {
        FileSSHRecordStore store = new FileSSHRecordStore(new File("/tmp"));
        assertNotNull(store.getConnection());
        store.setOperationTimeout(100);
        store.clearConnections();
    }

    @Test
    public void testEnableNotifications() {
        FileSSHRecordStore store = new FileSSHRecordStore(new File("/tmp"));
        assertFalse(store.enableNotifications(null, null, null));
    }

    @Test
    public void testFileSSHRecordStoreInvalidDirecory() {
        try {
            new FileSSHRecordStore(new File("/proc/usr/root"));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("cannot create specified root"));
        }
    }

    @Test
    public void testGetStoreException() {
        
        File file = new File("/tmp", "zts-ssh-file");
        try {
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write("test");
            fileWriter.close();
        } catch (IOException ignored) {
        }
        
        FileSSHRecordStore store = null;
        try {
            store = new FileSSHRecordStore(file);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
        assertNull(store);
    }

    @Test
    public void testLog() {

        FileSSHRecordStore store = new FileSSHRecordStore(new File("/tmp"));
        Principal principal = SimplePrincipal.create("user", "joe", "creds");

        // make sure no exceptions are thrown when processing log request

        store.log(principal, "10.11.12.13", "athenz.api", "1234");
    }
}
