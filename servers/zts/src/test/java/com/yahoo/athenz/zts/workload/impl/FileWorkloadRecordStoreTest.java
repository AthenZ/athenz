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

package com.yahoo.athenz.zts.workload.impl;

import org.testng.annotations.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertTrue;

public class FileWorkloadRecordStoreTest {
    @Test
    public void testGetConnection() {
        FileWorkloadRecordStore store = new FileWorkloadRecordStore(new File("/tmp"));
        assertNotNull(store.getConnection());
        store.setOperationTimeout(100);
        store.clearConnections();
    }

    @Test
    public void testFileCertRecordStoreInvalidDirectory() {
        try {
            new FileWorkloadRecordStore(new File("/proc/usr/root"));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("cannot create specified root"));
        }
    }

    @Test
    public void testGetStoreException() {

        File file = new File("/tmp", "zts-workload-file");
        try {
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write("test");
            fileWriter.close();
        } catch (IOException ignored) {
        }

        FileWorkloadRecordStore store = null;
        try {
            store = new FileWorkloadRecordStore(file);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
        assertNull(store);
    }
}