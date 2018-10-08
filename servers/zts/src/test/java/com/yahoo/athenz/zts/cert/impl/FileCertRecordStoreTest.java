/*
 * Copyright 2017 Yahoo Inc.
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
import java.io.FileWriter;
import java.io.IOException;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class FileCertRecordStoreTest {

    @Test
    public void testGetConnection() {
        FileCertRecordStore store = new FileCertRecordStore(new File("/tmp"));
        assertNotNull(store.getConnection());
        store.setOperationTimeout(100);
        store.clearConnections();
    }

    @Test
    public void testFileCertRecordStoreInvalidDirecory() {
        try {
            new FileCertRecordStore(new File("/usr/root"));
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().contains("cannot create specified root"));
        }
    }

    @Test
    public void testGetStoreException() {
        
        File file = new File("/tmp", "zts-cert-file");
        try {
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write("test");
            fileWriter.close();
        } catch (IOException ignored) {
        }
        
        FileCertRecordStore store = null;
        try {
            store = new FileCertRecordStore(file);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
        assertNull(store);
    }
}
