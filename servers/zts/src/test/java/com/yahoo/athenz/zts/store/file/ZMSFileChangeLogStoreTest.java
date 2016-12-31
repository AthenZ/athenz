/**
 * Copyright 2016 Yahoo Inc.
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
package com.yahoo.athenz.zts.store.file;

import static org.testng.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.zts.store.file.ZMSFileChangeLogStore;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;

public class ZMSFileChangeLogStoreTest {

    private final String FSTORE_PATH = "/tmp/zts_file_store_unit_test";
    
    private void touch(String fname) throws IOException {
        
        File file = new File(fname);
        
        if (!file.exists()) {
           new FileOutputStream(file).close();
        }

        file.setLastModified(System.currentTimeMillis());
    }
    
    @BeforeMethod
    public void setup() {
        ZMSFileChangeLogStore.deleteDirectory(new File(FSTORE_PATH));
    }
    
    @AfterMethod
    public void shutdown() {
        ZMSFileChangeLogStore.deleteDirectory(new File(FSTORE_PATH));
    }
 
    @Test
    public void FileStructStoreValidDir() {
        
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        assertNotNull(fstore);
    }
    
    @Test
    public void FileStructStoreInvalid() {
        
        try {
            File rootDir = new File(FSTORE_PATH);
            rootDir.mkdirs();
            
            String fpath = FSTORE_PATH + "/zts_file.tmp";
            touch(fpath);
            
            @SuppressWarnings("unused")
            ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(fpath, null, null);
            fail();
        } catch (RuntimeException | IOException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void getNonExistent() {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        Struct st = fstore.get("NotExistent", Struct.class);
        assertNull(st);
    }

    @Test
    public void getExistent() {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));
        
        Struct st = fstore.get("test1", Struct.class);
        assertNotNull(st);
        assertEquals(st.get("key"), "val1");
    }
    
    @Test
    public void deleteExistent() {
        
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));
        
        fstore.delete("test1");
        Struct st = fstore.get("test1", Struct.class);
        assertNull(st);
    }
    
    @Test
    public void deleteNonExistent() {
        
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        
        fstore.delete("test1");
        assertTrue(true);
    }
    
    @Test
    public void scanEmpty() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        List<String> ls = fstore.scan();
        assertEquals(ls.size(), 0);
    }
    
    @Test
    public void scanSingle() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));
        
        List<String> ls = fstore.scan();
        assertEquals(ls.size(), 1);
        assertTrue(ls.contains("test1"));
    }

    @Test
    public void scanMultiple() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        fstore.put("test2", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        fstore.put("test3", JSON.bytes(data));
        
        List<String> ls = fstore.scan();
        assertEquals(ls.size(), 3);
        assertTrue(ls.contains("test1"));
        assertTrue(ls.contains("test2"));
        assertTrue(ls.contains("test3"));
    }
    
    @Test
    public void scanHidden() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        fstore.put(".test2", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        fstore.put(".test3", JSON.bytes(data));
        
        List<String> ls = fstore.scan();
        assertEquals(ls.size(), 1);
        assertTrue(ls.contains("test1"));
    }
    
    @Test
    public void scanDelete() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        fstore.put("test2", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        fstore.put("test3", JSON.bytes(data));
        
        fstore.delete("test2");
        
        List<String> ls = fstore.scan();
        assertEquals(ls.size(), 2);
        assertTrue(ls.contains("test1"));
        assertTrue(ls.contains("test3"));
    }
    
    @Test
    public void testFullRefreshSupport() {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        assertTrue(fstore.supportsFullRefresh());
    }
}
