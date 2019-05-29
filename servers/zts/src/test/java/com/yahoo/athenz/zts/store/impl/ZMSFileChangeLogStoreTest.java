/*
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
package com.yahoo.athenz.zts.store.impl;

import static org.testng.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.security.PrivateKey;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.ZTSTestUtils;
import com.yahoo.athenz.zts.utils.FilesHelper;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import com.yahoo.athenz.zms.ZMSClient;
import com.yahoo.athenz.zms.ZMSClientException;

import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;

public class ZMSFileChangeLogStoreTest {

    private final String FSTORE_PATH = "/tmp/zts_file_store_unit_test";
    
    private void touch(String fname) throws IOException {
        
        File file = new File(fname);
        
        if (!file.exists()) {
           new FileOutputStream(file).close();
        }

        //noinspection ResultOfMethodCallIgnored
        file.setLastModified(System.currentTimeMillis());
    }
    
    @BeforeMethod
    public void setup() {
        ZTSTestUtils.deleteDirectory(new File(FSTORE_PATH));
        System.setProperty(ZTSConsts.ZTS_PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTSConsts.ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
    }
    
    @AfterMethod
    public void shutdown() {
        ZTSTestUtils.deleteDirectory(new File(FSTORE_PATH));
    }
 
    @Test
    public void testFileStructStoreValidDir() {
        
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        assertNotNull(fstore);
    }
    
    @Test
    public void testFileStructStoreInvalid() {
        
        try {
            File rootDir = new File(FSTORE_PATH);
            //noinspection ResultOfMethodCallIgnored
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
    public void testInvalidFileMkdirFail() {

        try {
            @SuppressWarnings("unused")
            ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore("/usr\ninvaliddir", null, null);
            fail();
        } catch (RuntimeException ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetNonExistent() {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        Struct st = fstore.get("NotExistent", Struct.class);
        assertNull(st);
    }

    @Test
    public void testGetExistent() {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));
        
        Struct st = fstore.get("test1", Struct.class);
        assertNotNull(st);
        assertEquals(st.get("key"), "val1");
    }
    
    @Test
    public void testDeleteExistent() {
        
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));
        
        fstore.delete("test1");
        Struct st = fstore.get("test1", Struct.class);
        assertNull(st);
    }
    
    @Test
    public void testDeleteNonExistent() {
        
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        
        fstore.delete("test1");
        assertTrue(true);
    }
    
    @Test
    public void testGetLocalDomainListEmpty() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        List<String> ls = fstore.getLocalDomainList();
        assertEquals(ls.size(), 0);
    }

    @Test
    public void testGetLocalDomainListError() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);

        File dir = Mockito.spy(fstore.rootDir);
        Mockito.when(dir.list()).thenReturn(null);
        fstore.rootDir = dir;

        List<String> ls = fstore.getLocalDomainList();
        assertEquals(ls.size(), 0);
    }

    @Test
    public void testGetLocalDomainListSingle() throws IOException {

        File rootDir = new File(FSTORE_PATH);
        //noinspection ResultOfMethodCallIgnored
        rootDir.mkdirs();
        Struct lastModStruct = new Struct();
        lastModStruct.put("lastModTime", 1001);
        File file = new File(FSTORE_PATH, ".lastModTime");
        Path path = Paths.get(file.toURI());
        Files.write(path, JSON.bytes(lastModStruct));

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));
        
        List<String> ls = fstore.getLocalDomainList();
        assertEquals(ls.size(), 1);
        assertTrue(ls.contains("test1"));
    }

    @Test
    public void testGetLocalDomainListMultiple() {
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
        
        List<String> ls = fstore.getLocalDomainList();
        assertEquals(ls.size(), 3);
        assertTrue(ls.contains("test1"));
        assertTrue(ls.contains("test2"));
        assertTrue(ls.contains("test3"));
    }
    
    @Test
    public void testGetLocalDomainListHidden() {
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
        
        List<String> ls = fstore.getLocalDomainList();
        assertEquals(ls.size(), 1);
        assertTrue(ls.contains("test1"));
    }
    
    @Test
    public void testGetLocalDomainListDelete() {
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
        
        List<String> ls = fstore.getLocalDomainList();
        assertEquals(ls.size(), 2);
        assertTrue(ls.contains("test1"));
        assertTrue(ls.contains("test3"));
    }
    
    @Test
    public void testFullRefreshSupport() {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        assertTrue(fstore.supportsFullRefresh());
    }
    
    @Test
    public void testGetSignedDomainList() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        
        List<SignedDomain> domains = new ArrayList<>();
        DomainData domData = new DomainData().setName("athenz");
        SignedDomain domain = new SignedDomain().setDomain(domData);
        domains.add(domain);
        SignedDomains domainList = new SignedDomains().setDomains(domains);
        
        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, null)).thenReturn(domainList);

        List<SignedDomain> returnList = fstore.getSignedDomainList(zmsClient, domainList);
        assertEquals(returnList.size(), 1);
        assertEquals(returnList.get(0).getDomain().getName(), "athenz");
    }

    @Test
    public void testGetSignedDomainListNonRateFailure() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);

        List<SignedDomain> domains = new ArrayList<>();
        DomainData domData = new DomainData().setName("athenz");
        SignedDomain domain = new SignedDomain().setDomain(domData);
        domains.add(domain);
        SignedDomains domainList = new SignedDomains().setDomains(domains);

        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, null))
                .thenThrow(new ZMSClientException(401, "invalid credentials"));

        List<SignedDomain> returnList = fstore.getSignedDomainList(zmsClient, domainList);
        assertEquals(returnList.size(), 0);
    }

    @Test
    public void testGetSignedDomainListRateFailure() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);

        List<SignedDomain> domains = new ArrayList<>();
        DomainData domData = new DomainData().setName("athenz");
        SignedDomain domain = new SignedDomain().setDomain(domData);
        domains.add(domain);
        SignedDomains domainList = new SignedDomains().setDomains(domains);

        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, null))
                .thenThrow(new ZMSClientException(429, "too many requests"))
                .thenReturn(domainList);

        List<SignedDomain> returnList = fstore.getSignedDomainList(zmsClient, domainList);
        assertEquals(returnList.size(), 1);
        assertEquals(returnList.get(0).getDomain().getName(), "athenz");
    }

    @Test
    public void testGetSignedDomainListOneBadDomain() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        
        DomainData domData1 = new DomainData().setName("athenz");
        SignedDomain domain1 = new SignedDomain().setDomain(domData1);
        
        DomainData domData2 = new DomainData().setName("sports");
        SignedDomain domain2 = new SignedDomain().setDomain(domData2);

        List<SignedDomain> domains = new ArrayList<>();
        domains.add(domain1);
        domains.add(domain2);
        
        SignedDomains domainList = new SignedDomains().setDomains(domains);
        
        List<SignedDomain> mockDomains = new ArrayList<>();
        mockDomains.add(domain1);
        SignedDomains mockDomainList = new SignedDomains().setDomains(mockDomains);
        
        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, null)).thenReturn(mockDomainList);
        Mockito.when(zmsClient.getSignedDomains("sports", null, null, null)).thenReturn(null);

        List<SignedDomain> returnList = fstore.getSignedDomainList(zmsClient, domainList);
        assertEquals(returnList.size(), 1);
        assertEquals(returnList.get(0).getDomain().getName(), "athenz");
    }

    @Test
    public void testGetZMSClient() {

        File privKeyFile = new File("src/test/resources/zts_private.pem");
        final String privKey = Crypto.encodedFile(privKeyFile);
        PrivateKey privateKey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, privateKey, "0");
        ZMSClient zmsClient = fstore.getZMSClient();
        assertNotNull(zmsClient);
    }

    @Test
    public void testGetUpdatedSignedDomainsNull() {
        MockZMSFileChangeLogStore store = new MockZMSFileChangeLogStore(FSTORE_PATH, null, "0");
        store.setSignedDomainsExc();
        StringBuilder str = new StringBuilder();
        assertNull(store.getUpdatedSignedDomains(str));
    }

    @Test
    public void testGetUpdatedSignedDomainsNullDomains() {
        MockZMSFileChangeLogStore store = new MockZMSFileChangeLogStore(FSTORE_PATH, null, "0");
        SignedDomains domains = new SignedDomains();
        store.setSignedDomains(domains);
        StringBuilder str = new StringBuilder();
        assertNull(store.getUpdatedSignedDomains(str));
    }

    @Test
    public void testJsonValueAsBytes() {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ObjectMapper mapper = Mockito.mock(ObjectMapper.class);
        Mockito.when(mapper.writerWithView(Struct.class)).thenThrow(new RuntimeException("invalid class"));
        fstore.jsonMapper = mapper;
        Struct testStruct = new Struct();
        testStruct.putIfAbsent("key", "value");
        assertNull(fstore.jsonValueAsBytes(testStruct, Struct.class));
    }

    @Test
    public void testGetJsonException() throws IOException {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));

        ObjectMapper mapper = Mockito.mock(ObjectMapper.class);
        File file = new File(FSTORE_PATH, "test1");
        Mockito.when(mapper.readValue(file, Struct.class)).thenThrow(new RuntimeException("invalid class"));
        fstore.jsonMapper = mapper;

        assertNull(fstore.get("test1", Struct.class));
    }

    @Test
    public void testPutException() throws IOException {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        FilesHelper helper = Mockito.mock(FilesHelper.class);
        Mockito.when(helper.write(Mockito.any(), Mockito.any()))
                .thenThrow(new IOException("io exception"));
        fstore.filesHelper = helper;

        Struct data = new Struct();
        data.put("key", "val1");
        try {
            fstore.put("test1", JSON.bytes(data));
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testDeleteException() throws IOException {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);

        // create the file

        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));

        // update the helper to be our mock

        FilesHelper helper = Mockito.mock(FilesHelper.class);
        Mockito.doThrow(new IOException("io exception")).when(helper).delete(Mockito.any());
        fstore.filesHelper = helper;

        try {
            fstore.delete("test1");
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testSetupDomainFileException() throws IOException {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        FilesHelper helper = Mockito.mock(FilesHelper.class);
        Mockito.doThrow(new IOException("io exception")).when(helper).createEmptyFile(Mockito.any());
        fstore.filesHelper = helper;

        try {
            File file = new File(FSTORE_PATH, "domain");
            fstore.setupDomainFile(file);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }

    @Test
    public void testSetFilePermissionsException() throws IOException {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        FilesHelper helper = Mockito.mock(FilesHelper.class);
        Mockito.when(helper.setPosixFilePermissions(Mockito.any(), Mockito.any()))
                .thenThrow(new IOException("io exception"));
        fstore.filesHelper = helper;

        try {
            File file = new File(FSTORE_PATH, "domain");
            Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
            fstore.setupFilePermissions(file, perms);
            fail();
        } catch (Exception ex) {
            assertTrue(true);
        }
    }
}
