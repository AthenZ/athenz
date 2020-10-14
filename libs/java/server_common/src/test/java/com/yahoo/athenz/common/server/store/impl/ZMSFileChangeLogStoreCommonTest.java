/*
 *  Copyright 2020 Verizon Media
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.yahoo.athenz.common.server.store.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.CommonTestUtils;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.util.FilesHelper;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;

import static com.yahoo.athenz.common.ServerCommonConsts.PROP_ATHENZ_CONF;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_FILE_NAME;
import static org.testng.Assert.*;

public class ZMSFileChangeLogStoreCommonTest {

    private final String FSTORE_PATH = "/tmp/zts_file_store_unit_test";
    
    @BeforeMethod
    public void setup() {
        CommonTestUtils.deleteDirectory(new File(FSTORE_PATH));
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
    }
    
    @AfterMethod
    public void shutdown() {
        CommonTestUtils.deleteDirectory(new File(FSTORE_PATH));
    }

    @Test
    public void testGetNonExistent() {

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        Struct st = fstore.get("NotExistent", Struct.class);
        assertNull(st);
    }

    @Test
    public void testGetExistent() {

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));

        Struct st = fstore.get("test1", Struct.class);
        assertNotNull(st);
        assertEquals(st.get("key"), "val1");
    }

    @Test
    public void testDeleteExistent() {

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        Struct data = new Struct();
        data.put("key", "val1");
        fstore.put("test1", JSON.bytes(data));

        fstore.delete("test1");
        Struct st = fstore.get("test1", Struct.class);
        assertNull(st);
    }

    @Test
    public void testDeleteNonExistent() {

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        fstore.delete("test1");
        assertTrue(true);
    }

    @Test
    public void testGetSignedDomainList() {
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
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
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
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
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
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
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
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
    public void testJsonValueAsBytes() {

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        ObjectMapper mapper = Mockito.mock(ObjectMapper.class);
        Mockito.when(mapper.writerWithView(Struct.class)).thenThrow(new RuntimeException("invalid class"));
        fstore.jsonMapper = mapper;
        Struct testStruct = new Struct();
        testStruct.putIfAbsent("key", "value");
        assertNull(fstore.jsonValueAsBytes(testStruct, Struct.class));
    }

    @Test
    public void testGetJsonException() throws IOException {

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
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

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
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

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

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

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
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

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
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

    @Test
    public void testRetrieveTagHeader() {

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        Map<String, List<String>> responseHeaders = new HashMap<>();

        assertNull(fstore.retrieveTagHeader(responseHeaders));

        // add a header but not the tag one

        responseHeaders.put("Content-Type", Collections.singletonList("application/json"));
        responseHeaders.put("Content-Length", Collections.singletonList("10000"));

        assertNull(fstore.retrieveTagHeader(responseHeaders));

        // now add the tag header

        responseHeaders.put("tag", Arrays.asList("tag1", "tag2"));
        assertEquals(fstore.retrieveTagHeader(responseHeaders), "tag1");
    }

    @Test
    public void testDeleteDomainOnInit() {

        final String domainName = "athenz";
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        DomainData domData = new DomainData().setName(domainName);
        SignedDomain domain = new SignedDomain().setDomain(domData);
        fstore.saveLocalDomain(domainName, domain);

        // create a new common store with the same path
        // and it should delete the domain since there
        // is no last modified time

        ZMSFileChangeLogStoreCommon fstore2 = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        assertNull(fstore2.getLocalSignedDomain("athenz"));
        assertNull(fstore.getLocalSignedDomain("athenz"));
    }

    @Test
    public void testGetLocalDomainListError() {
        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        File dir = Mockito.spy(cstore.rootDir);
        Mockito.when(dir.list()).thenReturn(null);
        cstore.rootDir = dir;

        List<String> ls = cstore.getLocalDomainList();
        assertTrue(ls.isEmpty());
    }

    @Test
    public void testRetrieveLastModificationTime() {

        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        try (PrintWriter out = new PrintWriter(FSTORE_PATH + "/.lastModTime")) {
            out.write("{\"lastModTime\":\"12345\"}");
        } catch (FileNotFoundException e) {
            fail();
        }

        assertEquals(cstore.retrieveLastModificationTime(), "12345");
    }
}
