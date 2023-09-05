/*
 *  Copyright The Athenz Authors
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
import com.yahoo.athenz.common.server.util.FilesHelper;
import com.yahoo.athenz.zms.*;
import com.yahoo.rdl.JSON;
import com.yahoo.rdl.Struct;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
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

import static com.yahoo.athenz.common.ServerCommonConsts.*;
import static org.mockito.ArgumentMatchers.any;
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

        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, true, false, null, null)).thenReturn(domainList);
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

        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, true, false,  null, null))
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

        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, true, false,  null, null))
                .thenThrow(new ZMSClientException(429, "too many requests"))
                .thenReturn(domainList);

        List<SignedDomain> returnList = fstore.getSignedDomainList(zmsClient, domainList);
        assertEquals(returnList.size(), 1);
        assertEquals(returnList.get(0).getDomain().getName(), "athenz");
    }

    @Test
    public void testGetSignedDomainListRateFailureComplete() {
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);

        List<SignedDomain> domains = new ArrayList<>();
        DomainData domData = new DomainData().setName("athenz");
        SignedDomain domain = new SignedDomain().setDomain(domData);
        domains.add(domain);
        SignedDomains domainList = new SignedDomains().setDomains(domains);

        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, true, false,  null, null))
                .thenThrow(new ZMSClientException(429, "too many requests"));

        fstore.maxRateLimitRetryCount = 2;
        List<SignedDomain> returnList = fstore.getSignedDomainList(zmsClient, domainList);
        assertEquals(returnList.size(), 0);
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
        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, true, false, null, null)).thenReturn(mockDomainList);
        Mockito.when(zmsClient.getSignedDomains("sports", null, null, true, false, null, null)).thenReturn(null);

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
        Mockito.when(helper.write(any(), any()))
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
        Mockito.doThrow(new IOException("io exception")).when(helper).delete(any());
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
        Mockito.doThrow(new IOException("io exception")).when(helper).createEmptyFile(any());
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
        Mockito.when(helper.setPosixFilePermissions(any(), any()))
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

        // create a new common store with the same path,
        // and it should delete the domain since there
        // is no last modified time

        ZMSFileChangeLogStoreCommon fstore2 = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        assertNull(fstore2.getLocalSignedDomain("athenz"));
        assertNull(fstore.getLocalSignedDomain("athenz"));
    }

    @Test
    public void testJWSDeleteDomainOnInit() {

        final String domainName = "athenz";
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        JWSDomain jwsDomain = new JWSDomain();
        fstore.saveLocalDomain(domainName, jwsDomain);

        // create a new common store with the same path,
        // and it should delete the domain since there
        // is no last modified time

        ZMSFileChangeLogStoreCommon fstore2 = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        assertNull(fstore2.getLocalJWSDomain("athenz"));
        assertNull(fstore.getLocalJWSDomain("athenz"));
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
    public void testGetLocalDomainAttributeListError() {
        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        File dir = Mockito.spy(cstore.rootDir);
        Mockito.when(dir.list()).thenReturn(null);
        cstore.rootDir = dir;

        Map<String, DomainAttributes> domainMap = cstore.getLocalDomainAttributeList();
        assertTrue(domainMap.isEmpty());
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

    @Test
    public void testSignedDomainsWithConditions() {
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);

        DomainData d1 = new DomainData().setName("no-conditions");
        SignedDomain sd1 = new SignedDomain().setDomain(d1);
        SignedDomains sds1 = new SignedDomains().setDomains(Collections.singletonList(sd1));

        DomainData d2 = new DomainData().setName("conditions");
        SignedDomain sd2 = new SignedDomain().setDomain(d2);
        SignedDomains sds2 = new SignedDomains().setDomains(new ArrayList<>());
        sds2.getDomains().add(sd1);
        sds2.getDomains().add(sd2);

        Mockito.when(zmsClient.getSignedDomains(null, "true", null, true, false, null, null))
                .thenReturn(sds1);
        Mockito.when(zmsClient.getSignedDomains(null, "true", null, true, true, null, null))
                .thenReturn(sds2);

        SignedDomains sds1Resp = fstore.getServerDomainModifiedList(zmsClient);
        MatcherAssert.assertThat(sds1Resp.getDomains(), Matchers.contains(sd1));
        ZMSFileChangeLogStoreCommon fstore2 = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        fstore2.setRequestConditions(true);
        SignedDomains sds2Resp = fstore2.getServerDomainModifiedList(zmsClient);
        MatcherAssert.assertThat(sds2Resp.getDomains(), Matchers.contains(sd1, sd2));
    }

    @Test
    public void testRandomSleepForRetry() {

        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        assertEquals(1000, fstore.randomSleepForRetry(1));
        assertEquals(2000, fstore.randomSleepForRetry(2));
        assertEquals(3000, fstore.randomSleepForRetry(3));
        long timeout = fstore.randomSleepForRetry(4);
        assertTrue(timeout >= 4000 && timeout <= 10000);
        timeout = fstore.randomSleepForRetry(5);
        assertTrue(timeout >= 4000 && timeout <= 10000);
        timeout = fstore.randomSleepForRetry(50);
        assertTrue(timeout >= 4000 && timeout <= 10000);
        timeout = fstore.randomSleepForRetry(100);
        assertTrue(timeout >= 4000 && timeout <= 10000);
        timeout = fstore.randomSleepForRetry(1000);
        assertTrue(timeout >= 4000 && timeout <= 10000);
    }

    @Test
    public void testGetJWSDomainList() {
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);

        List<SignedDomain> domains = new ArrayList<>();
        DomainData domData = new DomainData().setName("athenz");
        SignedDomain domain = new SignedDomain().setDomain(domData);
        domains.add(domain);
        SignedDomains domainList = new SignedDomains().setDomains(domains);

        JWSDomain jwsDomain = new JWSDomain();
        Mockito.when(zmsClient.getJWSDomain("athenz", null, null)).thenReturn(jwsDomain);

        List<JWSDomain> returnList = fstore.getJWSDomainList(zmsClient, domainList);
        assertEquals(returnList.size(), 1);
    }

    @Test
    public void testGetJWSDomainListNonRateFailure() {
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);

        List<SignedDomain> domains = new ArrayList<>();
        DomainData domData = new DomainData().setName("athenz");
        SignedDomain domain = new SignedDomain().setDomain(domData);
        domains.add(domain);
        SignedDomains domainList = new SignedDomains().setDomains(domains);

        Mockito.when(zmsClient.getJWSDomain("athenz", null, null))
                .thenThrow(new ZMSClientException(401, "invalid credentials"));

        List<JWSDomain> returnList = fstore.getJWSDomainList(zmsClient, domainList);
        assertEquals(returnList.size(), 0);
    }

    @Test
    public void testGetJWSDomainListRateFailure() {
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);

        List<SignedDomain> domains = new ArrayList<>();
        DomainData domData = new DomainData().setName("athenz");
        SignedDomain domain = new SignedDomain().setDomain(domData);
        domains.add(domain);
        SignedDomains domainList = new SignedDomains().setDomains(domains);

        JWSDomain jwsDomain = new JWSDomain();
        Mockito.when(zmsClient.getJWSDomain("athenz", null, null))
                .thenThrow(new ZMSClientException(429, "too many requests"))
                .thenReturn(jwsDomain);

        List<JWSDomain> returnList = fstore.getJWSDomainList(zmsClient, domainList);
        assertEquals(returnList.size(), 1);
    }

    @Test
    public void testGetJWSDomainListRateFailureComplete() {
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);

        List<SignedDomain> domains = new ArrayList<>();
        DomainData domData = new DomainData().setName("athenz");
        SignedDomain domain = new SignedDomain().setDomain(domData);
        domains.add(domain);
        SignedDomains domainList = new SignedDomains().setDomains(domains);

        Mockito.when(zmsClient.getJWSDomain("athenz", null, null))
                .thenThrow(new ZMSClientException(429, "too many requests"));

        fstore.maxRateLimitRetryCount = 2;
        List<JWSDomain> returnList = fstore.getJWSDomainList(zmsClient, domainList);
        assertEquals(returnList.size(), 0);
    }

    @Test
    public void testGetJWSDomainListOneBadDomain() {
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

        JWSDomain jwsDomain = new JWSDomain();
        Mockito.when(zmsClient.getJWSDomain("athenz", null, null)).thenReturn(jwsDomain);
        Mockito.when(zmsClient.getJWSDomain("sports", null, null)).thenReturn(null);

        List<JWSDomain> returnList = fstore.getJWSDomainList(zmsClient, domainList);
        assertEquals(returnList.size(), 1);
    }

    @Test
    public void testGetServerJWSDomain() {
        ZMSFileChangeLogStoreCommon fstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);

        JWSDomain jwsDomain = new JWSDomain();
        Mockito.when(zmsClient.getJWSDomain("athenz", null, null))
                .thenReturn(jwsDomain)
                .thenReturn(null);

        JWSDomain jwsDomain1 = fstore.getServerJWSDomain(zmsClient, "athenz");
        assertNotNull(jwsDomain1);
        jwsDomain1 = fstore.getServerJWSDomain(zmsClient, "athenz");
        assertNull(jwsDomain1);
    }
}
