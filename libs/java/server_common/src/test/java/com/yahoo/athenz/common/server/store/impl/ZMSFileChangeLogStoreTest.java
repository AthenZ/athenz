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

import static com.yahoo.athenz.common.ServerCommonConsts.PROP_ATHENZ_CONF;
import static com.yahoo.athenz.common.ServerCommonConsts.ZTS_PROP_FILE_NAME;
import static org.testng.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.security.PrivateKey;
import java.util.Map;
import java.util.Set;

import com.yahoo.athenz.CommonTestUtils;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zms.*;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

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
        CommonTestUtils.deleteDirectory(new File(FSTORE_PATH));
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        System.setProperty(ZTS_PROP_FILE_NAME, "src/test/resources/zts.properties");
    }
    
    @AfterMethod
    public void shutdown() {
        CommonTestUtils.deleteDirectory(new File(FSTORE_PATH));
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
            
            new ZMSFileChangeLogStore(fpath, null, null);
            fail();
        } catch (RuntimeException | IOException ignored) {
        }
    }

    @Test
    public void testInvalidFileMkdirFail() {

        try {
            new ZMSFileChangeLogStore("/proc/usr\ninvaliddir", null, null);
            fail();
        } catch (RuntimeException ignored) {
        }
    }
    
    @Test
    public void testGetLocalDomainListEmpty() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        List<String> ls = fstore.getLocalDomainList();
        assertTrue(ls.isEmpty());
    }

    @Test
    public void testGetLocalDomainListError() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        File dir = Mockito.spy(cstore.rootDir);
        Mockito.when(dir.list()).thenReturn(null);
        cstore.rootDir = dir;

        List<String> ls = fstore.getLocalDomainList();
        assertTrue(ls.isEmpty());
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
        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        Struct data = new Struct();
        data.put("key", "val1");
        cstore.put("test1", JSON.bytes(data));
        
        List<String> ls = fstore.getLocalDomainList();
        assertEquals(ls.size(), 1);
        assertTrue(ls.contains("test1"));
    }

    @Test
    public void testGetLocalDomainListMultiple() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        Struct data = new Struct();
        data.put("key", "val1");
        cstore.put("test1", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        cstore.put("test2", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        cstore.put("test3", JSON.bytes(data));
        
        List<String> ls = fstore.getLocalDomainList();
        assertEquals(ls.size(), 3);
        assertTrue(ls.contains("test1"));
        assertTrue(ls.contains("test2"));
        assertTrue(ls.contains("test3"));
    }
    
    @Test
    public void testGetLocalDomainListHidden() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        Struct data = new Struct();
        data.put("key", "val1");
        cstore.put("test1", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        cstore.put(".test2", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        cstore.put(".test3", JSON.bytes(data));
        
        List<String> ls = fstore.getLocalDomainList();
        assertEquals(ls.size(), 1);
        assertTrue(ls.contains("test1"));
    }
    
    @Test
    public void testGetLocalDomainListDelete() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        Struct data = new Struct();
        data.put("key", "val1");
        cstore.put("test1", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        cstore.put("test2", JSON.bytes(data));
        
        data = new Struct();
        data.put("key", "val1");
        cstore.put("test3", JSON.bytes(data));

        cstore.delete("test2");
        
        List<String> ls = fstore.getLocalDomainList();
        assertEquals(ls.size(), 2);
        assertTrue(ls.contains("test1"));
        assertTrue(ls.contains("test3"));
    }
    
    @Test
    public void testFullRefreshSupport() {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        assertFalse(fstore.supportsFullRefresh());
    }

    @Test
    public void testGetZMSClient() {

        File privKeyFile = new File("src/test/resources/unit_test_zts_private.pem");
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
    public void testGetServerDomainModifiedList() {
        MockZMSFileChangeLogStore fstore = new MockZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        fstore.setZMSClient(zmsClient);

        List<SignedDomain> domains = new ArrayList<>();
        DomainData domData = new DomainData().setName("athenz");
        SignedDomain domain = new SignedDomain().setDomain(domData);
        domains.add(domain);
        SignedDomains domainList = new SignedDomains().setDomains(domains);

        Mockito.when(zmsClient.getSignedDomains(null, "true", null, true, false,  null, null)).thenReturn(domainList);

        SignedDomains returnList = fstore.getServerDomainModifiedList();
        assertEquals(returnList.getDomains().size(), 1);
        assertEquals(returnList.getDomains().get(0).getDomain().getName(), "athenz");
    }

    @Test
    public void testGetServerDomainModifiedListNull() {
        MockZMSFileChangeLogStore fstore = new MockZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        fstore.setZMSClient(zmsClient);

        Mockito.when(zmsClient.getSignedDomains(null, "true", null, true, false,  null, null)).thenReturn(null);

        assertNull(fstore.getServerDomainModifiedList());
    }

    @Test
    public void testGetServerDomainModifiedListException() {
        MockZMSFileChangeLogStore fstore = new MockZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        fstore.setZMSClient(zmsClient);

        Mockito.when(zmsClient.getSignedDomains(null, "true", null, true, false,  null, null))
                .thenThrow(new ZMSClientException(500, "invalid server error:"));

        SignedDomains returnList = fstore.getServerDomainModifiedList();
        assertNull(returnList);
    }

    @Test
    public void testGetServerSignedDomain() {
        MockZMSFileChangeLogStore fstore = new MockZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        fstore.setZMSClient(zmsClient);

        List<SignedDomain> domains = new ArrayList<>();
        DomainData domData = new DomainData().setName("athenz");
        SignedDomain domain = new SignedDomain().setDomain(domData);
        domains.add(domain);
        SignedDomains domainList = new SignedDomains().setDomains(domains);

        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, true, false,  null, null)).thenReturn(domainList);

        SignedDomain signedDomain = fstore.getServerSignedDomain("athenz");
        assertNotNull(signedDomain);
        assertEquals(signedDomain.getDomain().getName(), "athenz");

        // invalid domain should return null

        assertNull(fstore.getServerSignedDomain("coretech"));
    }

    @Test
    public void testGetServerSignedDomainInvalidMultiple() {
        MockZMSFileChangeLogStore fstore = new MockZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        fstore.setZMSClient(zmsClient);

        List<SignedDomain> domains = new ArrayList<>();
        DomainData domData1 = new DomainData().setName("athenz");
        SignedDomain domain1 = new SignedDomain().setDomain(domData1);

        DomainData domData2 = new DomainData().setName("coretech");
        SignedDomain domain2 = new SignedDomain().setDomain(domData2);

        domains.add(domain1);
        domains.add(domain2);

        SignedDomains domainList = new SignedDomains().setDomains(domains);

        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, true, false,  null, null)).thenReturn(domainList);

        assertNull(fstore.getServerSignedDomain("athenz"));
    }

    @Test
    public void testGetServerSignedDomainException() {
        MockZMSFileChangeLogStore fstore = new MockZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        fstore.setZMSClient(zmsClient);

        Mockito.when(zmsClient.getSignedDomains("athenz", null, null, true, false,  null, null))
            .thenThrow(new ZMSClientException(500, "invalid server error:"));

        assertNull(fstore.getServerSignedDomain("athenz"));
    }

    @Test
    public void testDomainOperations() {
        final String domainName = "coretech";
        DomainData domainData = new DomainData().setName(domainName).setDescription("test domain");
        SignedDomain signedDomain = new SignedDomain().setDomain(domainData);

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);

        SignedDomain signedDomain1 = fstore.getLocalSignedDomain(domainName);
        assertNull(signedDomain1);

        fstore.saveLocalDomain(domainName, signedDomain);

        signedDomain1 = fstore.getLocalSignedDomain(domainName);
        assertNotNull(signedDomain1);

        fstore.removeLocalDomain(domainName);
        signedDomain1 = fstore.getLocalSignedDomain(domainName);
        assertNull(signedDomain1);
    }

    @Test
    public void testLastModificationTimestamp() {

        MockZMSFileChangeLogStore fstore = new MockZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        assertNull(cstore.retrieveLastModificationTime());

        final String now = Long.toString(System.currentTimeMillis());
        fstore.setLastModificationTimestamp(now);

        assertEquals(cstore.retrieveLastModificationTime(), now);

        fstore.setLastModificationTimestamp(null);
        assertNull(cstore.retrieveLastModificationTime());
    }

    @Test
    public void testGetServerDomainList() {
        MockZMSFileChangeLogStore fstore = new MockZMSFileChangeLogStore(FSTORE_PATH, null, null);
        MockZMSFileChangeLogStoreCommon storeCommon = new MockZMSFileChangeLogStoreCommon(FSTORE_PATH);
        fstore.setChangeLogStoreCommon(storeCommon);

        Set<String> domainList = fstore.getServerDomainList();
        assertTrue(domainList.contains("user"));

        fstore.setDomainList(null);
        assertNull(fstore.getServerDomainList());
    }

    @Test
    public void testRequestConditionsSet() {
        MockZMSFileChangeLogStore fstore = new MockZMSFileChangeLogStore(FSTORE_PATH, null, null);
        MockZMSFileChangeLogStoreCommon storeCommon = new MockZMSFileChangeLogStoreCommon(FSTORE_PATH);
        fstore.setChangeLogStoreCommon(storeCommon);
        fstore.setRequestConditions(true);
        assertTrue(storeCommon.requestConditions);
    }

    @Test
    public void testGetUpdatedJWSDomainsNull() {
        MockZMSFileChangeLogStore store = new MockZMSFileChangeLogStore(FSTORE_PATH, null, "0");
        store.setSignedDomainsExc();
        StringBuilder str = new StringBuilder();
        assertNull(store.getUpdatedJWSDomains(str));
    }

    @Test
    public void testGetUpdatedJWSDomainsNullDomains() {
        MockZMSFileChangeLogStore store = new MockZMSFileChangeLogStore(FSTORE_PATH, null, "0");
        SignedDomains domains = new SignedDomains();
        store.setSignedDomains(domains);
        StringBuilder str = new StringBuilder();
        assertNull(store.getUpdatedJWSDomains(str));
    }

    @Test
    public void testGetServerJWSDomain() {
        MockZMSFileChangeLogStore fstore = new MockZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        fstore.setZMSClient(zmsClient);

        JWSDomain jwsDomain = new JWSDomain();
        Mockito.when(zmsClient.getJWSDomain("athenz", null, null)).thenReturn(jwsDomain);

        JWSDomain jwsDomain1 = fstore.getServerJWSDomain("athenz");
        assertNotNull(jwsDomain1);

        // invalid domain should return null

        assertNull(fstore.getServerJWSDomain("coretech"));
    }

    @Test
    public void testGetServerJWSDomainException() {
        MockZMSFileChangeLogStore fstore = new MockZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSClient zmsClient = Mockito.mock(ZMSClient.class);
        fstore.setZMSClient(zmsClient);

        Mockito.when(zmsClient.getJWSDomain("athenz", null, null))
                .thenThrow(new ZMSClientException(500, "invalid server error:"));

        assertNull(fstore.getServerJWSDomain("athenz"));
    }

    @Test
    public void testJWSDomainOperations() {
        final String domainName = "coretech";
        JWSDomain jwsDomain = new JWSDomain();

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);

        JWSDomain jwsDomain1 = fstore.getLocalJWSDomain(domainName);
        assertNull(jwsDomain1);

        fstore.saveLocalDomain(domainName, jwsDomain);

        jwsDomain1 = fstore.getLocalJWSDomain(domainName);
        assertNotNull(jwsDomain1);

        fstore.removeLocalDomain(domainName);
        jwsDomain1 = fstore.getLocalJWSDomain(domainName);
        assertNull(jwsDomain1);
    }

    @Test
    public void testGetLocalDomainListAttributeListMultiple() {

        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        Struct data = new Struct();
        data.put("key", "val1");
        cstore.put("test1", JSON.bytes(data));

        data = new Struct();
        data.put("key", "val1");
        cstore.put("test2", JSON.bytes(data));

        data = new Struct();
        data.put("key", "val1");
        cstore.put("test3", JSON.bytes(data));

        Map<String, DomainAttributes> domainMap = fstore.getLocalDomainAttributeList();
        assertEquals(domainMap.size(), 3);

        DomainAttributes attrs = domainMap.get("test1");
        assertNotNull(attrs);
        assertTrue(attrs.getFetchTime() > 0);

        attrs = domainMap.get("test2");
        assertNotNull(attrs);
        assertTrue(attrs.getFetchTime() > 0);

        attrs = domainMap.get("test3");
        assertNotNull(attrs);
        assertTrue(attrs.getFetchTime() > 0);
    }

    @Test
    public void testGetLocalDomainAttributeListHidden() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        Struct data = new Struct();
        data.put("key", "val1");
        cstore.put("test1", JSON.bytes(data));

        data = new Struct();
        data.put("key", "val1");
        cstore.put(".test2", JSON.bytes(data));

        data = new Struct();
        data.put("key", "val1");
        cstore.put(".test3", JSON.bytes(data));

        Map<String, DomainAttributes> domainMap = fstore.getLocalDomainAttributeList();
        assertEquals(domainMap.size(), 1);

        DomainAttributes attrs = domainMap.get("test1");
        assertNotNull(attrs);
        assertTrue(attrs.getFetchTime() > 0);
    }

    @Test
    public void testGetLocalDomainAttributeListEmpty() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        Map<String, DomainAttributes> domainMap = fstore.getLocalDomainAttributeList();
        assertTrue(domainMap.isEmpty());
    }

    @Test
    public void testGetLocalDomainAttributeListError() {
        ZMSFileChangeLogStore fstore = new ZMSFileChangeLogStore(FSTORE_PATH, null, null);
        ZMSFileChangeLogStoreCommon cstore = new ZMSFileChangeLogStoreCommon(FSTORE_PATH);

        File dir = Mockito.spy(cstore.rootDir);
        Mockito.when(dir.list()).thenReturn(null);
        cstore.rootDir = dir;

        Map<String, DomainAttributes> domainMap = fstore.getLocalDomainAttributeList();
        assertTrue(domainMap.isEmpty());
    }
}
