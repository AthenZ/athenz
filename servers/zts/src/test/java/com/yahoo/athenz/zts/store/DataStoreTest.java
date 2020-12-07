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
package com.yahoo.athenz.zts.store;

import static com.yahoo.athenz.common.ServerCommonConsts.PROP_ATHENZ_CONF;
import static com.yahoo.athenz.common.ServerCommonConsts.PROP_USER_DOMAIN;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.util.StringUtils;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSTestUtils;
import com.yahoo.rdl.Timestamp;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.yahoo.athenz.auth.impl.FilePrivateKeyStore;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.utils.SignUtils;
import com.yahoo.athenz.zts.HostServices;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.cache.MemberRole;
import com.yahoo.athenz.zts.store.DataStore.DataUpdater;
import com.yahoo.rdl.JSON;

public class DataStoreTest {

    private PrivateKey pkey;
    private String userDomain;
    
    private static final String ZTS_DATA_STORE_PATH = "/tmp/zts_server_unit_tests/zts_root";
    private static final String ZTS_Y64_CERT0 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RR"
            + "RUJBUVVBQTRHTkFEQ0JpUUtCZ1FDMXRHU1ZDQTh3bDVldzVZNzZXajJySkFVRApZYW5FSmZLbUFseDVjUS84a"
            + "EtFVWZTU2dwWHIzQ3pkaDFhMjZkbGI3bW1LMjlxbVhKWGg2dW1XOUF5ZlRPS1ZvCis2QVNsb1ZVM2F2dnVmbE"
            + "dVT0VnMmpzbWRha1IyNEtjTGpBdTZRclVlNDE3bEczdDhxU1BJR2pTNUMrQ3NKVXcKaDA0aEh4NWYrUEV3eFY"
            + "0cmJRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    private static final String ZTS_PEM_CERT0 = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1tGSVCA8wl5ew5Y76Wj2rJAUD\n"
            + "YanEJfKmAlx5cQ/8hKEUfSSgpXr3Czdh1a26dlb7mmK29qmXJXh6umW9AyfTOKVo\n"
            + "+6ASloVU3avvuflGUOEg2jsmdakR24KcLjAu6QrUe417lG3t8qSPIGjS5C+CsJUw\n"
            + "h04hHx5f+PEwxV4rbQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    private static final String ZTS_Y64_CERT1 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RR"
            + "RUJBUVVBQTRHTkFEQ0JpUUtCZ1FETUhWaFRNZldJQWdvTEdhbkx2QkNNRytRdAoySU9pcml2cGRLSFNPSkpsYX"
            + "VKRUNlWlY1MTVmWG91SjhRb09IczA4UGlsdXdjeHF5dmhJSlduNWFrVEhGSWh5CkdDNkdtUTUzbG9WSEtTVE1WO"
            + "DM1M0FjNkhydzYxbmJZMVQ2TnA2bjdxdXI4a1UwR2tmdk5hWFZrK09LNVBaankKbkxzZ251UjlCeFZndlM4ZjJR"
            + "SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    private static final String ZTS_PEM_CERT1 = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMHVhTMfWIAgoLGanLvBCMG+Qt\n"
            + "2IOirivpdKHSOJJlauJECeZV515fXouJ8QoOHs08PiluwcxqyvhIJWn5akTHFIhy\n"
            + "GC6GmQ53loVHKSTMV8353Ac6Hrw61nbY1T6Np6n7qur8kU0GkfvNaXVk+OK5PZjy\n"
            + "nLsgnuR9BxVgvS8f2QIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    private static final String ZTS_Y64_CERT2 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RR"
            + "RUJBUVVBQTRHTkFEQ0JpUUtCZ1FEbmZsZVZ4d293aitRWStjQi8rbWs5YXZYZgpHUWVpTTdOMlMwby9LV3FWK2h"
            + "GVWtDZkExMWxEYVJoZUY0alFhSzVaM2pPUE9nbklOZE5hd3VXQ081NUxKdVJRCmI1R0ZSbzhPNjNJNzA3M3ZDZ0V"
            + "KdmNST09SdjJDYWhQbnBKbjc3bkhQdlV2Szl0M3JyRURhdi8vanA0UDN5REMKNEVNdHBScmduUXBXNmpJSWlRSUR"
            + "BUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    private static final String ZTS_PEM_CERT2 = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDnfleVxwowj+QY+cB/+mk9avXf\n"
            + "GQeiM7N2S0o/KWqV+hFUkCfA11lDaRheF4jQaK5Z3jOPOgnINdNawuWCO55LJuRQ\n"
            + "b5GFRo8O63I7073vCgEJvcROORv2CahPnpJn77nHPvUvK9t3rrEDav//jp4P3yDC\n"
            + "4EMtpRrgnQpW6jIIiQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    private static final String ZTS_Y64_CERT3 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RR"
            + "RUJBUVVBQTRHTkFEQ0JpUUtCZ1FETWRqSmUwY01wSGR4ZEJKTDcvR2poNTNVUAp5WTdVQ2VlYnZUa2M2S1ZmR0"
            + "RnVVlrMUhtaWJ5U21lbnZOYitkNkhXQ1YySGVicUptN1krL2VuaFNkcTR3QTJrCnFtdmFHY09rV1R2cUU2a2J1"
            + "MG5LemdUK21jck1sOVpqTHdBQXZPS1hTRi82MTJxQ0tlSElRd3ZtWlB1RkJJTjEKUnFteWgwT0k1aHN5VS9nYj"
            + "Z3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo-";
    private static final String ZTS_PEM_CERT3 = "-----BEGIN PUBLIC KEY-----\n"
            + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMdjJe0cMpHdxdBJL7/Gjh53UP\n"
            + "yY7UCeebvTkc6KVfGDgUYk1HmibySmenvNb+d6HWCV2HebqJm7Y+/enhSdq4wA2k\n"
            + "qmvaGcOkWTvqE6kbu0nKzgT+mcrMl9ZjLwAAvOKXSF/612qCKeHIQwvmZPuFBIN1\n"
            + "Rqmyh0OI5hsyU/gb6wIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    private static final String ROLE_POSTFIX = ":role.";

    @BeforeClass
    public void setUpClass() {
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/unit_test_zts_private.pem");
        System.setProperty(PROP_ATHENZ_CONF,  "src/test/resources/athenz.conf");
    }
    
    @BeforeMethod
    public void setup() {

        // we want to make sure we start we clean dir structure

        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
        
        String privKeyName = System.getProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY);
        File privKeyFile = new File(privKeyName);
        String privKey = Crypto.encodedFile(privKeyFile);
        
        pkey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
        userDomain = System.getProperty(PROP_USER_DOMAIN, "user");
    }
    
    @AfterMethod
    public void cleanup() {
        ZTSTestUtils.deleteDirectory(new File(ZTS_DATA_STORE_PATH));
    }
    
    private void setServicePublicKey(ServiceIdentity service, String id, String key) {
        com.yahoo.athenz.zms.PublicKeyEntry keyEntry = new com.yahoo.athenz.zms.PublicKeyEntry();
        keyEntry.setId(id);
        keyEntry.setKey(key);
        List<com.yahoo.athenz.zms.PublicKeyEntry> listKeys = new ArrayList<>();
        listKeys.add(keyEntry);
        service.setPublicKeys(listKeys);
    }
    
    @Test
    public void DataStorContstructorTest() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        assertNotNull(store);
        assertEquals(store.delDomainRefreshTime, 3600);
        assertEquals(store.updDomainRefreshTime, 60);

        System.setProperty("athenz.zts.zms_domain_update_timeout", "60");
        System.setProperty("athenz.zts.zms_domain_delete_timeout", "50");
        System.setProperty("athenz.zts.zms_domain_check_timeout", "45");
        store = new DataStore(clogStore, null);
        assertNotNull(store);
        assertEquals(store.delDomainRefreshTime, 60);
        assertEquals(store.updDomainRefreshTime, 60);
        assertEquals(store.checkDomainRefreshTime, 60);
        System.clearProperty("athenz.zts.zms_domain_update_timeout");
        System.clearProperty("athenz.zts.zms_domain_delete_timeout");
        System.clearProperty("athenz.zts.zms_domain_check_timeout");
    }

    @Test
    public void testLoadZMSPublicKeysInvalidKeys() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz_no_zms_publickeys.conf");
        try {
            new DataStore(clogStore, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Unable to initialize public keys"));
        }

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz_no_zts_publickeys.conf");
        try {
            new DataStore(clogStore, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Unable to initialize public keys"));
        }

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz_zms_invalid_publickeys.conf");
        try {
            new DataStore(clogStore, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Unable to initialize public keys"));
        }

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz_zts_invalid_publickeys.conf");
        try {
            new DataStore(clogStore, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Unable to initialize public keys"));
        }

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz_invalid.conf");
        try {
            new DataStore(clogStore, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Unable to initialize public keys"));
        }

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz_invalid_zts_pem_publickey.conf");
        try {
            new DataStore(clogStore, null);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Unable to initialize public keys"));
        }

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
    }

    @Test
    public void testGetDomainListFromZMS() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        List<String> list = new ArrayList<>();
        list.add("Test1");
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(list);
        
        Set<String> zmsDomainList = store.changeLogStore.getServerDomainList();
        assertEquals(zmsDomainList.size(), 1);
        assertTrue(zmsDomainList.contains("Test1"));
    }
    
    @Test
    public void testGetDomainListFromZMSNullClient() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        List<String> list = new ArrayList<>();
        list.add("Test1");
        list.add("Test2");
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(list);
        
        Set<String> zmsDomainList = store.changeLogStore.getServerDomainList();
        assertEquals(zmsDomainList.size(), 2);
        assertTrue(zmsDomainList.contains("Test1"));
        assertTrue(zmsDomainList.contains("Test2"));
    }
   
    @Test
    public void testGetDomainListFromZMSError() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(null);
        
        Set<String> zmsDomainList = store.changeLogStore.getServerDomainList();
        assertNull(zmsDomainList);
    }
    
    @Test
    public void testLoadZMSPublicKeys() {
        
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();
        PublicKey zmsKey = store.zmsPublicKeyCache.getIfPresent("0");
        assertNotNull(zmsKey);
        assertNull(store.zmsPublicKeyCache.getIfPresent("1"));
    }
    
    @Test
    public void testSaveLastModificationTime() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.changeLogStore.setLastModificationTimestamp("23456");

        String data = null;
        File f = new File("/tmp/zts_server_unit_tests/zts_root/.lastModTime");
        try {
            data = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            fail();
        }
        
        assertEquals(data, "{\"lastModTime\":\"23456\"}");
    }
    
    @Test
    public void testRemovePublicKeys() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_1", "PublicKey1");

        Map<String, String> remKeys = new HashMap<>();
        remKeys.put("sports.storage_0", "PublicKey0");
        
        store.removePublicKeys(remKeys);
        assertEquals(store.publicKeyCache.size(), 2);
        assertTrue(store.publicKeyCache.containsKey("coretech.storage_0"));
        assertTrue(store.publicKeyCache.containsKey("sports.storage_1"));
    }
    
    @Test
    public void testRemovePublicKeysAll() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_1", "PublicKey1");

        Map<String, String> remKeys = new HashMap<>();
        remKeys.put("coretech.storage_0", "PublicKey0");
        remKeys.put("sports.storage_0", "PublicKey0");
        remKeys.put("sports.storage_1", "PublicKey1");
        
        store.removePublicKeys(remKeys);
        assertEquals(store.publicKeyCache.size(), 0);
    }
    
    @Test
    public void testRemovePublicKeysInvalid() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_1", "PublicKey1");

        Map<String, String> remKeys = new HashMap<>();
        remKeys.put("sports.storage_2", "PublicKey2");
        
        store.removePublicKeys(remKeys);
        assertEquals(store.publicKeyCache.size(), 3);
        assertTrue(store.publicKeyCache.containsKey("coretech.storage_0"));
        assertTrue(store.publicKeyCache.containsKey("sports.storage_0"));
        assertTrue(store.publicKeyCache.containsKey("sports.storage_1"));
    }
    
    @Test
    public void testRemovePublicKeysEmpty() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");

        Map<String, String> remKeys = new HashMap<>();
        
        store.removePublicKeys(remKeys);
        assertEquals(store.publicKeyCache.size(), 1);
        assertTrue(store.publicKeyCache.containsKey("coretech.storage_0"));
    }
    
    @Test
    public void testRemovePublicKeysNull() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        
        store.removePublicKeys(null);
        assertEquals(store.publicKeyCache.size(), 1);
        assertTrue(store.publicKeyCache.containsKey("coretech.storage_0"));
    }
    
    @Test
    public void testAddPublicKeys() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_1", "PublicKey1");

        Map<String, String> addKeys = new HashMap<>();
        addKeys.put("sports.storage_1", "PublicKey1");
        addKeys.put("sports.storage_2", "PublicKey2");
        
        store.addPublicKeys(addKeys);
        assertEquals(store.publicKeyCache.size(), 4);
        assertTrue(store.publicKeyCache.containsKey("coretech.storage_0"));
        assertTrue(store.publicKeyCache.containsKey("sports.storage_0"));
        assertTrue(store.publicKeyCache.containsKey("sports.storage_1"));
        assertTrue(store.publicKeyCache.containsKey("sports.storage_2"));
    }
    
    @Test
    public void testAddPublicKeysUpdateValue() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_1", "PublicKey1");

        Map<String, String> addKeys = new HashMap<>();
        addKeys.put("coretech.storage_0", "PublicKey0");
        addKeys.put("sports.storage_0", "PublicKey100");
        addKeys.put("sports.storage_1", "PublicKey101");
        
        store.addPublicKeys(addKeys);
        assertEquals(store.publicKeyCache.size(), 3);
        String value = store.publicKeyCache.get("coretech.storage_0");
        assertEquals(value, "PublicKey0");
        
        value = store.publicKeyCache.get("sports.storage_0");
        assertEquals(value, "PublicKey100");
        
        value = store.publicKeyCache.get("sports.storage_1");
        assertEquals(value, "PublicKey101");
    }
    
    @Test
    public void testAddPublicKeysEmpty() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");

        Map<String, String> addKeys = new HashMap<>();
        
        store.addPublicKeys(addKeys);
        assertEquals(store.publicKeyCache.size(), 1);
        assertTrue(store.publicKeyCache.containsKey("coretech.storage_0"));
    }
    
    @Test
    public void testAddPublicKeysNull() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        
        store.addPublicKeys(null);
        assertEquals(store.publicKeyCache.size(), 1);
        assertTrue(store.publicKeyCache.containsKey("coretech.storage_0"));
    }
    
    @Test
    public void testGetPublicKey() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_1", "PublicKey1");

        Map<String, String> addKeys = new HashMap<>();
        addKeys.put("sports.storage_1", "PublicKey1");
        addKeys.put("sports.storage_2", "PublicKey2");
        
        store.addPublicKeys(addKeys);
        assertEquals(store.getPublicKey("coretech", "storage", "0"), "PublicKey0");
        assertEquals(store.getPublicKey("sports", "storage", "0"), "PublicKey0");
        assertEquals(store.getPublicKey("sports", "storage", "1"), "PublicKey1");
        assertEquals(store.getPublicKey("sports", "storage", "2"), "PublicKey2");
    }
    
    @Test
    public void testGetPublicKeyUpdated() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_1", "PublicKey1");

        Map<String, String> addKeys = new HashMap<>();
        addKeys.put("coretech.storage_0", "PublicKey0");
        addKeys.put("sports.storage_0", "PublicKey100");
        addKeys.put("sports.storage_1", "PublicKey101");
        
        store.addPublicKeys(addKeys);
        
        assertEquals(store.getPublicKey("coretech", "storage", "0"), "PublicKey0");
        assertEquals(store.getPublicKey("sports", "storage", "0"), "PublicKey100");
        assertEquals(store.getPublicKey("sports", "storage", "1"), "PublicKey101");
    }
    
    @Test
    public void testGetPublicKeyInvalid() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_0", "PublicKey0");
        store.publicKeyCache.put("sports.storage_1", "PublicKey1");

        Map<String, String> addKeys = new HashMap<>();
        addKeys.put("sports.storage_1", "PublicKey1");
        addKeys.put("sports.storage_2", "PublicKey2");
        
        store.addPublicKeys(addKeys);
        assertNull(store.getPublicKey("weather", "storage", "0"));
        assertNull(store.getPublicKey("sports", "storage", "101"));
        assertNull(store.getPublicKey("sports", "backup", "0"));
        assertNull(store.getPublicKey("sports", "storage", "-1"));
    }
   
    @Test
    public void testAddHostEntriesNotPresent() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Map<String, Set<String>> hostMap = new HashMap<>();
        Set<String> services = new HashSet<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        hostMap.put("host1", services);
        
        services = new HashSet<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        hostMap.put("host2", services);
        
        store.addHostEntries(hostMap);
        assertEquals(store.hostCache.size(), 2);
        List<String> retServices = store.hostCache.get("host1");
        assertEquals(retServices.size(), 2);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
        
        retServices = store.hostCache.get("host2");
        assertEquals(retServices.size(), 2);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
    }
    
    @Test
    public void testAddHostEntriesAddValue() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        List<String> services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host1", services);
        
        services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host2", services);
        
        Map<String, Set<String>> hostMap = new HashMap<>();
        Set<String> newServices = new HashSet<>();
        newServices.add("sports.storage");
        hostMap.put("host2", newServices);
        hostMap.put("host3", newServices);
        
        store.addHostEntries(hostMap);
        assertEquals(store.hostCache.size(), 3);
        List<String> retServices = store.hostCache.get("host1");
        assertEquals(retServices.size(), 2);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
        
        retServices = store.hostCache.get("host2");
        assertEquals(retServices.size(), 3);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
        assertTrue(retServices.contains("sports.storage"));
        
        retServices = store.hostCache.get("host3");
        assertEquals(retServices.size(), 1);
        assertTrue(retServices.contains("sports.storage"));
    }
    
    @Test
    public void testAddHostEntriesEmptyMap() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        List<String> services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host1", services);
        
        Map<String, Set<String>> hostMap = new HashMap<>();
        
        store.addHostEntries(hostMap);
        assertEquals(store.hostCache.size(), 1);
        List<String> retServices = store.hostCache.get("host1");
        assertEquals(retServices.size(), 2);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
    }
    
    @Test
    public void testAddHostEntrieNullMap() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        List<String> services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host1", services);
        
        services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host2", services);
        
        store.addHostEntries(null);
        assertEquals(store.hostCache.size(), 2);
        List<String> retServices = store.hostCache.get("host1");
        assertEquals(retServices.size(), 2);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
        
        retServices = store.hostCache.get("host2");
        assertEquals(retServices.size(), 2);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
    }
    
    @Test
    public void testRemoveHostEntriesNotPresent() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        List<String> services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host1", services);
        
        services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host2", services);
        
        Map<String, Set<String>> hostMap = new HashMap<>();
        Set<String> newServices = new HashSet<>();
        newServices.add("coretech.storage");
        newServices.add("coretech.backup");
        hostMap.put("host3", newServices);
        
        store.removeHostEntries(hostMap);
        assertEquals(store.hostCache.size(), 2);
        List<String> retServices = store.hostCache.get("host1");
        assertEquals(retServices.size(), 2);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
        
        retServices = store.hostCache.get("host2");
        assertEquals(retServices.size(), 2);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
    }
    
    @Test
    public void testRemoveHostEntriesRemoveValue() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        List<String> services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host1", services);
        
        services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host2", services);
        
        Map<String, Set<String>> hostMap = new HashMap<>();
        Set<String> newServices = new HashSet<>();
        newServices.add("coretech.storage");
        hostMap.put("host1", newServices);
        
        newServices = new HashSet<>();
        newServices.add("coretech.backup");
        hostMap.put("host2", newServices);
        
        store.removeHostEntries(hostMap);
        assertEquals(store.hostCache.size(), 2);
        List<String> retServices = store.hostCache.get("host1");
        assertEquals(retServices.size(), 1);
        assertTrue(retServices.contains("coretech.backup"));
        
        retServices = store.hostCache.get("host2");
        assertEquals(retServices.size(), 1);
        assertTrue(retServices.contains("coretech.storage"));
    }
    
    @Test
    public void testRemoveHostEntriesEmptyMap() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        List<String> services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host1", services);
        
        Map<String, Set<String>> hostMap = new HashMap<>();
        
        store.removeHostEntries(hostMap);
        assertEquals(store.hostCache.size(), 1);
        List<String> retServices = store.hostCache.get("host1");
        assertEquals(retServices.size(), 2);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
    }
    
    @Test
    public void testRemoveHostEntrieNullMap() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        List<String> services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host1", services);
        
        services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("coretech.backup");
        store.hostCache.put("host2", services);
        
        store.removeHostEntries(null);
        assertEquals(store.hostCache.size(), 2);
        List<String> retServices = store.hostCache.get("host1");
        assertEquals(retServices.size(), 2);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
        
        retServices = store.hostCache.get("host2");
        assertEquals(retServices.size(), 2);
        assertTrue(retServices.contains("coretech.storage"));
        assertTrue(retServices.contains("coretech.backup"));
    }
    
    @Test
    public void testGetHostServices() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        List<String> services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("sports.storage");
        store.hostCache.put("host1", services);
        
        services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("sports.storage");
        store.hostCache.put("host2", services);
        
        HostServices hostServices = store.getHostServices("host1");
        List<String> hosts = hostServices.getNames();
        assertEquals(hosts.size(), 2);
        assertTrue(hosts.contains("coretech.storage"));
        assertTrue(hosts.contains("sports.storage"));
        
        hostServices = store.getHostServices("host2");
        hosts = hostServices.getNames();
        assertEquals(hosts.size(), 2);
        assertTrue(hosts.contains("coretech.storage"));
        assertTrue(hosts.contains("sports.storage"));
    }
    
    @Test
    public void testGetHostServicesHostUpdated() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        List<String> services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("sports.storage");
        store.hostCache.put("host1", services);
        
        services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("sports.storage");
        store.hostCache.put("host2", services);
        
        Map<String, Set<String>> hostMap = new HashMap<>();
        Set<String> newServices = new HashSet<>();
        newServices.add("coretech.backup");
        hostMap.put("host3", newServices);
        
        newServices = new HashSet<>();
        newServices.add("sports.backup");
        hostMap.put("host1", newServices);
        
        store.addHostEntries(hostMap);
        
        Map<String, Set<String>> remMap = new HashMap<>();
        Set<String> remServices = new HashSet<>();
        remServices.add("sports.storage");
        remMap.put("host1", remServices);
        
        store.removeHostEntries(remMap);
        
        HostServices hostServices = store.getHostServices("host1");
        List<String> hosts = hostServices.getNames();
        assertEquals(hosts.size(), 2);
        assertTrue(hosts.contains("coretech.storage"));
        assertTrue(hosts.contains("sports.backup"));
        
        hostServices = store.getHostServices("host2");
        hosts = hostServices.getNames();
        assertEquals(hosts.size(), 2);
        assertTrue(hosts.contains("coretech.storage"));
        assertTrue(hosts.contains("sports.storage"));
        
        hostServices = store.getHostServices("host3");
        hosts = hostServices.getNames();
        assertEquals(hosts.size(), 1);
        assertTrue(hosts.contains("coretech.backup"));
    }
    
    @Test
    public void testGetHostServicesInvalid() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        List<String> services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("sports.storage");
        store.hostCache.put("host1", services);
        
        services = new ArrayList<>();
        services.add("coretech.storage");
        services.add("sports.storage");
        store.hostCache.put("host2", services);
        
        HostServices hostServices = store.getHostServices("host3");
        List<String> hosts = hostServices.getNames();
        assertNull(hosts);
    }
    
    @Test
    public void testGenerateServiceKeyName() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        assertEquals(store.generateServiceKeyName("coretech", "storage", "3"), "coretech.storage_3");
    }
    
    @Test
    public void testGenerateServiceKeyNameLongValues() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        String domain = "coretech0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        String service = "coretech0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        String expectedValue = domain + "." + service + "_2";
        assertEquals(store.generateServiceKeyName(domain, service, "2"), expectedValue);
    }
    
    @Test
    public void testCheckRoleSet() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        Set<String> checkSet = new HashSet<>();
        checkSet.add("role1");
        checkSet.add("role2");
        
        assertTrue(store.checkRoleSet("test1", null));
        assertTrue(store.checkRoleSet("role1", checkSet));
        assertTrue(store.checkRoleSet("role2", checkSet));
        assertFalse(store.checkRoleSet("role3", checkSet));
    }
    
    @Test
    public void testAddRoleToListPrefixNoMatch() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        Set<String> accessibleRoles = new HashSet<>();
        store.addRoleToList("sports:role.admin", "coretech:role.", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testAddRoleToList() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        store.addRoleToList("coretech:role.admin", "coretech:role.", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
    }
    
    @Test
    public void testAddRoleToListSingleRoleSpecified() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String[] requestedRoleList = { "admin" };
        store.addRoleToList("coretech:role.admin", "coretech:role.", requestedRoleList, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
    }
    
    @Test
    public void testAddRoleToListSingleRoleSpecifiedNoMatch() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String[] requestedRoleList = { "admin2" };
        store.addRoleToList("coretech:role.admin", "coretech:role.", requestedRoleList, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testAddRoleToListMultipleRoleSpecified() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String[] requestedRoleList = { "admin2", "admin3", "admin" };
        store.addRoleToList("coretech:role.admin", "coretech:role.", requestedRoleList, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
    }
    
    @Test
    public void testAddRoleToListMultipleRoleSpecifiedNoMatch() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String[] requestedRoleList = { "admin2", "admin3", "admin4" };
        store.addRoleToList("coretech:role.admin", "coretech:role.", requestedRoleList, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testAddDomainToCacheNewDomain() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        DataCache dataCache = new DataCache();
        
        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        DomainData domainData = new DomainData();
        domainData.setRoles(roles);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        DomainData domain = store.getDomainData("coretech");
        assertNotNull(domain);
        assertEquals(domain.getRoles().size(), 1);
        assertEquals(domain.getRoles().get(0).getName(), "coretech:role.admin");
        assertEquals(domain.getRoles().get(0).getRoleMembers().size(), 1);
        assertEquals(domain.getRoles().get(0).getRoleMembers().get(0).getMemberName(), "user_domain.user");
    }
    
    @Test
    public void testAddDomainToCacheUpdatedDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        DataCache dataCache = new DataCache();
        
        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);

        List<Role> roles = new ArrayList<>();
        roles.add(role);
        
        DomainData domainData = new DomainData();
        domainData.setRoles(roles);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        /* update member list */
        
        role = new Role();
        role.setName("coretech:role.admin");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user1"));
        members.add(new RoleMember().setMemberName("user_domain.user2"));
        role.setRoleMembers(members);

        roles = new ArrayList<>();
        roles.add(role);

        dataCache = new DataCache();
        domainData = new DomainData();
        domainData.setRoles(roles);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        DomainData domain = store.getDomainData("coretech");
        assertNotNull(domain);
        assertEquals(domain.getRoles().size(), 1);
        assertEquals(domain.getRoles().get(0).getName(), "coretech:role.admin");
        assertEquals(domain.getRoles().get(0).getRoleMembers().size(), 2);
        boolean user1 = false;
        boolean user2 = false;
        for (RoleMember member : domain.getRoles().get(0).getRoleMembers()) {
            switch (member.getMemberName()) {
                case "user_domain.user1":
                    user1 = true;
                    break;
                case "user_domain.user2":
                    user2 = true;
                    break;
            }
        }
        assertTrue(user1);
        assertTrue(user2);
    }
    
    @Test
    public void testAddDomainToCacheSameHosts() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        DataCache dataCache = new DataCache();
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("coretech.storage");
        
        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        service.setHosts(hosts);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);
        
        DomainData domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        /* same hosts - no changes */
        
        dataCache = new DataCache();
        service = new ServiceIdentity();
        service.setName("coretech.storage");

        hosts = new ArrayList<>();
        hosts.add("host1");
        service.setHosts(hosts);

        services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);
        
        domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        HostServices hostServices = store.getHostServices("host1");
        hosts = hostServices.getNames();
        assertEquals(hosts.size(), 1);
        assertTrue(hosts.contains("coretech.storage"));
    }
    
    @Test
    public void testAddDomainToCacheAddedHosts() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        DataCache dataCache = new DataCache();
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("coretech.storage");
        
        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        service.setHosts(hosts);

        List<ServiceIdentity> services = new ArrayList<>();
        dataCache.processServiceIdentity(service);
        services.add(service);
        
        DomainData domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        /* added hosts */
        
        dataCache = new DataCache();
        service = new ServiceIdentity();
        service.setName("coretech.storage");

        hosts = new ArrayList<>();
        hosts.add("host1");
        hosts.add("host2");
        service.setHosts(hosts);

        services = new ArrayList<>();
        dataCache.processServiceIdentity(service);
        services.add(service);
        
        domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        HostServices hostServices = store.getHostServices("host1");
        hosts = hostServices.getNames();
        assertEquals(hosts.size(), 1);
        assertTrue(hosts.contains("coretech.storage"));
        
        hostServices = store.getHostServices("host2");
        hosts = hostServices.getNames();
        assertEquals(hosts.size(), 1);
        assertTrue(hosts.contains("coretech.storage"));
    }
    
    @Test
    public void testAddDomainToCacheRemovedHosts() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        DataCache dataCache = new DataCache();
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("coretech.storage");
        
        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        hosts.add("host2");
        hosts.add("host3");
        service.setHosts(hosts);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);

        DomainData domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        /* removed hosts */
        
        dataCache = new DataCache();
        service = new ServiceIdentity();
        service.setName("coretech.storage");

        hosts = new ArrayList<>();
        hosts.add("host1");
        service.setHosts(hosts);

        services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);

        domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        HostServices hostServices = store.getHostServices("host1");
        hosts = hostServices.getNames();
        assertEquals(hosts.size(), 1);
        assertTrue(hosts.contains("coretech.storage"));
        
        hostServices = store.getHostServices("host2");
        hosts = hostServices.getNames();
        assertEquals(hosts.size(), 0);
        
        hostServices = store.getHostServices("host3");
        hosts = hostServices.getNames();
        assertEquals(hosts.size(), 0);
    }
    
    @Test
    public void testAddDomainToCacheSamePublicKeys() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        DataCache dataCache = new DataCache();
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("coretech.storage");
        
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        
        com.yahoo.athenz.zms.PublicKeyEntry publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT1);
        publicKey.setId("1");
        
        List<com.yahoo.athenz.zms.PublicKeyEntry> publicKeys = new ArrayList<>();
        publicKeys.add(publicKey);
        
        service.setPublicKeys(publicKeys);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);
        
        DomainData domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        /* same public keys - no changes */
        
        dataCache = new DataCache();
        service = new ServiceIdentity();
        service.setName("coretech.storage");

        publicKeys = new ArrayList<>();
        
        publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT0);
        publicKey.setId("0");
        publicKeys.add(publicKey);
        
        publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT1);
        publicKey.setId("1");
        publicKeys.add(publicKey);
        
        service.setPublicKeys(publicKeys);

        services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);
        
        domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        assertEquals(store.getPublicKey("coretech", "storage", "0"), ZTS_PEM_CERT0);
        assertEquals(store.getPublicKey("coretech", "storage", "1"), ZTS_PEM_CERT1);
        assertNull(store.getPublicKey("coretech", "storage", "2"));
    }

    @Test
    public void testAddDomainToCacheUpdatedPublicKeysVersions() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        DataCache dataCache = new DataCache();
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("coretech.storage");
        
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        
        com.yahoo.athenz.zms.PublicKeyEntry publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT1);
        publicKey.setId("1");
        
        List<com.yahoo.athenz.zms.PublicKeyEntry> publicKeys = new ArrayList<>();
        publicKeys.add(publicKey);
        
        service.setPublicKeys(publicKeys);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);
        
        DomainData domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        /* update multiple version public keys */
        
        dataCache = new DataCache();
        service = new ServiceIdentity();
        service.setName("coretech.storage");

        publicKeys = new ArrayList<>();
        
        publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT0);
        publicKey.setId("0");
        publicKeys.add(publicKey);
        
        publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT3);
        publicKey.setId("1");
        publicKeys.add(publicKey);
        
        publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT2);
        publicKey.setId("2");
        publicKeys.add(publicKey);
        
        service.setPublicKeys(publicKeys);

        services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);
        
        domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        assertEquals(store.getPublicKey("coretech", "storage", "0"), ZTS_PEM_CERT0);
        assertEquals(store.getPublicKey("coretech", "storage", "1"), ZTS_PEM_CERT3);
        assertEquals(store.getPublicKey("coretech", "storage", "2"), ZTS_PEM_CERT2);
        assertNull(store.getPublicKey("coretech", "storage", "3"));
    }
    
    @Test
    public void testAddDomainToCacheRemovedPublicKeysV0() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        DataCache dataCache = new DataCache();
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("coretech.storage");
        
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        
        com.yahoo.athenz.zms.PublicKeyEntry publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT1);
        publicKey.setId("1");
        
        List<com.yahoo.athenz.zms.PublicKeyEntry> publicKeys = new ArrayList<>();
        publicKeys.add(publicKey);
        
        service.setPublicKeys(publicKeys);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);

        DomainData domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        /* remove V0 public key */
        
        dataCache = new DataCache();
        service = new ServiceIdentity();
        service.setName("coretech.storage");

        publicKeys = new ArrayList<>();
        
        publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT1);
        publicKey.setId("1");
        publicKeys.add(publicKey);
        
        service.setPublicKeys(publicKeys);

        services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);

        domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        assertNull(store.getPublicKey("coretech", "storage", "0"));
        assertEquals(store.getPublicKey("coretech", "storage", "1"), ZTS_PEM_CERT1);
        assertNull(store.getPublicKey("coretech", "storage", "2"));
    }
    
    @Test
    public void testAddDomainToCacheRemovedPublicKeysVersions() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        DataCache dataCache = new DataCache();
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("coretech.storage");
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        
        List<com.yahoo.athenz.zms.PublicKeyEntry> publicKeys = new ArrayList<>();
        
        com.yahoo.athenz.zms.PublicKeyEntry publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT1);
        publicKey.setId("1");
        publicKeys.add(publicKey);
        
        publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT2);
        publicKey.setId("2");
        publicKeys.add(publicKey);
        
        service.setPublicKeys(publicKeys);
        
        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);

        DomainData domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        /* update multiple version public keys */
        
        dataCache = new DataCache();
        service = new ServiceIdentity();
        service.setName("coretech.storage");
        
        publicKeys = new ArrayList<>();
        
        publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT0);
        publicKey.setId("0");
        publicKeys.add(publicKey);
        
        publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT2);
        publicKey.setId("2");
        publicKeys.add(publicKey);
        
        service.setPublicKeys(publicKeys);
        
        services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);

        domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        
        assertEquals(store.getPublicKey("coretech", "storage", "0"), ZTS_PEM_CERT0);
        assertNull(store.getPublicKey("coretech", "storage", "1"));
        assertEquals(store.getPublicKey("coretech", "storage", "2"), ZTS_PEM_CERT2);
        assertNull(store.getPublicKey("coretech", "storage", "3"));
    }
    
    @Test
    public void testDeleteDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        SignedDomain signedDomain = new SignedDomain();
        
        List<Role> roles = new ArrayList<>();
        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domainData.setRoles(roles);
        
        signedDomain.setDomain(domainData);
        signedDomain.setKeyId("0");
        store.changeLogStore.saveLocalDomain("coretech", signedDomain);

        DataCache dataCache = new DataCache();
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);

        store.deleteDomainFromCache("coretech");
        store.changeLogStore.removeLocalDomain("coretech");
        
        assertNull(store.getCacheStore().getIfPresent("coretech"));
        
        File file = new File("/tmp/zts_server_unit_tests/zts_root/coretech");
        assertFalse(file.exists());
    }
    
    @Test
    public void testDeleteDomainFromCacheHosts() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        DataCache dataCache = new DataCache();
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("coretech.storage");
        
        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        service.setHosts(hosts);

        List<ServiceIdentity> services = new ArrayList<>();
        dataCache.processServiceIdentity(service);
        services.add(service);
        
        DomainData domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        store.deleteDomainFromCache("coretech");
        
        HostServices hostServices = store.getHostServices("host1");
        hosts = hostServices.getNames();
        assertEquals(hosts.size(), 0);
    }
    
    @Test
    public void testDeleteDomainFromCachePublicKeys() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        DataCache dataCache = new DataCache();
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("coretech.storage");
        
        setServicePublicKey(service, "0", ZTS_Y64_CERT0);
        
        com.yahoo.athenz.zms.PublicKeyEntry publicKey = new com.yahoo.athenz.zms.PublicKeyEntry();
        publicKey.setKey(ZTS_Y64_CERT1);
        publicKey.setId("1");
        
        List<com.yahoo.athenz.zms.PublicKeyEntry> publicKeys = new ArrayList<>();
        publicKeys.add(publicKey);
        
        service.setPublicKeys(publicKeys);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);
        dataCache.processServiceIdentity(service);
        
        DomainData domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache("coretech", dataCache);
        store.deleteDomainFromCache("coretech");

        assertNull(store.getPublicKey("coretech", "storage", "0"));
        assertNull(store.getPublicKey("coretech", "storage", "1"));
        assertNull(store.getPublicKey("coretech", "storage", "2"));
    }
    
    @Test
    public void testValidateSignedDomainValid() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        assertTrue(store.validateSignedDomain(signedDomain));

        // using default 0 value

        signedDomain.setKeyId(null);
        assertTrue(store.validateSignedDomain(signedDomain));
    }
    
    @Test
    public void testValidateSignedDomainInvalidSignature() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = new SignedDomain();
        
        List<Role> roles = new ArrayList<>();
        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        
        DomainData domain = new DomainData();
        domain.setRoles(roles);
        
        signedDomain.setDomain(domain);
        signedDomain.setSignature("InvalidSignature");
        signedDomain.setKeyId("0");
        
        assertFalse(store.validateSignedDomain(signedDomain));
    }
    
    @Test
    public void testValidateSignedDomainInvalidVersion() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = new SignedDomain();
        
        List<Role> roles = new ArrayList<>();
        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        
        DomainData domain = new DomainData();
        domain.setRoles(roles);
        
        signedDomain.setDomain(domain);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), pkey));
        signedDomain.setKeyId("100");
        
        assertFalse(store.validateSignedDomain(signedDomain));
    }
    
    @Test
    public void testValidateSignedDomainMissingRole() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = new SignedDomain();
        
        List<Role> roles = new ArrayList<>();
        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        roles.add(role);
        
        DomainData domain = new DomainData();
        domain.setRoles(roles);
        
        signedDomain.setDomain(domain);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), pkey));
        signedDomain.setKeyId("0");
        
        domain.setRoles(null);
        signedDomain.setDomain(domain);

        assertFalse(store.validateSignedDomain(signedDomain));
    }
    
    @Test
    public void testProcessDomainDeletesNoLocalDomains() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        assertTrue(store.processDomainDeletes());
    }
    
    private void addDomainToDataStore(DataStore store, String domainName) {
        
        SignedDomain signedDomain = new SignedDomain();
        
        Role role = new Role();
        role.setName(domainName + ":role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);

        List<Role> roles = new ArrayList<>();
        roles.add(role);
        
        DomainData domainData = new DomainData();
        domainData.setName(domainName);
        domainData.setRoles(roles);
        domainData.setModified(Timestamp.fromCurrentTime());
        
        signedDomain.setDomain(domainData);
        signedDomain.setKeyId("0");
        store.changeLogStore.saveLocalDomain(domainName, signedDomain);
        
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(domainData);
        
        store.addDomainToCache(domainName, dataCache);
    }
    
    @Test
    public void testProcessDomainDeletesZMSFailure() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(null);
        addDomainToDataStore(store, "coretech");
        
        /* this should throw an exception when obtaining domain list from ZMS */
        
        assertFalse(store.processDomainDeletes());
    }

    @Test
    public void testProcessDomainDeletesZMSInvalidResponse() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        // no sys.auth thus invalid response
        List<String> list = new ArrayList<>();
        list.add("sports");
        list.add("coretech");
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(list);

        addDomainToDataStore(store, "coretech");

        assertFalse(store.processDomainDeletes());
    }

    @Test
    public void testProcessDomainDeletesZMSSingleDelete() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        addDomainToDataStore(store, "coretech");
        addDomainToDataStore(store, "sports");
        
        List<String> list = new ArrayList<>();
        list.add(userDomain);
        list.add("sys.auth");
        list.add("coretech");
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(list);
        
        assertTrue(store.processDomainDeletes());
        assertNull(store.getDomainData("sports"));
        assertNotNull(store.getDomainData("coretech"));
    }
    
    @Test
    public void testProcessDomainDeletesZMSAllDelete() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        addDomainToDataStore(store, "coretech");
        addDomainToDataStore(store, "sports");
        
        List<String> list = new ArrayList<>();
        list.add(userDomain);
        list.add("sys.auth");
        list.add("coretech2");
        list.add("sports2");
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(list);
        
        assertTrue(store.processDomainDeletes());
        assertNull(store.getDomainData("sports"));
        assertNull(store.getDomainData("coretech"));
    }
    
    @Test
    public void testGetAccessibleRoles() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("writers"));
    }
    
    @Test
    public void testGetAccessibleRolesWildCards() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomainWildCardMembers("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("writers"));
        assertTrue(accessibleRoles.contains("all"));
        
        accessibleRoles.clear();
        store.getAccessibleRoles(data, "coretech", "user_domain.user3", null, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 3);
        assertTrue(accessibleRoles.contains("readers"));
        assertTrue(accessibleRoles.contains("writers"));
        assertTrue(accessibleRoles.contains("all"));
        
        accessibleRoles.clear();
        store.getAccessibleRoles(data, "coretech", "user_domain.user5", null, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("writers"));
        assertTrue(accessibleRoles.contains("all"));
        
        accessibleRoles.clear();
        store.getAccessibleRoles(data, "coretech", "athenz.service", null, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("all"));
        
        // make sure the prefix is fully matched
        
        accessibleRoles.clear();
        store.getAccessibleRoles(data, "coretech", "athenz.use", null, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("all"));
    }
    
    @Test
    public void testGetAccessibleRolesInvalidDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testGetAccessibleRolesSpecifiedRole() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        String[] requestedRoleList = { "coretech:role.admin" };
        store.getAccessibleRoles(data, "coretech", "user_domain.user", requestedRoleList, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
    }
    
    @Test
    public void testGetAccessibleRolesNoRoles() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.nonexistentuser", null, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testGetAccessibleRolesMultipleRoles() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user", null, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }
    
    @Test
    public void testStoreInitNoLastModTimeLocalDomainDelete() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.changeLogStore.setLastModificationTimestamp(null);
        
        /* this domain will be deleted since our last refresh is 0 */

        addDomainToDataStore(store, "coretech");
        File file = new File("/tmp/zts_server_unit_tests/zts_root/coretech");
        assertTrue(file.exists());
        
        /* initialize our datastore which will call init */
        
        clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        store = new DataStore(clogStore, null);
        assertNull(store.getDomainData("coretech"));
        assertFalse(file.exists());
    }
    
    @Test
    public void testStoreInitNoLocalDomains() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");

        DataStore store = new DataStore(clogStore, null);
        store.changeLogStore.setLastModificationTimestamp(null);
        
        List<SignedDomain> domains = new ArrayList<>();

        /* we're going to create a new domain */
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        domains.add(signedDomain);
        
        /* we're going to update the coretech domain and set new roles */
        
        signedDomain = createSignedDomain("sports", "weather");
        domains.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        
        ((MockZMSFileChangeLogStore) store.changeLogStore).setSignedDomains(signedDomains);
        store.init();

        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
        
        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }
    
    @Test
    public void testStoreInitNoLastModTimeDomainUpdateFailure() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        clogStore.getClogStoreCommon().setTagHeader(null);

        DataStore store = new DataStore(clogStore, null);
        addDomainToDataStore(store, "coretech");
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(null);

        /* our mock is going to throw an exception for domain list so failure */
        
        try {
            store.init();
            fail();
        } catch (ResourceException ex) {
            assertEquals(500, ex.getCode());
        }
    }
    
    @Test
    public void testStoreInitLocalDomainUpdated() {
        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");

        DataStore setupStore = new DataStore(clogStore, null);
        setupStore.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        setupStore.processDomain(signedDomain, true);

        /* create a new store instance */
        
        DataStore store = new DataStore(clogStore, null);

        List<SignedDomain> domains = new ArrayList<>();

        /* we're going to create a new domain */
        
        signedDomain = createSignedDomain("sports", "weather");
        domains.add(signedDomain);
        
        /* we're going to update the coretech domain and set new roles */
        
        signedDomain = createSignedDomain("coretech", "weather");

        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user8"));
        role.setRoleMembers(members);
        
        List<Role> roles = new ArrayList<>();
        roles.add(role);
        signedDomain.getDomain().setRoles(roles);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(signedDomain.getDomain()), pkey));
        domains.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        
        ((MockZMSFileChangeLogStore) store.changeLogStore).setSignedDomains(signedDomains);

        List<String> domainNames = new ArrayList<>();
        domainNames.add("coretech");
        domainNames.add("sports");
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(domainNames);
        store.init();

        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
        
        accessibleRoles = new HashSet<>();
        store.getAccessibleRoles(data, "coretech", "user_domain.user8", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
        
        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }
    
    @Test
    public void testStoreInitLastModTimeDomainCorrupted() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");

        DataStore store = new DataStore(clogStore, null);
        store.changeLogStore.setLastModificationTimestamp("2014-01-01T12:00:00");
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        signedDomain.setSignature("ABCD"); /* invalid signature which will cause domain to be deleted */
        
        store.changeLogStore.saveLocalDomain("coretech", signedDomain);
        
        store = new DataStore(clogStore, null);

        List<String> list = new ArrayList<>();
        list.add("coretech");
        list.add("sports");
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(list);
        
        List<SignedDomain> domains = new ArrayList<>();

        /* we're going to create a new domain */
        
        signedDomain = createSignedDomain("sports", "weather");
        domains.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        
        ((MockZMSFileChangeLogStore) store.changeLogStore).setSignedDomains(signedDomains);
        store.init();

        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
        
        File file = new File("/tmp/zts_server_unit_tests/zts_root/coretech");
        assertFalse(file.exists());
        
        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }
    
    @Test
    public void testProcessDomainRoles() {
    
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        List<Role> roles = new ArrayList<>();
        
        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName("coretech:role.readers");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        roles.add(role);
        
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domainData.setRoles(roles);
        
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(domainData);
        
        store.processDomainRoles(domainData, dataCache);
        assertEquals(dataCache.getMemberRoleSet("user_domain.user").size(), 2);
        
        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.admin", 0)));
        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.readers", 0)));
    }
    
    @Test
    public void testProcessDomainRolesNullRoles() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        DomainData domainData = new DomainData();
        domainData.setName("coretech");

        DataCache dataCache = new DataCache();
        dataCache.setDomainData(domainData);
        
        store.processDomainRoles(domainData, dataCache);
        assertEquals(dataCache.getMemberCount(), 0);
    }
    
    @Test
    public void testProcessDomainPolicies() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();
        
        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource("sports:role.readers");
        assertion.setAction("assume_role");
        assertion.setRole("coretech:role.readers");
        
        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);
        
        policy.setAssertions(assertions);
        policies.add(policy);
        
        List<Role> roles = new ArrayList<>();
        
        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName("coretech:role.readers");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        roles.add(role);
        
        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain("coretech");
        domainPolicies.setPolicies(policies);
        
        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), pkey));
        signedPolicies.setKeyId("0");
        
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domainData.setPolicies(signedPolicies);
        domainData.setRoles(roles);

        DataCache dataCache = new DataCache();
        dataCache.setDomainData(domainData);
        
        store.processDomainRoles(domainData, dataCache);
        assertEquals(dataCache.getMemberRoleSet("user_domain.user").size(), 2);
        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.admin", 0)));
        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.readers", 0)));
    }
    
    @Test
    public void testProcessDomainPoliciesNullPolicies() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        DomainData domainData = new DomainData();
        domainData.setName("coretech");

        DataCache dataCache = new DataCache();
        dataCache.setDomainData(domainData);
        
        store.processDomainPolicies(domainData, dataCache);
        assertEquals(dataCache.getMemberCount(), 0);

        SignedPolicies signedPolicies = new SignedPolicies();
        domainData.setPolicies(signedPolicies);
        store.processDomainPolicies(domainData, dataCache);
        assertEquals(dataCache.getMemberCount(), 0);

        DomainPolicies domainPolicies = new DomainPolicies();
        signedPolicies.setContents(domainPolicies);
        store.processDomainPolicies(domainData, dataCache);
        assertEquals(dataCache.getMemberCount(), 0);
    }

    @Test
    public void testProcessDomainServiceIdentities() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName("coretech.storage");
        
        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        service.setHosts(hosts);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);
        
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domainData.setServices(services);
        
        DataCache dataCache = new DataCache();
        dataCache.setDomainData(domainData);
        
        store.processDomainServiceIdentities(domainData, dataCache);
        store.addDomainToCache(domainData.getName(), dataCache);
        
        HostServices hostServices = store.getHostServices("host1");
        hosts = hostServices.getNames();
        assertEquals(hosts.size(), 1);
        assertTrue(hosts.contains("coretech.storage"));
    }
    
    @Test
    public void testProcessDomainServiceIdentitiesNullPolicies() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        DataCache dataCache = new DataCache();
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        dataCache.setDomainData(domainData);
        
        store.processDomainServiceIdentities(domainData, dataCache);
        
        HostServices hostServices = store.getHostServices("host1");
        List<String> hosts = hostServices.getNames();
        assertNull(hosts);
    }
    
    private SignedDomain createSignedDomain(String domainName, String tenantDomain) {
        
        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(domainName + ":role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName(domainName + ":role.writers");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        members.add(new RoleMember().setMemberName("user_domain.user1"));
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName(domainName + ":role.readers");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user3"));
        members.add(new RoleMember().setMemberName("user_domain.user4"));
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName(domainName + ":role.tenant.readers");
        role.setTrust(tenantDomain);
        roles.add(role);
        
        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();
        
        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":tenant.weather.*");
        assertion.setAction("read");
        assertion.setRole(domainName + ":role.tenant.readers");
        
        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);
        
        policy.setAssertions(assertions);
        policy.setName(domainName + ":policy.tenant.reader");
        policies.add(policy);
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName(domainName + ".storage");
        setServicePublicKey(service, "0", "abcdefgh");
        
        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        service.setHosts(hosts);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);
        
        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);
        
        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), pkey));
        signedPolicies.setKeyId("0");
        
        DomainData domain = new DomainData();
        domain.setModified(Timestamp.fromCurrentTime());
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setServices(services);
        domain.setPolicies(signedPolicies);
        
        signedDomain.setDomain(domain);

        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), pkey));
        signedDomain.setKeyId("0");
        
        return signedDomain;
    }
    
    private SignedDomain createSignedDomainWildCardMembers(String domainName, String tenantDomain) {
        
        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(domainName + ":role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName(domainName + ":role.writers");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user*"));
        members.add(new RoleMember().setMemberName("user_domain.user1"));
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName(domainName + ":role.readers");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user3"));
        members.add(new RoleMember().setMemberName("user_domain.user4"));
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName(domainName + ":role.all");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("*"));
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName(domainName + ":role.tenant.readers");
        role.setTrust(tenantDomain);
        roles.add(role);
        
        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();
        
        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(domainName + ":tenant.weather.*");
        assertion.setAction("read");
        assertion.setRole(domainName + ":role.tenant.readers");
        
        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);
        
        policy.setAssertions(assertions);
        policy.setName(domainName + ":policy.tenant.reader");
        policies.add(policy);
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName(domainName + ".storage");
        setServicePublicKey(service, "0", "abcdefgh");
        
        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        service.setHosts(hosts);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);
        
        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);
        
        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), pkey));
        signedPolicies.setKeyId("0");
        
        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setServices(services);
        domain.setPolicies(signedPolicies);
        
        signedDomain.setDomain(domain);

        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), pkey));
        signedDomain.setKeyId("0");
        
        return signedDomain;
    }
    
    private SignedDomain createTenantSignedDomain(String domainName, String providerDomain) {
        
        SignedDomain signedDomain = new SignedDomain();

        List<Role> roles = new ArrayList<>();

        Role role = new Role();
        role.setName(domainName + ":role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        roles.add(role);
        
        role = new Role();
        role.setName(domainName + ":role.readers");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user100"));
        members.add(new RoleMember().setMemberName("user_domain.user101"));
        role.setRoleMembers(members);
        roles.add(role);
        
        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();
        
        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        com.yahoo.athenz.zms.Assertion assertion = new com.yahoo.athenz.zms.Assertion();
        assertion.setResource(providerDomain + ":role.tenant.readers");
        assertion.setAction("assume_role");
        assertion.setRole(domainName + ":role.readers");
        
        List<com.yahoo.athenz.zms.Assertion> assertions = new ArrayList<>();
        assertions.add(assertion);
        
        policy.setAssertions(assertions);
        policy.setName(domainName + ":policy.tenancy.readers");
        policies.add(policy);
        
        ServiceIdentity service = new ServiceIdentity();
        service.setName(domainName + ".storage");
        setServicePublicKey(service, "0", "abcdefgh");
        
        List<String> hosts = new ArrayList<>();
        hosts.add("host1");
        service.setHosts(hosts);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);
        
        com.yahoo.athenz.zms.DomainPolicies domainPolicies = new com.yahoo.athenz.zms.DomainPolicies();
        domainPolicies.setDomain(domainName);
        domainPolicies.setPolicies(policies);
        
        com.yahoo.athenz.zms.SignedPolicies signedPolicies = new com.yahoo.athenz.zms.SignedPolicies();
        signedPolicies.setContents(domainPolicies);
        signedPolicies.setSignature(Crypto.sign(SignUtils.asCanonicalString(domainPolicies), pkey));
        signedPolicies.setKeyId("0");
        
        DomainData domain = new DomainData();
        domain.setName(domainName);
        domain.setRoles(roles);
        domain.setServices(services);
        domain.setPolicies(signedPolicies);
        
        signedDomain.setDomain(domain);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(domain), pkey));
        signedDomain.setKeyId("0");
        
        return signedDomain;
    }
   
    @Test
    public void testProcessDomainSaveInStore() throws IOException {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        File file = new File("/tmp/zts_server_unit_tests/zts_root/coretech");
        assertTrue(file.exists());
        
        Path path = Paths.get(file.toURI());
        SignedDomain signedDomain2 = JSON.fromBytes(Files.readAllBytes(path), SignedDomain.class);
        assertEquals(signedDomain2.getDomain().getName(), "coretech");

        assertNotNull(store.getDomainData("coretech"));
    }
    
    @Test
    public void testProcessDomainNotSaveInStore() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, false);
        
        File file = new File("/tmp/zts_server_unit_tests/zts_root/coretech");
        assertFalse(file.exists());
        
        assertNotNull(store.getDomainData("coretech"));
    }
    
    @Test
    public void testProcessLocalDomain() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        store = new DataStore(clogStore, null);
        boolean result = store.processLocalDomain("coretech");
        assertTrue(result);
        assertNotNull(store.getDomainData("coretech"));
    }
    
    @Test
    public void testProcessLocalDomainInvalidFile() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        boolean result = store.processLocalDomain("coretech");
        assertFalse(result);
    }
    
    @Test
    public void testProcessLocalDomains() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore setupStore = new DataStore(clogStore, null);
        setupStore.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        setupStore.processDomain(signedDomain, true);

        signedDomain = createSignedDomain("sports", "weather");
        setupStore.processDomain(signedDomain, true);
        
        DataStore store = new DataStore(clogStore, null);
        
        List<String> list = new ArrayList<>();
        list.add("coretech");
        list.add("sports");
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(list);
        
        int badDomains = store.processLocalDomains(list);
        assertEquals(badDomains, 0);
        
        assertNotNull(store.getDomainData("coretech"));
        assertNotNull(store.getDomainData("sports"));
    }

    @Test
    public void testProcessLocalDomainsOneBadDomain() throws FileNotFoundException {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");

        DataStore setupStore = new DataStore(clogStore, null);
        setupStore.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        setupStore.processDomain(signedDomain, true);

        signedDomain = createSignedDomain("sports", "weather");
        setupStore.processDomain(signedDomain, true);

        signedDomain = createSignedDomain("finance", "weather");
        setupStore.processDomain(signedDomain, true);

        signedDomain = createSignedDomain("news", "weather");
        setupStore.processDomain(signedDomain, true);

        signedDomain = createSignedDomain("fantasy", "weather");
        setupStore.processDomain(signedDomain, true);

        signedDomain = createSignedDomain("ads", "weather");
        setupStore.processDomain(signedDomain, true);

        signedDomain = createSignedDomain("platforms", "weather");
        setupStore.processDomain(signedDomain, true);

        signedDomain = createSignedDomain("dev", "weather");
        setupStore.processDomain(signedDomain, true);

        try (PrintWriter out = new PrintWriter("/tmp/zts_server_unit_tests/zts_root/athenz")) {
            out.write("{\"domain\":\"athenz\"}");
        }

        DataStore store = new DataStore(clogStore, null);

        List<String> list = Arrays.asList("coretech", "sports", "finance", "news", "fantasy",
                "ads", "platforms", "dev", "athenz");
        clogStore.setDomainList(list);

        store.init();

        // verify our valid domains

        assertNotNull(store.getDomainData("coretech"));
        assertNotNull(store.getDomainData("sports"));
        assertNotNull(store.getDomainData("finance"));
        assertNotNull(store.getDomainData("news"));
        assertNotNull(store.getDomainData("fantasy"));
        assertNotNull(store.getDomainData("ads"));
        assertNotNull(store.getDomainData("platforms"));
        assertNotNull(store.getDomainData("dev"));

        // athenz valid invalid

        assertNull(store.getDomainData("athenz"));
    }

    @Test
    public void testProcessLocalDomainsZMSDomainListNull() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore setupStore = new DataStore(clogStore, null);
        setupStore.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        setupStore.processDomain(signedDomain, true);

        signedDomain = createSignedDomain("sports", "weather");
        setupStore.processDomain(signedDomain, true);
        
        DataStore store = new DataStore(clogStore, null);
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(null);
        
        List<String> list = new ArrayList<>();
        list.add("coretech");
        list.add("sports");
        
        int badDomains = store.processLocalDomains(list);
        assertEquals(badDomains, 0);

        assertNotNull(store.getDomainData("coretech"));
        assertNotNull(store.getDomainData("sports"));
    }
    
    @Test
    public void testProcessLocalDomainsDeletedDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore setupStore = new DataStore(clogStore, null);
        setupStore.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        setupStore.processDomain(signedDomain, true);

        signedDomain = createSignedDomain("sports", "weather");
        setupStore.processDomain(signedDomain, true);
        
        DataStore store = new DataStore(clogStore, null);
        List<String> zmsList = new ArrayList<>();
        zmsList.add("coretech");
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(zmsList);

        List<String> list = new ArrayList<>();
        list.add("coretech");
        list.add("sports");

        int badDomains = store.processLocalDomains(list);
        assertEquals(badDomains, 0);
        
        assertNotNull(store.getDomainData("coretech"));
        assertNull(store.getDomainData("sports"));
        File file = new File("/tmp/zts_server_unit_tests/zts_root/sports");
        assertFalse(file.exists());
    }
    
    @Test
    public void testProcessLocalDomainsInvalidLocalDomainBelowThreshold() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore setupStore = new DataStore(clogStore, null);
        setupStore.loadAthenzPublicKeys();

        // create 8 records so our 1/4 threashold for bad domains is 2

        setupStore.processDomain(createSignedDomain("coretech", "weather"), true);
        setupStore.processDomain(createSignedDomain("sports", "weather"), true);
        setupStore.processDomain(createSignedDomain("mail", "weather"), true);
        setupStore.processDomain(createSignedDomain("fantasy", "weather"), true);
        setupStore.processDomain(createSignedDomain("profile", "weather"), true);
        setupStore.processDomain(createSignedDomain("news", "weather"), true);
        setupStore.processDomain(createSignedDomain("politics", "weather"), true);
        setupStore.processDomain(createSignedDomain("finance", "weather"), true);

        DataStore store = new DataStore(clogStore, null);
        List<String> zmsList = new ArrayList<>();
        zmsList.addAll(Arrays.asList("coretech", "sports", "mail", "fantasy", "profile",
                "news", "politics", "finance", "invalid"));
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(zmsList);

        int badDomains = store.processLocalDomains(zmsList);
        assertEquals(badDomains, 1);
    }

    @Test
    public void testProcessLocalDomainsInvalidLocalDomainRefreshRequired() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore setupStore = new DataStore(clogStore, null);
        setupStore.loadAthenzPublicKeys();

        setupStore.processDomain(createSignedDomain("coretech", "weather"), true);
        setupStore.processDomain(createSignedDomain("sports", "weather"), true);
        setupStore.processDomain(createSignedDomain("mail", "weather"), true);
        setupStore.processDomain(createSignedDomain("fantasy", "weather"), true);
        setupStore.processDomain(createSignedDomain("profile", "weather"), true);
        setupStore.processDomain(createSignedDomain("news", "weather"), true);
        setupStore.processDomain(createSignedDomain("politics", "weather"), true);
        setupStore.processDomain(createSignedDomain("finance", "weather"), true);

        DataStore store = new DataStore(clogStore, null);
        List<String> zmsList = new ArrayList<>();
        zmsList.addAll(Arrays.asList("coretech", "sports", "mail", "fantasy", "profile",
                "news", "politics", "finance", "invalid"));
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(zmsList);
        ((MockZMSFileChangeLogStore) store.changeLogStore).setRefreshSupport(true);

        int badDomains = store.processLocalDomains(zmsList);
        assertEquals(badDomains, -1);
    }

    @Test
    public void testProcessLocalDomainsInvalidLocalDomainAboveThreshold() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore setupStore = new DataStore(clogStore, null);
        setupStore.loadAthenzPublicKeys();

        setupStore.processDomain(createSignedDomain("coretech", "weather"), true);
        setupStore.processDomain(createSignedDomain("sports", "weather"), true);

        DataStore store = new DataStore(clogStore, null);
        List<String> zmsList = new ArrayList<>();
        zmsList.add("coretech");
        zmsList.add("sports");
        zmsList.add("invalid");
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(zmsList);

        List<String> list = new ArrayList<>();
        list.add("coretech");
        list.add("sports");
        list.add("invalid");

        // below the 1/4 threshold so we'll get back full failure

        int badDomains = store.processLocalDomains(list);
        assertEquals(badDomains, -1);
    }

    @Test
    public void testProcessSignedDomains() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        List<SignedDomain> list = new ArrayList<>();
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        list.add(signedDomain);
        
        signedDomain = createSignedDomain("sports", "weather");
        list.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(list);

        boolean result = store.processSignedDomains(signedDomains);
        assertTrue(result);
        assertNotNull(store.getDomainData("coretech"));
        assertNotNull(store.getDomainData("sports"));
    }
    
    @Test
    public void testProcessSignedDomainsNullList() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        boolean result = store.processSignedDomains(null);
        assertTrue(result);
    }
    
    @Test
    public void testProcessSignedDomainsEmptyList() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(null);

        boolean result = store.processSignedDomains(signedDomains);
        assertTrue(result);
    }
    
    @Test
    public void testProcessSignedDomainsInvalidDomainWithSuccess() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        List<SignedDomain> list = new ArrayList<>();
        
        // if we have one successful domain and one failure
        // then our result is going to be success
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        list.add(signedDomain);
        
        signedDomain = createSignedDomain("sports", "weather");
        signedDomain.setSignature("Invalid0");
        list.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(list);

        boolean result = store.processSignedDomains(signedDomains);
        assertTrue(result);
    }
    
    @Test
    public void testProcessSignedDomainsAllInvalidDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        List<SignedDomain> list = new ArrayList<>();
        
        // if we have only failures, then our result
        // is going to be failure
        
        SignedDomain signedDomain = createSignedDomain("sports", "weather");
        signedDomain.setSignature("Invalid0");
        list.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(list);

        boolean result = store.processSignedDomains(signedDomains);
        assertFalse(result);
    }
    
    private DataCache createDataCache(String domainName) {
        
        DataCache dataCache = new DataCache();
        List<Role> roles = new ArrayList<>();
        
        Role role = new Role();
        role.setName(domainName + ":role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user1"));
        role.setRoleMembers(members);
        roles.add(role);
        dataCache.processRole(role);
        
        role = new Role();
        role.setName(domainName + ":role.readers");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user1"));
        members.add(new RoleMember().setMemberName("user_domain.user2"));
        role.setRoleMembers(members);
        roles.add(role);
        dataCache.processRole(role);
        
        role = new Role();
        role.setName(domainName + ":role.writers");
        role.setTrust(domainName + "Trust");
        roles.add(role);
        dataCache.processRole(role);
        
        DomainData domainData = new DomainData();
        domainData.setName(domainName);
        domainData.setRoles(roles);
        
        dataCache.setDomainData(domainData);
        return dataCache;
    }
    
    private DataCache createDataCacheWildCard(String domainName) {
        
        DataCache dataCache = new DataCache();
        List<Role> roles = new ArrayList<>();
        
        Role role = new Role();
        role.setName(domainName + ":role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user*"));
        role.setRoleMembers(members);
        roles.add(role);
        dataCache.processRole(role);
        
        role = new Role();
        role.setName(domainName + ":role.readers");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user1"));
        members.add(new RoleMember().setMemberName("user_domain.joe"));
        role.setRoleMembers(members);
        roles.add(role);
        dataCache.processRole(role);
        
        role = new Role();
        role.setName(domainName + ":role.editors");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("*"));
        role.setRoleMembers(members);
        roles.add(role);
        dataCache.processRole(role);
        
        role = new Role();
        role.setName(domainName + ":role.writers");
        role.setTrust(domainName + "Trust");
        roles.add(role);
        dataCache.processRole(role);
        
        DomainData domainData = new DomainData();
        domainData.setName(domainName);
        domainData.setRoles(roles);
        
        dataCache.setDomainData(domainData);
        return dataCache;
    }
    
    @Test
    public void testProcessTrustedDomainDataNull() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String identity = "user_domain.user1";
        String[] requestedRoleList = { "coretech:role.admin" };
        
        Set<String> trustedResources = new HashSet<>();
        trustedResources.add("coretech:role.admin");
        trustedResources.add("coretech:role.readers");
        
        store.processTrustedDomain(null, identity, prefix, requestedRoleList, trustedResources, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessTrustedDomainResourcesNull() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        DataCache dataCache = createDataCache("coretech");
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String identity = "user_domain.user1";
        String[] requestedRoleList = { "coretech:role.admin" };
        
        store.processTrustedDomain(dataCache, identity, prefix, requestedRoleList, null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessTrustedDomainMemberRolesNull() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        DataCache dataCache = createDataCache("coretech");
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String identity = "user_domain.user3";
        String[] requestedRoleList = { "coretech:role.admin" };
        
        Set<String> trustedResources = new HashSet<>();
        trustedResources.add("coretech:role.admin");
        trustedResources.add("coretech:role.readers");
        
        store.processTrustedDomain(dataCache, identity, prefix, requestedRoleList, trustedResources, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessTrustedDomainNoRole() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        DataCache dataCache = createDataCache("coretech");
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String identity = "user_domain.user1";
        
        Set<String> trustedResources = new HashSet<>();
        trustedResources.add("coretech:role.admin");
        trustedResources.add("coretech:role.readers");
        
        store.processTrustedDomain(dataCache, identity, prefix, null, trustedResources, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("readers"));
    }
    
    @Test
    public void testProcessTrustedDomainMemberRoleNotValid() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        DataCache dataCache = createDataCache("coretech");
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String identity = "user_domain.user1";
        String[] requestedRoleList = { "coretech:role.writers" }; /* invalid role causing no match */
        
        Set<String> trustedResources = new HashSet<>();
        trustedResources.add("coretech:role.admin");
        trustedResources.add("coretech:role.readers");
        
        store.processTrustedDomain(dataCache, identity, prefix, requestedRoleList, trustedResources, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessTrustedDomainRoleValid() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        DataCache dataCache = createDataCache("coretech");
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String identity = "user_domain.user1";
        String[] requestedRoleList = { "coretech:role.admin" };
        
        Set<String> trustedResources = new HashSet<>();
        trustedResources.add("coretech:role.admin");
        trustedResources.add("coretech:role.readers");
        
        store.processTrustedDomain(dataCache, identity, prefix, requestedRoleList, trustedResources, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
    }
    
    @Test
    public void testProcessTrustedDomainRoleValidWildCard() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        DataCache dataCache = createDataCacheWildCard("coretech");
        
        // first we're going tor process user1
        // which should match all three roles including
        // both wildcard roles
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String identity = "user_domain.user1";
        
        Set<String> trustedResources = new HashSet<>();
        trustedResources.add("coretech:role.admin");
        trustedResources.add("coretech:role.readers");
        trustedResources.add("coretech:role.editors");
        
        store.processTrustedDomain(dataCache, identity, prefix, null,
                trustedResources, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 3);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("editors"));
        assertTrue(accessibleRoles.contains("readers"));
        
        // user_domain.joe should match readers and editors
        
        accessibleRoles.clear();
        identity = "user_domain.joe";
        
        store.processTrustedDomain(dataCache, identity, prefix, null,
                trustedResources, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("readers"));
        assertTrue(accessibleRoles.contains("editors"));
        
        // random service should only match editors
        
        accessibleRoles.clear();
        identity = "athenz.service";
        
        store.processTrustedDomain(dataCache, identity, prefix, null,
                trustedResources, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("editors"));
    }
    
    @Test
    public void testProcessTrustedDomainRoleInvalid() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        DataCache dataCache = createDataCache("coretech");
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech2" + ROLE_POSTFIX; /* invalid prefix to cause no match */
        String identity = "user_domain.user1";
        String[] requestedRoleList = { "coretech:role.readers" };
        
        Set<String> trustedResources = new HashSet<>();
        trustedResources.add("coretech:role.admin");
        trustedResources.add("coretech:role.readers");
        
        store.processTrustedDomain(dataCache, identity, prefix, requestedRoleList, trustedResources, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessStandardMembershipMemberRolesNull() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        
        store.processStandardMembership(null, prefix, null, null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessStandardMembershipRoleCheckNull() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, null, null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("readers"));
    }
    
    @Test
    public void testProcessStandardMembershipRoleValid() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String[] requestedRoleList = { "coretech:role.admin" };
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, null, requestedRoleList, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
    }
    
    @Test
    public void testProcessStandardMembershipRoleExpired() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String[] requestedRoleList = { "coretech:role.admin" };
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", System.currentTimeMillis() - 1000));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, null, requestedRoleList, accessibleRoles, false);
        assertTrue(accessibleRoles.isEmpty());
    }
    
    @Test
    public void testProcessStandardMembershipRoleSuffixValid() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String[] requestedRoleList = { "admin" };
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, null, requestedRoleList, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
    }
    
    @Test
    public void testProcessStandardMembershipRoleInvalid() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech2" + ROLE_POSTFIX; /* invalid prefix causing no match */
        String[] requestedRoleList = { "coretech:role.admin" };
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, null, requestedRoleList, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessStandardMembershipRoleSuffixInValid() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String[] requestedRoleList = { "2admin" };
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, null, requestedRoleList, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessTrustMembershipNoTrustDomainMatch() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        signedDomain = createTenantSignedDomain("weather", "coretech");
        store.processDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String identity = "user_domain.user100";
        
        store.processTrustMembership(store.getCacheStore().getIfPresent("coretech"), identity,
                prefix, null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("tenant.readers"));
    }
    
    @Test
    public void testProcessTrustMembershipNoTrustDomainMatchRoleCheck() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        signedDomain = createTenantSignedDomain("weather", "coretech");
        store.processDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String identity = "user_domain.user100";
        
        String[] requestedRoleList = { "coretech:role.tenant.readers" };

        store.processTrustMembership(store.getCacheStore().getIfPresent("coretech"), identity, prefix,
                requestedRoleList, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("tenant.readers"));
    }
    
    @Test
    public void testProcessTrustMembershipNoTrustDomainNoMatch() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        signedDomain = createTenantSignedDomain("weather", "coretech");
        store.processDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String identity = "user_domain.user400";
        
        store.processTrustMembership(store.getCacheStore().getIfPresent("coretech"), identity,
                prefix, null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessDomainUpdatesFromZMSNoTagHeader() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        clogStore.getClogStoreCommon().setTagHeader(null);
        DataStore store = new DataStore(clogStore, null);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        
        List<SignedDomain> domains = new ArrayList<>();
        domains.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        
        ((MockZMSFileChangeLogStore) store.changeLogStore).setSignedDomains(signedDomains);
        
        boolean result = store.processDomainUpdates();
        assertFalse(result);
    }
    
    @Test
    public void testProcessDomainUpdatesFromZMSInvalidSignedDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");

        DataStore store = new DataStore(clogStore, null);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        signedDomain.setSignature("ABCD"); /* invalidate the signature */
        
        List<SignedDomain> domains = new ArrayList<>();
        domains.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        
        ((MockZMSFileChangeLogStore) store.changeLogStore).setSignedDomains(signedDomains);
        
        boolean result = store.processDomainUpdates();
        assertFalse(result);
    }
   
    @Test
    public void testProcessDomainUpdatesFromZMS() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");

        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        List<SignedDomain> domains = new ArrayList<>();

        /* we're going to create a new domain */
        
        signedDomain = createSignedDomain("sports", "weather");
        domains.add(signedDomain);
        
        /* we're going to update the coretech domain and set new roles */
        
        signedDomain = createSignedDomain("coretech", "weather");

        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user8"));
        role.setRoleMembers(members);
        
        List<Role> roles = new ArrayList<>();
        roles.add(role);
        signedDomain.getDomain().setRoles(roles);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(signedDomain.getDomain()), pkey));
        domains.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        
        ((MockZMSFileChangeLogStore) store.changeLogStore).setSignedDomains(signedDomains);
        
        boolean result = store.processDomainUpdates();
        assertTrue(result);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
        
        accessibleRoles = new HashSet<>();
        store.getAccessibleRoles(data, "coretech", "user_domain.user8", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
        
        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }
    
    @Test
    public void testProcessDomainUpdatesFromZMSWithUpdater() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processDomain(signedDomain, true);
        
        List<SignedDomain> domains = new ArrayList<>();

        // we're going to create a new domain
        
        signedDomain = createSignedDomain("sports", "weather");
        domains.add(signedDomain);
        
        // we're going to update the coretech domain and set new roles
        
        signedDomain = createSignedDomain("coretech", "weather");

        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user8"));
        role.setRoleMembers(members);
        
        List<Role> roles = new ArrayList<>();
        roles.add(role);
        signedDomain.getDomain().setRoles(roles);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(signedDomain.getDomain()), pkey));
        domains.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        
        ((MockZMSFileChangeLogStore) store.changeLogStore).setSignedDomains(signedDomains);

        store.lastDeleteRunTime = System.currentTimeMillis() - 59 * 60 * 1000;
        store.lastCheckRunTime = System.currentTimeMillis() - 9 * 60 * 1000;
        DataUpdater updater = store.new DataUpdater();
        updater.run();
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
        
        accessibleRoles = new HashSet<>();
        store.getAccessibleRoles(data, "coretech", "user_domain.user8", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
        
        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));

        // run again with both checks enabled

        store.lastDeleteRunTime = System.currentTimeMillis() - 61 * 60 * 60 * 1000;
        store.lastCheckRunTime = System.currentTimeMillis() - 11 * 60 * 1000;
        updater = store.new DataUpdater();
        updater.run();

        accessibleRoles = new HashSet<>();
        data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);

        accessibleRoles = new HashSet<>();
        store.getAccessibleRoles(data, "coretech", "user_domain.user8", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));

        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }

    @Test
    public void testDataUpdaterException() {

        DataStore store = Mockito.mock(DataStore.class);
        when(store.processDomainUpdates()).thenThrow(new ResourceException(401, "exc"));
        when(store.processDomainDeletes()).thenThrow(new ResourceException(401, "exc"));
        doThrow(new ResourceException(401, "exc")).when(store).processDomainChecks();

        DataUpdater updater = store.new DataUpdater();
        updater.run();
    }
    
    @Test
    public void testRoleMatchInSetPlain() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        Set<MemberRole> checkSet = new HashSet<>();
        checkSet.add(new MemberRole("writers", 0));
        checkSet.add(new MemberRole("readers", 0));
        
        assertTrue(store.roleMatchInSet("writers", checkSet));
        assertTrue(store.roleMatchInSet("readers", checkSet));
        assertFalse(store.roleMatchInSet("admin", checkSet));
        assertFalse(store.roleMatchInSet("testwriters", checkSet));
        assertFalse(store.roleMatchInSet("writerstest", checkSet));
    }
    
    @Test
    public void testRoleMatchInSetExpiration() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        Set<MemberRole> checkSet = new HashSet<>();
        checkSet.add(new MemberRole("expired", System.currentTimeMillis() - 100000));
        checkSet.add(new MemberRole("notexpired", System.currentTimeMillis() + 100000));
        
        assertFalse(store.roleMatchInSet("expired", checkSet));
        assertTrue(store.roleMatchInSet("notexpired", checkSet));
    }
    
    @Test
    public void testRoleMatchInSetRegex() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        Set<MemberRole> checkSet = new HashSet<>();
        checkSet.add(new MemberRole("coretech:role.readers", 0));
        checkSet.add(new MemberRole("coretech:role.writers", 0));
        checkSet.add(new MemberRole("*:role.update", 0));
        checkSet.add(new MemberRole("weather:role.*", 0));
        
        assertTrue(store.roleMatchInSet("coretech:role.readers", checkSet));
        assertTrue(store.roleMatchInSet("coretech:role.writers", checkSet));
        assertTrue(store.roleMatchInSet("sports:role.update", checkSet));
        assertTrue(store.roleMatchInSet("weather:role.update", checkSet));
        assertFalse(store.roleMatchInSet("coretech:role.admin", checkSet));
    }
    
    @Test
    public void testProcessSingleTrustedDomainRoleNoMatchInSet() {
    
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String role = "coretech:role.writers"; /* invalid role causing no match */
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processSingleTrustedDomainRole(role, prefix, null, memberRoles, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessSingleTrustedDomainRoleAddRoleTrue() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String role = "coretech:role.readers"; /* invalid role causing no match */
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processSingleTrustedDomainRole(role, prefix, null, memberRoles, accessibleRoles, false);
        assertTrue(accessibleRoles.contains("readers"));
    }
    
    @Test
    public void testProcessSingleTrustedDomainRoleAddRoleFalse() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech2" + ROLE_POSTFIX;
        String role = "coretech:role.readers"; /* invalid role causing no match */
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processSingleTrustedDomainRole(role, prefix, null, memberRoles, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testValidDomainListResponseEmpty() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        Set<String> domainList = new HashSet<>();
        assertFalse(store.validDomainListResponse(domainList));
    }
    
    @Test
    public void testValidDomainListResponse() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        Set<String> domainList = new HashSet<>();
        domainList.add("sys.auth");
        domainList.add("coretech");
        domainList.add(userDomain);
        assertTrue(store.validDomainListResponse(domainList));
    }
    
    @Test
    public void testValidDomainListResponseNoSysAuth() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        Set<String> domainList = new HashSet<>();
        domainList.add(userDomain);
        domainList.add("coretech");
        assertFalse(store.validDomainListResponse(domainList));
    }

    @Test
    public void testGetInvalidCurveName() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        ECParameterSpec spec = Mockito.mock(ECParameterSpec.class);
        when(spec.getCurve()).thenReturn(null);
        when(spec.getG()).thenReturn(null);
        when(spec.getH()).thenReturn(new BigInteger("100"));
        when(spec.getN()).thenReturn(new BigInteger("100"));
        assertNull(store.getCurveName(spec, false));
    }

    @Test
    public void testRfcEllipticCurveName() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        assertNull(store.rfcEllipticCurveName(null));
        assertEquals(store.rfcEllipticCurveName("prime256v1"), "P-256");
        assertEquals(store.rfcEllipticCurveName("secp256r1"), "P-256");
        assertEquals(store.rfcEllipticCurveName("secp384r1"), "P-384");
        assertEquals(store.rfcEllipticCurveName("secp521r1"), "P-521");

        // not defined in the spec thus considered as unknown so
        // we keep the name as is

        assertEquals(store.rfcEllipticCurveName("prime192v1"), "prime192v1");
        assertEquals(store.rfcEllipticCurveName("newcurve"), "newcurve");
    }

    @Test
    public void testProcessDomainChecks() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        addDomainToDataStore(store, "coretech");

        // first null which will have no effect

        clogStore.setSignedDomains(null);
        store.processDomainChecks();

        // create a new signed domain

        List<SignedDomain> domains = new ArrayList<>();

        SignedDomain signedDomain = createSignedDomain("sports", "weather");
        domains.add(signedDomain);

        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        clogStore.setSignedDomains(signedDomains);

        // now process check which should return new domain sports that
        // we need to add to our store

        store.processDomainChecks();

        // verify we have two domains now

        assertNotNull(store.getDomainData("sports"));
        assertNotNull(store.getDomainData("coretech"));
    }

    @Test
    public void testProcessDomainChecksGetDomainFailure() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        addDomainToDataStore(store, "coretech");
        addDomainToDataStore(store, "sports");

        // create a new signed domain

        List<SignedDomain> domains = new ArrayList<>();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        domains.add(signedDomain);

        signedDomain = createSignedDomain("sports", "weather");
        domains.add(signedDomain);

        signedDomain = createSignedDomain("finance", "weather");
        domains.add(signedDomain);

        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        clogStore.setSignedDomains(signedDomains);

        // now process check which should return three domains due our
        // our mock set with one new one but then when we try to fetch
        // each one individually we'll get nulls so we'll have no impact
        // on our store and no new domain will be added

        store.processDomainChecks();

        // verify we have two domains still

        assertNotNull(store.getDomainData("sports"));
        assertNotNull(store.getDomainData("coretech"));
        assertNull(store.getDomainData("finance"));
    }

    /**
     * Unit tests from the Apache codec library correspoding to
     * toIntegerBytes function
     * https://github.com/apache/commons-codec/blob/master/src/test/java/org/apache/commons/codec/binary/Base64Test.java
     */
    @Test
    public void testToIntegerBytes1() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        final Base64.Encoder encoder = Base64.getEncoder();

        final String encodedInt1 = "li7dzDacuo67Jg7mtqEm2TRuOMU=";
        final BigInteger bigInt1 = new BigInteger("85739377120809420210425962799" + "0318636601332086981");

        assertEquals(encodedInt1, new String(encoder.encode(store.toIntegerBytes(bigInt1, true))));
    }

    @Test
    public void testToIntegerBytes2() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        final Base64.Encoder encoder = Base64.getEncoder();

        final String encodedInt2 = "9B5ypLY9pMOmtxCeTDHgwdNFeGs=";
        final BigInteger bigInt2 = new BigInteger("13936727572861167254666467268" + "91466679477132949611");

        assertEquals(encodedInt2, new String(encoder.encode(store.toIntegerBytes(bigInt2, true))));
    }

    @Test
    public void testToIntegerBytes3() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        final Base64.Encoder encoder = Base64.getEncoder();

        final String encodedInt3 = "FKIhdgaG5LGKiEtF1vHy4f3y700zaD6QwDS3IrNVGzNp2"
                + "rY+1LFWTK6D44AyiC1n8uWz1itkYMZF0/aKDK0Yjg==";
        final BigInteger bigInt3 = new BigInteger(
                "10806548154093873461951748545" + "1196989136416448805819079363524309897749044958112417136240557"
                        + "4495062430572478766856090958495998158114332651671116876320938126");

        assertEquals(encodedInt3, new String(encoder.encode(store.toIntegerBytes(bigInt3, true))));
    }

    @Test
    public void testToIntegerBytes4() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        final Base64.Encoder encoder = Base64.getEncoder();

        final String encodedInt4 = "ctA8YGxrtngg/zKVvqEOefnwmViFztcnPBYPlJsvh6yKI"
                + "4iDm68fnp4Mi3RrJ6bZAygFrUIQLxLjV+OJtgJAEto0xAs+Mehuq1DkSFEpP3o"
                + "DzCTOsrOiS1DwQe4oIb7zVk/9l7aPtJMHW0LVlMdwZNFNNJoqMcT2ZfCPrfvYv" + "Q0=";
        final BigInteger bigInt4 = new BigInteger(
                "80624726256040348115552042320" + "6968135001872753709424419772586693950232350200555646471175944"
                        + "519297087885987040810778908507262272892702303774422853675597"
                        + "748008534040890923814202286633163248086055216976551456088015"
                        + "338880713818192088877057717530169381044092839402438015097654"
                        + "53542091716518238707344493641683483917");

        assertEquals(encodedInt4, new String(encoder.encode(store.toIntegerBytes(bigInt4, true))));
    }

    @Test
    public void testGetRolesByDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        DataCache dataCache = new DataCache();

        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);

        List<Role> roles = new ArrayList<>();
        roles.add(role);

        DomainData domainData = new DomainData();
        domainData.setRoles(roles);
        dataCache.setDomainData(domainData);

        store.addDomainToCache("coretech", dataCache);
        List<Role> fetchedRoles = store.getRolesByDomain("coretech");

        assertEquals(fetchedRoles.size(), 1);
        assertEquals(fetchedRoles.get(0).getName(), "coretech:role.admin");

        fetchedRoles = store.getRolesByDomain("unknownDomain");
        assertEquals(fetchedRoles.size(), 0);
    }

    @Test
    public void testProcessGroup() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root", pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        // we have no group

        assertNull(store.principalGroupCache.getIfPresent("user.user1"));
        assertNull(store.groupMemberCache.getIfPresent("coretech:group.dev-team"));

        // process a group with no members

        Group group = new Group().setName("coretech:group.dev-team");
        store.processGroup(group);

        assertTrue(store.groupMemberCache.getIfPresent("coretech:group.dev-team").isEmpty());
        assertNull(store.principalGroupCache.getIfPresent("user.user1"));

        // update the group and add a two new members

        List<GroupMember> members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team"));
        members.add(new GroupMember().setMemberName("user.user2")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team"));
        group.setGroupMembers(members);
        store.processGroup(group);

        // create and process another group

        group = new Group().setName("coretech:group.pe-team");
        members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.pe-team"));
        members.add(new GroupMember().setMemberName("coretech.api")
                .setPrincipalType(Principal.Type.SERVICE.getValue())
                .setGroupName("coretech:group.pe-team"));
        group.setGroupMembers(members);
        store.processGroup(group);

        // verify our groups now

        members = store.groupMemberCache.getIfPresent("coretech:group.dev-team");
        assertNotNull(members);
        assertEquals(members.size(), 2);
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user1"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user2"));

        members = store.groupMemberCache.getIfPresent("coretech:group.pe-team");
        assertNotNull(members);
        assertEquals(members.size(), 2);
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user1"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "coretech.api"));

        members = store.principalGroupCache.getIfPresent("user.user1");
        assertNotNull(members);
        assertEquals(members.size(), 2);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.pe-team"));

        members = store.principalGroupCache.getIfPresent("user.user2");
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));

        members = store.principalGroupCache.getIfPresent("coretech.api");
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.pe-team"));

        // delete user2 and add user3

        group = new Group().setName("coretech:group.dev-team");
        members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team"));
        members.add(new GroupMember().setMemberName("user.user3")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team"));
        group.setGroupMembers(members);
        store.processGroup(group);

        members = store.groupMemberCache.getIfPresent("coretech:group.dev-team");
        assertNotNull(members);
        assertEquals(members.size(), 2);
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user1"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user3"));

        members = store.principalGroupCache.getIfPresent("user.user1");
        assertNotNull(members);
        assertEquals(members.size(), 2);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.pe-team"));

        members = store.principalGroupCache.getIfPresent("user.user2");
        assertNotNull(members);
        assertTrue(members.isEmpty());

        members = store.principalGroupCache.getIfPresent("user.user3");
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));

        // add new members that are disabled and expired

        group = new Group().setName("coretech:group.dev-team");
        members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000)));
        members.add(new GroupMember().setMemberName("user.user3")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team"));
        members.add(new GroupMember().setMemberName("user.user4")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setSystemDisabled(1));
        members.add(new GroupMember().setMemberName("user.user5")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setExpiration(Timestamp.fromMillis(1000)));
        members.add(new GroupMember().setMemberName("user.user6")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setExpiration(Timestamp.fromMillis(1000)));
        group.setGroupMembers(members);
        store.processGroup(group);

        members = store.groupMemberCache.getIfPresent("coretech:group.dev-team");
        assertNotNull(members);
        assertEquals(members.size(), 5);
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user1"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user3"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user4"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user5"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user6"));

        members = store.principalGroupCache.getIfPresent("user.user1");
        assertNotNull(members);
        assertEquals(members.size(), 2);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.pe-team"));

        members = store.principalGroupCache.getIfPresent("user.user3");
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));

        // expired and disabled users are not present

        assertNull(store.principalGroupCache.getIfPresent("user.user4"));
        assertNull(store.principalGroupCache.getIfPresent("user.user5"));
        assertNull(store.principalGroupCache.getIfPresent("user.user6"));

        // now make user4 as enabled, expire user 3 and delete user6

        group = new Group().setName("coretech:group.dev-team");
        members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000)));
        members.add(new GroupMember().setMemberName("user.user3")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setExpiration(Timestamp.fromMillis(1000)));
        members.add(new GroupMember().setMemberName("user.user4")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setSystemDisabled(0));
        members.add(new GroupMember().setMemberName("user.user5")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setExpiration(Timestamp.fromMillis(1000)));
        group.setGroupMembers(members);
        store.processGroup(group);

        members = store.groupMemberCache.getIfPresent("coretech:group.dev-team");
        assertNotNull(members);
        assertEquals(members.size(), 4);
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user1"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user3"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user4"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user5"));

        members = store.principalGroupCache.getIfPresent("user.user1");
        assertNotNull(members);
        assertEquals(members.size(), 2);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.pe-team"));

        members = store.principalGroupCache.getIfPresent("user.user3");
        assertNotNull(members);
        assertTrue(members.isEmpty());

        members = store.principalGroupCache.getIfPresent("user.user4");
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));

        assertNull(store.principalGroupCache.getIfPresent("user.user5"));
        assertNull(store.principalGroupCache.getIfPresent("user.user6"));

        // now make user5 as valid as well

        group = new Group().setName("coretech:group.dev-team");
        members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000)));
        members.add(new GroupMember().setMemberName("user.user3")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setExpiration(Timestamp.fromMillis(1000)));
        members.add(new GroupMember().setMemberName("user.user4")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setSystemDisabled(0));
        members.add(new GroupMember().setMemberName("user.user5")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 100000)));
        group.setGroupMembers(members);
        store.processGroup(group);

        members = store.groupMemberCache.getIfPresent("coretech:group.dev-team");
        assertNotNull(members);
        assertEquals(members.size(), 4);
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user1"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user3"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user4"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user5"));

        members = store.principalGroupCache.getIfPresent("user.user1");
        assertNotNull(members);
        assertEquals(members.size(), 2);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.pe-team"));

        members = store.principalGroupCache.getIfPresent("user.user3");
        assertNotNull(members);
        assertTrue(members.isEmpty());

        members = store.principalGroupCache.getIfPresent("user.user4");
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));

        members = store.principalGroupCache.getIfPresent("user.user5");
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));

        // update the pe-team with no changes

        group = new Group().setName("coretech:group.pe-team");
        members = new ArrayList<>();
        members.add(new GroupMember().setMemberName("user.user1")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.pe-team"));
        members.add(new GroupMember().setMemberName("coretech.api")
                .setPrincipalType(Principal.Type.SERVICE.getValue())
                .setGroupName("coretech:group.pe-team"));
        group.setGroupMembers(members);
        store.processGroup(group);

        members = store.groupMemberCache.getIfPresent("coretech:group.pe-team");
        assertNotNull(members);
        assertEquals(members.size(), 2);
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user1"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "coretech.api"));

        members = store.principalGroupCache.getIfPresent("user.user1");
        assertNotNull(members);
        assertEquals(members.size(), 2);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.dev-team"));
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.pe-team"));

        members = store.principalGroupCache.getIfPresent("coretech.api");
        assertNotNull(members);
        assertEquals(members.size(), 1);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(members, "coretech:group.pe-team"));
    }

    @Test
    public void testGetAccessibleRolesWithGroups() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root", pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        final String domainName = "access-domain";
        ZTSTestUtils.setupDomainsWithGroups(store, pkey, domainName, Collections.emptyList());

        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("access-domain1");
        store.getAccessibleRoles(data, "access-domain1", "user.user1", null, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("role1"));
        assertTrue(accessibleRoles.contains("role2"));

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain1", "user.user2", null, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 4);
        assertTrue(accessibleRoles.contains("role1"));
        assertTrue(accessibleRoles.contains("role2"));
        assertTrue(accessibleRoles.contains("role3"));
        assertTrue(accessibleRoles.contains("role4"));

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain1", "user.user3", null, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 4);
        assertTrue(accessibleRoles.contains("role1"));
        assertTrue(accessibleRoles.contains("role2"));
        assertTrue(accessibleRoles.contains("role3"));
        assertTrue(accessibleRoles.contains("role4"));

        data = store.getDataCache("access-domain3");
        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain3", "user.user4", null, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("role5"));

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain3", "user.user5", null, accessibleRoles, false);
        assertTrue(accessibleRoles.isEmpty());

        // sleep for a second so user6 becomes expired

        ZTSTestUtils.sleep(1000);

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain3", "user.user6", null, accessibleRoles, false);
        assertTrue(accessibleRoles.isEmpty());

        // now we're going to delete group1, group4 and group6 so user1 will no longer have access to role1
        // and role2 so we'll have an empty result and user3 will no longer be in role4

        ZTSTestUtils.setupDomainsWithGroups(store, pkey, domainName,
                Arrays.asList("access-domain1:group.group1", "access-domain3:group.group6", "access-domain2:group.group4"));

        data = store.getDataCache("access-domain1");

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain1", "user.user1", null, accessibleRoles, false);
        assertTrue(accessibleRoles.isEmpty());

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain1", "user.user3", null, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 3);
        assertTrue(accessibleRoles.contains("role1"));
        assertTrue(accessibleRoles.contains("role2"));
        assertTrue(accessibleRoles.contains("role3"));
    }

    @Test
    public void testDomainDeleteWithGroups() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root", pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        final String domainName = "access-domain";
        ZTSTestUtils.setupDomainsWithGroups(store, pkey, domainName, Collections.emptyList());

        List<GroupMember> groupMembers = store.principalGroupCache.getIfPresent("user.user1");
        assertEquals(groupMembers.size(), 2);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(groupMembers, "access-domain1:group.group1"));
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(groupMembers, "access-domain3:group.group3"));

        store.deleteDomain("access-domain1");

        groupMembers = store.principalGroupCache.getIfPresent("user.user1");
        assertEquals(groupMembers.size(), 1);
        assertTrue(ZTSTestUtils.verifyGroupMemberGroup(groupMembers, "access-domain3:group.group3"));

        store.deleteDomain("access-domain2");
        store.deleteDomain("access-domain3");

        groupMembers = store.principalGroupCache.getIfPresent("user.user1");
        assertTrue(groupMembers.isEmpty());
    }

    @Test
    public void testProcessGroupDeletedMembersNull() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root", pkey, "0");
        DataStore store = new DataStore(clogStore, null);
        store.loadAthenzPublicKeys();

        // if we pass null for the members then we return right
        // away so sno exceptions even if we pass null for the group name

        store.processGroupDeletedMembers(null, null);
    }

    @Test
    public void testRoleMatchInTrustSet() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root", pkey, "0");
        DataStore store = new DataStore(clogStore, null);

        Set<String> memberRoles = new HashSet<>();
        memberRoles.add("athenz:role.readers");
        memberRoles.add("sports:role.writers");
        memberRoles.add("*:role.testers");

        assertTrue(store.roleMatchInTrustSet("athenz:role.readers", memberRoles));
        assertTrue(store.roleMatchInTrustSet("sports:role.writers", memberRoles));

        assertFalse(store.roleMatchInTrustSet("athenz:role.poets", memberRoles));
        assertFalse(store.roleMatchInTrustSet("sports:role.readers", memberRoles));

        assertTrue(store.roleMatchInTrustSet("athenz:role.testers", memberRoles));
        assertTrue(store.roleMatchInTrustSet("sports:role.testers", memberRoles));
    }
}
