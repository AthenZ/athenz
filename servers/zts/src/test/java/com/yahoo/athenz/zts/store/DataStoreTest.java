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
package com.yahoo.athenz.zts.store;

import static com.yahoo.athenz.common.ServerCommonConsts.PROP_ATHENZ_CONF;
import static com.yahoo.athenz.common.ServerCommonConsts.PROP_USER_DOMAIN;
import static com.yahoo.athenz.zts.ZTSConsts.ZTS_ISSUE_ROLE_CERT_TAG;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.primitives.Bytes;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSTestUtils;
import com.yahoo.rdl.Timestamp;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.mockito.ArgumentMatchers;
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
    private Metric ztsMetric;
    private String userDomain;
    protected ObjectMapper jsonMapper;

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
    private static final byte[] PERIOD = { 46 };

    @BeforeClass
    public void setUpClass() {
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory");
        System.setProperty(FilePrivateKeyStore.ATHENZ_PROP_PRIVATE_KEY,
                "src/test/resources/unit_test_zts_private.pem");
        System.setProperty(PROP_ATHENZ_CONF,  "src/test/resources/athenz.conf");

        // set up our metric class

        ztsMetric = new com.yahoo.athenz.common.metrics.impl.NoOpMetric();

        // set up our json mapper

        jsonMapper = new ObjectMapper();
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        assertNotNull(store);
        assertEquals(store.delDomainRefreshTime, 3600);
        assertEquals(store.updDomainRefreshTime, 60);

        System.setProperty("athenz.zts.zms_domain_update_timeout", "60");
        System.setProperty("athenz.zts.zms_domain_delete_timeout", "50");
        System.setProperty("athenz.zts.zms_domain_check_timeout", "45");
        store = new DataStore(clogStore, null, ztsMetric);
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
            new DataStore(clogStore, null, ztsMetric);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Unable to initialize public keys"));
        }

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz_no_zts_publickeys.conf");
        try {
            new DataStore(clogStore, null, ztsMetric);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Unable to initialize public keys"));
        }

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz_zms_invalid_publickeys.conf");
        try {
            new DataStore(clogStore, null, ztsMetric);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Unable to initialize public keys"));
        }

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz_zts_invalid_publickeys.conf");
        try {
            new DataStore(clogStore, null, ztsMetric);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Unable to initialize public keys"));
        }

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz_invalid.conf");
        try {
            new DataStore(clogStore, null, ztsMetric);
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Unable to initialize public keys"));
        }

        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz_invalid_zts_pem_publickey.conf");
        try {
            new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(null);
        
        Set<String> zmsDomainList = store.changeLogStore.getServerDomainList();
        assertNull(zmsDomainList);
    }
    
    @Test
    public void testLoadZMSPublicKeys() {
        
        System.setProperty(PROP_ATHENZ_CONF, "src/test/resources/athenz.conf");
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();
        PublicKey zmsKey = store.zmsPublicKeyCache.getIfPresent("0");
        assertNotNull(zmsKey);
        assertNull(store.zmsPublicKeyCache.getIfPresent("1"));
    }
    
    @Test
    public void testSaveLastModificationTime() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.changeLogStore.setLastModificationTimestamp("23456");

        String data = null;
        File f = new File("/tmp/zts_server_unit_tests/zts_root/.lastModTime");
        try {
            data = Files.readString(f.toPath());
        } catch (IOException e) {
            fail();
        }
        
        assertEquals(data, "{\"lastModTime\":\"23456\"}");
    }
    
    @Test
    public void testRemovePublicKeys() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        
        store.removePublicKeys(null);
        assertEquals(store.publicKeyCache.size(), 1);
        assertTrue(store.publicKeyCache.containsKey("coretech.storage_0"));
    }
    
    @Test
    public void testAddPublicKeys() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.publicKeyCache.put("coretech.storage_0", "PublicKey0");
        
        store.addPublicKeys(null);
        assertEquals(store.publicKeyCache.size(), 1);
        assertTrue(store.publicKeyCache.containsKey("coretech.storage_0"));
    }
    
    @Test
    public void testGetPublicKey() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        assertEquals(store.generateServiceKeyName("coretech", "storage", "3"), "coretech.storage_3");
    }
    
    @Test
    public void testGenerateServiceKeyNameLongValues() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        String domain = "coretech0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        String service = "coretech0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        String expectedValue = domain + "." + service + "_2";
        assertEquals(store.generateServiceKeyName(domain, service, "2"), expectedValue);
    }
    
    @Test
    public void testCheckRoleSet() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        Set<String> accessibleRoles = new HashSet<>();
        store.addRoleToList("sports:role.admin", "coretech:role.", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testAddRoleToList() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        store.addRoleToList("coretech:role.admin", "coretech:role.", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
    }
    
    @Test
    public void testAddRoleToListSingleRoleSpecified() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        String[] requestedRoleList = { "admin" };
        store.addRoleToList("coretech:role.admin", "coretech:role.", requestedRoleList, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));

        accessibleRoles.clear();
        store.addRoleToList("coretech:role.admin", "coretech:role.", requestedRoleList, true, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));

        accessibleRoles.clear();
        store.addRoleToList("coretech:role.cluster-admin", "coretech:role.", requestedRoleList, true, accessibleRoles, false);
        assertTrue(accessibleRoles.isEmpty());

        accessibleRoles.clear();
        String[] updatedRequestedRoleList = { "admin", "cluster-admin" };
        store.addRoleToList("coretech:role.cluster-admin", "coretech:role.", updatedRequestedRoleList, true, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("cluster-admin"));

        accessibleRoles.clear();
        store.addRoleToList("coretech:role.admin", "coretech:role.", updatedRequestedRoleList, true, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));

        accessibleRoles.clear();
        store.addRoleToList("coretech:role.cluster-reader", "coretech:role.", requestedRoleList, true, accessibleRoles, false);
        assertTrue(accessibleRoles.isEmpty());
    }
    
    @Test
    public void testAddRoleToListSingleRoleSpecifiedNoMatch() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        String[] requestedRoleList = { "admin2" };
        store.addRoleToList("coretech:role.admin", "coretech:role.", requestedRoleList, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testAddRoleToListMultipleRoleSpecified() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        String[] requestedRoleList = { "admin2", "admin3", "admin" };
        store.addRoleToList("coretech:role.admin", "coretech:role.", requestedRoleList, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
    }
    
    @Test
    public void testAddRoleToListMultipleRoleSpecifiedNoMatch() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        String[] requestedRoleList = { "admin2", "admin3", "admin4" };
        store.addRoleToList("coretech:role.admin", "coretech:role.", requestedRoleList, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testAddDomainToCacheNewDomain() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(null);
        addDomainToDataStore(store, "coretech");
        
        /* this should throw an exception when obtaining domain list from ZMS */
        
        assertFalse(store.processDomainDeletes());
    }

    @Test
    public void testProcessDomainDeletesZMSInvalidResponse() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, false, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("writers"));
    }
    
    @Test
    public void testGetAccessibleRolesWildCards() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomainWildCardMembers("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, false, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("writers"));
        assertTrue(accessibleRoles.contains("all"));
        
        accessibleRoles.clear();
        store.getAccessibleRoles(data, "coretech", "user_domain.user3", null, false, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 3);
        assertTrue(accessibleRoles.contains("readers"));
        assertTrue(accessibleRoles.contains("writers"));
        assertTrue(accessibleRoles.contains("all"));
        
        accessibleRoles.clear();
        store.getAccessibleRoles(data, "coretech", "user_domain.user5", null, false, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("writers"));
        assertTrue(accessibleRoles.contains("all"));
        
        accessibleRoles.clear();
        store.getAccessibleRoles(data, "coretech", "athenz.service", null, false, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("all"));
        
        // make sure the prefix is fully matched
        
        accessibleRoles.clear();
        store.getAccessibleRoles(data, "coretech", "athenz.use", null, false, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("all"));
    }
    
    @Test
    public void testGetAccessibleRolesInvalidDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, false, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testGetAccessibleRolesSpecifiedRole() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        String[] requestedRoleList = { "coretech:role.admin" };
        store.getAccessibleRoles(data, "coretech", "user_domain.user", requestedRoleList, false, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
    }
    
    @Test
    public void testGetAccessibleRolesNoRoles() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.nonexistentuser", null, false, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testGetAccessibleRolesMultipleRoles() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user", null, false, accessibleRoles, false);
        
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }

    @Test
    public void testGetRolesForPrincipal() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);

        // an unknown domain will return an empty set

        Set<String> roles = store.getRolesForPrincipal("sports", "user_domain.user1");
        assertTrue(roles.isEmpty());

        roles = store.getRolesForPrincipal("coretech", "user_domain.user1");
        assertEquals(roles.size(), 1);
        assertTrue(roles.contains("writers"));
    }

    @Test
    public void testStoreInitNoLastModTimeLocalDomainDelete() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.changeLogStore.setLastModificationTimestamp(null);
        
        /* this domain will be deleted since our last refresh is 0 */

        addDomainToDataStore(store, "coretech");
        File file = new File("/tmp/zts_server_unit_tests/zts_root/coretech");
        assertTrue(file.exists());
        
        /* initialize our datastore which will call init */
        
        clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        store = new DataStore(clogStore, null, ztsMetric);
        assertNull(store.getDomainData("coretech"));
        assertFalse(file.exists());
    }
    
    @Test
    public void testStoreInitNoLocalDomains() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");

        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        store.getAccessibleRoles(data, "coretech", "user_domain.user", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
        
        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }
    
    @Test
    public void testStoreInitNoLastModTimeDomainUpdateFailure() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        clogStore.getClogStoreCommon().setTagHeader(null);

        DataStore store = new DataStore(clogStore, null, ztsMetric);
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

        DataStore setupStore = new DataStore(clogStore, null, ztsMetric);
        setupStore.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        /* create a new store instance */
        
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
        
        accessibleRoles = new HashSet<>();
        store.getAccessibleRoles(data, "coretech", "user_domain.user8", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
        
        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }
    
    @Test
    public void testStoreInitLastModTimeDomainCorrupted() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");

        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.changeLogStore.setLastModificationTimestamp("2014-01-01T12:00:00");
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        signedDomain.setSignature("ABCD"); /* invalid signature which will cause domain to be deleted */
        
        store.changeLogStore.saveLocalDomain("coretech", signedDomain);
        
        store = new DataStore(clogStore, null, ztsMetric);

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
        store.getAccessibleRoles(data, "coretech", "user_domain.user", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
        
        File file = new File("/tmp/zts_server_unit_tests/zts_root/coretech");
        assertFalse(file.exists());
        
        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }

    @Test
    public void testProcessDomainRoles() {
        testProcessDomainRoles(false, false);
        testProcessDomainRoles(true, true);
        testProcessDomainRoles(true, false);
    }

    private void testProcessDomainRoles(boolean existingDomainWithNullRoles, boolean existingDomainWithEmptyRoles) {
    
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root", pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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

        // if configured, create an empty domain with no roles
        // in our cache (either null roles or empty set)

        if (existingDomainWithNullRoles) {
            DomainData existingDomain = new DomainData();
            existingDomain.setName("coretech");
            if (existingDomainWithEmptyRoles) {
                existingDomain.setRoles(Collections.emptyList());
            }
            store.processDomainData(existingDomain);
        }

        store.processDomainRoles(domainData, dataCache);
        assertEquals(dataCache.getMemberRoleSet("user_domain.user").size(), 2);
        
        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.admin", 0)));
        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.readers", 0)));
    }

    @Test
    public void testProcessDomainRolesDelete() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

        DomainData domainData = getDomainData(true);
        store.processDomainData(domainData);

        DataCache dataCache = store.getDataCache("coretech");
        assertEquals(dataCache.getMemberRoleSet("user_domain.user").size(), 2);

        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.admin", 0)));
        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.readers", 0)));

        // Getting getRolesRequireRoleCert will return the tagged role
        List<String> rolesRequireRoleCert = store.requireRoleCertCache.getRolesRequireRoleCert("user_domain.user");
        assertEquals(rolesRequireRoleCert.size(), 1);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.readers");

        // Now remove the tagged role and verify cache is updated
        domainData = getDomainData(false);
        store.processDomainData(domainData);
        dataCache = store.getDataCache("coretech");
        assertEquals(dataCache.getMemberRoleSet("user_domain.user").size(), 1);

        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.admin", 0)));

        rolesRequireRoleCert = store.requireRoleCertCache.getRolesRequireRoleCert("user_domain.user");
        assertEquals(rolesRequireRoleCert.size(), 0);
    }

    private DomainData getDomainData(boolean withRequireRoleCertTagRole) {
        List<Role> roles = new ArrayList<>();

        Role role1 = new Role();
        role1.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role1.setRoleMembers(members);
        roles.add(role1);

        if (withRequireRoleCertTagRole) {
            Role role2 = new Role();
            role2.setName("coretech:role.readers");
            members = new ArrayList<>();
            members.add(new RoleMember().setMemberName("user_domain.user"));
            role2.setRoleMembers(members);

            TagValueList tagValueList = new TagValueList();
            tagValueList.setList(Collections.singletonList("true"));
            Map<String, TagValueList> tagsIssueRoleCert = new HashMap<>();
            tagsIssueRoleCert.put("zts.IssueRoleCerts", tagValueList);
            role2.setTags(tagsIssueRoleCert);
            roles.add(role2);
        }

        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domainData.setRoles(roles);
        return domainData;
    }

    @Test
    public void testProcessDomainRolesWithRequireRole() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        // Set tag
        Map<String, TagValueList> tags = new HashMap<>();
        tags.put(ZTS_ISSUE_ROLE_CERT_TAG, new TagValueList().setList(Collections.singletonList("true")));
        role.setTags(tags);
        roles.add(role);

        role = new Role();
        role.setName("coretech:role.different.tag");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        // Set tag
        tags = new HashMap<>();
        tags.put("othertag", new TagValueList().setList(Collections.singletonList("true")));
        role.setTags(tags);
        roles.add(role);

        role = new Role();
        role.setName("coretech:role.tag.set.false");
        members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user"));
        role.setRoleMembers(members);
        // Set tag
        tags = new HashMap<>();
        tags.put(ZTS_ISSUE_ROLE_CERT_TAG, new TagValueList().setList(Collections.singletonList("false")));
        role.setTags(tags);
        roles.add(role);

        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        domainData.setRoles(roles);

        DataCache dataCache = new DataCache();

        store.processDomainRoles(domainData, dataCache);
        assertEquals(dataCache.getMemberRoleSet("user_domain.user").size(), 4);

        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.admin", 0)));
        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.readers", 0)));
        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.different.tag", 0)));
        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("coretech:role.tag.set.false", 0)));

        List<String> rolesRequireRoleCert = store.getRolesRequireRoleCert("user_domain.user");
        assertEquals(rolesRequireRoleCert.size(), 1);
        assertEquals(rolesRequireRoleCert.get(0), "coretech:role.readers");
    }

    @Test
    public void testProcessDomainRolesNullRoles() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        DomainData domainData = new DomainData();
        domainData.setName("coretech");

        DataCache dataCache = new DataCache();
        
        store.processDomainRoles(domainData, dataCache);
        assertEquals(dataCache.getMemberCount(), 0);
    }
    
    @Test
    public void testProcessDomainPolicies() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        
        store.processDomainPolicies(domainData, dataCache);
        assertEquals(dataCache.getMemberRoleSet("user_domain.user").size(), 1);
        assertTrue(dataCache.getMemberRoleSet("user_domain.user")
                .contains(new MemberRole("sports:role.readers", 0)));
    }

    @Test
    public void testProcessDomainPoliciesInactive() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root", pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

        List<com.yahoo.athenz.zms.Policy> policies = new ArrayList<>();

        com.yahoo.athenz.zms.Policy policy = new com.yahoo.athenz.zms.Policy();
        policy.setActive(false);
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

        store.processDomainPolicies(domainData, dataCache);

        // we should not get any members

        assertNull(dataCache.getMemberRoleSet("user_domain.user"));
    }

    @Test
    public void testProcessDomainPoliciesNullPolicies() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
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

    private JWSDomain createJWSDomain(String domainName, String tenantDomain, String keyId) {

        SignedDomain signedDomain = createSignedDomain(domainName, tenantDomain);
        return signJwsDomain(signedDomain.getDomain(), keyId);
    }

    private JWSDomain signJwsDomain(DomainData domainData, String keyId) {

        JWSDomain jwsDomain = null;
        try {
            // spec requires base64 url encoder without any padding

            final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

            // generate our domain data payload and encode it

            final byte[] jsonDomain = jsonMapper.writeValueAsBytes(domainData);
            final byte[] encodedDomain = encoder.encode(jsonDomain);

            // generate our protected header - just includes the key id + algorithm

            final String protectedHeader = "{\"kid\":\"" + keyId + "\",\"alg\":\"ES256\"}";
            final byte[] encodedHeader = encoder.encode(protectedHeader.getBytes(StandardCharsets.UTF_8));

            // combine protectedHeader . payload and sign the result

            final byte[] signature = encoder.encode(Crypto.sign(
                    Bytes.concat(encodedHeader, PERIOD, encodedDomain), pkey, Crypto.SHA256));

            // our header contains a single entry with the keyid

            final Map<String, String> headerMap = new HashMap<>();
            headerMap.put("kid", "0");

            jwsDomain = new JWSDomain().setHeader(headerMap)
                    .setPayload(new String(encodedDomain))
                    .setProtectedHeader(new String(encodedHeader))
                    .setSignature(new String(signature));

        } catch (Exception ignored) {
        }
        return jwsDomain;
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, false);
        
        File file = new File("/tmp/zts_server_unit_tests/zts_root/coretech");
        assertFalse(file.exists());
        
        assertNotNull(store.getDomainData("coretech"));
    }
    
    @Test
    public void testProcessLocalSignedDomain() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        assertTrue(store.processSignedDomain(signedDomain, true));
        
        store = new DataStore(clogStore, null, ztsMetric);
        assertTrue(store.processLocalDomain("coretech"));
        assertNotNull(store.getDomainData("coretech"));
    }

    @Test
    public void testProcessLocalJWSDomain() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "0");
        assertTrue(store.processJWSDomain(jwsDomain, true));

        store = new DataStore(clogStore, null, ztsMetric);
        assertTrue(store.processLocalJWSDomain("coretech"));
        assertNotNull(store.getDomainData("coretech"));
    }

    @Test
    public void testProcessLocalJWSDomainDisabled() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        signedDomain.getDomain().setEnabled(false);
        JWSDomain jwsDomain = signJwsDomain(signedDomain.getDomain(), "0");
        assertTrue(store.processJWSDomain(jwsDomain, false));
        assertTrue(store.processJWSDomain(jwsDomain, true));

        // verify that we don't have the data in our cache

        assertNull(store.getDomainData("coretech"));
    }

    @Test
    public void testProcessLocalJWSDomainInvalidPayload() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;
        store.loadAthenzPublicKeys();

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "0");
        jwsDomain.setPayload("invalid-payload");
        clogStore.saveLocalDomain("coretech", jwsDomain);

        assertFalse(store.processLocalDomain("coretech"));
    }

    @Test
    public void testProcessLocalJWSDomainException() {

        ChangeLogStore clogStore = Mockito.mock(ChangeLogStore.class);
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;
        store.loadAthenzPublicKeys();

        Mockito.when(clogStore.getLocalJWSDomain("coretech")).thenThrow(new IllegalArgumentException());
        assertFalse(store.processLocalDomain("coretech"));
    }

    @Test
    public void testProcessLocalDomainInvalidFile() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        assertFalse(store.processLocalDomain("coretech"));
    }
    
    @Test
    public void testProcessLocalDomains() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore setupStore = new DataStore(clogStore, null, ztsMetric);
        setupStore.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        signedDomain = createSignedDomain("sports", "weather");
        setupStore.processSignedDomain(signedDomain, true);
        
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
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

        DataStore setupStore = new DataStore(clogStore, null, ztsMetric);
        setupStore.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        signedDomain = createSignedDomain("sports", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        signedDomain = createSignedDomain("finance", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        signedDomain = createSignedDomain("news", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        signedDomain = createSignedDomain("fantasy", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        signedDomain = createSignedDomain("ads", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        signedDomain = createSignedDomain("platforms", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        signedDomain = createSignedDomain("dev", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        try (PrintWriter out = new PrintWriter("/tmp/zts_server_unit_tests/zts_root/athenz")) {
            out.write("{\"domain\":\"athenz\"}");
        }

        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore setupStore = new DataStore(clogStore, null, ztsMetric);
        setupStore.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        signedDomain = createSignedDomain("sports", "weather");
        setupStore.processSignedDomain(signedDomain, true);
        
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore setupStore = new DataStore(clogStore, null, ztsMetric);
        setupStore.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        setupStore.processSignedDomain(signedDomain, true);

        signedDomain = createSignedDomain("sports", "weather");
        setupStore.processSignedDomain(signedDomain, true);
        
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore setupStore = new DataStore(clogStore, null, ztsMetric);
        setupStore.loadAthenzPublicKeys();

        // create 8 records so our 1/4 threashold for bad domains is 2

        setupStore.processSignedDomain(createSignedDomain("coretech", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("sports", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("mail", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("fantasy", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("profile", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("news", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("politics", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("finance", "weather"), true);

        DataStore store = new DataStore(clogStore, null, ztsMetric);
        List<String> zmsList = new ArrayList<>(Arrays.asList("coretech", "sports", "mail", "fantasy", "profile",
                "news", "politics", "finance", "invalid"));
        ((MockZMSFileChangeLogStore) store.changeLogStore).setDomainList(zmsList);

        int badDomains = store.processLocalDomains(zmsList);
        assertEquals(badDomains, 1);
    }

    @Test
    public void testProcessLocalDomainsInvalidLocalDomainRefreshRequired() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore setupStore = new DataStore(clogStore, null, ztsMetric);
        setupStore.loadAthenzPublicKeys();

        setupStore.processSignedDomain(createSignedDomain("coretech", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("sports", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("mail", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("fantasy", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("profile", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("news", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("politics", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("finance", "weather"), true);

        DataStore store = new DataStore(clogStore, null, ztsMetric);
        List<String> zmsList = new ArrayList<>(Arrays.asList("coretech", "sports", "mail", "fantasy", "profile",
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
        DataStore setupStore = new DataStore(clogStore, null, ztsMetric);
        setupStore.loadAthenzPublicKeys();

        setupStore.processSignedDomain(createSignedDomain("coretech", "weather"), true);
        setupStore.processSignedDomain(createSignedDomain("sports", "weather"), true);

        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        List<SignedDomain> list = new ArrayList<>();
        
        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        list.add(signedDomain);
        
        signedDomain = createSignedDomain("sports", "weather");
        list.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(list);

        assertTrue(store.processSignedDomains(signedDomains));
        assertNotNull(store.getDomainData("coretech"));
        assertNotNull(store.getDomainData("sports"));
    }
    
    @Test
    public void testProcessSignedDomainsNullList() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

        assertTrue(store.processSignedDomains(null));
    }
    
    @Test
    public void testProcessSignedDomainsEmptyList() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(null);

        assertTrue(store.processSignedDomains(signedDomains));
    }
    
    @Test
    public void testProcessSignedDomainsInvalidDomainWithSuccess() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
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

        assertTrue(store.processSignedDomains(signedDomains));
    }
    
    @Test
    public void testProcessSignedDomainsAllInvalidDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        List<SignedDomain> list = new ArrayList<>();
        
        // if we have only failures, then our result
        // is going to be failure
        
        SignedDomain signedDomain = createSignedDomain("sports", "weather");
        signedDomain.setSignature("Invalid0");
        list.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(list);

        assertFalse(store.processSignedDomains(signedDomains));
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        
        store.processStandardMembership(null, prefix, null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessStandardMembershipRoleCheckNull() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("readers"));
    }
    
    @Test
    public void testProcessStandardMembershipRoleValid() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String[] requestedRoleList = { "coretech:role.admin" };
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, requestedRoleList, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
    }
    
    @Test
    public void testProcessStandardMembershipRoleExpired() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String[] requestedRoleList = { "coretech:role.admin" };
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", System.currentTimeMillis() - 1000));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, requestedRoleList, false, accessibleRoles, false);
        assertTrue(accessibleRoles.isEmpty());
    }
    
    @Test
    public void testProcessStandardMembershipRoleSuffixValid() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String[] requestedRoleList = { "admin" };
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, requestedRoleList, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
    }
    
    @Test
    public void testProcessStandardMembershipRoleInvalid() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech2" + ROLE_POSTFIX; /* invalid prefix causing no match */
        String[] requestedRoleList = { "coretech:role.admin" };
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, requestedRoleList, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessStandardMembershipRoleSuffixInValid() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        
        Set<String> accessibleRoles = new HashSet<>();
        String prefix = "coretech" + ROLE_POSTFIX;
        String[] requestedRoleList = { "2admin" };
        
        Set<MemberRole> memberRoles = new HashSet<>();
        memberRoles.add(new MemberRole("coretech:role.admin", 0));
        memberRoles.add(new MemberRole("coretech:role.readers", 0));
        
        store.processStandardMembership(memberRoles, prefix, requestedRoleList, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
    }
    
    @Test
    public void testProcessTrustMembershipNoTrustDomainMatch() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
        signedDomain = createTenantSignedDomain("weather", "coretech");
        store.processSignedDomain(signedDomain, true);
        
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
        signedDomain = createTenantSignedDomain("weather", "coretech");
        store.processSignedDomain(signedDomain, true);
        
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
        signedDomain = createTenantSignedDomain("weather", "coretech");
        store.processSignedDomain(signedDomain, true);
        
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        
        List<SignedDomain> domains = new ArrayList<>();
        domains.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        
        ((MockZMSFileChangeLogStore) store.changeLogStore).setSignedDomains(signedDomains);

        assertFalse(store.processDomainUpdates());
    }
    
    @Test
    public void testProcessDomainUpdatesFromZMSInvalidSignedDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");

        DataStore store = new DataStore(clogStore, null, ztsMetric);

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        signedDomain.setSignature("ABCD"); /* invalidate the signature */
        
        List<SignedDomain> domains = new ArrayList<>();
        domains.add(signedDomain);
        
        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        
        ((MockZMSFileChangeLogStore) store.changeLogStore).setSignedDomains(signedDomains);

        assertFalse(store.processDomainUpdates());
    }
   
    @Test
    public void testProcessDomainUpdatesFromZMS() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");

        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
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

        assertTrue(store.processDomainUpdates());

        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
        
        accessibleRoles = new HashSet<>();
        store.getAccessibleRoles(data, "coretech", "user_domain.user8", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
        
        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }
    
    @Test
    public void testProcessSignedDomainUpdatesFromZMSWithUpdater() {
        
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);
        
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
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);
        
        accessibleRoles = new HashSet<>();
        store.getAccessibleRoles(data, "coretech", "user_domain.user8", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));
        
        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, false, accessibleRoles, false);
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
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);

        accessibleRoles = new HashSet<>();
        store.getAccessibleRoles(data, "coretech", "user_domain.user8", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));

        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, false, accessibleRoles, false);
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

        DataUpdater updater1 = store.new DataUpdater();
        updater1.run();

        store.jwsDomainSupport = true;
        DataUpdater updater2 = store.new DataUpdater();
        updater2.run();
    }
    
    @Test
    public void testRoleMatchInSetPlain() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        Set<String> domainList = new HashSet<>();
        assertFalse(store.validDomainListResponse(domainList));
    }
    
    @Test
    public void testValidDomainListResponse() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        Set<String> domainList = new HashSet<>();
        domainList.add(userDomain);
        domainList.add("coretech");
        assertFalse(store.validDomainListResponse(domainList));
    }

    @Test
    public void testGetInvalidCurveName() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
    public void testSignedProcessDomainChecks() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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

        // with this setup process our refresh domains

        long now = System.currentTimeMillis() / 1000;
        Map<String, DomainAttributes> domainMap = new HashMap<>();
        domainMap.put("coretech", new DomainAttributes().setFetchTime(now - store.domainFetchRefreshTime - 1));
        domainMap.put("sports", new DomainAttributes().setFetchTime(now - store.domainFetchRefreshTime - 1));
        clogStore.setLocalDomainAttributeList(domainMap);

        // now process check which should return new domain sports that
        // we need to add to our store

        store.processDomainChecks();

        // verify we have two domains now

        assertNotNull(store.getDomainData("sports"));
        assertNotNull(store.getDomainData("coretech"));
    }

    @Test
    public void testProcessSignedDomainChecksGetDomainFailure() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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

        // with this setup, coretech should be processed, sports should be
        // skipped, finance should be processed, but it's null so skipped

        long now = System.currentTimeMillis() / 1000;
        Map<String, DomainAttributes> domainMap = new HashMap<>();
        domainMap.put("coretech", new DomainAttributes().setFetchTime(now - store.domainFetchRefreshTime - 1));
        domainMap.put("sports", new DomainAttributes().setFetchTime(now));
        domainMap.put("finance", new DomainAttributes().setFetchTime(now - store.domainFetchRefreshTime - 1));
        clogStore.setLocalDomainAttributeList(domainMap);

        // now process check which should return three domains due our
        // mock set with one new one but then when we try to fetch
        // each one individually we'll get nulls, so we'll have no impact
        // on our store and no new domain will be added

        store.processDomainChecks();

        // verify we have two domains still

        assertNotNull(store.getDomainData("sports"));
        assertNotNull(store.getDomainData("coretech"));
        assertNull(store.getDomainData("finance"));
    }

    @Test
    public void testGetRolesByDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

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
    public void testGetPubKeysByService() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

        List<PublicKeyEntry> pubKeys = List.of(
                new PublicKeyEntry().setKey(ZTS_Y64_CERT0).setId("0"),
                new PublicKeyEntry().setKey(ZTS_Y64_CERT1).setId("1")
        );

        ServiceIdentity service = new ServiceIdentity()
                .setName("coretech.storage")
                .setPublicKeys(pubKeys);

        List<ServiceIdentity> services = new ArrayList<>();
        services.add(service);

        DataCache dataCache = new DataCache();
        dataCache.processServiceIdentity(service);

        DomainData domainData = new DomainData();
        domainData.setServices(services);
        dataCache.setDomainData(domainData);

        store.addDomainToCache("coretech", dataCache);

        // Happy path
        List<PublicKeyEntry> result = store.getPubKeysByService("coretech", "storage");
        assertEquals(result.size(), 2);
        assertListContains(result, i -> i.getId().equals("0") && i.getKey().equals(ZTS_Y64_CERT0), "cert0 not found");
        assertListContains(result, i -> i.getId().equals("1") && i.getKey().equals(ZTS_Y64_CERT1), "cert1 not found");

        // Domain not found
        result = store.getPubKeysByService("unknown", "storage");
        assertEquals(result.size(), 0);

        // Service not found
        result = store.getPubKeysByService("coretech", "unknown");
        assertEquals(result.size(), 0);
    }

    @Test
    public void testProcessGroup() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root", pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

        // we have no group

        assertNull(store.principalGroupCache.getIfPresent("user.user1"));
        assertNull(store.groupMemberCache.getIfPresent("coretech:group.dev-team"));
        assertNull(store.getPrincipalGroups("user.user1", "coretech", null));
        assertNull(store.getPrincipalGroups("user.user1", "coretech", Collections.singleton("dev-team")));

        // process a group with no members

        Group group = new Group().setName("coretech:group.dev-team");
        store.processGroup(group);

        assertTrue(store.groupMemberCache.getIfPresent("coretech:group.dev-team").isEmpty());
        assertNull(store.principalGroupCache.getIfPresent("user.user1"));
        assertNull(store.getPrincipalGroups("user.user1", "coretech", null));
        assertNull(store.getPrincipalGroups("user.user1", "coretech", Collections.singleton("dev-team")));

        // update the group and add two new members

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

        List<String> groupNames = store.getPrincipalGroups("user.user1", "coretech", null);
        assertEquals(groupNames.size(), 2);
        assertTrue(groupNames.contains("dev-team"));
        assertTrue(groupNames.contains("pe-team"));

        groupNames = store.getPrincipalGroups("user.user1", "coretech", Collections.singleton("dev-team"));
        assertEquals(groupNames.size(), 1);
        assertTrue(groupNames.contains("dev-team"));

        assertNull(store.getPrincipalGroups("user.user1", "coretech", Collections.singleton("prod-team")));
        assertNull(store.getPrincipalGroups("user.user1", "unknown-domain", Collections.singleton("dev-team")));

        groupNames = store.getPrincipalGroups("user.user2", "coretech", null);
        assertEquals(groupNames.size(), 1);
        assertTrue(groupNames.contains("dev-team"));

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

        groupNames = store.getPrincipalGroups("user.user1", "coretech", null);
        assertEquals(groupNames.size(), 2);
        assertTrue(groupNames.contains("dev-team"));
        assertTrue(groupNames.contains("pe-team"));

        assertNull(store.getPrincipalGroups("user.user2", "coretech", null));

        // add new members that are disabled, expired and soon to be expired

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
        members.add(new GroupMember().setMemberName("user.user7")
                .setPrincipalType(Principal.Type.USER.getValue())
                .setGroupName("coretech:group.dev-team")
                .setExpiration(Timestamp.fromMillis(System.currentTimeMillis() + 2000)));
        group.setGroupMembers(members);
        store.processGroup(group);

        members = store.groupMemberCache.getIfPresent("coretech:group.dev-team");
        assertNotNull(members);
        assertEquals(members.size(), 6);
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user1"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user3"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user4"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user5"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user6"));
        assertTrue(ZTSTestUtils.verifyGroupMemberName(members, "user.user7"));

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

        assertNull(store.getPrincipalGroups("user.user4", "coretech", null));
        assertNull(store.getPrincipalGroups("user.user5", "coretech", null));
        assertNull(store.getPrincipalGroups("user.user6", "coretech", null));

        groupNames = store.getPrincipalGroups("user.user3", "coretech", null);
        assertEquals(groupNames.size(), 1);
        assertTrue(groupNames.contains("dev-team"));

        // first get and then wait for 3 seconds for the user7 to expire

        groupNames = store.getPrincipalGroups("user.user7", "coretech", null);
        assertEquals(groupNames.size(), 1);
        assertTrue(groupNames.contains("dev-team"));

        ZTSTestUtils.sleep(3000);

        assertNull(store.getPrincipalGroups("user.user7", "coretech", null));

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

        assertNull(store.getPrincipalGroups("user.user3", "coretech", null));

        groupNames = store.getPrincipalGroups("user.user4", "coretech", null);
        assertEquals(groupNames.size(), 1);
        assertTrue(groupNames.contains("dev-team"));

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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        final String domainName = "access-domain";
        ZTSTestUtils.setupDomainsWithGroups(store, pkey, domainName, Collections.emptyList());

        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("access-domain1");
        store.getAccessibleRoles(data, "access-domain1", "user.user1", null, false, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("role1"));
        assertTrue(accessibleRoles.contains("role2"));

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain1", "user.user2", null, false, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 4);
        assertTrue(accessibleRoles.contains("role1"));
        assertTrue(accessibleRoles.contains("role2"));
        assertTrue(accessibleRoles.contains("role3"));
        assertTrue(accessibleRoles.contains("role4"));

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain1", "user.user3", null, false, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 4);
        assertTrue(accessibleRoles.contains("role1"));
        assertTrue(accessibleRoles.contains("role2"));
        assertTrue(accessibleRoles.contains("role3"));
        assertTrue(accessibleRoles.contains("role4"));

        data = store.getDataCache("access-domain3");
        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain3", "user.user4", null, false, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("role5"));

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain3", "user.user5", null, false, accessibleRoles, false);
        assertTrue(accessibleRoles.isEmpty());

        // sleep for a couple of seconds so user6 becomes expired

        ZTSTestUtils.sleep(2000);

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain3", "user.user6", null, false, accessibleRoles, false);
        assertTrue(accessibleRoles.isEmpty());

        // now we're going to delete group1, group4 and group6 so user1 will no longer have access to role1
        // and role2 so we'll have an empty result and user3 will no longer be in role4

        ZTSTestUtils.setupDomainsWithGroups(store, pkey, domainName,
                Arrays.asList("access-domain1:group.group1", "access-domain3:group.group6", "access-domain2:group.group4"));

        data = store.getDataCache("access-domain1");

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain1", "user.user1", null, false, accessibleRoles, false);
        assertTrue(accessibleRoles.isEmpty());

        accessibleRoles.clear();
        store.getAccessibleRoles(data, "access-domain1", "user.user3", null, false, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 3);
        assertTrue(accessibleRoles.contains("role1"));
        assertTrue(accessibleRoles.contains("role2"));
        assertTrue(accessibleRoles.contains("role3"));
    }

    @Test
    public void testDomainDeleteWithGroups() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root", pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
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
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        // if we pass null for the members then we return right
        // away so sno exceptions even if we pass null for the group name

        store.processGroupDeletedMembers(null, null);
    }

    @Test
    public void testDisabledDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        store.processSignedDomain(signedDomain, true);

        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, false, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("writers"));

        // now mark the domain as disabled and verify no roles are returned

        signedDomain.getDomain().setEnabled(false);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(signedDomain.getDomain()), pkey));
        store.processSignedDomain(signedDomain, true);

        accessibleRoles = new HashSet<>();
        data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, false, accessibleRoles, false);
        assertTrue(accessibleRoles.isEmpty());
    }

    @Test
    public void testProcessDomainCheck() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);

        DomainData domainData = new DomainData();
        assertTrue(store.processDomainCheck(null, domainData));

        domainData.setEnabled(Boolean.TRUE);
        assertTrue(store.processDomainCheck(null, domainData));

        domainData.setEnabled(false);
        assertFalse(store.processDomainCheck(null, domainData));

        DomainData localData = new DomainData();
        assertTrue(store.processDomainCheck(localData, domainData));

        domainData.setEnabled(true);
        localData.setModified(Timestamp.fromMillis(100));
        domainData.setModified(Timestamp.fromMillis(200));
        assertTrue(store.processDomainCheck(localData, domainData));

        localData.setModified(Timestamp.fromMillis(201));
        assertFalse(store.processDomainCheck(localData, domainData));
    }

    @Test
    public void testValidateJWSDomainValid() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "0");
        assertTrue(store.validateJWSDomain("coretech", jwsDomain));
    }

    @Test
    public void testValidateJWSDomainInvalidSignature() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "0");
        final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        jwsDomain.setSignature(encoder.encodeToString("unknown signature".getBytes(StandardCharsets.UTF_8)));

        assertFalse(store.validateJWSDomain("coretech", jwsDomain));
    }

    @Test
    public void testValidateJWSDomainInvalidVersion() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "100");
        assertFalse(store.validateJWSDomain("coretech", jwsDomain));
    }

    @Test
    public void testValidateJWSDomainInvalidHeader() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "0");
        jwsDomain.setProtectedHeader("invalid-base64-header");

        assertFalse(store.validateJWSDomain("coretech", jwsDomain));
        assertFalse(store.processJWSDomain(jwsDomain, false));
    }

    @Test
    public void testValidateJWSDomainMissingKid() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "0");
        final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        final String protectedHeader = "{\"alg\":\"SHA256\"}";
        jwsDomain.setProtectedHeader(encoder.encodeToString(protectedHeader.getBytes(StandardCharsets.UTF_8)));

        assertFalse(store.validateJWSDomain("coretech", jwsDomain));
    }

    @Test
    public void testValidateJWSDomainInvalidBases64Signature() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "0");
        jwsDomain.setSignature("invalid-base64-header");

        assertFalse(store.validateJWSDomain("coretech", jwsDomain));
    }

    @Test
    public void testProcessJWSDomainUpdatesFromZMSWithUpdater() {

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;
        store.loadAthenzPublicKeys();

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "0");
        store.processJWSDomain(jwsDomain, true);

        List<JWSDomain> domains = new ArrayList<>();

        // we're going to create a new domain

        jwsDomain = createJWSDomain("sports", "weather", "0");
        domains.add(jwsDomain);

        // we're going to update the coretech domain and set new roles

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");

        Role role = new Role();
        role.setName("coretech:role.admin");
        List<RoleMember> members = new ArrayList<>();
        members.add(new RoleMember().setMemberName("user_domain.user8"));
        role.setRoleMembers(members);

        List<Role> roles = new ArrayList<>();
        roles.add(role);
        signedDomain.getDomain().setRoles(roles);

        jwsDomain = signJwsDomain(signedDomain.getDomain(), "0");
        domains.add(jwsDomain);

        ((MockZMSFileChangeLogStore) store.changeLogStore).setJWSDomains(domains);

        store.lastDeleteRunTime = System.currentTimeMillis() - 59 * 60 * 1000;
        store.lastCheckRunTime = System.currentTimeMillis() - 9 * 60 * 1000;
        DataUpdater updater = store.new DataUpdater();
        updater.run();

        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache("coretech");
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);

        accessibleRoles = new HashSet<>();
        store.getAccessibleRoles(data, "coretech", "user_domain.user8", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));

        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, false, accessibleRoles, false);
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
        store.getAccessibleRoles(data, "coretech", "user_domain.user1", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 0);

        accessibleRoles = new HashSet<>();
        store.getAccessibleRoles(data, "coretech", "user_domain.user8", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 1);
        assertTrue(accessibleRoles.contains("admin"));

        accessibleRoles = new HashSet<>();
        data = store.getDataCache("sports");
        store.getAccessibleRoles(data, "sports", "user_domain.user", null, false, accessibleRoles, false);
        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("writers"));
    }

    @Test
    public void testProcessJWSDomainChecks() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;
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

        JWSDomain jwsDomain = signJwsDomain(signedDomain.getDomain(), "0");
        clogStore.setJWSDomain("sports", jwsDomain);

        // allow sports to be processed

        long now = System.currentTimeMillis() / 1000;
        Map<String, DomainAttributes> domainMap = new HashMap<>();
        domainMap.put("coretech", new DomainAttributes().setFetchTime(now - store.domainFetchRefreshTime - 1));
        domainMap.put("sports", new DomainAttributes().setFetchTime(now - store.domainFetchRefreshTime - 1));
        clogStore.setLocalDomainAttributeList(domainMap);

        // now process check which should return new domain sports that
        // we need to add to our store

        store.processDomainChecks();

        // verify we have two domains now

        assertNotNull(store.getDomainData("sports"));
        assertNotNull(store.getDomainData("coretech"));
    }

    @Test
    public void testProcessJWSDomainChecksGetDomainFailure() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;
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

        // with this setup, coretech should be processed, sports should be
        // skipped, finance should be processed, but it's null so skipped

        long now = System.currentTimeMillis() / 1000;
        Map<String, DomainAttributes> domainMap = new HashMap<>();
        domainMap.put("coretech", new DomainAttributes().setFetchTime(now - store.domainFetchRefreshTime - 1));
        domainMap.put("sports", new DomainAttributes().setFetchTime(now));
        domainMap.put("finance", new DomainAttributes().setFetchTime(now - store.domainFetchRefreshTime - 1));
        clogStore.setLocalDomainAttributeList(domainMap);

        // now process check which should return three domains due to
        // our mock set with one new one but then when we try to fetch
        // each one individually we'll get nulls, so we'll have no impact
        // on our store and no new domain will be added

        store.processDomainChecks();

        // verify we have two domains still

        assertNotNull(store.getDomainData("sports"));
        assertNotNull(store.getDomainData("coretech"));
        assertNull(store.getDomainData("finance"));
    }

    @Test
    public void testProcessJWSDomains() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;

        List<JWSDomain> list = new ArrayList<>();

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "0");
        list.add(jwsDomain);

        jwsDomain = createJWSDomain("sports", "weather", "0");
        list.add(jwsDomain);

        assertTrue(store.processJWSDomains(list));
        assertNotNull(store.getDomainData("coretech"));
        assertNotNull(store.getDomainData("sports"));
    }

    @Test
    public void testProcessJWSDomainsNullList() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;

        assertTrue(store.processJWSDomains(null));
    }

    @Test
    public void testProcessJWSDomainsEmptyList() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;

        assertTrue(store.processJWSDomains(Collections.emptyList()));
    }

    @Test
    public void testProcessJWSDomainsInvalidDomainWithSuccess() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;

        List<JWSDomain> list = new ArrayList<>();

        // if we have one successful domain and one failure
        // then our result is going to be success

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "0");
        list.add(jwsDomain);

        // use invalid version key id

        jwsDomain = createJWSDomain("sports", "weather", "1");
        list.add(jwsDomain);

        assertTrue(store.processJWSDomains(list));
    }

    @Test
    public void testProcessJWSDomainsAllInvalidDomain() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;

        List<JWSDomain> list = new ArrayList<>();

        // if we have only failures, then our result
        // is going to be failure

        JWSDomain jwsDomain = createJWSDomain("coretech", "weather", "1");
        list.add(jwsDomain);

        jwsDomain = createJWSDomain("sports", "weather", "1");
        list.add(jwsDomain);

        assertFalse(store.processJWSDomains(list));
    }

    @Test
    public void testProcessJWSDomainChecksSkip() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;

        // create a new signed domain

        List<SignedDomain> domains = new ArrayList<>();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        signedDomain.getDomain().setEnabled(false);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(signedDomain.getDomain()), pkey));
        domains.add(signedDomain);

        signedDomain = createSignedDomain("sports", "weather");
        signedDomain.getDomain().setEnabled(false);
        signedDomain.setSignature(Crypto.sign(SignUtils.asCanonicalString(signedDomain.getDomain()), pkey));
        domains.add(signedDomain);

        SignedDomains signedDomains = new SignedDomains();
        signedDomains.setDomains(domains);
        clogStore.setSignedDomains(signedDomains);

        // now process check which should return three domains due to
        // our mock set with one new one but then when we try to fetch
        // each one individually we'll get nulls so we'll have no impact
        // on our store and no new domain will be added

        store.processJWSDomainChecks();

        // verify we have no domains since all are disabled

        assertNull(store.getDomainData("sports"));
        assertNull(store.getDomainData("coretech"));
    }

    @Test
    public void testProcessJWSDomainUpdateFailures() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;
        addDomainToDataStore(store, "coretech");

        // first we should get null jws domain list

        assertFalse(store.processJWSDomainUpdates());

        // set to return invalid jws domain

        JWSDomain jwsDomain = createJWSDomain("sports", "weather", "1");
        List<JWSDomain> jwsDomains = new ArrayList<>();
        jwsDomains.add(jwsDomain);
        clogStore.setJWSDomains(jwsDomains);

        // we should still get failure since our key version is incorrect

        assertFalse(store.processJWSDomainUpdates());

        // verify we still have our original domain

        assertNotNull(store.getDomainData("coretech"));
        assertNull(store.getDomainData("sports"));
    }

    @Test
    public void testProcessSignedDomainException() {
        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = Mockito.mock(SignedDomain.class);
        DomainData domainData = new DomainData();
        domainData.setName("coretech");
        Mockito.when(signedDomain.getDomain()).thenReturn(domainData)
                        .thenThrow(new ResourceException(400, "invalid-domain"));

        assertFalse(store.processSignedDomain(signedDomain, true));
    }

    @Test
    public void testProcessJWSDomainException() {
        ChangeLogStore clogStore = Mockito.mock(ChangeLogStore.class);
        doThrow(new ResourceException(400, "invalid-domain"))
                .when(clogStore).saveLocalDomain(ArgumentMatchers.any(), (JWSDomain) ArgumentMatchers.any());

        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain signedDomain = createSignedDomain("coretech", "weather");
        signedDomain.getDomain().setEnabled(false);
        JWSDomain jwsDomain = signJwsDomain(signedDomain.getDomain(), "0");

        assertFalse(store.processJWSDomain(jwsDomain, true));
    }

    @Test
    public void testProcessSysDisabledGroupMember() {

        final String roleDomainName = "role-domain";
        final String group1DomainName = "group1-domain";
        final String group2DomainName = "group2-domain";
        final String roleName = "readers";
        final String groupName = "readers-team";
        final String memberName = "user_domain.user";

        ChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.loadAthenzPublicKeys();

        SignedDomain group1SignedDomain = ZTSTestUtils.setupDomainWithGroupMemberState(group1DomainName, groupName,
                roleName, memberName, false);
        JWSDomain group1JwsDomain = signJwsDomain(group1SignedDomain.getDomain(), "0");
        store.processJWSDomain(group1JwsDomain, true);

        SignedDomain roleSignedDomain = ZTSTestUtils.setupDomainWithRoleGroupMember(roleDomainName, roleName,
                memberName, ResourceUtils.groupResourceName(group1DomainName, groupName), false);
        JWSDomain roleJwsDomain = signJwsDomain(roleSignedDomain.getDomain(), "0");
        store.processJWSDomain(roleJwsDomain, true);

        SignedDomain group2SignedDomain = ZTSTestUtils.setupDomainWithGroupMemberState(group2DomainName, groupName,
                roleName, memberName, false);
        JWSDomain group2JwsDomain = signJwsDomain(group2SignedDomain.getDomain(), "0");
        store.processJWSDomain(group2JwsDomain, true);

        Set<String> accessibleRoles = new HashSet<>();
        DataCache data = store.getDataCache(roleDomainName);
        store.getAccessibleRoles(data, roleDomainName, memberName, null, false, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("readers"));

        // now let's disable the user

        roleSignedDomain = ZTSTestUtils.setupDomainWithRoleGroupMember(roleDomainName, roleName,
                memberName, ResourceUtils.groupResourceName(group1DomainName, groupName), true);
        roleJwsDomain = signJwsDomain(roleSignedDomain.getDomain(), "0");
        store.processJWSDomain(roleJwsDomain, true);

        group1SignedDomain = ZTSTestUtils.setupDomainWithGroupMemberState(group1DomainName, groupName,
                roleName, memberName, true);
        group1JwsDomain = signJwsDomain(group1SignedDomain.getDomain(), "0");
        store.processJWSDomain(group1JwsDomain, true);

        // this time around we should not get any roles for the user

        data = store.getDataCache(roleDomainName);
        accessibleRoles.clear();
        store.getAccessibleRoles(data, roleDomainName, memberName, null, false, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 0);

        // now let's enable our user and verify we get back the role

        roleSignedDomain = ZTSTestUtils.setupDomainWithRoleGroupMember(roleDomainName, roleName,
                memberName, ResourceUtils.groupResourceName(group1DomainName, groupName), false);
        roleJwsDomain = signJwsDomain(roleSignedDomain.getDomain(), "0");
        store.processJWSDomain(roleJwsDomain, true);

        group1SignedDomain = ZTSTestUtils.setupDomainWithGroupMemberState(group1DomainName, groupName,
                roleName, memberName, false);
        group1JwsDomain = signJwsDomain(group1SignedDomain.getDomain(), "0");
        store.processJWSDomain(group1JwsDomain, true);

        data = store.getDataCache(roleDomainName);
        accessibleRoles.clear();
        store.getAccessibleRoles(data, roleDomainName, memberName, null, false, accessibleRoles, false);

        assertEquals(accessibleRoles.size(), 2);
        assertTrue(accessibleRoles.contains("admin"));
        assertTrue(accessibleRoles.contains("readers"));
    }

    @Test
    public void testGetDomainRefreshList() {

        MockZMSFileChangeLogStore clogStore = new MockZMSFileChangeLogStore("/tmp/zts_server_unit_tests/zts_root",
                pkey, "0");
        DataStore store = new DataStore(clogStore, null, ztsMetric);
        store.jwsDomainSupport = true;

        // initially we should get an empty list

        assertTrue(store.getDomainRefreshList().isEmpty());

        // now let's create a single entry without being expired

        long now = System.currentTimeMillis() / 1000;

        Map<String, DomainAttributes> domainMap = new HashMap<>();
        clogStore.setLocalDomainAttributeList(domainMap);

        domainMap.put("domain1", new DomainAttributes().setFetchTime(now));
        assertTrue(store.getDomainRefreshList().isEmpty());

        // now let's add another one with expired timeout

        domainMap.put("domain2", new DomainAttributes().setFetchTime(now - store.domainFetchRefreshTime - 1));
        List<String> domains = store.getDomainRefreshList();
        assertEquals(1, domains.size());
        assertEquals("domain2", domains.get(0));

        // now let's add domains more than the configured limit

        for (int i = 0; i < store.domainFetchCount + 5; i++) {
            domainMap.put("domain-" + i, new DomainAttributes().setFetchTime(now - store.domainFetchRefreshTime - 1));
        }

        domains = store.getDomainRefreshList();
        assertEquals(store.domainFetchCount, domains.size());
    }
}
