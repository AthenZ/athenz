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
package com.yahoo.athenz.sia.impl;

import java.io.File;
import java.io.Writer;
import java.io.OutputStreamWriter;
import java.io.FileOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.sia.impl.SIAClient;

public class SIAClientTest {

    @Mock Socket mockSocket;

    @BeforeClass
    public void setUp() throws Exception {
        System.setProperty(SIAClient.SIA_PROP_NTOKEN_PATH, "src/test/resources/svc.ntoken");
        System.setProperty(SIAClient.SIA_PROP_NTOKEN_SERVICE, "storage");
        System.setProperty(SIAClient.SIA_PROP_CFG_FILE, "src/test/resources/testcfg.conf");

        MockitoAnnotations.initMocks(this);
        prepareNtokenFile("_test");
    }

    // writes an ntoken to the configured ntoken path
    void prepareNtokenFile(String pathSuffix) throws Exception {

        // prepare the ntoken file
        // ex: ntoken = "v=S1;d=athenz;n=storage;t=55555;e=57955;s=fake";
        String ntoken_path = System.getProperty(SIAClient.SIA_PROP_NTOKEN_PATH);
        ntoken_path = ntoken_path + pathSuffix;
        Path path = Paths.get(ntoken_path);
        String token = new String(Files.readAllBytes(path));
        long curTimeSecs = System.currentTimeMillis() / 1000;
        String curTime = Long.toString(curTimeSecs);
        token = token.replaceFirst("55555", curTime);
        curTimeSecs += 2400;
        curTime = Long.toString(curTimeSecs);
        token = token.replaceFirst("55555", curTime);

        // write it to the configured ntoken file
        ntoken_path = System.getProperty(SIAClient.SIA_PROP_NTOKEN_PATH);
        File file = new File(ntoken_path);
        file.createNewFile();
        Writer fw = new OutputStreamWriter(new FileOutputStream(file));
        fw.write(token + "\n");
        fw.close();
    }

    @AfterMethod
    public void cleanup() {
    }
    
    @Test
    public void testIsExpiredTokenSmallerThanMin() {
        SIAClient client = new SIAClient();
        assertTrue(client.isExpiredToken(100, 200, null));
    }
    
    @Test
    public void testIsExpiredTokenBiggerThanMax() {
        SIAClient client = new SIAClient();
        assertTrue(client.isExpiredToken(500, null, 300));
        assertTrue(client.isExpiredToken(500, 200, 300));
    }
    
    @Test
    public void testIsExpiredTokenAtLeastOneLimitIsNotNull() {
        SIAClient client = new SIAClient();
        assertFalse(client.isExpiredToken(500, null, 600));
        assertFalse(client.isExpiredToken(500, 200, null));
        assertFalse(client.isExpiredToken(500, 200, 501));
    }
    
    @Test
    public void testIsExpiredTokenAtLeastBothLimitsNullSmallerThanMin() {
        // the min is 1800
        SIAClient client = new SIAClient();
        assertTrue(client.isExpiredToken(1700, null, null));
    }
    
    @Test
    public void testIsExpiredTokenAtLeastBothLimitsNullBiggerThanMin() {
        // the min is 1800
        SIAClient client = new SIAClient();
        assertFalse(client.isExpiredToken(2100, null, null));
    }
    
    @Test
    public void testGetPrincipalTokenCacheKey() {
        SIAClient client = new SIAClient();
        assertEquals(client.getPrincipalTokenCacheKey("coretech", "service"), "coretech.service");
        assertEquals(client.getPrincipalTokenCacheKey(null, "service"), "null.service");
        assertEquals(client.getPrincipalTokenCacheKey("coretech", null), "coretech.null");
    }

    @Test
    public void testSiaSocketFile() {
        SIAClient client = new SIAClient();
        assertEquals(client.siaSocketFile(), "/home/athenz/var/run/sia/sia.ds");
    }
    
    @Test
    public void testLookupPrincipalTokenInCacheNotPresent() {
        SIAClient client = new SIAClient();
        
        String cacheKey = "coretech.notpresent";
        assertNull(client.lookupPrincipalTokenInCache(cacheKey, null, null));
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void testLookupPrincipalTokenInCacheExpired() {

        SIAClient client = new SIAClient();
        
        String cacheKey = "coretech.storage";
        PrincipalToken token = new PrincipalToken.Builder("S1", "coretech", "storage")
            .issueTime((System.currentTimeMillis() / 1000)).expirationWindow(1000).build();
        client.principalTokenCache.put(cacheKey, token);
        
        assertNull(client.lookupPrincipalTokenInCache(cacheKey, 3000, 4000));
        assertNull(client.lookupPrincipalTokenInCache(cacheKey, 500, 800));
        
        client.principalTokenCache.clear();
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void testLookupPrincipalTokenInCache() {
        
        SIAClient client = new SIAClient();
        
        String cacheKey = "coretech.storage";
        PrincipalToken token = new PrincipalToken.Builder("S1", "coretech", "storage")
            .issueTime((System.currentTimeMillis() / 1000)).expirationWindow(3500).build();
        client.principalTokenCache.put(cacheKey, token);
        
        assertNotNull(client.lookupPrincipalTokenInCache(cacheKey, 3000, 4000));
        
        client.principalTokenCache.clear();
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void testLookupPrincipalTokenInCacheSecondClient() {
        
        SIAClient client = new SIAClient();
        
        String cacheKey = "coretech.storage";
        PrincipalToken token = new PrincipalToken.Builder("S1", "coretech", "storage")
            .issueTime((System.currentTimeMillis() / 1000)).expirationWindow(3500).build();
        client.principalTokenCache.put(cacheKey, token);

        assertNotNull(client.lookupPrincipalTokenInCache(cacheKey, 3000, 4000));
        
        // now let's get another client
        
        SIAClient client1 = new SIAClient();
        assertNotNull(client1.lookupPrincipalTokenInCache(cacheKey, 3000, 4000));
        
        client.principalTokenCache.clear();
    }
    
    @Test
    public void testProcessRequestDomainList() throws IOException {
       
        ByteBuffer statusBuf = ByteBuffer.allocate(4);
        statusBuf.order(ByteOrder.LITTLE_ENDIAN);
        statusBuf.putInt(0);
        byte[] status = statusBuf.array();
        
        ByteBuffer sizeBuf = ByteBuffer.allocate(4);
        sizeBuf.order(ByteOrder.LITTLE_ENDIAN);
        sizeBuf.putInt(15);
        byte[] size = sizeBuf.array();

        byte[] list = "domain1,domain2".getBytes();

        byte[] data = new byte[status.length + size.length + list.length];

        System.arraycopy(status, 0, data, 0, status.length);
        System.arraycopy(size, 0, data, status.length, size.length);
        System.arraycopy(list, 0, data, status.length + size.length, list.length);
        
        InputStream inputStream = new ByteArrayInputStream(data);
        OutputStream outputStream = new ByteArrayOutputStream();
        
        SIAClient mockSIAClient = Mockito.mock(SIAClient.class);
        Mockito.when(mockSIAClient.getSIADomainSocket()).thenReturn(mockSocket);
        Mockito.when(mockSocket.getInputStream()).thenReturn(inputStream);
        Mockito.when(mockSocket.getOutputStream()).thenReturn(outputStream);
        
        SIAClient siaClient = new SIAClient();
        String domains = null;
        try {
            domains = siaClient.processRequest(mockSocket, SIAClient.OP_LIST_DOMAINS, null);
        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
        assertEquals(domains, "domain1,domain2");
    }
    
    @Test
    public void testProcessRequestPrincipalToken() throws IOException {
       
        ByteBuffer statusBuf = ByteBuffer.allocate(4);
        statusBuf.order(ByteOrder.LITTLE_ENDIAN);
        statusBuf.putInt(0);
        byte[] status = statusBuf.array();
        
        ByteBuffer sizeBuf = ByteBuffer.allocate(4);
        sizeBuf.order(ByteOrder.LITTLE_ENDIAN);
        sizeBuf.putInt(36);
        byte[] size = sizeBuf.array();

        byte[] token = "v=S1;d=coretech;n=storage;k=0;s=fake".getBytes();

        byte[] data = new byte[status.length + size.length + token.length];

        System.arraycopy(status, 0, data, 0, status.length);
        System.arraycopy(size, 0, data, status.length, size.length);
        System.arraycopy(token, 0, data, status.length + size.length, token.length);
        
        InputStream inputStream = new ByteArrayInputStream(data);
        OutputStream outputStream = new ByteArrayOutputStream();
        
        SIAClient mockSIAClient = Mockito.mock(SIAClient.class);
        Mockito.when(mockSIAClient.getSIADomainSocket()).thenReturn(mockSocket);
        Mockito.when(mockSocket.getInputStream()).thenReturn(inputStream);
        Mockito.when(mockSocket.getOutputStream()).thenReturn(outputStream);
        
        SIAClient siaClient = new SIAClient();
        String ntoken = null;
        try {
            ntoken = siaClient.processRequest(mockSocket, SIAClient.OP_GET_NTOKEN, "d=coretech,n=storage,e=1800".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
        assertEquals(ntoken, "v=S1;d=coretech;n=storage;k=0;s=fake");
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void testGetServicePrincipal() throws IOException {

        SIAClient client = new SIAClient();
        
        String cacheKey = "coretech.storage";
        String nToken = "v=S1;d=coretech;n=storage;t=" + (System.currentTimeMillis() / 1000)
                + ";e=" + ((System.currentTimeMillis() / 1000) + 3500) + ";k=0;s=fake";
        PrincipalToken token = new PrincipalToken(nToken);
        client.principalTokenCache.put(cacheKey, token);
        
        Principal principal = client.getServicePrincipal("coretech", "storage", null, null, false);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "coretech");
        assertEquals(principal.getName(), "storage");
        
        client.principalTokenCache.clear();
    }
    
    @SuppressWarnings("static-access")
    @Test
    public void testGetServicePrincipalMixedCase() throws IOException {

        SIAClient client = new SIAClient();
        
        String cacheKey = "coretech.storage";
        String nToken = "v=S1;d=coretech;n=storage;t=" + (System.currentTimeMillis() / 1000)
                + ";e=" + ((System.currentTimeMillis() / 1000) + 3500) + ";k=0;s=fake";
        PrincipalToken token = new PrincipalToken(nToken);
        client.principalTokenCache.put(cacheKey, token);
        
        Principal principal = client.getServicePrincipal("CoreTech", "Storage", null, null, false);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "coretech");
        assertEquals(principal.getName(), "storage");
        
        client.principalTokenCache.clear();
    }

    @Test (groups = "tokenfileA")
    public void testGetServicePrincipalTokenFile() {
        SIAClient client = new SIAClient();
        String domain   = "athenz";
        String service  = "storage";
        // Configured service=athenz.storage
        try {
            client.getServicePrincipal(domain, service, 500, 3600, false);
        } catch (java.io.IOException exc) {
            fail("getServicePrincipal");
        }
    }

    @Test (groups = "tokenfileA")
    public void testGetServicePrincipalTokenFileWrongDomain() {
        SIAClient client = new SIAClient();
        String domain   = "test.aaa";
        String service  = "storage";
        String fullSvc = domain + "." + service;
        // Configured service=athenz.storage
        try {
            client.getServicePrincipal(domain, service, 500, 3600, false);
            fail("getServicePrincipal");
        } catch (java.io.IOException exc) {
            assertTrue(exc.getMessage().contains("get ntoken from file: Unknown service=" + fullSvc), exc.getMessage());
        }
    }

    @Test (groups = "tokenfileA")
    public void testGetServicePrincipalTokenFileWrongService() {
        SIAClient client = new SIAClient();
        String domain   = "athenz";
        String service  = "destroyage";
        String fullSvc = domain + "." + service;
        // Configured service=athenz.storage
        try {
            client.getServicePrincipal(domain, service, 500, 3600, false);
            fail("getServicePrincipal");
        } catch (java.io.IOException exc) {
            assertTrue(exc.getMessage().contains("get ntoken from file: Unknown service=" + fullSvc), exc.getMessage());
        }
    }

    @Test (dependsOnGroups = "tokenfileA")
    public void testGetServicePrincipalTokenFileEmptyConfigMissingDomainProperty() throws java.io.IOException {
        System.setProperty(SIAClient.SIA_PROP_CFG_FILE, "src/test/resources/testcfg_empty.conf");
        try {
            SIAClient.initConfigVars();
            SIAClient client = new SIAClient();
            String domain   = "athenz";
            String service  = "storage";
            // Configured service=athenz.storage
            client.getServicePrincipal(domain, service, 500, 3600, false);
            fail("getServicePrincipal");
        } catch (java.lang.IllegalArgumentException exc) {
            assertTrue(exc.getMessage().contains("SIACLT: invalid ntoken configuration settings"), exc.getMessage());
        }
    }

    @Test (dependsOnMethods={"testGetServicePrincipalTokenFileEmptyConfigMissingDomainProperty"})
    public void testGetServicePrincipalTokenFileEmptyConfig() {
        System.setProperty(SIAClient.SIA_PROP_NTOKEN_DOMAIN, "athenz");
        System.setProperty(SIAClient.SIA_PROP_CFG_FILE, "src/test/resources/testcfg_empty.conf");
        SIAClient.initConfigVars();
        SIAClient client = new SIAClient();
        String domain   = "athenz";
        String service  = "storage";
        // Configured service=athenz.storage
        try {
            client.getServicePrincipal(domain, service, 500, 3600, false);
        } catch (java.io.IOException exc) {
            fail("getServicePrincipal");
        }
    }

    @Test
    public void testTokenRequestBuilder() {
        SIAClient client = new SIAClient();
        assertEquals("d=test,s=db".getBytes(StandardCharsets.UTF_8), client.tokenRequestBuilder("test", "db", null));
        assertEquals("d=test,s=db,e=100".getBytes(StandardCharsets.UTF_8), client.tokenRequestBuilder("test", "db", new Integer(100)));
        assertEquals("d=null,s=db,e=100".getBytes(StandardCharsets.UTF_8), client.tokenRequestBuilder(null, "db", new Integer(100)));
        assertEquals("d=test,s=null,e=100".getBytes(StandardCharsets.UTF_8), client.tokenRequestBuilder("test", null, new Integer(100)));
        assertEquals("d=null,s=null,e=100".getBytes(StandardCharsets.UTF_8), client.tokenRequestBuilder(null, null, new Integer(100)));
    }
    
    private class SIATestClient extends SIAClient {
        
        @Override
        Socket getSIADomainSocket() throws IOException {
            return null;
        }
        
        @Override
        String processRequest(Socket sock, int sia_op, byte[] data) throws IOException {
            String result = null;
            switch (sia_op) {
            case SIAClient.OP_LIST_DOMAINS:
                result = "test;hoge;athenz";
                break;
            case SIAClient.OP_GET_NTOKEN:
                result = "v=S1;d=coretech;n=storage;k=0;s=fake";
                break;
            }
            return result;
        }
    }
    
    @Test
    public void testGetServicePrincipalNullExpiry() throws IOException {

        // we need to make sure not to use our ntoken path which doesn't
        // call the expected get service principal api. so we're going
        // to save the value and and then restore it after the test case

        String ntoken_path = SIAClient.cfgNtokenPath;
        SIAClient.cfgNtokenPath = null;

        SIAClient client = new SIATestClient();

        Principal principal = client.getServicePrincipal("coretech", "storage", 500, null, false);
        assertNotNull(principal);
        assertEquals(principal.getDomain(), "coretech");
        assertEquals(principal.getName(), "storage");

        // restore the property

        SIAClient.cfgNtokenPath = ntoken_path;
    }

    @Test
    public void testGetDomainList() throws IOException {
        SIAClient client = new SIATestClient();
        ArrayList<String> result = client.getDomainList();
        assertNotNull(result);
        assertEquals(result.toString(), "[test, hoge, athenz]");
    }

    @Test
    public void testGetServicePrincipalException() throws Exception {
        SIAClient client = new SIATestClient();

        try {
            client.getServicePrincipal(null, null, 0, 3600, true);
            fail();
        } catch (IOException e) {
        }

        SIATestClient.cfgNtokenPath = null;
        Principal p = client.getServicePrincipal("test", "hoge", 0, 3600, true);

        assertNotNull(p);
        assertEquals(p.getDomain(), "test");
        assertEquals(p.getName(), "hoge");

        SIATestClient.cfgNtokenPath = "src/test/resources/svc.ntoken";
    }

    @Test
    public void testGetFilePrincipalTokenIlligalFile() throws IOException{
        SIAClient client = new SIATestClient();

        SIATestClient.cfgNtokenPath = "src/test/resources/dummy.ntoken";
        String s = client.getFilePrincipalToken("athenz", "storage");

        assertEquals(s, "");
    }

    @Test
    public void testReadResponseData() throws IOException {
        SIAClient client = new SIATestClient();

        byte[] dummy = { (byte) 0x47, (byte) 0x4e, (byte) 0x54, (byte) 0x2d, (byte) 0x30, (byte) 0x30, (byte) 0x30,
                (byte) 0x30 };
        InputStream is = Mockito.mock(InputStream.class);

        Mockito.when(is.read(dummy, 0, dummy.length)).thenReturn(1);
        Mockito.when(is.read(dummy, 1, dummy.length - 1)).thenReturn(-1);

        int check = client.readResponseData(is, dummy);
        assertEquals(check, 1);

        Mockito.when(is.read(dummy, 0, dummy.length)).thenReturn(-1);

        check = client.readResponseData(is, dummy);
        assertEquals(check, 0);
    }

    @Test
    public void testInitConfigVarsIlligalCFGflag() throws Exception {

        System.clearProperty(SIAClient.SIA_PROP_CFG_FILE);

        SIAClient.initConfigVars();
        assertNull(SIATestClient.cfgNtokenPath);
        assertNull(SIATestClient.cfgNtokenDomain);
        assertNull(SIATestClient.cfgNtokenService);
    }

    @Test
    public void testSetConfigVarsIlligal() throws Exception {

        SIAClient.setupConfigVars(null, null, null);
        assertNull(SIATestClient.cfgNtokenDomain);
        assertNull(SIATestClient.cfgNtokenService);
    }
}
