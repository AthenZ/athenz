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
package com.yahoo.athenz.zts.cert.impl;

import static org.testng.Assert.*;

import java.util.concurrent.TimeoutException;

import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class HttpCertSignerTest {
    
    @BeforeClass
    public void setup() {
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI, "https://localhost:443/certsign/v2");
    }
    
    @Test
    public void testHttpCertSignerFactory() {
        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        assertNotNull(certFactory);

        CertSigner certSigner = certFactory.create();
        assertNotNull(certSigner);

        certSigner.close();
    }

    @Test
    public void testGenerateX509CertificateException() throws Exception {
 
        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);
        
        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.POST("https://localhost:443/certsign/v2/x509")).thenReturn(request);
        Mockito.when(request.send()).thenThrow(new TimeoutException());

        assertNull(certSigner.generateX509Certificate("aws", "us-west-2", "csr", null, 0));
        certSigner.close();
    }

    @Test
    public void testGenerateX509CertificateInvalidStatus() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.POST("https://localhost:443/certsign/v2/x509")).thenReturn(request);

        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(request.send()).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(400);

        assertNull(certSigner.generateX509Certificate("aws", "us-west-2", "csr", null, 0));
        certSigner.close();
    }

    @Test
    public void testGenerateX509CertificateResponseNull() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.POST("https://localhost:443/certsign/v2/x509")).thenReturn(request);

        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(request.send()).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(201);
        Mockito.when(response.getContentAsString()).thenReturn(null);

        assertNull(certSigner.generateX509Certificate("aws", "us-west-2", "csr", null, 0));
        certSigner.close();
    }

    @Test
    public void testGenerateX509CertificateResponseEmpty() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.POST("https://localhost:443/certsign/v2/x509")).thenReturn(request);

        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(request.send()).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(201);
        Mockito.when(response.getContentAsString()).thenReturn("");

        assertNull(certSigner.generateX509Certificate("aws", "us-west-2", "csr", null, 0));
        certSigner.close();
    }

    @Test
    public void testGenerateX509Certificate() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.POST("https://localhost:443/certsign/v2/x509")).thenReturn(request);

        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(request.send()).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(201);
        Mockito.when(response.getContentAsString()).thenReturn("{\"pem\": \"pem-value\"}");

        String pem = certSigner.generateX509Certificate("aws", "us-west-2", "csr", null, 0);
        assertEquals(pem, "pem-value");

        pem = certSigner.generateX509Certificate("aws", "us-west-2", "csr", InstanceProvider.ZTS_CERT_USAGE_CLIENT, 0);
        assertEquals(pem, "pem-value");

        pem = certSigner.generateX509Certificate("aws", "us-west-2", "csr", InstanceProvider.ZTS_CERT_USAGE_CLIENT, 30);
        assertEquals(pem, "pem-value");

        certSigner.requestTimeout = 120;
        pem = certSigner.generateX509Certificate("aws", "us-west-2", "csr", InstanceProvider.ZTS_CERT_USAGE_CLIENT, 30);
        assertEquals(pem, "pem-value");

        certSigner.close();
    }

    @Test
    public void testGenerateX509CertificateInvalidData() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        Request request = Mockito.mock(Request.class);
        Mockito.when(httpClient.POST("https://localhost:443/certsign/v2/x509")).thenReturn(request);

        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(request.send()).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(201);
        Mockito.when(response.getContentAsString()).thenReturn("{\"pem2\": \"pem-value\"}");

        assertNull(certSigner.generateX509Certificate("aws", "us-west-2", "csr", null, 0));

        Mockito.when(response.getContentAsString()).thenReturn("invalid-json");
        assertNull(certSigner.generateX509Certificate("aws", "us-west-2", "csr", null, 0));
        certSigner.close();
    }

    @Test
    public void testGetCACertificateException() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        Mockito.when(httpClient.GET("https://localhost:443/certsign/v2/x509")).thenThrow(new TimeoutException());

        assertNull(certSigner.getCACertificate("aws"));
        certSigner.close();
    }

    @Test
    public void testGetCACertificateInvalidStatus() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(httpClient.GET("https://localhost:443/certsign/v2/x509")).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(400);

        assertNull(certSigner.getCACertificate("aws"));
        certSigner.close();
    }

    @Test
    public void testGetCACertificateResponseNull() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(httpClient.GET("https://localhost:443/certsign/v2/x509")).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn(null);

        assertNull(certSigner.getCACertificate("aws"));
        certSigner.close();
    }

    @Test
    public void testGetCACertificateResponseEmpty() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(httpClient.GET("https://localhost:443/certsign/v2/x509")).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("");

        assertNull(certSigner.getCACertificate("aws"));
        certSigner.close();
    }

    @Test
    public void testGetCACertificate() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(httpClient.GET("https://localhost:443/certsign/v2/x509")).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("{\"pem\": \"pem-value\"}");

        String pem = certSigner.getCACertificate("aws");
        assertEquals(pem, "pem-value");
        certSigner.close();
    }

    @Test
    public void testGetCACertificateInvalidData() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        ContentResponse response = Mockito.mock(ContentResponse.class);
        Mockito.when(httpClient.GET("https://localhost:443/certsign/v2/x509")).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.getContentAsString()).thenReturn("{\"pem2\": \"pem-value\"}");

        assertNull(certSigner.getCACertificate("aws"));

        Mockito.when(response.getContentAsString()).thenReturn("invalid-json");
        assertNull(certSigner.getCACertificate("aws"));
        certSigner.close();
    }
    
    @Test
    public void testGetMaxCertExpiryTime() {
        
        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME);
        
        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        assertEquals(certSigner.getMaxCertExpiryTimeMins(), 43200);
        certSigner.close();
        
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME, "1200");
        certSigner = (HttpCertSigner) certFactory.create();
        assertEquals(certSigner.getMaxCertExpiryTimeMins(), 1200);
        certSigner.close();

        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME);
    }

    @Test
    public void testInitInvalidUri() {

        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();

        try {
            certFactory.create();
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("No CertSigner base uri specified"));
        }

        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI, "https://localhost:443/certsign/v2");
    }

    @Test
    public void testSetupHttpClient() throws Exception {

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        HttpClient client = Mockito.mock(HttpClient.class);
        Mockito.doThrow(new Exception("Invalid client")).when(client).start();

        try {
            certSigner.setupHttpClient(client, 120, 120);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }
    }

    @Test
    public void testStopNullHttpClient() {

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(null);
        certSigner.close();
    }

    @Test
    public void testLoadServicePrivateKeyInvalid() {

        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS, "invalid.class");
        try {
            HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
            certFactory.create();
            fail();
        } catch (IllegalArgumentException ex) {
            assertTrue(ex.getMessage().contains("Invalid private key store"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);
    }
}
