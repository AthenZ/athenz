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
package com.yahoo.athenz.zts.cert.impl;

import static org.testng.Assert.*;

import java.util.concurrent.TimeoutException;

import com.yahoo.athenz.zts.cert.CertSigner;
import com.yahoo.athenz.zts.cert.impl.HttpCertSigner;
import com.yahoo.athenz.zts.cert.impl.HttpCertSignerFactory;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.mockito.Mockito;
import org.testng.annotations.Test;

public class HttpCertSignerTest {

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

        assertNull(certSigner.generateX509Certificate("csr"));
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

        assertNull(certSigner.generateX509Certificate("csr"));
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

        assertNull(certSigner.generateX509Certificate("csr"));
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

        assertNull(certSigner.generateX509Certificate("csr"));
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

        String pem = certSigner.generateX509Certificate("csr");
        assertEquals(pem, "pem-value");
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

        assertNull(certSigner.generateX509Certificate("csr"));

        Mockito.when(response.getContentAsString()).thenReturn("invalid-json");
        assertNull(certSigner.generateX509Certificate("csr"));
    }

    @Test
    public void testGetCACertificateException() throws Exception {

        HttpClient httpClient = Mockito.mock(HttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        Mockito.when(httpClient.GET("https://localhost:443/certsign/v2/x509")).thenThrow(new TimeoutException());

        assertNull(certSigner.getCACertificate());
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

        assertNull(certSigner.getCACertificate());
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

        assertNull(certSigner.getCACertificate());
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

        assertNull(certSigner.getCACertificate());
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

        String pem = certSigner.getCACertificate();
        assertEquals(pem, "pem-value");
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

        assertNull(certSigner.getCACertificate());

        Mockito.when(response.getContentAsString()).thenReturn("invalid-json");
        assertNull(certSigner.getCACertificate());
    }
}
