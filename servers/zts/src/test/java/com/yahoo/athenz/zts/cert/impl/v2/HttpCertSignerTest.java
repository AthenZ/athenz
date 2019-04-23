package com.yahoo.athenz.zts.cert.impl.v2;

import static org.mockito.Mockito.times;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.rest.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;

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

    private CloseableHttpResponse mockRequest(int expectedStatusCode, String expectedReponseContent) throws Exception {
        CloseableHttpResponse response = Mockito.mock(CloseableHttpResponse.class);
        StatusLine statusLine = Mockito.mock(StatusLine.class);
        Mockito.when(response.getStatusLine()).thenReturn(statusLine);
        Mockito.when(statusLine.getStatusCode()).thenReturn(expectedStatusCode);
        
        HttpEntity httpEntity = Mockito.mock(HttpEntity.class);
        Mockito.when(response.getEntity()).thenReturn(httpEntity);

        if (expectedReponseContent != null) {
            InputStream stream = new ByteArrayInputStream(expectedReponseContent.getBytes(StandardCharsets.UTF_8));
            Mockito.when(httpEntity.getContent()).thenReturn(stream);
        }
        
        return response;
    }
    
    @Test
    public void testGenerateX509CertificateException() throws Exception {
 
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);
        
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenThrow(new IOException());
        assertNull(certSigner.generateX509Certificate("csr", null, 0));
        Mockito.verify(httpClient, times(3)).execute(Mockito.any(HttpPost.class));
        
        certSigner.close();
    }

    @Test
    public void testGenerateX509CertificateInvalidStatus() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        CloseableHttpResponse response = mockRequest(400, null);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);

        assertNull(certSigner.generateX509Certificate("csr", null, 0));
        certSigner.close();
    }

    @Test
    public void testGenerateX509CertificateResponseNull() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        CloseableHttpResponse response = mockRequest(201, null);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);

        assertNull(certSigner.generateX509Certificate("csr", null, 0));
        certSigner.close();
    }

    @Test
    public void testGenerateX509Certificate() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        String pemResponse = "{\"pem\": \"pem-value\"}";
        CloseableHttpResponse response = mockRequest(201, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);

        String pem = certSigner.generateX509Certificate("csr", null, 0);
        assertEquals(pem, "pem-value");
        Mockito.verify(httpClient, times(1)).execute(Mockito.any(HttpPost.class));

        response = mockRequest(201, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);
        pem = certSigner.generateX509Certificate("csr", ZTSConsts.ZTS_CERT_USAGE_CLIENT, 0);
        assertEquals(pem, "pem-value");
        Mockito.verify(httpClient, times(2)).execute(Mockito.any(HttpPost.class));

        response = mockRequest(201, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);
        pem = certSigner.generateX509Certificate("csr", ZTSConsts.ZTS_CERT_USAGE_CLIENT, 30);
        assertEquals(pem, "pem-value");
        Mockito.verify(httpClient, times(3)).execute(Mockito.any(HttpPost.class));

        certSigner.close();
    }
    


    @Test
    public void testGenerateX509CertificateInvalidData() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        String pemResponse = "{\"pem2\": \"pem-value\"}";
        CloseableHttpResponse response = mockRequest(201, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);
        assertNull(certSigner.generateX509Certificate("csr", null, 0));

        pemResponse = "invalid-json";
        response = mockRequest(201, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);
        assertNull(certSigner.generateX509Certificate("csr", null, 0));

        certSigner.close();
    }

    @Test
    public void testGetCACertificateException() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenThrow(new IOException());
        assertNull(certSigner.getCACertificate());
        certSigner.close();
    }

    @Test
    public void testGetCACertificateInvalidStatus() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        CloseableHttpResponse response = mockRequest(400, null);
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(response);
        
        assertNull(certSigner.getCACertificate());
        certSigner.close();
    }

    @Test
    public void testGetCACertificateResponseNull() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        CloseableHttpResponse response = mockRequest(201, null);
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(response);
        
        assertNull(certSigner.getCACertificate());
        certSigner.close();
    }

    @Test
    public void testGetCACertificate() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        String pemResponse = "{\"pem\": \"pem-value\"}";
        CloseableHttpResponse response = mockRequest(200, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(response);
        
        String pem = certSigner.getCACertificate();
        assertEquals(pem, "pem-value");
        Mockito.verify(httpClient, times(1)).execute(Mockito.any(HttpGet.class));

        certSigner.close();
    }

    @Test
    public void testGetCACertificateInvalidData() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        String pemResponse = "{\"pem2\": \"pem-value\"}";
        CloseableHttpResponse response = mockRequest(200, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(response);

        assertNull(certSigner.getCACertificate());

        pemResponse = "invalid-json";
        response = mockRequest(200, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(response);
        
        assertNull(certSigner.getCACertificate());

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

