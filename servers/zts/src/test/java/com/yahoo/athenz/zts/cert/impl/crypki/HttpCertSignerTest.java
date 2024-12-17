package com.yahoo.athenz.zts.cert.impl.crypki;

import static org.mockito.Mockito.times;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.nio.charset.StandardCharsets;

import com.yahoo.athenz.common.server.cert.Priority;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.zts.ResourceException;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.zts.ZTSConsts;

public class HttpCertSignerTest {
    
    @BeforeClass
    public void setup() {
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI, "https://localhost:443/v3");
    }
    
    @Test
    public void testHttpCertSignerFactory() {
        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        assertNotNull(certFactory);

        CertSigner certSigner = certFactory.create();
        assertNotNull(certSigner);

        certSigner.close();
    }

    private CloseableHttpResponse mockRequest(int expectedStatusCode, String expectedResponseContent) throws Exception {
        CloseableHttpResponse response = Mockito.mock(CloseableHttpResponse.class);

        HttpEntity httpEntity = Mockito.mock(HttpEntity.class);
        Mockito.when(response.getEntity()).thenReturn(httpEntity);
        Mockito.when(response.getCode()).thenReturn(expectedStatusCode);

        if (expectedResponseContent != null) {
            InputStream stream = new ByteArrayInputStream(expectedResponseContent.getBytes(StandardCharsets.UTF_8));
            Mockito.when(httpEntity.getContent()).thenReturn(stream);
        }
        
        return response;
    }
    
    @Test
    public void testGenerateX509CertificateExceptionNoRetry() throws Exception {
 
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);
        
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenThrow(new IOException());
        assertNull(certSigner.generateX509Certificate("aws", null, "csr", null, 0, Priority.Unspecified_priority, null));
        Mockito.verify(httpClient, times(1)).execute(Mockito.any(HttpPost.class));
        
        certSigner.close();
    }

    @Test
    public void testGenerateX509CertificateExceptionIOExceptionRetry() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_RETRY_CONN_ONLY, "false");

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenThrow(new IOException());
        assertNull(certSigner.generateX509Certificate("aws", null, "csr", null, 0, Priority.Unspecified_priority, null));
        Mockito.verify(httpClient, times(2)).execute(Mockito.any(HttpPost.class));

        certSigner.close();
        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_RETRY_CONN_ONLY);
    }

    @Test
    public void testGenerateX509CertificateExceptionWithRetry() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenThrow(new ConnectException());
        assertNull(certSigner.generateX509Certificate("aws", null, "csr", null, 0, Priority.Unspecified_priority, null));
        Mockito.verify(httpClient, times(2)).execute(Mockito.any(HttpPost.class));

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

        assertNull(certSigner.generateX509Certificate("aws", null, "csr", null, 0, Priority.Unspecified_priority, null));
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

        assertNull(certSigner.generateX509Certificate("aws", null, "csr", null, 0, Priority.Unspecified_priority, null));
        certSigner.close();
    }

    @Test
    public void testGenerateX509Certificate() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        String pemResponse = "{\"cert\": \"pem-value\"}";
        CloseableHttpResponse response = mockRequest(201, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);

        String pem = certSigner.generateX509Certificate("aws", null, "csr", null, 0, Priority.Unspecified_priority, null);
        assertEquals(pem, "pem-value");
        Mockito.verify(httpClient, times(1)).execute(Mockito.any(HttpPost.class));

        response = mockRequest(201, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);
        pem = certSigner.generateX509Certificate("aws", null, "csr", InstanceProvider.ZTS_CERT_USAGE_CLIENT, 0,
                Priority.Unspecified_priority, null);
        assertEquals(pem, "pem-value");
        Mockito.verify(httpClient, times(2)).execute(Mockito.any(HttpPost.class));

        response = mockRequest(201, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);
        pem = certSigner.generateX509Certificate("aws", null, "csr", InstanceProvider.ZTS_CERT_USAGE_CLIENT, 30,
                Priority.Unspecified_priority, null);
        assertEquals(pem, "pem-value");
        Mockito.verify(httpClient, times(3)).execute(Mockito.any(HttpPost.class));

        response = mockRequest(201, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);
        pem = certSigner.generateX509Certificate("aws", null, "csr", InstanceProvider.ZTS_CERT_USAGE_CODE_SIGNING,
                15, Priority.Unspecified_priority, null);
        assertEquals(pem, "pem-value");
        Mockito.verify(httpClient, times(4)).execute(Mockito.any(HttpPost.class));

        response = mockRequest(201, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);
        pem = certSigner.generateX509Certificate("aws", null, "csr", InstanceProvider.ZTS_CERT_USAGE_TIMESTAMPING,
                30, Priority.Unspecified_priority, null);
        assertEquals(pem, "pem-value");
        Mockito.verify(httpClient, times(5)).execute(Mockito.any(HttpPost.class));

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
        assertNull(certSigner.generateX509Certificate("aws", null, "csr", null, 0, Priority.Unspecified_priority, null));

        pemResponse = "invalid-json";
        response = mockRequest(201, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);
        assertNull(certSigner.generateX509Certificate("aws", null, "csr", null, 0, Priority.Unspecified_priority, null));

        certSigner.close();
    }
    
    @Test
    public void testGenerateX509CertificateInvalidCsr() {
       HttpCertSigner testHttpCertSigner = new HttpCertSigner() {
            @Override
            public Object getX509CertSigningRequest(String provider, String csr, String keyUsage, int expireMins,
                    Priority priority, String keyId) {
                throw new IllegalArgumentException();
            }
        };
        assertNull(testHttpCertSigner.generateX509Certificate("aws", null, "csr", null, 0,
                Priority.Unspecified_priority, null));
        assertNull(testHttpCertSigner.generateX509Certificate("aws", null, "csr", null, 0, Priority.High, null));
        assertNull(testHttpCertSigner.generateX509Certificate("aws", null, "csr", null, 0, Priority.High, "keyid"));
        testHttpCertSigner.close();
    }

    @Test
    public void testGetCACertificateException() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenThrow(new IOException());
        assertNull(certSigner.getCACertificate("aws", null));
        certSigner.close();
    }

    @Test
    public void testGetCACertificateInvalidStatus() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        CloseableHttpResponse response = mockRequest(400, "invalid-status");
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(response);
        
        assertNull(certSigner.getCACertificate("aws", null));
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
        
        assertNull(certSigner.getCACertificate("aws", null));
        certSigner.close();
    }

    @Test
    public void testGetCACertificate() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        String pemResponse = "{\"cert\": \"pem-value\"}";
        CloseableHttpResponse response = mockRequest(200, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(response);
        
        String pem = certSigner.getCACertificate("aws", null);
        assertEquals(pem, "pem-value");
        Mockito.verify(httpClient, times(1)).execute(Mockito.any(HttpGet.class));

        certSigner.close();
    }

    @Test
    public void testGetCACertificateWithKeyId() throws Exception {

        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);

        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();
        certSigner.setHttpClient(httpClient);

        String pemResponse = "{\"cert\": \"pem-value\"}";
        CloseableHttpResponse response = mockRequest(200, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(response);

        String pem = certSigner.getCACertificate("aws", "keyid");
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

        assertNull(certSigner.getCACertificate("aws", null));

        pemResponse = "invalid-json";
        response = mockRequest(200, pemResponse);
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(response);
        
        assertNull(certSigner.getCACertificate("aws", null));

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
    
    @Test
    public void testInvalidSSLContext() {
        System.setProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PATH, "src/test/resources/invalid_keystore.jks");
        try {
            HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
            certFactory.create();
            fail();
        } catch (ResourceException ex) {
            assertTrue(ex.getMessage().contains("unable to start sslContextFactory"));
        }
        System.clearProperty(ZTSConsts.ZTS_PROP_KEYSTORE_PATH);
    }
 
    @Test
    public void tesKeyMeta() {
        KeyMeta keyMeta = new KeyMeta("keymeta");
        Assert.assertEquals(keyMeta.getIdentifier(), "keymeta");
        keyMeta.setIdentifier("");
        Assert.assertEquals(keyMeta.getIdentifier(), "");
    }

    @Test
    public void testProviderKeyLookup() {
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_PROVIDER_KEYS_FNAME, "src/test/resources/crypki_key_providers.json");
        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();

        assertEquals(certSigner.getProviderKeyId("unknown", null), "x509-key-data");
        assertEquals(certSigner.getProviderKeyId(null, null), "x509-key-data");
        assertEquals(certSigner.getProviderKeyId("", null), "x509-key-data");

        assertEquals(certSigner.getProviderKeyId("unknown", ""), "x509-key-data");
        assertEquals(certSigner.getProviderKeyId(null, ""), "x509-key-data");
        assertEquals(certSigner.getProviderKeyId("", ""), "x509-key-data");

        // using null for the key-id argument

        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-east-1", null), "x509-aws-key");
        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-east-2", null), "x509-aws-key");
        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-west-1", null), "x509-aws-key");
        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-west-2", null), "x509-aws-key");

        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-west-3", null), "x509-key-data");

        assertEquals(certSigner.getProviderKeyId("athenz.azure.eastus", null), "x509-azure-key");
        assertEquals(certSigner.getProviderKeyId("athenz.azure.westus", null), "x509-azure-key");

        assertEquals(certSigner.getProviderKeyId("athenz.azure.eastus2", null), "x509-key-data");

        assertEquals(certSigner.getProviderKeyId("athenz.azure.eastus2", "x509-key-data-id"), "x509-key-data-id");

        // using empty string for key-id argument

        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-east-1", ""), "x509-aws-key");
        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-east-2", ""), "x509-aws-key");
        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-west-1", ""), "x509-aws-key");
        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-west-2", ""), "x509-aws-key");

        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-west-3", ""), "x509-key-data");

        assertEquals(certSigner.getProviderKeyId("athenz.azure.eastus", ""), "x509-azure-key");
        assertEquals(certSigner.getProviderKeyId("athenz.azure.westus", ""), "x509-azure-key");

        assertEquals(certSigner.getProviderKeyId("athenz.azure.eastus2", ""), "x509-key-data");

        assertEquals(certSigner.getProviderKeyId("athenz.azure.eastus2", "x509-key-data-id2"), "x509-key-data-id2");

        certSigner.close();
        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_PROVIDER_KEYS_FNAME);
    }

    @Test
    public void testProviderKeyLookupNoConfig() {

        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_PROVIDER_KEYS_FNAME);
        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();

        assertEquals(certSigner.getProviderKeyId("unknown", null), "x509-key");
        assertEquals(certSigner.getProviderKeyId(null, ""), "x509-key");
        assertEquals(certSigner.getProviderKeyId("", null), "x509-key");

        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-east-1", null), "x509-key");
        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-east-1", "x509-key-id"), "x509-key-id");
        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-east-2", ""), "x509-key");
        assertEquals(certSigner.getProviderKeyId("athenz.azure.eastus", null), "x509-key");
        assertEquals(certSigner.getProviderKeyId("athenz.azure.eastus", "x509-key-id2"), "x509-key-id2");
        assertEquals(certSigner.getProviderKeyId("athenz.azure.westus", ""), "x509-key");
        certSigner.close();
    }

    @Test
    public void testProviderKeyLookupInvalidFields() {
        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_PROVIDER_KEYS_FNAME, "src/test/resources/crypki_key_providers_missing_fields.json");
        HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
        HttpCertSigner certSigner = (HttpCertSigner) certFactory.create();

        assertEquals(certSigner.getProviderKeyId("unknown", null), "x509-key");
        assertEquals(certSigner.getProviderKeyId(null, null), "x509-key");
        assertEquals(certSigner.getProviderKeyId("", ""), "x509-key");

        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-west-1", ""), "x509-aws-key");
        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-west-2", null), "x509-aws-key");

        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-east-1", null), "x509-key");
        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-east-2", ""), "x509-key");
        assertEquals(certSigner.getProviderKeyId("athenz.aws.us-west-3", null), "x509-key");

        assertEquals(certSigner.getProviderKeyId("athenz.azure.eastus", null), "x509-azure-key");
        assertEquals(certSigner.getProviderKeyId("athenz.azure.westus", null), "x509-azure-key");

        assertEquals(certSigner.getProviderKeyId("athenz.azure.eastus2", null), "x509-key");

        certSigner.close();
        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_PROVIDER_KEYS_FNAME);
    }

    @Test
    public void testProviderKeyLookupInvalidJson() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_PROVIDER_KEYS_FNAME, "src/test/resources/crypki_key_providers_invalid.json");

        try {
            HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
            certFactory.create();
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_PROVIDER_KEYS_FNAME);
    }

    @Test
    public void testProviderKeyLookupInvalidFile() {

        System.setProperty(ZTSConsts.ZTS_PROP_CERTSIGN_PROVIDER_KEYS_FNAME, "invalid-json-file");

        try {
            HttpCertSignerFactory certFactory = new HttpCertSignerFactory();
            certFactory.create();
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 500);
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_CERTSIGN_PROVIDER_KEYS_FNAME);
    }
}

