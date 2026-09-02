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
package com.yahoo.athenz.crypki.http;

import com.yahoo.athenz.common.server.cert.Priority;
import com.yahoo.athenz.crypki.CrypkiConsts;
import com.yahoo.athenz.crypki.CrypkiException;
import com.yahoo.athenz.crypki.X509SignRequest;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

public class HttpCrypkiSignerTest {

    @BeforeMethod
    public void setup() {
        System.setProperty(CrypkiConsts.PROP_CERTSIGN_BASE_URI, "https://localhost:443/v3");
    }

    @AfterMethod
    public void cleanup() {
        System.clearProperty(CrypkiConsts.PROP_CERTSIGN_PROVIDER_KEYS_FNAME);
        System.clearProperty(CrypkiConsts.PROP_CERTSIGN_RETRY_CONN_ONLY);
        System.clearProperty(CrypkiConsts.PROP_CERTSIGN_MAX_EXPIRY_TIME);
        System.clearProperty(CrypkiConsts.PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);
        System.clearProperty(CrypkiConsts.PROP_KEYSTORE_PATH);
        System.clearProperty(CrypkiConsts.PROP_KEYSTORE_PASSWORD);
        System.clearProperty(CrypkiConsts.PROP_TRUSTSTORE_PATH);
        System.clearProperty(CrypkiConsts.PROP_TRUSTSTORE_PASSWORD);
        System.setProperty(CrypkiConsts.PROP_CERTSIGN_BASE_URI, "https://localhost:443/v3");
    }

    @Test
    public void testFactoryAndSign() throws Exception {
        HttpCrypkiSigner signer = new HttpCrypkiSigner();
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        CloseableHttpResponse response = Mockito.mock(CloseableHttpResponse.class);
        HttpEntity entity = Mockito.mock(HttpEntity.class);
        Mockito.when(response.getEntity()).thenReturn(entity);
        Mockito.when(response.getCode()).thenReturn(201);
        Mockito.when(entity.getContent()).thenReturn(
                new ByteArrayInputStream("{\"cert\":\"pem-value\"}".getBytes(StandardCharsets.UTF_8)));
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(response);
        signer.setHttpClient(httpClient);

        assertEquals(signer.sign(X509SignRequest.builder().csrPem("csr").keyId("x509-key")
                .validitySeconds(45).extKeyUsage(List.of(2, 3)).priority(Priority.High).build()),
                "pem-value");
        assertEquals(signer.getProviderKeyId("unknown", null), "x509-key");
        assertEquals(signer.getMaxCertExpiryTimeMins(), 43200);
        X509CertificateSigningRequest mapped = signer.toHttpSigningRequest(
                X509SignRequest.builder().csrPem("csr").keyId("x509-key")
                        .validitySeconds(45).extKeyUsage(List.of(2, 3)).build());
        assertEquals(mapped.getValidity(), Integer.valueOf(45));
        assertEquals(mapped.getExtKeyUsage(), List.of(2, 3));
        assertEquals(mapped.getCsr(), "csr");
        assertEquals(signer.toHttpSigningRequest(X509SignRequest.builder().csrPem("csr").build())
                .getValidity(), Integer.valueOf((int) TimeUnit.SECONDS.convert(30, TimeUnit.DAYS)));
        assertNotNull(signer.getX509CertSigningRequest("aws", "csr", CrypkiConsts.CERT_USAGE_CLIENT,
                30, Priority.High, null));
        assertNotNull(signer.getX509CertSigningRequest("aws", "csr",
                CrypkiConsts.CERT_USAGE_CODE_SIGNING, 15, Priority.High, null));
        assertNotNull(signer.getX509CertSigningRequest("aws", "csr",
                CrypkiConsts.CERT_USAGE_TIMESTAMPING, 15, Priority.High, null));
        assertNotNull(signer.getX509CertSigningRequest("aws", "csr", null, 0, Priority.High, "kid"));
        signer.close();
    }

    @Test
    public void testMissingBaseUri() {
        System.clearProperty(CrypkiConsts.PROP_CERTSIGN_BASE_URI);
        expectThrows(CrypkiException.class, HttpCrypkiSigner::new);
        System.setProperty(CrypkiConsts.PROP_CERTSIGN_BASE_URI, "https://localhost:443/v3");
    }

    @Test
    public void testFactory() {
        assertNotNull(new HttpCrypkiSignerFactory().create());
        assertNotNull(new HttpCrypkiSignerFactory().createSigner());
    }

    @Test
    public void testInvalidProviderFile() {
        System.setProperty(CrypkiConsts.PROP_CERTSIGN_PROVIDER_KEYS_FNAME, "invalid-json-file");
        expectThrows(CrypkiException.class, HttpCrypkiSigner::new);
    }

    @Test
    public void testKeyMeta() {
        KeyMeta keyMeta = new KeyMeta("keymeta");
        assertEquals(keyMeta.getIdentifier(), "keymeta");
        keyMeta.setIdentifier("");
        assertEquals(keyMeta.getIdentifier(), "");
        X509Certificate cert = new X509Certificate();
        cert.setCert("pem");
        assertEquals(cert.getCert(), "pem");
        ProviderSignerKey providerKey = new ProviderSignerKey();
        providerKey.setKeyId("k");
        providerKey.setProviders(java.util.List.of("p"));
        assertEquals(providerKey.getKeyId(), "k");
        assertEquals(providerKey.getProviders(), java.util.List.of("p"));
        ProviderSignerKeys keys = new ProviderSignerKeys();
        keys.setDefaultKeyId("d");
        keys.setProviderKeys(java.util.List.of(providerKey));
        assertEquals(keys.getDefaultKeyId(), "d");
        assertEquals(keys.getProviderKeys().size(), 1);
        assertNull(HttpCrypkiSigner.readFileContents("/tmp/does-not-exist-crypki-keys.json"));
    }

    @Test
    public void testSignPreservesSecondsAndRetries() throws Exception {
        HttpCrypkiSigner signer = new HttpCrypkiSigner();
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenThrow(new ConnectException());
        signer.setHttpClient(httpClient);
        assertNull(signer.sign(X509SignRequest.builder().csrPem("csr").validitySeconds(45)
                .extKeyUsage(List.of(2)).build()));
        Mockito.verify(httpClient, Mockito.times(2)).execute(Mockito.any(HttpPost.class));

        Mockito.reset(httpClient);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenThrow(new IOException());
        assertNull(signer.generateX509Certificate("aws", null, "csr", null, 0,
                Priority.Unspecified_priority, null));
        Mockito.verify(httpClient, Mockito.times(1)).execute(Mockito.any(HttpPost.class));

        System.setProperty(CrypkiConsts.PROP_CERTSIGN_RETRY_CONN_ONLY, "false");
        HttpCrypkiSigner retrySigner = new HttpCrypkiSigner();
        retrySigner.setHttpClient(httpClient);
        Mockito.reset(httpClient);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenThrow(new IOException());
        assertNull(retrySigner.generateX509Certificate("aws", null, "csr", null, 0,
                Priority.Unspecified_priority, null));
        Mockito.verify(httpClient, Mockito.times(2)).execute(Mockito.any(HttpPost.class));
        retrySigner.close();
        signer.close();
    }

    @Test
    public void testHttpStatusAndCaCertificate() throws Exception {
        HttpCrypkiSigner signer = new HttpCrypkiSigner();
        CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
        signer.setHttpClient(httpClient);

        CloseableHttpResponse bad = mockResponse(400, null);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(bad);
        assertNull(signer.generateX509Certificate("aws", null, "csr", null, 0,
                Priority.Unspecified_priority, null));

        CloseableHttpResponse empty = mockResponse(201, null);
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(empty);
        assertNull(signer.generateX509Certificate("aws", null, "csr", null, 0,
                Priority.Unspecified_priority, null));

        CloseableHttpResponse badJson = mockResponse(201, "not-json");
        Mockito.when(httpClient.execute(Mockito.any(HttpPost.class))).thenReturn(badJson);
        assertNull(signer.generateX509Certificate("aws", null, "csr", null, 0,
                Priority.Unspecified_priority, null));

        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenThrow(new IOException());
        assertNull(signer.getCACertificate("aws", null));
        assertNull(signer.getCACertificate("x509-key"));

        CloseableHttpResponse caBad = mockResponse(400, "nope");
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(caBad);
        assertNull(signer.getCACertificate("aws", "kid"));

        CloseableHttpResponse caOk = mockResponse(200, "{\"cert\":\"ca-pem\"}");
        Mockito.when(httpClient.execute(Mockito.any(HttpGet.class))).thenReturn(caOk);
        assertEquals(signer.getCACertificate("aws", "kid"), "ca-pem");
        signer.close();
    }

    @Test
    public void testInvalidRequestBuildIsSoftFail() {
        HttpCrypkiSigner signer = new HttpCrypkiSigner() {
            @Override
            public Object getX509CertSigningRequest(String provider, String csr, String keyUsage,
                    int expireMins, Priority priority, String signerKeyId) {
                throw new IllegalArgumentException("bad csr");
            }
        };
        assertNull(signer.generateX509Certificate("aws", null, "csr", null, 0,
                Priority.High, "keyid"));
        signer.close();
    }

    @Test
    public void testProviderKeyFile() {
        System.setProperty(CrypkiConsts.PROP_CERTSIGN_PROVIDER_KEYS_FNAME,
                "src/test/resources/crypki_key_providers.json");
        HttpCrypkiSigner signer = new HttpCrypkiSigner();
        assertEquals(signer.getProviderKeyId("athenz.aws.us-east-1", null), "x509-aws-key");
        assertEquals(signer.getProviderKeyId("unknown", null), "x509-key-data");
        assertEquals(signer.getProviderKeyId(null, "explicit"), "explicit");
        signer.close();
    }

    @Test
    public void testProviderKeyFileMissingFields() {
        System.setProperty(CrypkiConsts.PROP_CERTSIGN_PROVIDER_KEYS_FNAME,
                "src/test/resources/crypki_key_providers_missing_fields.json");
        HttpCrypkiSigner signer = new HttpCrypkiSigner();
        assertEquals(signer.getProviderKeyId("athenz.aws.us-west-1", ""), "x509-aws-key");
        assertEquals(signer.getProviderKeyId("athenz.aws.us-east-1", null), "x509-key");
        signer.close();
    }

    @Test
    public void testProviderKeyFileInvalidJson() {
        System.setProperty(CrypkiConsts.PROP_CERTSIGN_PROVIDER_KEYS_FNAME,
                "src/test/resources/crypki_key_providers_invalid.json");
        expectThrows(CrypkiException.class, HttpCrypkiSigner::new);
    }

    @Test
    public void testInvalidPrivateKeyStoreAndMaxExpiry() {
        System.setProperty(CrypkiConsts.PROP_PRIVATE_KEY_STORE_FACTORY_CLASS, "invalid.class");
        expectThrows(IllegalArgumentException.class, HttpCrypkiSigner::new);
        System.clearProperty(CrypkiConsts.PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);

        System.setProperty(CrypkiConsts.PROP_CERTSIGN_MAX_EXPIRY_TIME, "1200");
        HttpCrypkiSigner signer = new HttpCrypkiSigner();
        assertEquals(signer.getMaxCertExpiryTimeMins(), 1200);
        X509CertificateSigningRequest capped = signer.toHttpSigningRequest(
                X509SignRequest.builder().csrPem("csr").validitySeconds(999999).build());
        assertEquals(capped.getValidity(), Integer.valueOf(1200 * 60));
        signer.close();
    }

    @Test
    public void testSslFactoryProperties() throws Exception {
        HttpCrypkiSigner signer = new HttpCrypkiSigner();
        java.io.File keyStore = java.io.File.createTempFile("crypki-ks", ".p12");
        keyStore.deleteOnExit();
        System.setProperty(CrypkiConsts.PROP_KEYSTORE_PATH, keyStore.getAbsolutePath());
        System.setProperty(CrypkiConsts.PROP_KEYSTORE_PASSWORD, "changeit");
        System.setProperty(CrypkiConsts.PROP_TRUSTSTORE_PATH, keyStore.getAbsolutePath());
        System.setProperty(CrypkiConsts.PROP_TRUSTSTORE_PASSWORD, "changeit");
        com.yahoo.athenz.auth.PrivateKeyStore pkey = Mockito.mock(com.yahoo.athenz.auth.PrivateKeyStore.class);
        Mockito.when(pkey.getSecret(Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn("changeit".toCharArray());
        assertNotNull(signer.createSslContextFactory(pkey));
        assertNotNull(signer.createSslContextFactory(null));
        signer.close();
    }

    @Test
    public void testX509CertUri() {
        HttpCrypkiSigner signer = new HttpCrypkiSigner();
        assertTrue(signer.getX509CertUri(signer.serverBaseUri, "aws", "kid")
                .endsWith("/sig/x509-cert/keys/kid"));
        assertTrue(signer.getX509CertUri(signer.serverBaseUri, null, null)
                .endsWith("/sig/x509-cert/keys/x509-key"));
        signer.close();
    }

    private static CloseableHttpResponse mockResponse(int status, String body) throws Exception {
        CloseableHttpResponse response = Mockito.mock(CloseableHttpResponse.class);
        HttpEntity entity = Mockito.mock(HttpEntity.class);
        Mockito.when(response.getEntity()).thenReturn(entity);
        Mockito.when(response.getCode()).thenReturn(status);
        if (body != null) {
            Mockito.when(entity.getContent()).thenReturn(
                    new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        }
        return response;
    }
}
