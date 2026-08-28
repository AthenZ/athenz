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
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.expectThrows;

public class HttpCrypkiSignerTest {

    @BeforeMethod
    public void setup() {
        System.setProperty(CrypkiConsts.PROP_CERTSIGN_BASE_URI, "https://localhost:443/v3");
    }

    @AfterMethod
    public void cleanup() {
        System.clearProperty(CrypkiConsts.PROP_CERTSIGN_PROVIDER_KEYS_FNAME);
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

        assertEquals(signer.sign(X509SignRequest.builder().csrPem("csr").keyId("x509-key").build()), "pem-value");
        assertEquals(signer.getProviderKeyId("unknown", null), "x509-key");
        assertEquals(signer.getMaxCertExpiryTimeMins(), 43200);
        assertNotNull(signer.getX509CertSigningRequest("aws", "csr", CrypkiConsts.CERT_USAGE_CLIENT,
                30, Priority.High, null));
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
}
