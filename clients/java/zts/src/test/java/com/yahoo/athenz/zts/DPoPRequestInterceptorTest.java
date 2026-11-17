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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.token.DPoPProof;
import com.yahoo.athenz.auth.token.DPoPProofOptions;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import static org.testng.Assert.*;

public class DPoPRequestInterceptorTest {

    private static final String ZTS_URL = "https://zts.athenz.io:4443/zts/v1";
    private static final String HTU = ZTS_URL + "/oauth2/token";

    private KeyPair keyPair;

    @BeforeClass
    public void setup() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = generator.generateKeyPair();
    }

    private DPoPProof validate(final String proof) {
        DPoPProofOptions options = DPoPProofOptions.builder().addAllowedHtu(HTU).build();
        return new DPoPProof(proof, "POST", options, System.currentTimeMillis() / 1000);
    }

    @Test
    public void testTokenRequestGetsProof() {
        DPoPRequestInterceptor interceptor = new DPoPRequestInterceptor(ZTS_URL, () -> keyPair);
        assertEquals(interceptor.getHtu(), HTU);

        BasicHttpRequest request = new BasicHttpRequest("POST", "/zts/v1/oauth2/token");
        interceptor.process(request, null, null);

        Header[] headers = request.getHeaders(DPoPProof.HTTP_HEADER);
        assertEquals(headers.length, 1);
        DPoPProof proof = validate(headers[0].getValue());
        assertEquals(proof.getJwkThumbprint(), DPoPProof.computeJwkThumbprint(keyPair.getPublic()));
        assertNull(proof.getAccessTokenHash());

        // a retry replaces the proof with a fresh one instead of adding another header

        final String firstJti = proof.getJwtId();
        interceptor.process(request, null, null);
        headers = request.getHeaders(DPoPProof.HTTP_HEADER);
        assertEquals(headers.length, 1);
        assertNotEquals(validate(headers[0].getValue()).getJwtId(), firstJti);
    }

    @Test
    public void testTokenRequestWithQuery() {
        DPoPRequestInterceptor interceptor = new DPoPRequestInterceptor(ZTS_URL + "/", () -> keyPair);
        assertEquals(interceptor.getHtu(), HTU);

        BasicHttpRequest request = new BasicHttpRequest("post", "/zts/v1/oauth2/token?x=y");
        interceptor.process(request, null, null);
        assertNotNull(request.getFirstHeader(DPoPProof.HTTP_HEADER));
    }

    @Test
    public void testOtherRequestsUntouched() {
        DPoPRequestInterceptor interceptor = new DPoPRequestInterceptor(ZTS_URL, () -> keyPair);

        BasicHttpRequest getRequest = new BasicHttpRequest("GET", "/zts/v1/oauth2/token");
        interceptor.process(getRequest, null, null);
        assertNull(getRequest.getFirstHeader(DPoPProof.HTTP_HEADER));

        BasicHttpRequest introspect = new BasicHttpRequest("POST", "/zts/v1/oauth2/introspect");
        interceptor.process(introspect, null, null);
        assertNull(introspect.getFirstHeader(DPoPProof.HTTP_HEADER));

        BasicHttpRequest tokenInQuery = new BasicHttpRequest("POST", "/zts/v1/rolecert?p=/oauth2/token");
        interceptor.process(tokenInQuery, null, null);
        assertNull(tokenInQuery.getFirstHeader(DPoPProof.HTTP_HEADER));
    }

    @Test
    public void testNoKeyConfigured() {
        DPoPRequestInterceptor interceptor = new DPoPRequestInterceptor(ZTS_URL, () -> null);
        BasicHttpRequest request = new BasicHttpRequest("POST", "/zts/v1/oauth2/token");
        interceptor.process(request, null, null);
        assertNull(request.getFirstHeader(DPoPProof.HTTP_HEADER));
    }

    @Test
    public void testIsTokenEndpoint() {
        assertTrue(DPoPRequestInterceptor.isTokenEndpoint("/zts/v1/oauth2/token"));
        assertTrue(DPoPRequestInterceptor.isTokenEndpoint("/oauth2/token?a=b"));
        assertFalse(DPoPRequestInterceptor.isTokenEndpoint(null));
        assertFalse(DPoPRequestInterceptor.isTokenEndpoint("/zts/v1/oauth2/tokens"));
        assertFalse(DPoPRequestInterceptor.isTokenEndpoint("/zts/v1/oauth2/keys"));
    }
}
