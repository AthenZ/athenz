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
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.protocol.HttpContext;

import java.security.KeyPair;

/**
 * Apache HttpClient 5 request interceptor that adds a freshly generated DPoP
 * proof (RFC 9449) to every POST request sent to the ZTS oauth2 token endpoint.
 * A new proof (new jti and iat) is generated for each execution, including
 * retries. ZTSClient installs this interceptor automatically; callers that
 * provide their own client with ZTSClient.setZTSRDLGeneratedClient must
 * register it on their http client.
 */
public class DPoPRequestInterceptor implements HttpRequestInterceptor {

    static final String TOKEN_ENDPOINT_PATH = "/oauth2/token";
    private static final String HTTP_POST = "POST";

    private final String htu;
    private final DPoPKeyProvider keyProvider;

    /**
     * @param ztsUrl ZTS server url including the /zts/v1 path
     * @param keyProvider provider of the key pair used to sign proofs
     */
    public DPoPRequestInterceptor(final String ztsUrl, DPoPKeyProvider keyProvider) {
        String baseUrl = ztsUrl;
        while (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        this.htu = baseUrl + TOKEN_ENDPOINT_PATH;
        this.keyProvider = keyProvider;
    }

    @Override
    public void process(HttpRequest request, EntityDetails entity, HttpContext context) {

        if (!HTTP_POST.equalsIgnoreCase(request.getMethod()) || !isTokenEndpoint(request.getPath())) {
            return;
        }
        final KeyPair keyPair = keyProvider.getKeyPair();
        if (keyPair == null) {
            return;
        }
        request.setHeader(DPoPProof.HTTP_HEADER, DPoPProof.generate(keyPair.getPrivate(), keyPair.getPublic(),
                HTTP_POST, htu, null, null, System.currentTimeMillis() / 1000));
    }

    static boolean isTokenEndpoint(final String requestPath) {
        if (requestPath == null) {
            return false;
        }
        final int queryIdx = requestPath.indexOf('?');
        final String path = queryIdx == -1 ? requestPath : requestPath.substring(0, queryIdx);
        return path.endsWith(TOKEN_ENDPOINT_PATH);
    }

    String getHtu() {
        return htu;
    }
}
