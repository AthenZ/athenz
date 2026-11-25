/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.pdp.impl;

import com.yahoo.athenz.common.server.pdp.ExternalPdpException;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Minimal JSON-over-HTTPS transport for PDP calls: no automatic retries,
 * no redirects, no cookies and a bounded response size. Request and
 * response bodies are never logged since they carry principal data.
 */
public class AuthZenHttpClient implements Closeable {

    private static final int HTTP_OK = 200;
    private static final int HTTP_TOO_MANY_REQUESTS = 429;
    private static final int HTTP_SERVER_ERROR = 500;

    private final CloseableHttpClient client;
    private final int maxResponseBytes;

    /**
     * @param sslContext client ssl context (null for the JVM default)
     * @param connectTimeoutMs connect timeout in milliseconds
     * @param readTimeoutMs socket read timeout in milliseconds
     * @param maxConnections maximum number of pooled connections
     * @param maxResponseBytes maximum accepted response body size
     */
    public AuthZenHttpClient(final SSLContext sslContext, int connectTimeoutMs, int readTimeoutMs,
            int maxConnections, int maxResponseBytes) {
        this(HttpClients.custom()
                .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                        .setTlsSocketStrategy(new DefaultClientTlsStrategy(
                                sslContext == null ? SSLContexts.createDefault() : sslContext))
                        .setDefaultConnectionConfig(ConnectionConfig.custom()
                                .setConnectTimeout(Timeout.ofMilliseconds(connectTimeoutMs))
                                .setSocketTimeout(Timeout.ofMilliseconds(readTimeoutMs))
                                .build())
                        .setMaxConnTotal(maxConnections)
                        .setMaxConnPerRoute(maxConnections)
                        .build())
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .disableCookieManagement()
                .build(), maxResponseBytes);
    }

    AuthZenHttpClient(final CloseableHttpClient client, int maxResponseBytes) {
        this.client = client;
        this.maxResponseBytes = maxResponseBytes;
    }

    /**
     * Post the given JSON body and return the JSON response body.
     * @param url target url
     * @param body JSON request body
     * @param headers additional request headers
     * @return response body for a 200 response
     * @throws ExternalPdpException for transport failures or non-200 responses
     */
    public String postJson(final String url, final String body, final Map<String, String> headers)
            throws ExternalPdpException {
        HttpPost httpPost = new HttpPost(url);
        httpPost.setEntity(new StringEntity(body, ContentType.APPLICATION_JSON));
        return execute(httpPost, headers);
    }

    /**
     * Get the JSON document at the given url.
     * @param url target url
     * @param headers additional request headers
     * @return response body for a 200 response
     * @throws ExternalPdpException for transport failures or non-200 responses
     */
    public String getJson(final String url, final Map<String, String> headers) throws ExternalPdpException {
        return execute(new HttpGet(url), headers);
    }

    String execute(final ClassicHttpRequest request, final Map<String, String> headers)
            throws ExternalPdpException {

        request.setHeader("Accept", ContentType.APPLICATION_JSON.getMimeType());
        for (Map.Entry<String, String> header : headers.entrySet()) {
            request.setHeader(header.getKey(), header.getValue());
        }

        HttpResult result;
        try {
            result = client.execute(request, this::readResponse);
        } catch (InterruptedIOException ex) {
            throw new ExternalPdpException(ExternalPdpException.Code.TIMEOUT, "pdp request timed out", ex);
        } catch (IOException ex) {
            throw new ExternalPdpException(ExternalPdpException.Code.UNAVAILABLE,
                    "pdp request failed: " + ex.getClass().getSimpleName(), ex);
        }

        if (result.tooLarge) {
            throw new ExternalPdpException(ExternalPdpException.Code.INVALID_RESPONSE,
                    "pdp response exceeds " + maxResponseBytes + " bytes");
        }
        if (result.status == HTTP_OK) {
            return result.body;
        }
        final ExternalPdpException.Code code = (result.status >= HTTP_SERVER_ERROR
                || result.status == HTTP_TOO_MANY_REQUESTS)
                ? ExternalPdpException.Code.UNAVAILABLE : ExternalPdpException.Code.INVALID_RESPONSE;
        throw new ExternalPdpException(code, "pdp returned status " + result.status);
    }

    HttpResult readResponse(final ClassicHttpResponse response) throws IOException {
        final HttpEntity entity = response.getEntity();
        if (entity == null) {
            return new HttpResult(response.getCode(), "", false);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        try (InputStream in = entity.getContent()) {
            int read;
            while ((read = in.read(buffer)) != -1) {
                if (out.size() + read > maxResponseBytes) {
                    return new HttpResult(response.getCode(), null, true);
                }
                out.write(buffer, 0, read);
            }
        }
        return new HttpResult(response.getCode(), out.toString(StandardCharsets.UTF_8), false);
    }

    @Override
    public void close() {
        try {
            client.close();
        } catch (IOException ignored) {
            // nothing to recover on shutdown
        }
    }

    static final class HttpResult {
        final int status;
        final String body;
        final boolean tooLarge;

        HttpResult(int status, final String body, boolean tooLarge) {
            this.status = status;
            this.body = body;
            this.tooLarge = tooLarge;
        }
    }
}
