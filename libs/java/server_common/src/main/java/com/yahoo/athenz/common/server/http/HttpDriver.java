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

package com.yahoo.athenz.common.server.http;

import com.oath.auth.KeyRefresher;
import com.oath.auth.KeyRefresherException;
import com.oath.auth.Utils;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.pool.PoolConcurrencyPolicy;
import org.apache.hc.core5.pool.PoolReusePolicy;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.NoRouteToHostException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * HttpDriver warps CloseableHttpClient and a PoolingHttpClientConnectionManager
 * Uses the Builder pattern to construct a new driver object and initialize the HttpClient and Connection Manager
 */
public class HttpDriver implements Closeable {
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpDriver.class);

    private static final int DEFAULT_MAX_POOL_TOTAL = 30;
    private static final int DEFAULT_MAX_POOL_PER_ROUTE = 20;
    private static final int DEFAULT_CLIENT_INTERVAL_MS = 1000;
    private static final int DEFAULT_CLIENT_MAX_RETRIES = 2;
    private static final int DEFAULT_CLIENT_CONNECT_TIMEOUT_MS = 5000;
    private static final int DEFAULT_CLIENT_READ_TIMEOUT_MS = 5000;

    private CloseableHttpClient client;
    private final PoolingHttpClientConnectionManager connManager;

    public static class Builder {
        private String truststorePath = null;
        private char[] truststorePassword = null;
        private String certPath = null;
        private String keyPath = null;
        private SSLContext sslContext = null;

        // Optional Parameters
        private int maxPoolPerRoute = DEFAULT_MAX_POOL_PER_ROUTE;
        private int maxPoolTotal = DEFAULT_MAX_POOL_TOTAL;
        private int clientMaxRetries = DEFAULT_CLIENT_MAX_RETRIES;
        private long clientRetryIntervalMs = DEFAULT_CLIENT_INTERVAL_MS;
        private long clientConnectTimeoutMs = DEFAULT_CLIENT_CONNECT_TIMEOUT_MS;
        private long clientReadTimeoutMs = DEFAULT_CLIENT_READ_TIMEOUT_MS;
        private long clientInactiveValidateTimeoutMs = 0;

        public Builder(String trustStorePath, char[] trustStorePassword, String certPath, String keyPath) {
            this.truststorePath = trustStorePath;
            this.truststorePassword = trustStorePassword;
            this.certPath = certPath;
            this.keyPath = keyPath;
        }

        public Builder(SSLContext sslContext) {
            this.sslContext = sslContext;
        }

        public Builder maxPoolPerRoute(int value) {
            maxPoolPerRoute = value;
            return this;
        }

        public Builder maxPoolTotal(int value) {
            maxPoolTotal = value;
            return this;
        }

        public Builder clientRetryIntervalMs(long value) {
            clientRetryIntervalMs = value;
            return this;
        }

        public Builder clientMaxRetries(int value) {
            clientMaxRetries = value;
            return this;
        }

        public Builder clientConnectTimeoutMs(long value) {
            clientConnectTimeoutMs = value;
            return this;
        }

        public Builder clientReadTimeoutMs(long value) {
            clientReadTimeoutMs = value;
            return this;
        }

        public Builder clientInactiveValidateTimeoutMs(long value) {
            clientInactiveValidateTimeoutMs = value;
            return this;
        }

        public HttpDriver build() {
            return new HttpDriver(this);
        }
    }

     public HttpDriver(Builder builder) {

        SSLContext sslContext = builder.sslContext;
        if (sslContext == null && builder.keyPath != null && builder.certPath != null) {
            try {
                sslContext = createSSLContext(builder.truststorePath, builder.truststorePassword,
                        builder.certPath, builder.keyPath);
            } catch (IOException | InterruptedException | KeyRefresherException e) {
                //This is hard failure.
                LOGGER.error("Unable to create TLS/SSL context.", e);
                throw new IllegalArgumentException("Unable to create TLS/SSL context.", e);
            }
        }

        connManager = createConnectionPooling(builder, sslContext);
        client = createHttpClient(builder, connManager);

        LOGGER.info("initialized HttpDriver with connectionTimeoutMs: {} readTimeoutMs: {}",
                builder.clientConnectTimeoutMs, builder.clientReadTimeoutMs);
    }

    public void setHttpClient(CloseableHttpClient httpClient) {
        client = httpClient;
    }

    public static SSLContext createSSLContext(String trustStorePath, char[] trustStorePassword, String certPath,
            String keyPath) throws IOException, InterruptedException, KeyRefresherException {

        if (trustStorePath == null) {
            return null;
        }
        KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                certPath, keyPath);
        keyRefresher.startup();
        return Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                keyRefresher.getTrustManagerProxy());
    }

    protected PoolingHttpClientConnectionManager createConnectionPooling(Builder clientBuilder, SSLContext sslContext) {

        if (sslContext == null) {
            sslContext = SSLContexts.createDefault();
        }

        final TlsSocketStrategy tlsStrategy = new DefaultClientTlsStrategy(sslContext);

        return PoolingHttpClientConnectionManagerBuilder.create()
                .setTlsSocketStrategy(tlsStrategy)
                .setDefaultTlsConfig(TlsConfig.custom()
                        .setSupportedProtocols(TLS.V_1_2, TLS.V_1_3)
                        .build())
                .setPoolConcurrencyPolicy(PoolConcurrencyPolicy.STRICT)
                .setConnPoolPolicy(PoolReusePolicy.LIFO)
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setSocketTimeout(Timeout.ofMilliseconds(clientBuilder.clientReadTimeoutMs))
                        .setConnectTimeout(Timeout.ofMilliseconds(clientBuilder.clientConnectTimeoutMs))
                        .setValidateAfterInactivity(TimeValue.ofMilliseconds(clientBuilder.clientInactiveValidateTimeoutMs))
                        .build())
                .setMaxConnPerRoute(clientBuilder.maxPoolPerRoute)
                .setMaxConnTotal(clientBuilder.maxPoolTotal)
                .build();
    }

    protected CloseableHttpClient createHttpClient(Builder clientBuilder,
            PoolingHttpClientConnectionManager poolingHttpClientConnectionManager) {

        HttpRequestRetryStrategy retryStrategy = null;
        if (clientBuilder.clientMaxRetries > 0) {
            retryStrategy = new CustomRequestRetryStrategy(clientBuilder.clientMaxRetries,
                    TimeValue.ofMilliseconds(clientBuilder.clientRetryIntervalMs));
        }

        RequestConfig config = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .build();
        return HttpClients.custom()
                .setConnectionManager(poolingHttpClientConnectionManager)
                .setDefaultRequestConfig(config)
                .setRetryStrategy(retryStrategy)
                .build();
    }

    @Override
    public void close() {
        if (client != null) {
            try {
                this.client.close();
                LOGGER.info("Successfully closed httpclient.");
            } catch (IOException ignored) {
            }
        }
        if (connManager != null) {
            connManager.close();
            LOGGER.info("Successfully closed httpclient connection manager.");
        }
    }

    /**
     * doGet performs GET method with the url supplied and returns a string
     * @param url including query parameters
     * @return response string
     * @throws IOException in case of any errors
     */
    public String doGet(final String url) throws IOException {
        return doGet(url, null);
    }

    /**
     * doGet performs GET method with the url supplied and the list of specified
     * http headers and returns a string
     * @param url including query parameters
     * @param headers include given http headers
     * @return response string
     * @throws IOException in case of any errors
     */
    public String doGet(final String url, final Map<String, String> headers) throws IOException {

        LOGGER.debug("Requesting api for {}", url);
        HttpGet httpGet = new HttpGet(url);

        if (headers != null) {
            for (String headerName : headers.keySet()) {
                httpGet.addHeader(headerName, headers.get(headerName));
            }
        }

        try (CloseableHttpResponse response = client.execute(httpGet)) {
            if (response != null) {
                int statusCode = response.getCode();
                if (statusCode == 200) {
                    String data = EntityUtils.toString(response.getEntity());
                    LOGGER.debug("Data received: {}, from: {}", data, url);
                    return data;
                }

                LOGGER.error("Received bad status: {} from: {}", statusCode, url);
                response.getEntity().getContent().close();
                return "";
            }
        } catch (IOException | ParseException ex) {
            LOGGER.error("Failed to get response from server {}, exception: ", url, ex);
        }
        throw new IOException("Failed to get response from server: " + url);
    }

    protected String getRequestUri(HttpPost httpPost) {
        try {
            return httpPost.getUri().toString();
        } catch (URISyntaxException e) {
            return httpPost.getRequestUri();
        }
    }

    public HttpDriverResponse doPostHttpResponse(HttpPost httpPost) throws IOException {
        final String url = getRequestUri(httpPost);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Requesting from {} with query {}", url, getPostQuery(httpPost));
        }

        try (CloseableHttpResponse response = this.client.execute(httpPost)) {
            if (response != null) {
                int statusCode = response.getCode();
                String out = EntityUtils.toString(response.getEntity());
                LOGGER.debug("StatusCode: {} Data received: {}", statusCode, out);
                return new HttpDriverResponse(statusCode, out, new StatusLine(response));
            }
        } catch (IOException | ParseException ex) {
            LOGGER.error("Failed to get response from {} for query: {}, exception: ", url, getPostQuery(httpPost), ex);
        }

        throw new IOException("Failed to get response from server: " + url);
    }

    /**
     * doPost performs post operation and returns a string
     * @param httpPost post request to process
     * @return response string
     * @throws IOException in case of any errors
     */
    public String doPost(HttpPost httpPost) throws IOException {
        HttpDriverResponse httpDriverResponse = doPostHttpResponse(httpPost);
        switch (httpDriverResponse.getStatusCode()) {
            case 200:
            case 201:
                String out = httpDriverResponse.getMessage();
                LOGGER.debug("Data received: {}", out);
                return out;
            default:
                //received bad status code, don't bother resending request.
                LOGGER.error("Received bad status code: {} from: {} reason: {}", httpDriverResponse.getStatusCode(),
                        getRequestUri(httpPost), httpDriverResponse.getStatusLine());
                return "";
        }
    }

    /**
     * doPost performs post operation and returns a string
     * @param url target url
     * @param fields form fields that need to posted to the url
     * @return response string
     * @throws IOException in case of any errors
     */
    public String doPost(final String url, final List<NameValuePair> fields) throws IOException {
        HttpPost httpPost = new HttpPost(url);
        httpPost.setEntity(new UrlEncodedFormEntity(fields));

        return doPost(httpPost);
    }

    private String getPostQuery(HttpPost httpPost) {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            httpPost.getEntity().writeTo(byteArrayOutputStream);
            return byteArrayOutputStream.toString();
        } catch (IOException ignored) {
        }
        return "";
    }

    static class CustomRequestRetryStrategy extends DefaultHttpRequestRetryStrategy {
        public CustomRequestRetryStrategy(int maxRetries, TimeValue defaultRetryInterval) {
            super(maxRetries, defaultRetryInterval,
                    Arrays.asList(InterruptedIOException.class, UnknownHostException.class, NoRouteToHostException.class),
                    Arrays.asList(429, 503));
        }
    }
}
