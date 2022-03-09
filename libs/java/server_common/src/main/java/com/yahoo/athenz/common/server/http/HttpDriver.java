/*
 * Copyright 2020 Verizon Media
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
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

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

    private final String baseUrl;
    private final int maxPoolPerRoute;
    private final int maxPoolTotal;
    private final int clientRetryIntervalMs;
    private final int clientMaxRetries;
    private final int clientConnectTimeoutMs;
    private final int clientReadTimeoutMs;

    private CloseableHttpClient client;
    private final PoolingHttpClientConnectionManager connManager;

    public static class Builder {
        // Required Parameters
        private final String baseUrl;
        private String truststorePath = null;
        private char[] truststorePassword = null;
        private String certPath = null;
        private String keyPath = null;
        private SSLContext sslContext = null;

        // Optional Parameters
        private int maxPoolPerRoute = DEFAULT_MAX_POOL_PER_ROUTE;
        private int maxPoolTotal = DEFAULT_MAX_POOL_TOTAL;
        private int clientRetryIntervalMs = DEFAULT_CLIENT_INTERVAL_MS;
        private int clientMaxRetries = DEFAULT_CLIENT_MAX_RETRIES;
        private int clientConnectTimeoutMs = DEFAULT_CLIENT_CONNECT_TIMEOUT_MS;
        private int clientReadTimeoutMs = DEFAULT_CLIENT_READ_TIMEOUT_MS;

        public Builder(String baseUrl, String trustorePath, char[] trustorePassword, String certPath, String keyPath) {
            this.baseUrl = baseUrl;
            this.truststorePath = trustorePath;
            this.truststorePassword = trustorePassword;
            this.certPath = certPath;
            this.keyPath = keyPath;
        }

        public Builder(String baseUrl, SSLContext sslContext) {
            this.baseUrl = baseUrl;
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

        public Builder clientRetryIntervalMs(int value) {
            clientRetryIntervalMs = value;
            return this;
        }

        public Builder clientMaxRetries(int value) {
            clientMaxRetries = value;
            return this;
        }

        public Builder clientConnectTimeoutMs(int value) {
            clientConnectTimeoutMs = value;
            return this;
        }

        public Builder clientReadTimeoutMs(int value) {
            clientReadTimeoutMs = value;
            return this;
        }

        public HttpDriver build() {
            return new HttpDriver(this);
        }
    }

     public HttpDriver(Builder builder) {
        baseUrl = builder.baseUrl;
        maxPoolPerRoute = builder.maxPoolPerRoute;
        maxPoolTotal = builder.maxPoolTotal;
        clientRetryIntervalMs = builder.clientRetryIntervalMs;
        clientMaxRetries = builder.clientMaxRetries;
        clientConnectTimeoutMs = builder.clientConnectTimeoutMs;
        clientReadTimeoutMs = builder.clientReadTimeoutMs;

        SSLContext sslContext = builder.sslContext;
        if (sslContext == null) {
            try {
                sslContext = createSSLContext(builder.truststorePath, builder.truststorePassword, builder.certPath, builder.keyPath);
            } catch (IOException | InterruptedException | KeyRefresherException e) {
                //This is hard failure.
                LOGGER.error("Unable to create TLS/SSL context.", e);
                throw new IllegalArgumentException("Unable to create TLS/SSL context.", e);
            }
        }

        connManager = createConnectionPooling(sslContext);
        client = createHttpClient(clientConnectTimeoutMs, clientReadTimeoutMs, sslContext, connManager);

        LOGGER.info("initialized Names HttpDriver with base url: {} connectionTimeoutMs: {} readTimeoutMs: {}",
                baseUrl, clientConnectTimeoutMs, clientReadTimeoutMs);
    }

    public void setHttpClient(CloseableHttpClient httpClient) {
        client = httpClient;
    }

    public static SSLContext createSSLContext(String trustorePath, char[] trustorePassword, String certPath,
                                          String keyPath) throws FileNotFoundException, IOException, InterruptedException, KeyRefresherException {
        if (trustorePath == null) {
            return null;
        }
        KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustorePath, trustorePassword,
                certPath, keyPath);
        keyRefresher.startup();
        return Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                keyRefresher.getTrustManagerProxy());
    }

    protected PoolingHttpClientConnectionManager createConnectionPooling(SSLContext sslContext) {
        if (sslContext == null) {
            return null;
        }
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("https", new SSLConnectionSocketFactory(sslContext))
                .register("http", new PlainConnectionSocketFactory())
                .build();
        PoolingHttpClientConnectionManager poolingHttpClientConnectionManager = new PoolingHttpClientConnectionManager(registry);

        //route is host + port.  Since we have only one, set the max and the route the same
        poolingHttpClientConnectionManager.setDefaultMaxPerRoute(maxPoolPerRoute);
        poolingHttpClientConnectionManager.setMaxTotal(maxPoolTotal);
        return poolingHttpClientConnectionManager;
    }

    protected CloseableHttpClient createHttpClient(int connTimeoutMs, int readTimeoutMs, SSLContext sslContext,
                                         PoolingHttpClientConnectionManager poolingHttpClientConnectionManager) {
        //apache http client expects in milliseconds
        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(connTimeoutMs)
                .setSocketTimeout(readTimeoutMs)
                .setRedirectsEnabled(false)
                .build();
        return HttpClients.custom()
                .setConnectionManager(poolingHttpClientConnectionManager)
                .setDefaultRequestConfig(config)
                .setSSLContext(sslContext)
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

        // Retry when IOException occurs
        for (int i = 0; i < clientMaxRetries; i++) {
            try (CloseableHttpResponse response = client.execute(httpGet)) {
                if (response != null) {
                    int statusCode = response.getStatusLine().getStatusCode();
                    if (statusCode == 200) {
                        String data = EntityUtils.toString(response.getEntity());
                        LOGGER.debug("Data received: {}, from: {}", data, url);
                        return data;
                    }

                    LOGGER.error("Received bad status: {} from: {}", statusCode, url);
                    response.getEntity().getContent().close();
                    return "";
                }
            } catch (IOException ex) {
                LOGGER.error("Failed to get response from server {} retry: {}/{}, exception: ", url, i, clientMaxRetries, ex);
                try {
                    TimeUnit.MILLISECONDS.sleep(clientRetryIntervalMs);
                } catch (InterruptedException ignored) {
                }
            }
        }
        throw new IOException("Failed to get response from server: " + url);
    }

    public HttpDriverResponse doPostHttpResponse(HttpPost httpPost) throws IOException {
        String url = httpPost.getURI().toString();
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Requesting from {} with query {}", url, getPostQuery(httpPost));
        }
        // Retry when IOException occurs
        for (int i = 0; i <  clientMaxRetries;  i++) {
            try (CloseableHttpResponse response = this.client.execute(httpPost)) {
                if (response != null) {
                    int statusCode = response.getStatusLine().getStatusCode();
                    String out = EntityUtils.toString(response.getEntity());
                    LOGGER.debug("StatusCode: {} Data received: {}", statusCode, out);
                    return new HttpDriverResponse(statusCode, out, response.getStatusLine());
                }
            } catch (IOException ex) {
                LOGGER.error("Failed to get response from {} for query: {} retry: {}/{}, exception: ", url, getPostQuery(httpPost), i, clientMaxRetries, ex);
                try {
                    TimeUnit.MILLISECONDS.sleep(clientRetryIntervalMs);
                } catch (InterruptedException ignored) {
                }
            }
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
                //received bad statuscode, don't bother resending request.
                String url = httpPost.getURI().toString();
                LOGGER.error("Received bad status code: {} from: {} reason: {}", httpDriverResponse.getStatusCode(), url, httpDriverResponse.getStatusLine());
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
}
