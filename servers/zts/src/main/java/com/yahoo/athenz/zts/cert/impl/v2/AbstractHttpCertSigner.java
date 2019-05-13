/*
 * Copyright 2019 Oath Holdings Inc.
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

package com.yahoo.athenz.zts.cert.impl.v2;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.rest.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.utils.ZTSUtils;

public abstract class AbstractHttpCertSigner implements CertSigner {
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpCertSigner.class);
    private static final String CONTENT_JSON = "application/json";
    
    protected static final ObjectMapper JACKSON_MAPPER = new ObjectMapper();

    private static final int DEFAULT_MAX_POOL_TOTAL = 30;
    private static final int DEFAULT_MAX_POOL_PER_ROUTE = 20;
    
    private CloseableHttpClient httpClient;
    private final PoolingHttpClientConnectionManager connManager;
    private final SslContextFactory sslContextFactory;
    
    String x509CertUri;
    int requestRetryCount;
    int maxCertExpiryTimeMins;

    
    public AbstractHttpCertSigner() {

        PrivateKeyStore privateKeyStore = loadServicePrivateKey();

        // retrieve our default timeout and retry timer
        
        int connectionTimeoutSec = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_CONNECT_TIMEOUT, "10"));

        int readTimeoutSec = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_REQUEST_TIMEOUT, "5"));
        
        requestRetryCount = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_RETRY_COUNT, "3"));

        // max expiry time in minutes.  Max is is 30 days
        maxCertExpiryTimeMins = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME, "43200"));
        
        // Instantiate HttpClient with SSLContext
        //TODO: Switch from using jetty's SslContextFactory and possible use SSLUtils class from athenz-client-common
        this.sslContextFactory = ZTSUtils.createSSLContextObject(new String[] {"TLSv1.2"}, privateKeyStore);
        try {
            this.sslContextFactory.start();
        } catch (Exception e) {
            LOGGER.error("HttpCertSigner v2: unable to start SSL Context.");
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR, "unable to start sslContextFactory");
        }
        
        String serverBaseUri = System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI);
        if (serverBaseUri == null) {
            LOGGER.error("HttpCertSigner v2: no base uri specified");
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "No CertSigner base uri specified: " + ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI);
        }
        
        x509CertUri = getX509CertUri(serverBaseUri);
        this.connManager = createConnectionPooling(sslContextFactory.getSslContext());
        this.httpClient = createHttpClient(connectionTimeoutSec, readTimeoutSec, sslContextFactory.getSslContext(), this.connManager);

        LOGGER.info("HttpCertSigner initialized with url: {} connectionTimeoutSec: {}, readTimeoutSec: {}", x509CertUri, connectionTimeoutSec, readTimeoutSec);
        LOGGER.info("HttpCertSigner connection pool stats {} ", this.connManager.getTotalStats().toString());
    }

    /**
     * 
     * @return
     */
    public abstract String getX509CertUri(String serverBaseUri);


    /**
     * 
     * @return
     */
    public abstract Object getX509CertSigningRequest(String csr, String keyUsage, int expireMins);

    /**
     * 
     * @param response
     * @return
     */
    public abstract String parseResponse(InputStream response) throws IOException;
    
    
    /**
     * 
     * @param sslContext
     * @return
     */
    PoolingHttpClientConnectionManager createConnectionPooling(SSLContext sslContext) {
        SSLConnectionSocketFactory sslsf = null;
        Registry<ConnectionSocketFactory> registry = null;
        PoolingHttpClientConnectionManager poolingHttpClientConnectionManager = null;
        sslsf = new SSLConnectionSocketFactory(sslContext);
        registry = RegistryBuilder.<ConnectionSocketFactory>create().register("https", sslsf).build();
        poolingHttpClientConnectionManager = new PoolingHttpClientConnectionManager(registry);
        
        //route is host + port.  Since we have only one, set the max and the route the same
        poolingHttpClientConnectionManager.setDefaultMaxPerRoute(DEFAULT_MAX_POOL_PER_ROUTE);
        poolingHttpClientConnectionManager.setMaxTotal(DEFAULT_MAX_POOL_TOTAL);
        return poolingHttpClientConnectionManager;
    }

    /**
     * 
     * @param connectionTimeoutSec
     * @param readTimeoutSec
     * @param sslContext
     * @param poolingHttpClientConnectionManager
     * @return
     */
    CloseableHttpClient createHttpClient(int connectionTimeoutSec, int readTimeoutSec, SSLContext sslContext, PoolingHttpClientConnectionManager poolingHttpClientConnectionManager) {
        
        //apache http client expects in milliseconds
        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout((int) TimeUnit.MILLISECONDS.convert(connectionTimeoutSec, TimeUnit.SECONDS))
                .setSocketTimeout((int) TimeUnit.MILLISECONDS.convert(readTimeoutSec, TimeUnit.SECONDS))
                .setRedirectsEnabled(false)
                .build();
        return HttpClients.custom()
                .setConnectionManager(poolingHttpClientConnectionManager)
                .setDefaultRequestConfig(config)
                .setSSLContext(sslContext)
                .build();
    }
    

    public void setHttpClient(CloseableHttpClient client) {
        this.httpClient = client;
    }

    @Override
    public void close() {
        try {
            this.sslContextFactory.stop();
            this.httpClient.close();
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("connManager stats close(): {}" , this.connManager.getTotalStats().toString());
            }
            this.connManager.close();
        } catch (Exception ignored) {
        }
    }
    
    @Override
    public int getMaxCertExpiryTimeMins() {
        return maxCertExpiryTimeMins;
    }
    
    private PrivateKeyStore loadServicePrivateKey() {
        String pkeyFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZTSConsts.ZTS_PKEY_STORE_FACTORY_CLASS);
        PrivateKeyStoreFactory pkeyFactory;
        try {
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid PrivateKeyStoreFactory class: " + pkeyFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid private key store");
        }
        return pkeyFactory.create();
    }

    @Override
    public String generateX509Certificate(String csr, String keyUsage, int expireMins) {
        StringEntity entity = null;
        try {
            String requestContent = JACKSON_MAPPER.writeValueAsString(getX509CertSigningRequest(csr, keyUsage, expireMins));
            entity = new StringEntity(requestContent);
        } catch (Throwable t) {
            LOGGER.error("unable to generate csr", t);
            return null;
        }

        HttpPost httpPost = new HttpPost(x509CertUri);
        httpPost.setHeader("Accept", CONTENT_JSON);
        httpPost.setHeader("Content-Type", CONTENT_JSON);
        httpPost.setEntity(entity);
        
        //Retry
        for (int i = 0; i < requestRetryCount; i++) {
            try {
                return processHttpResponse(httpPost, 201);
            } catch (IOException e) {
                LOGGER.error("Unable to process x509 certificate request to url " + x509CertUri + " Retring " + i + 1 + "/" + requestRetryCount, e);
            }
        }
        
        return null;
    }
    

    /**
     * 
     * @param request
     * @param expectedStatusCode
     * @return x509 Certificate or Null if expectedStatusCode doesn't match or empty response from the server.
     * @throws ClientProtocolException
     * @throws IOException
     */
    String processHttpResponse(HttpUriRequest request, int expectedStatusCode) throws ClientProtocolException, IOException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("connManager stats before: {}" , this.connManager.getTotalStats().toString());
        }
        CloseableHttpResponse response = httpClient.execute(request);
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("connManager stats after: {}" , this.connManager.getTotalStats().toString());
        }
        // check for status code first
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != expectedStatusCode) {
            // we have a response but not 201. Don't bother retry
            LOGGER.error("unable to fetch requested uri '" + x509CertUri + "' status: " + statusCode);
            return null;
        }
        // check for content
        try (InputStream data = response.getEntity().getContent()) {
            if (data == null) {
                LOGGER.error("received empty response from uri '" + x509CertUri + "' status: " + statusCode);
                return null;
            }
            return parseResponse(data);
        }
    }
    
    @Override
    public String getCACertificate() {
        HttpGet httpGet = new HttpGet(x509CertUri);
        String data = null;
        try {
            data = processHttpResponse(httpGet, 200);
        } catch (IOException e) {
            LOGGER.error("Unable to process x509 CA certificate request", e);
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getCACertificate: CA Certificate" + data);
        }
        return data;
    }
}
