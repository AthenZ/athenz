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

package com.yahoo.athenz.zts.cert.impl.crypki;

import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
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
import org.eclipse.jetty.util.StringUtil;
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

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractHttpCertSigner.class);
    private static final String CONTENT_JSON = "application/json";
    private static final String X509_KEY_META_IDENTIFIER = "x509-key";

    protected static final ObjectMapper JACKSON_MAPPER = new ObjectMapper();

    private static final int DEFAULT_MAX_POOL_TOTAL = 30;
    private static final int DEFAULT_MAX_POOL_PER_ROUTE = 20;
    
    private CloseableHttpClient httpClient;
    private final PoolingHttpClientConnectionManager connManager;
    private final SslContextFactory sslContextFactory;
    
    String serverBaseUri;
    int certsignRequestRetryCount;
    boolean retryConnFailuresOnly;
    int maxCertExpiryTimeMins;
    String defaultProviderSignerKeyId = X509_KEY_META_IDENTIFIER;
    Map<String, String> providerSignerKeys = new ConcurrentHashMap<>();

    public AbstractHttpCertSigner() {

        PrivateKeyStore privateKeyStore = loadServicePrivateKey();

        // retrieve our default timeout and retry timer
        
        int connectionTimeoutSec = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_CONNECT_TIMEOUT, "10"));
        int readTimeoutSec = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_REQUEST_TIMEOUT, "25"));

        certsignRequestRetryCount = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_RETRY_COUNT, "2"));
        retryConnFailuresOnly = Boolean.parseBoolean(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_RETRY_CONN_ONLY, "true"));

        // max expiry time in minutes.  Max is 30 days

        maxCertExpiryTimeMins = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME, "43200"));
        
        // Instantiate HttpClient with SSLContext
        this.sslContextFactory = ZTSUtils.createSSLContextObject(new String[] {"TLSv1.2"}, privateKeyStore);
        try {
            this.sslContextFactory.start();
        } catch (Exception e) {
            LOGGER.error("HttpCertSigner: unable to start SSL Context.");
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR, "unable to start sslContextFactory");
        }
        
        serverBaseUri = System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI);
        if (serverBaseUri == null) {
            LOGGER.error("HttpCertSigner: no base uri specified");
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "No CertSigner base uri specified: " + ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI);
        }
        
        this.connManager = createConnectionPooling(sslContextFactory.getSslContext());
        this.httpClient = createHttpClient(connectionTimeoutSec, readTimeoutSec,
                sslContextFactory.getSslContext(), this.connManager);

        // load our provider signer key details

        if (!loadProviderSignerKeyConfig()) {
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Unable to initialize provider signer key configuration");
        }

        LOGGER.info("HttpCertSigner initialized with url: {} connectionTimeoutSec: {}, readTimeoutSec: {}",
                serverBaseUri, connectionTimeoutSec, readTimeoutSec);
        LOGGER.info("HttpCertSigner connection pool stats {} ", this.connManager.getTotalStats().toString());
    }

    private boolean loadProviderSignerKeyConfig() {

        // read the file list of providers and allowed IP addresses
        // if the config is not set then we have no restrictions
        // otherwise all providers must be specified in the list

        final String providerSignerKeysFile =  System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_PROVIDER_KEYS_FNAME);
        if (StringUtil.isEmpty(providerSignerKeysFile)) {
            return true;
        }

        byte[] data = ZTSUtils.readFileContents(providerSignerKeysFile);
        if (data == null) {
            return false;
        }

        ProviderSignerKeys signerKeys = null;
        try {
            signerKeys = JACKSON_MAPPER.readValue(data, ProviderSignerKeys.class);
        } catch (Exception ex) {
            LOGGER.error("Unable to parse Provider Signer Key file: {}", providerSignerKeysFile, ex);
        }

        if (signerKeys == null) {
            return false;
        }

        // update our default key id if one was specified

        if (!StringUtil.isEmpty(signerKeys.getDefaultKeyId())) {
            defaultProviderSignerKeyId = signerKeys.getDefaultKeyId();
        }

        // load all configured provider key/name pairs

        for (ProviderSignerKey providerKey : signerKeys.getProviderKeys()) {

            final String keyId = providerKey.getKeyId();
            if (StringUtil.isEmpty(keyId)) {
                continue;
            }
            for (String provider : providerKey.getProviders()) {
                providerSignerKeys.put(provider, keyId);
            }
        }

        return true;
    }

    /**
     * Return x.509 certificate uri based on server uri
     * @param serverBaseUri server's base uri
     * @param provider provider service name
     * @return uri
     */
    public abstract String getX509CertUri(String serverBaseUri, String provider);

    /**
     * Return object based on given csr, usage and expiry
     * @param provider provider service name
     * @param csr certificate signing request
     * @param keyUsage client or server usage for the certificate
     * @param expireMins expiry time in minutes for the certificate
     * @return CSR Object
     */
    public abstract Object getX509CertSigningRequest(String provider, String csr, String keyUsage, int expireMins);

    /**
     * Parse the response from certificate sisnger
     * @param response input stream
     * @return response as string
     * @throws IOException for any IO errors
     */
    public abstract String parseResponse(InputStream response) throws IOException;

    /**
     * Create a http client connection manager based on given ssl context
     * @param sslContext ssl context containing keystore with client key/cert
     * @return connection manager object
     */
    PoolingHttpClientConnectionManager createConnectionPooling(SSLContext sslContext) {

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext);
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create().register("https", sslsf).build();
        PoolingHttpClientConnectionManager poolingHttpClientConnectionManager = new PoolingHttpClientConnectionManager(registry);
        
        //route is host + port.  Since we have only one, set the max and the route the same

        poolingHttpClientConnectionManager.setDefaultMaxPerRoute(DEFAULT_MAX_POOL_PER_ROUTE);
        poolingHttpClientConnectionManager.setMaxTotal(DEFAULT_MAX_POOL_TOTAL);
        return poolingHttpClientConnectionManager;
    }

    /**
     * Create an http client based on given configuration settings
     * @param connectionTimeoutSec connection timeout in seconds
     * @param readTimeoutSec read timeout in seconds
     * @param sslContext ssl context object
     * @param poolingHttpClientConnectionManager http connection manager object
     * @return http client
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
                LOGGER.debug("connManager stats close(): {}", this.connManager.getTotalStats().toString());
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
            LOGGER.error("Invalid PrivateKeyStoreFactory class: {} error: {}",
                    pkeyFactoryClass, e.getMessage());
            throw new IllegalArgumentException("Invalid private key store");
        }
        return pkeyFactory.create();
    }

    @Override
    public String generateX509Certificate(String provider, String certIssuer, String csr, String keyUsage, int expireMins) {

        StringEntity entity;
        try {
            String requestContent = JACKSON_MAPPER.writeValueAsString(getX509CertSigningRequest(provider, csr, keyUsage, expireMins));
            entity = new StringEntity(requestContent);
        } catch (Throwable t) {
            LOGGER.error("unable to generate csr", t);
            return null;
        }

        final String x509CertUri = getX509CertUri(serverBaseUri, provider);
        HttpPost httpPost = new HttpPost(x509CertUri);
        httpPost.setHeader("Accept", CONTENT_JSON);
        httpPost.setHeader("Content-Type", CONTENT_JSON);
        httpPost.setEntity(entity);
        
        // Retry configured number of times before returning failure

        for (int i = 0; i < certsignRequestRetryCount; i++) {
            try {
                return processHttpResponse(httpPost, 201);
            } catch (ConnectException ex) {
                LOGGER.error("Unable to process x509 certificate request to url {}, retrying {}/{}, {}",
                        x509CertUri, i + 1, certsignRequestRetryCount, ex);
            } catch (IOException ex) {
                LOGGER.error("Unable to process x509 certificate request to url {}, try: {}",
                        x509CertUri, i + 1, ex);
                if (retryConnFailuresOnly) {
                    break;
                }
            }
        }
        
        return null;
    }

    /**
     * Process http response from crypki server
     * @param request http request object
     * @param expectedStatusCode expected http status code
     * @return x509 Certificate or Null if expectedStatusCode doesn't match or empty response from the server.
     * @throws ClientProtocolException in case of any client protocol errors
     * @throws IOException in case of general io errors
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
            LOGGER.error("unable to fetch requested uri '{}' status: {}", request.getURI(), statusCode);
            // Close an inputstream so that connections can go back to the pool.
            if (response.getEntity().getContent() != null) {
                response.getEntity().getContent().close();
            }
            return null;
        }
        // check for content
        try (InputStream data = response.getEntity().getContent()) {
            if (data == null) {
                LOGGER.error("received empty response from uri '{}', status:  {}", request.getURI(), statusCode);
                return null;
            }
            return parseResponse(data);
        }
    }
    
    @Override
    public String getCACertificate(String provider) {
        HttpGet httpGet = new HttpGet(getX509CertUri(serverBaseUri, provider));
        String data = null;
        try {
            data = processHttpResponse(httpGet, 200);
        } catch (IOException e) {
            LOGGER.error("Unable to process x509 CA certificate request", e);
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getCACertificate: CA Certificate {}", data);
        }
        return data;
    }
}
