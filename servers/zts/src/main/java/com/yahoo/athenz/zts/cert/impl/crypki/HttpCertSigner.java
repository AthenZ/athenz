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
package com.yahoo.athenz.zts.cert.impl.crypki;

import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.cert.Priority;
import com.yahoo.athenz.common.server.rest.ResourceException;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigBoolean;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigInteger;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.utils.ZTSUtils;
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

import javax.net.ssl.SSLContext;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

/**
 * This is an implementation of the Yahoo's Crypki certificate signer.
 *          https://github.com/theparanoids/crypki
 * Crypki is a service for interacting with an HSM or other PKCS #11 device.
 * It supports minting and signing of both SSH and x509 certificates.
 */
public class HttpCertSigner implements CertSigner {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpCertSigner.class);

    private static final String X509_CERTIFICATE_PATH = "/sig/x509-cert/keys/";
    private static final String CONTENT_JSON = "application/json";
    private static final String X509_KEY_META_IDENTIFIER = "x509-key";

    //default certificate expiration value of 30 days in seconds
    private static final int DEFAULT_CERT_EXPIRE_SECS = (int) TimeUnit.SECONDS.convert(30, TimeUnit.DAYS);

    protected static final ObjectMapper JACKSON_MAPPER = new ObjectMapper();

    private CloseableHttpClient httpClient;
    private final PoolingHttpClientConnectionManager connManager;
    private final SslContextFactory sslContextFactory;

    String serverBaseUri;
    DynamicConfigInteger certsignRequestRetryCount;
    DynamicConfigBoolean retryConnFailuresOnly;
    int maxCertExpiryTimeMins;
    String defaultProviderSignerKeyId = X509_KEY_META_IDENTIFIER;
    Map<String, String> providerSignerKeys = new ConcurrentHashMap<>();

    public HttpCertSigner() {

        PrivateKeyStore privateKeyStore = loadServicePrivateKey();

        // retrieve our default timeout and retry timer

        int connectionTimeoutSec = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_CONNECT_TIMEOUT, "10"));
        int readTimeoutSec = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_REQUEST_TIMEOUT, "25"));

        certsignRequestRetryCount = new DynamicConfigInteger(CONFIG_MANAGER, ZTSConsts.ZTS_PROP_CERTSIGN_RETRY_COUNT, 2);
        retryConnFailuresOnly = new DynamicConfigBoolean(CONFIG_MANAGER, ZTSConsts.ZTS_PROP_CERTSIGN_RETRY_CONN_ONLY, true);

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
     * Create a http client connection manager based on given ssl context
     * @param sslContext ssl context containing keystore with client key/cert
     * @return connection manager object
     */
    PoolingHttpClientConnectionManager createConnectionPooling(SSLContext sslContext) {

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext);
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create().register("https", sslsf).build();
        PoolingHttpClientConnectionManager poolingHttpClientConnectionManager = new PoolingHttpClientConnectionManager(registry);

        // route is host + port

        int defaultMaxPerRoute = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_CONN_MAX_PER_ROUTE, "20"));
        int maxTotal = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_CONN_MAX_TOTAL, "30"));

        poolingHttpClientConnectionManager.setDefaultMaxPerRoute(defaultMaxPerRoute);
        poolingHttpClientConnectionManager.setMaxTotal(maxTotal);
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
        return generateX509Certificate(provider, certIssuer, csr, keyUsage, expireMins, Priority.Unspecified_priority);
    }

    @Override
    public String generateX509Certificate(String provider, String certIssuer, String csr, String keyUsage, int expireMins, Priority priority) {

        StringEntity entity;
        try {
            final String requestContent = JACKSON_MAPPER.writeValueAsString(getX509CertSigningRequest(provider, csr, keyUsage, expireMins, priority));
            entity = new StringEntity(requestContent);
        } catch (Exception ex) {
            LOGGER.error("unable to generate csr", ex);
            return null;
        }

        final String x509CertUri = getX509CertUri(serverBaseUri, provider);
        HttpPost httpPost = new HttpPost(x509CertUri);
        httpPost.setHeader("Accept", CONTENT_JSON);
        httpPost.setHeader("Content-Type", CONTENT_JSON);
        httpPost.setEntity(entity);

        // Retry configured number of times before returning failure

        for (int i = 0; i < certsignRequestRetryCount.get(); i++) {
            try {
                return processHttpResponse(httpPost, 201);
            } catch (ConnectException ex) {
                LOGGER.error("Unable to process x509 certificate request to url {}, retrying {}/{}, {}",
                        x509CertUri, i + 1, certsignRequestRetryCount.get(), ex);
            } catch (IOException ex) {
                LOGGER.error("Unable to process x509 certificate request to url {}, try: {}",
                        x509CertUri, i + 1, ex);
                if (retryConnFailuresOnly.get()) {
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
                LOGGER.error("received empty response from uri '{}', status: {}", request.getURI(), statusCode);
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

    String getProviderKeyId(String provider) {
        if (StringUtil.isEmpty(provider)) {
            return defaultProviderSignerKeyId;
        }
        final String keyId = providerSignerKeys.get(provider);
        return keyId == null ? defaultProviderSignerKeyId : keyId;
    }

    public String getX509CertUri(String serverBaseUri, String provider) {
        return serverBaseUri + X509_CERTIFICATE_PATH + getProviderKeyId(provider);
    }

    public Object getX509CertSigningRequest(String provider, String csr, String keyUsage, int expireMins, Priority priority) {

        // Key Usage value used in Go - https://golang.org/src/crypto/x509/x509.go?s=18153:18173#L558

        List<Integer> extKeyUsage = null;
        if (InstanceProvider.ZTS_CERT_USAGE_CLIENT.equals(keyUsage)) {
            extKeyUsage = new ArrayList<>();
            extKeyUsage.add(2);
        }

        if (InstanceProvider.ZTS_CERT_USAGE_CODE_SIGNING.equals(keyUsage)) {
            extKeyUsage = new ArrayList<>();
            extKeyUsage.add(3);
        }

        if (InstanceProvider.ZTS_CERT_USAGE_TIMESTAMPING.equals(keyUsage)) {
            extKeyUsage = new ArrayList<>();
            extKeyUsage.add(8);
        }

        X509CertificateSigningRequest csrCert = new X509CertificateSigningRequest();
        csrCert.setKeyMeta(new KeyMeta(getProviderKeyId(provider)));
        csrCert.setCsr(csr);
        csrCert.setExtKeyUsage(extKeyUsage);
        csrCert.setValidity(DEFAULT_CERT_EXPIRE_SECS);
        csrCert.setPriority(priority);

        // Validity period of the certificate in seconds in Crypki API.  Convert mins to seconds

        if (expireMins > 0 && expireMins < getMaxCertExpiryTimeMins()) {
            csrCert.setValidity((int) TimeUnit.SECONDS.convert(expireMins, TimeUnit.MINUTES));
        }
            
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("keyMeta: {} keyUsage: {} expireSec: {} priority: {}", csrCert.getKeyMeta(),
                    csrCert.getExtKeyUsage(), csrCert.getValidity(), priority.getPriorityValue());
        }
        return csrCert;
    }

    public String parseResponse(InputStream response) throws IOException {
        X509Certificate cert = JACKSON_MAPPER.readValue(response, X509Certificate.class);
        return cert.getCert();
    }
}
