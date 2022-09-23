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
package com.yahoo.athenz.zts.cert.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.common.server.cert.Priority;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.X509CertSignObject;
import com.yahoo.athenz.zts.utils.ZTSUtils;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.util.StringContentProvider;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.rdl.JSON;

public class HttpCertSigner implements CertSigner {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpCertSigner.class);
    private static final String CONTENT_JSON = "application/json";

    private HttpClient httpClient;
    String x509CertUri;
    long requestTimeout;
    int requestRetryCount;
    int maxCertExpiryTimeMins;

    public HttpCertSigner() {

        PrivateKeyStore privateKeyStore = loadServicePrivateKey();

        // retrieve our default timeout and retry timer
        
        long timeout = Long.parseLong(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_CONNECT_TIMEOUT, "10"));
        long connectTimeout = TimeUnit.MILLISECONDS.convert(timeout, TimeUnit.SECONDS);

        requestTimeout = Long.parseLong(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_REQUEST_TIMEOUT, "5"));
        requestRetryCount = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_RETRY_COUNT, "3"));

        // max expiry time in minutes
        
        maxCertExpiryTimeMins = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_MAX_EXPIRY_TIME, "43200"));
        
        // Instantiate and start our HttpClient
        
        httpClient = new HttpClient(ZTSUtils.createSSLContextObject(new String[] {"TLSv1.2"}, privateKeyStore));
        setupHttpClient(httpClient, requestTimeout, connectTimeout);

        // generate our post and get certificate URIs

        String serverBaseUri = System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI);
        if (serverBaseUri == null) {
            LOGGER.error("HttpCertSigner: no base uri specified");
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "No CertSigner base uri specified: " + ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI);
        }
        x509CertUri = serverBaseUri + "/x509";
    }

    void setupHttpClient(HttpClient client, long requestTimeout, long connectTimeout) {

        client.setFollowRedirects(false);
        client.setConnectTimeout(connectTimeout);
        client.setStopTimeout(TimeUnit.MILLISECONDS.convert(requestTimeout, TimeUnit.SECONDS));
        try {
            client.start();
        } catch (Exception ex) {
            LOGGER.error("HttpCertSigner: unable to start http client", ex);
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Http client not available");
        }
    }

    void setHttpClient(HttpClient client) {
        stopHttpClient();
        this.httpClient = client;
    }

    private void stopHttpClient() {
        if (httpClient == null) {
            return;
        }
        try {
            httpClient.stop();
        } catch (Exception ignored) {
        }
    }

    @Override
    public void close() {
        stopHttpClient();
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
            LOGGER.error("Invalid PrivateKeyStoreFactory class: {} error: {}", pkeyFactoryClass, e.getMessage());
            throw new IllegalArgumentException("Invalid private key store");
        }
        return pkeyFactory.create();
    }

    ContentResponse processX509CertRequest(final String csr, final List<Integer> extKeyUsage,
            int expiryTime, int retryCount) {
        
        ContentResponse response = null;
        try {
            Request request = httpClient.POST(x509CertUri);
            request.header(HttpHeader.ACCEPT, CONTENT_JSON);
            request.header(HttpHeader.CONTENT_TYPE, CONTENT_JSON);
            
            X509CertSignObject csrCert = new X509CertSignObject();
            csrCert.setPem(csr);
            csrCert.setX509ExtKeyUsage(extKeyUsage);
            if (expiryTime > 0 && expiryTime < maxCertExpiryTimeMins) {
                csrCert.setExpiryTime(expiryTime);
            }
            request.content(new StringContentProvider(JSON.string(csrCert)), CONTENT_JSON);
            
            // our max timeout is going to be 30 seconds. By default
            // we're picking a small value to quickly recognize when
            // our idle connections are disconnected by certsigner but
            // we won't allow any connections taking longer than 30 secs
            
            long timeout = retryCount * requestTimeout;
            if (timeout > 30) {
                timeout = 30;
            }
            request.timeout(timeout, TimeUnit.SECONDS);
            response = request.send();
        } catch (Exception ex) {
            LOGGER.error("Unable to process x509 certificate request", ex);
        }
        return response;
    }

    @Override
    public String generateX509Certificate(String provider, String certIssuer, String csr, String keyUsage, int expireMins) {
        return generateX509Certificate(provider, certIssuer, csr, keyUsage, expireMins, Priority.Unspecified_priority);
    }

    @Override
    public String generateX509Certificate(String provider, String certIssuer, String csr, String keyUsage, int expireMins, Priority priority) {
        
        // Key Usage value used in Go - https://golang.org/src/crypto/x509/x509.go?s=18153:18173#L558
        // we're only interested in ExtKeyUsageClientAuth - with value of 2
        
        List<Integer> extKeyUsage = null;
        if (InstanceProvider.ZTS_CERT_USAGE_CLIENT.equals(keyUsage)) {
            extKeyUsage = new ArrayList<>();
            extKeyUsage.add(2);
        }

        ContentResponse response = null;
        for (int i = 0; i < requestRetryCount; i++) {
            response = processX509CertRequest(csr, extKeyUsage, expireMins, i + 1);
            if (response != null) {
                break;
            }
        }
        if (response == null) {
            return null;
        }
        
        if (response.getStatus() != HttpStatus.CREATED_201) {
            LOGGER.error("unable to fetch requested uri '{}' status: {}", x509CertUri, response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (data == null || data.isEmpty()) {
            LOGGER.error("received empty response from uri '{}' status: {}", x509CertUri, response.getStatus());
            return null;
        }

        X509CertSignObject pemCert = JSON.fromString(data, X509CertSignObject.class);
        return (pemCert != null) ? pemCert.getPem() : null;
    }
    
    @Override
    public String getCACertificate(String provider) {

        ContentResponse response;
        try {
            response = httpClient.GET(x509CertUri);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            LOGGER.error("getCACertificate: unable to fetch requested uri '{}': {}", x509CertUri, e.getMessage());
            return null;
        }
        if (response.getStatus() != HttpStatus.OK_200) {
            LOGGER.error("getCACertificate: unable to fetch requested uri '{}' status: {}", x509CertUri, response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (data == null || data.isEmpty()) {
            LOGGER.error("getCACertificate: received empty response from uri '{}' status: {}", x509CertUri, response.getStatus());
            return null;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getCACertificate: CA Certificate {}", data);
        }

        X509CertSignObject pemCert = JSON.fromString(data, X509CertSignObject.class);
        return (pemCert != null) ? pemCert.getPem() : null;
    }
}
