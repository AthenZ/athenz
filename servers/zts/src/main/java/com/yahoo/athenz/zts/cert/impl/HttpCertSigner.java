/**
 * Copyright 2016 Yahoo Inc.
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

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.common.server.cert.CertSigner;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.SSHCertificate;
import com.yahoo.athenz.zts.cert.SSHCertificates;
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

    private final PrivateKeyStore privateKeyStore;
    private HttpClient httpClient = null;
    String x509CertUri = null;
    String sshCertUri = null;
    long requestTimeout;
    int requestRetryCount;

    public HttpCertSigner() {

        this.privateKeyStore = loadServicePrivateKey();

        // retrieve our default timeout and retry timer
        
        long timeout = Long.parseLong(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_CONNECT_TIMEOUT, "10"));
        long connectTimeout = TimeUnit.MILLISECONDS.convert(timeout, TimeUnit.SECONDS);

        requestTimeout = Long.parseLong(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_REQUEST_TIMEOUT, "5"));
        requestRetryCount = Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_RETRY_COUNT, "3"));

        // Instantiate and start our HttpClient
        
        httpClient = new HttpClient(ZTSUtils.createSSLContextObject(new String[] {"TLSv1.2"}, privateKeyStore));
        httpClient.setFollowRedirects(false);
        httpClient.setConnectTimeout(connectTimeout);
        try {
            httpClient.start();
        } catch (Exception ex) {
            LOGGER.error("HttpCertSigner: unable to start http client: " + ex.getMessage());
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Http client not available");
        }

        // generate our post and get certificate URIs

        String serverBaseUri = System.getProperty(ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI);
        if (serverBaseUri == null) {
            LOGGER.error("HttpCertSigner: no base uri specified");
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "No CertSigner base uri specified: " + ZTSConsts.ZTS_PROP_CERTSIGN_BASE_URI);
        }
        x509CertUri = serverBaseUri + "/x509";
        sshCertUri = serverBaseUri + "/ssh";
        
    }

    private PrivateKeyStore loadServicePrivateKey() {
        String pkeyFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZTSConsts.ZTS_PKEY_STORE_FACTORY_CLASS);
        PrivateKeyStoreFactory pkeyFactory = null;
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
    public void close() {
        try {
            if (httpClient != null) {
                httpClient.stop();
            }
        } catch (Exception ex) {
            LOGGER.error("close: unable to stop httpClient" + ex.getMessage());
        }
    }

    ContentResponse processX509CertRequest(final String csr, final String keyUsage, int retryCount) {
        
        ContentResponse response = null;
        try {
            Request request = httpClient.POST(x509CertUri);
            request.header(HttpHeader.ACCEPT, CONTENT_JSON);
            request.header(HttpHeader.CONTENT_TYPE, CONTENT_JSON);
            
            X509CertSignObject csrCert = new X509CertSignObject()
                    .setPem(csr).setExtusage(keyUsage);
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
            String msg = ex.getMessage();
            if (msg == null) {
                msg = ex.getClass().getName();
            }
            LOGGER.error("generateX509Certificate: Unable to fetch requested uri '{}': {}",
                    x509CertUri, msg);
        }
        return response;
    }
    
    @Override
    public String generateX509Certificate(String csr, String keyUsage) {
        
        // Key Usage value used in go - https://golang.org/src/crypto/x509/x509.go?s=18153:18173#L558
        // we're only interested in ExtKeyUsageClientAuth - with value of 2
        
        final String extKeyUsage = ZTSConsts.ZTS_CERT_USAGE_CLIENT.equals(keyUsage) ? "2" : null;

        ContentResponse response = null;
        for (int i = 0; i < requestRetryCount; i++) {
            if ((response = processX509CertRequest(csr, extKeyUsage, i + 1)) != null) {
                break;
            }
        }
        if (response == null) {
            return null;
        }
        
        if (response.getStatus() != HttpStatus.CREATED_201) {
            LOGGER.error("generateX509Certificate: unable to fetch requested uri '" + x509CertUri +
                    "' status: " + response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (data == null || data.isEmpty()) {
            LOGGER.error("generateX509Certificate: received empty response from uri '" + x509CertUri +
                    "' status: " + response.getStatus());
            return null;
        }

        X509CertSignObject pemCert = null;
        try {
            pemCert = JSON.fromString(data, X509CertSignObject.class);
        } catch (Exception ex) {
            LOGGER.error("generateX509Certificate: unable to decode object from '" + x509CertUri +
                    "' error: " + ex.getMessage());
        }
        return (pemCert != null) ? pemCert.getPem() : null;
    }

    ContentResponse processSSHKeyRequest(String sshKeyReq, int retryCount) {
        
        ContentResponse response = null;
        try {
            Request request = httpClient.POST(sshCertUri);
            request.header(HttpHeader.ACCEPT, CONTENT_JSON);
            request.header(HttpHeader.CONTENT_TYPE, CONTENT_JSON);

            request.content(new StringContentProvider(sshKeyReq), CONTENT_JSON);
            
            // our max timeout is going to be 30 seconds. By default
            // we're picking a small value to quickly recognize when
            // our idle connections are disconnected by signer but
            // we won't allow any connections taking longer than 30 secs
            
            long timeout = retryCount * requestTimeout;
            if (timeout > 30) {
                timeout = 30;
            }
            request.timeout(timeout, TimeUnit.SECONDS);
            response = request.send();
        } catch (Exception ex) {
            String msg = ex.getMessage();
            if (msg == null) {
                msg = ex.getClass().getName();
            }
            LOGGER.error("processSSHKeyRequest: Unable to fetch requested uri '{}': {}",
                    sshCertUri, msg);
        }
        return response;
    }
    
    @Override
    public String generateSSHCertificate(String sshKeyReq) {

        ContentResponse response = null;
        for (int i = 0; i < requestRetryCount; i++) {
            if ((response = processSSHKeyRequest(sshKeyReq, i + 1)) != null) {
                break;
            }
        }
        if (response == null) {
            return null;
        }

        if (response.getStatus() != HttpStatus.CREATED_201) {
            LOGGER.error("generateSSHCertificate: unable to fetch requested uri '" + sshCertUri +
                    "' status: " + response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (data == null || data.isEmpty()) {
            LOGGER.error("generateSSHCertificate: received empty response from uri '" + sshCertUri +
                    "' status: " + response.getStatus());
            return null;
        }

        SSHCertificate cert = null;
        try {
            cert = JSON.fromString(data, SSHCertificate.class);
        } catch (Exception ex) {
            LOGGER.error("generateSSHCertificate: unable to decode object from '" + sshCertUri +
                    "' error: " + ex.getMessage());
        }
        return (cert != null) ? cert.getOpensshkey() : null;
    }
    
    @Override
    public String getCACertificate() {

        ContentResponse response = null;
        try {
            response = httpClient.GET(x509CertUri);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            LOGGER.error("getCACertificate: unable to fetch requested uri '" + x509CertUri + "': "
                    + e.getMessage());
            return null;
        }
        if (response.getStatus() != HttpStatus.OK_200) {
            LOGGER.error("getCACertificate: unable to fetch requested uri '" + x509CertUri +
                    "' status: " + response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (data == null || data.isEmpty()) {
            LOGGER.error("getCACertificate: received empty response from uri '" + x509CertUri +
                    "' status: " + response.getStatus());
            return null;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getCACertificate: CA Certificate" + data);
        }

        X509CertSignObject pemCert = null;
        try {
            pemCert = JSON.fromString(data, X509CertSignObject.class);
        } catch (Exception ex) {
            LOGGER.error("getCACertificate: unable to decode object from '" + x509CertUri +
                    "' error: " + ex.getMessage());
        }
        return (pemCert != null) ? pemCert.getPem() : null;
    }
    
    @Override
    public String getSSHCertificate(String type) {

        ContentResponse response = null;
        try {
            response = httpClient.GET(sshCertUri);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            LOGGER.error("getSSHCertificate: unable to fetch requested uri '" + sshCertUri + "': "
                    + e.getMessage());
            return null;
        }
        if (response.getStatus() != HttpStatus.OK_200) {
            LOGGER.error("getSSHCertificate: unable to fetch requested uri '" + sshCertUri +
                    "' status: " + response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (data == null || data.isEmpty()) {
            LOGGER.error("getSSHCertificate: received empty response from uri '" + sshCertUri +
                    "' status: " + response.getStatus());
            return null;
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("getSSHCertificate: SSH Certificate" + data);
        }

        SSHCertificates sshCerts = null;
        try {
            sshCerts = JSON.fromString(data, SSHCertificates.class);
        } catch (Exception ex) {
            LOGGER.error("getSSHCertificate: unable to decode object from '" + sshCertUri +
                    "' error: " + ex.getMessage());
            return null;
        }
        
        if (sshCerts != null && sshCerts.getCerts() != null) {
            for (SSHCertificate sshCert : sshCerts.getCerts()) {
                if (sshCert.getType().equals(type)) {
                    return sshCert.getOpensshkey();
                }
            }
        }
        
        return null;
    }
    
    void setHttpClient(HttpClient client) {
        close();
        this.httpClient = client;
    }
}
