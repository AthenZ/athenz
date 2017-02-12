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
import java.util.concurrent.TimeoutException;

import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.cert.CertSigner;
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
    private HttpClient httpClient = null;
    String certUri = null;

    private static final String ZTS_PROP_CERTSIGN_BASE_URI = "athenz.zts.certsign_base_uri";
    private static final String DEFAULT_CERTSIGN_BASE_URI = "https://localhost:443/certsign/v2";

    public HttpCertSigner() {

        // Instantiate and start our HttpClient
            
        httpClient = new HttpClient(ZTSUtils.createSSLContextObject(new String[] {"TLSv1.2"}));
        httpClient.setFollowRedirects(false);
        try {
            httpClient.start();
        } catch (Exception ex) {
            LOGGER.error("HttpCertSigner: unable to start http client: " + ex.getMessage());
            throw new ResourceException(ResourceException.INTERNAL_SERVER_ERROR,
                    "Http client not available");
        }

        // generate our post and get certificate URIs

        String serverBaseUri = System.getProperty(ZTS_PROP_CERTSIGN_BASE_URI, DEFAULT_CERTSIGN_BASE_URI);
        certUri = serverBaseUri + "/x509";
    }

    @Override
    public void close() {
        try {
            if (httpClient != null) {
                httpClient.stop();
            }
        } catch (Exception ex) {
            LOGGER.error("close(): unable to stop httpClient" + ex.getMessage());
        }
    }

    @Override
    public String generateX509Certificate(String csr) {

        ContentResponse response = null;
        try {
            Request request = httpClient.POST(certUri);
            request.header(HttpHeader.ACCEPT, "application/json");
            request.header(HttpHeader.CONTENT_TYPE, "application/json");

            X509CertSignObject csrCert = new X509CertSignObject();
            csrCert.setPem(csr);
            request.content(new StringContentProvider(JSON.string(csrCert)), "application/json");
            response = request.send();

        } catch (Exception ex) {
            LOGGER.error("generateX509Certificate: unable to fetch requested uri '" + certUri + "': "
                    + ex.getMessage());
            return null;
        }
        if (response.getStatus() != HttpStatus.CREATED_201) {
            LOGGER.error("generateX509Certificate: unable to fetch requested uri '" + certUri +
                    "' status: " + response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (data == null || data.isEmpty()) {
            LOGGER.error("generateX509Certificate: received empty response from uri '" + certUri +
                    "' status: " + response.getStatus());
            return null;
        }

        X509CertSignObject pemCert = null;
        try {
            pemCert = JSON.fromString(data, X509CertSignObject.class);
        } catch (Exception ex) {
            LOGGER.error("generateX509Certificate: unable to decode object from '" + certUri +
                    "' error: " + ex.getMessage());
        }
        return (pemCert != null) ? pemCert.getPem() : null;
    }

    @Override
    public String getCACertificate() {

        ContentResponse response = null;
        try {
            response = httpClient.GET(certUri);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            LOGGER.error("getCACertificate: unable to fetch requested uri '" + certUri + "': "
                    + e.getMessage());
            return null;
        }
        if (response.getStatus() != HttpStatus.OK_200) {
            LOGGER.error("getCACertificate: unable to fetch requested uri '" + certUri +
                    "' status: " + response.getStatus());
            return null;
        }

        String data = response.getContentAsString();
        if (data == null || data.isEmpty()) {
            LOGGER.error("getCACertificate: received empty response from uri '" + certUri +
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
            LOGGER.error("getCACertificate: unable to decode object from '" + certUri +
                    "' error: " + ex.getMessage());
        }
        return (pemCert != null) ? pemCert.getPem() : null;
    }
    
    void setHttpClient(HttpClient client) {
        close();
        this.httpClient = client;
    }
}
