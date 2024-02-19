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
package com.yahoo.athenz.auth.token.jwts;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;


public class JwtsHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtsHelper.class);
    private static final ObjectMapper JSON_MAPPER = initJsonMapper();

    static ObjectMapper initJsonMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }

    public String extractJwksUri(final String openIdConfigUri, final SSLContext sslContext) {
        return this.extractJwksUri(openIdConfigUri, sslContext, null);
    }

    public String extractJwksUri(final String openIdConfigUri, final SSLContext sslContext, final String proxyUrl) {

        final String opendIdConfigData = getHttpData(openIdConfigUri, sslContext, proxyUrl);
        if (opendIdConfigData == null) {
            return null;
        }

        try {
            OpenIdConfiguration openIdConfig = JSON_MAPPER.readValue(opendIdConfigData, OpenIdConfiguration.class);
            return openIdConfig.getJwksUri();
        } catch (Exception ex) {
            LOGGER.error("Unable to extract jwks uri", ex);
        }

        return null;
    }

    public String getHttpData(final String serverUri, final SSLContext sslContext) {
        return getHttpData(serverUri, sslContext, null);
    }

    public String getHttpData(final String serverUri, final SSLContext sslContext, final String proxyUrl) {

        if (serverUri == null || serverUri.isEmpty()) {
            return null;
        }

        try {
            URLConnection con;
            if (proxyUrl == null || proxyUrl.isEmpty()) {
                con = getUrlConnection(serverUri);
            } else {
                URL url = new URL(proxyUrl);
                con = getUrlConnection(serverUri, url.getHost(), url.getPort());
            }

            con.setRequestProperty("Accept", "application/json");
            con.setConnectTimeout(10000);
            con.setReadTimeout(15000);
            con.setDoOutput(true);
            if (con instanceof HttpURLConnection) {
                HttpURLConnection httpCon = (HttpURLConnection) con;
                httpCon.setRequestMethod("GET");
            }
            if (con instanceof HttpsURLConnection) {
                HttpsURLConnection httpsCon = (HttpsURLConnection) con;
                SSLSocketFactory sslSocketFactory = getSocketFactory(sslContext);
                if (sslSocketFactory != null) {
                    httpsCon.setSSLSocketFactory(sslSocketFactory);
                }
            }

            con.connect();
            if (con instanceof HttpURLConnection) {
                HttpURLConnection httpCon = (HttpURLConnection) con;
                if (httpCon.getResponseCode() != HttpURLConnection.HTTP_OK) {
                    LOGGER.error("Unable to extract document from {} error: {}", serverUri, httpCon.getResponseCode());
                    return null;
                }
            }

            try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                StringBuilder sb = new StringBuilder();

                // not using assignment in expression in order to
                // get clover to calculate coverage

                String line = br.readLine();
                while (line != null) {
                    sb.append(line);
                    line = br.readLine();
                }

                return sb.toString();
            }
        } catch (Exception ex) {
            LOGGER.error("Unable to extract document from {} error: {}", serverUri, ex.getMessage());
        }

        return null;
    }

    SSLSocketFactory getSocketFactory(SSLContext sslContext) {
        return (sslContext == null) ? null : sslContext.getSocketFactory();
    }

    URLConnection getUrlConnection(final String serverUrl) throws IOException {
        return new URL(serverUrl).openConnection();
    }

    URLConnection getUrlConnection(final String serverUrl, final String proxyHost, final Integer proxyPort) throws IOException {
        SocketAddress addr = new InetSocketAddress(proxyHost, proxyPort);
        Proxy proxy = new Proxy(Proxy.Type.HTTP, addr);
        return new URL(serverUrl).openConnection(proxy);
    }
}
