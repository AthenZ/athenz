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
package com.yahoo.athenz.creds.gcp;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.gson.GsonFactory;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.ExternalAccountCredentials;
import com.oath.auth.KeyRefresher;
import com.oath.auth.KeyRefresherException;
import com.oath.auth.Utils;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.ZTSClient;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class GCPZTSCredentials {

    private final String keyFile;
    private final String certFile;
    private final String trustStorePath;
    private final String audience;
    private final String serviceUrl;
    private final String tokenUrl;
    private final char[] trustStorePassword;
    int certRefreshTimeout;
    int tokenLifetimeSeconds = 3600;
    KeyRefresher keyRefresher = null;

    GCPZTSCredentials(Builder builder) {

        this.keyFile = builder.keyFile;
        this.certFile = builder.certFile;
        this.trustStorePath = builder.trustStorePath;
        this.trustStorePassword = builder.trustStorePassword;
        this.certRefreshTimeout = builder.certRefreshTimeout;
        if (builder.tokenLifetimeSeconds > 0) {
            this.tokenLifetimeSeconds = builder.tokenLifetimeSeconds;
        }
        audience = String.format("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
                builder.projectNumber, builder.workloadPoolName, builder.workloadProviderName);
        serviceUrl = String.format("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s@%s.iam.gserviceaccount.com:generateAccessToken",
                builder.serviceAccountName, builder.projectId);
        final String scope = URLEncoder.encode(ZTSClient.generateIdTokenScope(builder.domainName, builder.roleNames), StandardCharsets.UTF_8);
        final String redirectUri = URLEncoder.encode(ZTSClient.generateRedirectUri(builder.clientId, builder.redirectUriSuffix), StandardCharsets.UTF_8);
        tokenUrl = String.format("%s/oauth2/auth?response_type=id_token&client_id=%s&redirect_uri=%s&scope=%s&nonce=%s&keyType=EC&fullArn=true&output=json",
                builder.ztsUrl, builder.clientId, redirectUri, scope, Crypto.randomSalt());

    }

    public void close() {
        if (keyRefresher != null) {
            keyRefresher.shutdown();
        }
    }

    public ExternalAccountCredentials getTokenAPICredentials() throws KeyRefresherException,
            IOException, InterruptedException {

        keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                certFile, keyFile);
        if (certRefreshTimeout > 0) {
            keyRefresher.startup(certRefreshTimeout);
        }
        SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                keyRefresher.getTrustManagerProxy());

        final AthenztHttpTransportFactory transportFactory = new AthenztHttpTransportFactory(sslContext);
        final InputStream inputStream = createTokenAPIStream();
        return ExternalAccountCredentials.fromStream(inputStream, transportFactory);
    }

    InputStream createTokenAPIStream() {

        GenericJson config = new GenericJson();
        config.setFactory(GsonFactory.getDefaultInstance());

        config.set("type", "external_account");
        config.set("audience", audience);
        config.set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt");
        config.set("token_url", "https://sts.googleapis.com/v1/token");

        config.set("service_account_impersonation_url", serviceUrl);

        GenericJson serviceAccountImpersonation = new GenericJson();
        serviceAccountImpersonation.set("token_lifetime_seconds", tokenLifetimeSeconds);
        config.set("service_account_impersonation", serviceAccountImpersonation);

        GenericJson credentialSource = new GenericJson();
        credentialSource.set("url", tokenUrl);

        GenericJson credentialSourceFormat = new GenericJson();
        credentialSourceFormat.set("type", "json");
        credentialSourceFormat.set("subject_token_field_name", "id_token");

        credentialSource.set("format", credentialSourceFormat);
        config.set("credential_source", credentialSource);

        return new ByteArrayInputStream(config.toString().getBytes(StandardCharsets.UTF_8));
    }

    static class AthenztHttpTransportFactory implements HttpTransportFactory {

        final SSLContext sslContext;

        AthenztHttpTransportFactory(SSLContext sslContext) {
            this.sslContext = sslContext;
        }

        public HttpTransport create() {
            return new NetHttpTransport.Builder().setSslSocketFactory(sslContext.getSocketFactory()).build();
        }
    }

    public static class Builder {

        private String projectNumber;
        private String projectId;
        private String workloadPoolName;
        private String workloadProviderName;
        private String ztsUrl;
        private String clientId;
        private String redirectUriSuffix;
        private String domainName;
        private List<String> roleNames;
        private String serviceAccountName;
        private String keyFile;
        private String certFile;
        private String trustStorePath;
        private char[] trustStorePassword;
        int certRefreshTimeout;
        int tokenLifetimeSeconds;

        public Builder() {
        }

        public void setProjectId(String projectId) {
            this.projectId = projectId;
        }

        public void setWorkloadPoolName(String workloadPoolName) {
            this.workloadPoolName = workloadPoolName;
        }

        public void setWorkloadProviderName(String workloadProviderName) {
            this.workloadProviderName = workloadProviderName;
        }

        public void setZtsUrl(String ztsUrl) {
            this.ztsUrl = ztsUrl;
        }

        public void setRedirectUriSuffix(String redirectUriSuffix) {
            this.redirectUriSuffix = redirectUriSuffix;
        }

        public void setDomainName(String domainName) {
            this.domainName = domainName;
        }

        public void setRoleNames(List<String> roleNames) {
            this.roleNames = roleNames;
        }

        public void setServiceAccountName(String serviceAccountName) {
            this.serviceAccountName = serviceAccountName;
        }

        public void setKeyFile(String keyFile) {
            this.keyFile = keyFile;
        }

        public void setCertFile(String certFile) {
            this.certFile = certFile;
        }

        public void setTrustStorePath(String trustStorePath) {
            this.trustStorePath = trustStorePath;
        }

        public void setTrustStorePassword(char[] trustStorePassword) {
            this.trustStorePassword = trustStorePassword;
        }

        public void setProjectNumber(String projectNumber) {
            this.projectNumber = projectNumber;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public void setCertRefreshTimeout(int certRefreshTimeout) {
            this.certRefreshTimeout = certRefreshTimeout;
        }

        public void setTokenLifetimeSeconds(int tokenLifetimeSeconds) {
            // GCP requires that field must be between 600 and 43200 seconds
            if (tokenLifetimeSeconds < 600 || tokenLifetimeSeconds > 43200) {
                throw new IllegalArgumentException("field must be between 600 and 43200 seconds");
            }
            this.tokenLifetimeSeconds = tokenLifetimeSeconds;
        }

        public GCPZTSCredentials build() {
            return new GCPZTSCredentials(this);
        }
    }
}
