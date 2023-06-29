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
import java.net.InetSocketAddress;
import java.net.Proxy;
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
    private Proxy proxy = null;
    int certRefreshTimeout;
    int tokenLifetimeSeconds = 3600;
    KeyRefresher keyRefresher = null;

    /**
     * Internal constructor with required details. See {@link GCPZTSCredentials.Builder}.
     *
     * @param builder the {@code Builder} object used to construct the credentials.
     */
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
        if (builder.proxyHost != null && !builder.proxyHost.isEmpty()) {
            proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(builder.proxyHost, builder.proxyPort));
        }
    }

    /**
     * Close the credentials object. If we have a Certificate Key Refresher configured
     * and running, then calling this method is required to properly shut down any
     * background tasks.
     */
    public void close() {
        if (keyRefresher != null) {
            keyRefresher.shutdown();
        }
    }


    /**
     * Return ExternalAccountCredentials object based on the configured details
     * that could be used in other GCP SDK APIs as credentials to access requested
     * GCP resources.
     *
     * @return ExternalAccountCredentials credentials object
     */
    public ExternalAccountCredentials getTokenAPICredentials() throws KeyRefresherException,
            IOException, InterruptedException {

        keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                certFile, keyFile);
        if (certRefreshTimeout > 0) {
            keyRefresher.startup(certRefreshTimeout);
        }
        SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                keyRefresher.getTrustManagerProxy());

        final AthenztHttpTransportFactory transportFactory = new AthenztHttpTransportFactory(sslContext, proxy);
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
        final Proxy proxy;

        AthenztHttpTransportFactory(SSLContext sslContext, Proxy proxy) {
            this.sslContext = sslContext;
            this.proxy = proxy;
        }

        public HttpTransport create() {
            return new NetHttpTransport.Builder()
                    .setSslSocketFactory(sslContext.getSocketFactory())
                    .setProxy(proxy)
                    .build();
        }
    }

    /** Base builder for GCP external account credentials based on ZTS ID Tokens */
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
        private String proxyHost;
        private int proxyPort = 443;
        int certRefreshTimeout;
        int tokenLifetimeSeconds;

        public Builder() {
        }

        /**
         * Sets the GCP Project ID
         *
         * @param projectId GCP project id
         * @return this {@code Builder} object
         */
        public Builder setProjectId(String projectId) {
            this.projectId = projectId;
            return this;
        }

        /**
         * Sets the GCP Project Number
         *
         * @param projectNumber GCP project number
         * @return this {@code Builder} object
         */
        public Builder setProjectNumber(String projectNumber) {
            this.projectNumber = projectNumber;
            return this;
        }

        /**
         * Sets the Workload Identity Pool name configured in the project
         *
         * @param workloadPoolName GCP project workload identity pool name
         * @return this {@code Builder} object
         */
        public Builder setWorkloadPoolName(String workloadPoolName) {
            this.workloadPoolName = workloadPoolName;
            return this;
        }

        /**
         * Sets the Workload Identity Provider name configured in the project
         *
         * @param workloadProviderName GCP project workload identity provider name
         * @return this {@code Builder} object
         */
        public Builder setWorkloadProviderName(String workloadProviderName) {
            this.workloadProviderName = workloadProviderName;
            return this;
        }

        /**
         * Sets the ZTS Url that the library needs to connect to fetch the ID tokens.
         * This value must be full url. For example, https://zts.athenz.io:4443/zts/v1
         *
         * @param ztsUrl ZTS Server Url
         * @return this {@code Builder} object
         */
        public Builder setZtsUrl(String ztsUrl) {
            this.ztsUrl = ztsUrl;
            return this;
        }

        /**
         * Sets the Redirect URI suffix configured in the ZTS Server. According to
         * the OIDC spec, as part of the ID token request, the caller must specify
         * the redirect uri which in the case of ZTS is auto-generated based on the
         * client id: https://{service-name}.{domain-with-dashes}.{redirect-suffix}.
         *
         * @param redirectUriSuffix Redirect URI suffix configured in ZTS
         * @return this {@code Builder} object
         */
        public Builder setRedirectUriSuffix(String redirectUriSuffix) {
            this.redirectUriSuffix = redirectUriSuffix;
            return this;
        }

        /**
         * Sets the Athenz domain name for the roles.
         *
         * @param domainName Domain name
         * @return this {@code Builder} object
         */
        public Builder setDomainName(String domainName) {
            this.domainName = domainName;
            return this;
        }

        /**
         * Sets the list of role names in the configured domain that
         * will be included in the groups claim in the generated
         * id token assuming the principal has access to those roles.
         *
         * @param roleNames list of role names
         * @return this {@code Builder} object
         */
        public Builder setRoleNames(List<String> roleNames) {
            this.roleNames = roleNames;
            return this;
        }

        /**
         * Sets the GCP Service account name that we're going to
         * impersonate using the ZTS ID token. The value must only
         * contain the name of the service and not the full GCP
         * generated email address. For example, deployment-service.
         *
         * @param serviceAccountName service account name
         * @return this {@code Builder} object
         */
        public Builder setServiceAccountName(String serviceAccountName) {
            this.serviceAccountName = serviceAccountName;
            return this;
        }

        /**
         * Sets the private key path of the principal that will
         * request the ID token from ZTS.
         *
         * @param keyFile service private key path
         * @return this {@code Builder} object
         */
        public Builder setKeyFile(String keyFile) {
            this.keyFile = keyFile;
            return this;
        }

        /**
         * Sets the x.509 certificate path of the principal that will
         * request the ID token from ZTS.
         *
         * @param certFile service x.509 certificate path
         * @return this {@code Builder} object
         */
        public Builder setCertFile(String certFile) {
            this.certFile = certFile;
            return this;
        }

        /**
         * Sets the truststore path for the request. This truststore
         * must include the CA root keys for both GCP and ZTS
         * services. Typically, this would the JDK trusttore path:
         * {java-home}/jre/lib/security/cacerts.
         *
         * @param trustStorePath truststore path
         * @return this {@code Builder} object
         */
        public Builder setTrustStorePath(String trustStorePath) {
            this.trustStorePath = trustStorePath;
            return this;
        }

        /**
         * Sets the password for the truststore configured. If using
         * the default JDK truststore, the value is changeit.
         *
         * @param trustStorePassword truststore password
         * @return this {@code Builder} object
         */
        public Builder setTrustStorePassword(char[] trustStorePassword) {
            this.trustStorePassword = trustStorePassword;
            return this;
        }

        /**
         * Sets the client id for the request. This must match
         * the value configured in the project Workload Identity
         * Provider. The client id is an Athenz identity in the
         * {domain-name}.{service-name} format. This client id is
         * also used to automatically generate the redirect uri
         * required for the request.
         *
         * @param clientId client id for the request
         * @return this {@code Builder} object
         */
        public Builder setClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Sets the optional refresh timeout for the principal private key
         * and certificate files in seconds. If configured, the library
         * will automatically create a background task and check for
         * updated key/cert files every configured number of seconds and
         * automatically reloading the SSL context used for connections.
         *
         * @param certRefreshTimeout certificate refresh timeout in seconds
         * @return this {@code Builder} object
         */
        public Builder setCertRefreshTimeout(int certRefreshTimeout) {
            this.certRefreshTimeout = certRefreshTimeout;
            return this;
        }

        /**
         * Sets the requested lifetime for the Google access tokens.
         * GCP requires that the value must be between 600 and 43200 seconds.
         *
         * @param tokenLifetimeSeconds token lifetime in seconds
         * @return this {@code Builder} object
         */
        public Builder setTokenLifetimeSeconds(int tokenLifetimeSeconds) {
            // GCP requires that field must be between 600 and 43200 seconds
            if (tokenLifetimeSeconds < 600 || tokenLifetimeSeconds > 43200) {
                throw new IllegalArgumentException("field must be between 600 and 43200 seconds");
            }
            this.tokenLifetimeSeconds = tokenLifetimeSeconds;
            return this;
        }

        /**
         * Sets the proxy hostname for the request.
         *
         * @param proxyHost proxy server hostname
         * @return this {@code Builder} object
         */
        public Builder setProxyHost(String proxyHost) {
            this.proxyHost = proxyHost;
            return this;
        }

        /**
         * Sets the proxy port number for the request. The default
         * value for the proxy port is 443. A valid port value is between
         * 0 and 65535. A port number of zero will let the system
         * pick up an ephemeral port in a bind operation.
         *
         * @param proxyPort proxy server port number
         * @return this {@code Builder} object
         */
        public Builder setProxyPort(int proxyPort) {
            if (proxyPort < 0 || proxyPort > 65535) {
                throw new IllegalArgumentException("proxy port must be between 0 and 65535");
            }
            this.proxyPort = proxyPort;
            return this;
        }

        /**
         * Return GCPZTSCredentials object based on the builder that could be
         * used to obtain ExternalAccountCredentials credentials object by using
         * the getTokenAPICredentials() method of the object.
         *
         * @return GCPZTSCredentials object
         */
        public GCPZTSCredentials build() {
            return new GCPZTSCredentials(this);
        }
    }
}
