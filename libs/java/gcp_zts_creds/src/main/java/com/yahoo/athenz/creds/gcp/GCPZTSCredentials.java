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
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.gson.GsonFactory;
import com.google.auth.http.HttpTransportFactory;
import com.google.auth.oauth2.ExternalAccountCredentials;
import com.oath.auth.KeyRefresher;
import com.oath.auth.KeyRefresherException;
import com.oath.auth.Utils;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.ZTSClient;
import org.apache.http.*;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.*;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestExecutor;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.apache.http.conn.ssl.SSLConnectionSocketFactory.getDefaultHostnameVerifier;

public class GCPZTSCredentials {

    KeyRefresher keyRefresher;
    final AthenztHttpTransportFactory httpTransportFactory;
    final InputStream tokenApiStream;

    /**
     * Internal constructor with required details. See {@link GCPZTSCredentials.Builder}.
     *
     * @param builder the {@code Builder} object used to construct the credentials.
     */
    GCPZTSCredentials(Builder builder) throws KeyRefresherException, IOException, InterruptedException {

        final String audience = String.format("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
                builder.projectNumber, builder.workloadPoolName, builder.workloadProviderName);
        final String serviceUrl = String.format("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s@%s.iam.gserviceaccount.com:generateAccessToken",
                builder.serviceAccountName, builder.projectId);
        final String scope = URLEncoder.encode(ZTSClient.generateIdTokenScope(builder.domainName, builder.roleNames), StandardCharsets.UTF_8);
        final String redirectUri = URLEncoder.encode(ZTSClient.generateRedirectUri(builder.clientId, builder.redirectUriSuffix), StandardCharsets.UTF_8);
        final String tokenUrl = String.format("%s/oauth2/auth?response_type=id_token&client_id=%s&redirect_uri=%s&scope=%s&nonce=%s&keyType=EC&fullArn=true&output=json",
                builder.ztsUrl, builder.clientId, redirectUri, scope, Crypto.randomSalt());

        // create our input stream

        tokenApiStream = createTokenAPIStream(audience, serviceUrl, tokenUrl, builder.tokenLifetimeSeconds);

        // Use the sslcontext directly if it is provided
        SSLContext sslContext;
        if (builder.sslContext != null) {
            sslContext = builder.sslContext;
        } else {
            // generate the key refresher object based on your provided details
            // if we have a truststore configured then we need to use it
            // to refresh our key/cert files (if configured
            keyRefresher = Utils.generateKeyRefresher(builder.trustStorePath, builder.trustStorePassword,
                    builder.certFile, builder.keyFile);
            if (builder.certRefreshTimeout > 0) {
                keyRefresher.startup(builder.certRefreshTimeout);
            }
            sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());
        }

        SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslContext,
                new String[]{"TLSv1.2", "TLSv1.3"}, null, getDefaultHostnameVerifier());

        // set up http client builder with our ssl context and proxy details if configured

        HttpClientBuilder httpClientBuilder = ApacheHttpTransport.newDefaultHttpClientBuilder()
                .setSSLSocketFactory(sslConnectionSocketFactory);

        if (builder.proxyHost != null && !builder.proxyHost.isEmpty()) {
            HttpHost proxy = new HttpHost(builder.proxyHost, builder.proxyPort);
            httpClientBuilder.setRoutePlanner(new DefaultProxyRoutePlanner(proxy));
            if (builder.proxyAuth != null && !builder.proxyAuth.isEmpty()) {
                httpClientBuilder.setRequestExecutor(new AthenzProxyHttpRequestExecutor(builder.proxyAuth));
            }
        }

        // finally create our transport factory

        httpTransportFactory = new AthenztHttpTransportFactory(new ApacheHttpTransport(httpClientBuilder.build()));
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
    public ExternalAccountCredentials getTokenAPICredentials() throws IOException {
        return ExternalAccountCredentials.fromStream(tokenApiStream, httpTransportFactory);
    }

    InputStream createTokenAPIStream(final String audience, final String serviceUrl, final String tokenUrl,
            int tokenLifetimeSeconds) {

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

        final HttpTransport httpTransport;

        AthenztHttpTransportFactory(HttpTransport httpTransport) {
            this.httpTransport = httpTransport;
        }

        public HttpTransport create() {
            return httpTransport;
        }
    }

    static class AthenzProxyHttpRequestExecutor extends HttpRequestExecutor {

        final String proxyAuth;

        public AthenzProxyHttpRequestExecutor(final String proxyAuth) {
            super();
            this.proxyAuth = proxyAuth;
        }

        @Override
        public HttpResponse execute(HttpRequest request, HttpClientConnection conn, HttpContext context)
                throws IOException, HttpException {
            if ("CONNECT".equalsIgnoreCase(request.getRequestLine().getMethod())) {
                request.setHeader(HttpHeaders.PROXY_AUTHORIZATION, proxyAuth);
            }
            return super.execute(request, conn, context);
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
        private String proxyAuth;
        private int proxyPort = 4080;
        int certRefreshTimeout = 0;
        int tokenLifetimeSeconds = 3600;
        SSLContext sslContext = null;

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
         * Sets the SSL context for the request. This overrides the certificate and key settings.
         * Note that the ssl context must support reloading of the key/cert files if they are updated.
         * @param sslContext SSL context for the request
         * @return this {@code Builder} object
         */
        public Builder setSslContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        /**
         * Sets the requested lifetime for the Google access tokens.
         * GCP requires that the value must be between 600 and 43200 seconds.
         * Default value is 600 seconds.
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
         * value for the proxy port is 4080. A valid port value is between
         * 0 and 65535.
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
         * Sets the proxy authorization value for the request. This will
         * be included as the value for the Proxy-Authorization header
         * if proxy host is configured.
         *
         * @param proxyAuth proxy-authorization header value
         * @return this {@code Builder} object
         */
        public Builder setProxyAuth(String proxyAuth) {
            this.proxyAuth = proxyAuth;
            return this;
        }

        /**
         * Return GCPZTSCredentials object based on the builder that could be
         * used to obtain ExternalAccountCredentials credentials object by using
         * the getTokenAPICredentials() method of the object.
         *
         * @return GCPZTSCredentials object
         */
        public GCPZTSCredentials build() throws KeyRefresherException, IOException, InterruptedException {
            return new GCPZTSCredentials(this);
        }
    }
}
