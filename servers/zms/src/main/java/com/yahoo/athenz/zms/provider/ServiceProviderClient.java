/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.zms.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oath.auth.KeyRefresher;
import com.oath.auth.KeyRefresherException;
import com.oath.auth.Utils;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.http.HttpDriver;
import com.yahoo.athenz.common.server.http.HttpDriverResponse;
import com.yahoo.athenz.zms.ZMSConsts;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;

import static com.yahoo.athenz.zms.ZMSConsts.*;

public class ServiceProviderClient {
    private final HttpDriver httpDriver;
    private final ObjectMapper jsonMapper = new ObjectMapper();
    private final String homeDomainPrefix;

    private static final Logger LOG = LoggerFactory.getLogger(ServiceProviderClient.class);

    public ServiceProviderClient(PrivateKeyStore keyStore, String homeDomainPrefix)
            throws KeyRefresherException, IOException, InterruptedException {

        SSLContext sslContext = getDomainDependencyProviderSSLContext(keyStore);
        if (sslContext != null) {
            this.httpDriver = getHttpDriver(sslContext);
            this.homeDomainPrefix = homeDomainPrefix;
        } else {
            this.httpDriver = null;
            this.homeDomainPrefix = null;
        }
    }

    public ServiceProviderClient(HttpDriver httpDriver, String homeDomainPrefix) {
        this.httpDriver = httpDriver;
        this.homeDomainPrefix = homeDomainPrefix;
    }

    public DomainDependencyProviderResponse getDependencyStatus(
            ServiceProviderManager.DomainDependencyProvider domainDependencyProvider,
            String domain, String principal) {

        if (this.httpDriver == null) {
            // ServiceProviderClient wasn't initialized. Do not enforce dependency check.
            DomainDependencyProviderResponse domainDependencyProviderResponse = new DomainDependencyProviderResponse();
            domainDependencyProviderResponse.setStatus(PROVIDER_RESPONSE_ALLOW);
            domainDependencyProviderResponse.setMessage("ServiceProviderClient is disabled");
            return domainDependencyProviderResponse;
        }
        if (domain.startsWith(homeDomainPrefix)) {
            // We won't enforce dependency on user domains
            DomainDependencyProviderResponse domainDependencyProviderResponse = new DomainDependencyProviderResponse();
            domainDependencyProviderResponse.setStatus(PROVIDER_RESPONSE_ALLOW);
            domainDependencyProviderResponse.setMessage("Dependency on home domain " + domain + " is invalid");
            return domainDependencyProviderResponse;
        }

        if (StringUtil.isEmpty(domainDependencyProvider.getProviderEndpoint())) {
            // If no endpoint is listed, consider it dependent
            DomainDependencyProviderResponse domainDependencyProviderResponse = new DomainDependencyProviderResponse();
            domainDependencyProviderResponse.setStatus(PROVIDER_RESPONSE_DENY);
            domainDependencyProviderResponse.setMessage("No provider endpoint is listed. Please contact an administrator");
            return domainDependencyProviderResponse;
        }

        try {
            return getDependencyStatusFromProvider(domainDependencyProvider, domain, principal);
        } catch (Exception ex) {
            // On failure to contact provider, consider it dependent
            DomainDependencyProviderResponse domainDependencyProviderResponse = new DomainDependencyProviderResponse();
            domainDependencyProviderResponse.setStatus(PROVIDER_RESPONSE_DENY);
            domainDependencyProviderResponse.setMessage("Exception thrown during call to provider: " + ex.getMessage());
            return domainDependencyProviderResponse;
        }
    }

    private SSLContext getDomainDependencyProviderSSLContext(PrivateKeyStore keyStore)
            throws KeyRefresherException, IOException, InterruptedException {

        final String trustStore = System.getProperty(ZMSConsts.ZMS_PROP_PROVIDER_TRUST_STORE, "");
        final String trustStorePassword = System.getProperty(ZMSConsts.ZMS_PROP_PROVIDER_TRUST_STORE_PASSWORD, "");
        final String appName = System.getProperty(ZMSConsts.ZMS_PROP_PROVIDER_APP_NAME, "");
        final String certPath = System.getProperty(ZMSConsts.ZMS_PROP_PROVIDER_CERT_PATH, "");
        final String keyPath = System.getProperty(ZMSConsts.ZMS_PROP_PROVIDER_KEY_PATH, "");

        if (StringUtil.isEmpty(trustStore) || StringUtil.isEmpty(certPath) ||
                StringUtil.isEmpty(keyPath) || StringUtil.isEmpty(trustStorePassword)) {
            LOG.warn("ServiceProviderClient Configuration properties are missing. Providers will not be contacted when deleting domains.");
            return null;
        }
        KeyRefresher keyRefresher = Utils.generateKeyRefresher(
                trustStore,
                keyStore.getSecret(appName, trustStorePassword),
                certPath,
                keyPath);
        keyRefresher.startup();

        return Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                keyRefresher.getTrustManagerProxy());
    }

    private HttpDriver getHttpDriver(SSLContext sslContext) {

        int maxPoolRoute = Integer.parseInt(System.getProperty(ZMS_PROP_PROVIDER_MAX_POOL_ROUTE, "45"));
        int maxPoolTotal = Integer.parseInt(System.getProperty(ZMS_PROP_PROVIDER_MAX_POOL_TOTAL, "50"));
        int clientRetryIntervalMs = Integer.parseInt(System.getProperty(ZMS_PROP_PROVIDER_RETRY_INTERVAL_MS, "1000"));
        int clientMaxRetries = Integer.parseInt(System.getProperty(ZMS_PROP_PROVIDER_MAX_RETRIES, "2"));
        int clientConnectTimeoutMs = Integer.parseInt(System.getProperty(ZMS_PROP_PROVIDER_CONNECT_TIMEOUT_MS, "5000"));
        int clientReadTimeoutMs = Integer.parseInt(System.getProperty(ZMS_PROP_PROVIDER_READ_TIMEOUT_MS, "15000"));

        return new HttpDriver.Builder("", sslContext)
                .maxPoolPerRoute(maxPoolRoute)
                .maxPoolTotal(maxPoolTotal)
                .clientRetryIntervalMs(clientRetryIntervalMs)
                .clientMaxRetries(clientMaxRetries)
                .clientConnectTimeoutMs(clientConnectTimeoutMs)
                .clientReadTimeoutMs(clientReadTimeoutMs)
                .build();
    }

    private DomainDependencyProviderResponse getDependencyStatusFromProvider(
            ServiceProviderManager.DomainDependencyProvider domainDependencyProvider,
            String domain, String principal) throws IOException {

        DomainDependencyProviderResponse domainDependencyProviderResponse = new DomainDependencyProviderResponse();
        String url = getProviderEndpoint(domainDependencyProvider);

        HttpPost httpPost = new HttpPost(url);
        httpPost.setHeader("Content-type", "application/json");
        ProviderDependencyRequest providerDependencyRequest = new ProviderDependencyRequest(
                "delete",
                domain,
                "domain",
                domain,
                principal,
                domainDependencyProvider.getProvider()
        );
        String body = jsonMapper.writeValueAsString(providerDependencyRequest);
        StringEntity stringEntity = new StringEntity(body);
        httpPost.setEntity(stringEntity);
        HttpDriverResponse httpResponse = httpDriver.doPostHttpResponse(httpPost);
        if (httpResponse.getStatusCode() >= 500 && httpResponse.getStatusCode() <= 599) {
            // provider error - principal should retry operation
            domainDependencyProviderResponse.setStatus(PROVIDER_RESPONSE_DENY);
            domainDependencyProviderResponse.setMessage("Http Status: " + httpResponse.getStatusCode() + ", error: " + httpResponse.getMessage());
        } else if (httpResponse.getStatusCode() >= 400 && httpResponse.getStatusCode() <= 499) {
            String errorMessage = String.format("Invalid dependency status request to service provider '%s' with endpoint '%s', Received error code %d", domainDependencyProvider.getProvider(), url, httpResponse.getStatusCode());
            LOG.error(errorMessage);
            domainDependencyProviderResponse.setStatus(PROVIDER_RESPONSE_DENY);
            domainDependencyProviderResponse.setMessage(errorMessage);
        } else if (httpResponse.getStatusCode() >= 200 && httpResponse.getStatusCode() <= 299) {
            domainDependencyProviderResponse = jsonMapper.readValue(httpResponse.getMessage(), DomainDependencyProviderResponse.class);
        }
        return domainDependencyProviderResponse;
    }

    private String getProviderEndpoint(ServiceProviderManager.DomainDependencyProvider domainDependencyProvider) {
        String url = domainDependencyProvider.getProviderEndpoint();
        if (domainDependencyProvider.isInstanceProvider()) {
            if (!url.endsWith("/")) {
                url += "/";
            }
            url += "dependency-check";
        }
        return url;
    }
}
