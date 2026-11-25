/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.pdp.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.pdp.ExternalPdpContext;
import com.yahoo.athenz.common.server.pdp.ExternalPdpException;
import com.yahoo.athenz.common.server.pdp.ExternalPdpSupport;
import com.yahoo.athenz.common.server.pdp.ExternalPolicyDecisionPoint;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationRequest;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationResponse;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsRequest;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * Built-in PDP that speaks the AuthZEN Authorization API over HTTPS with
 * mTLS. Capability properties allow the use of PDPs that implement only
 * the single Access Evaluation endpoint.
 */
public class AuthZenHttpPdp implements ExternalPolicyDecisionPoint {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthZenHttpPdp.class);

    static final String PROP_PREFIX = "athenz.zts.external_pdp.https.";
    static final String PROP_BATCH_ENABLED = PROP_PREFIX + "batch_enabled";
    static final String PROP_EVALUATIONS_PATH = PROP_PREFIX + "evaluations_path";
    static final String PROP_EVALUATION_PATH = PROP_PREFIX + "evaluation_path";
    static final String PROP_DISCOVERY = PROP_PREFIX + "discovery";
    static final String PROP_MAX_RESPONSE_BYTES = PROP_PREFIX + "max_response_bytes";
    static final String PROP_AUTH_HEADER_NAME = PROP_PREFIX + "auth_header_name";
    static final String PROP_AUTH_HEADER_PREFIX = PROP_PREFIX + "auth_header_prefix";
    static final String PROP_AUTH_SECRET_APP_NAME = PROP_PREFIX + "auth_secret_app_name";
    static final String PROP_AUTH_SECRET_KEYGROUP_NAME = PROP_PREFIX + "auth_secret_keygroup_name";
    static final String PROP_AUTH_SECRET_KEY_NAME = PROP_PREFIX + "auth_secret_key_name";
    static final String PROP_AUTH_SECRET_REFRESH_SECS = PROP_PREFIX + "auth_secret_refresh_secs";

    static final String DEFAULT_EVALUATIONS_PATH = "/access/v1/evaluations";
    static final String DEFAULT_EVALUATION_PATH = "/access/v1/evaluation";
    static final String DISCOVERY_PATH = "/.well-known/authzen-configuration";

    static final String META_EVALUATION_ENDPOINT = "access_evaluation_endpoint";
    static final String META_EVALUATIONS_ENDPOINT = "access_evaluations_endpoint";

    static final String HDR_REQUEST_ID = "X-Request-ID";
    static final String CONTEXT_REQUEST_ID = "request_id";

    private static final String SCHEME_HTTPS = "https";
    private static final int DEFAULT_HTTPS_PORT = 443;
    private static final int DEFAULT_MAX_RESPONSE_BYTES = 65536;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AuthZenHttpClient client;
    private ExecutorService executor;
    private String evaluationUrl;
    private String evaluationsUrl;
    private boolean batchEnabled;

    private PrivateKeyStore privateKeyStore;
    private String authHeaderName;
    private String authHeaderPrefix;
    private long authSecretRefreshMs;
    private volatile String authHeaderValue;
    private volatile long authSecretFetchTime;
    LongSupplier clock = System::currentTimeMillis;

    @Override
    public void initialize(final ExternalPdpContext context) throws ExternalPdpException {

        final URI baseUri = parseEndpoint(context.getEndpoint());
        final String baseUrl = stripTrailingSlash(context.getEndpoint());

        final int maxResponseBytes = Integer.parseInt(System.getProperty(PROP_MAX_RESPONSE_BYTES,
                Integer.toString(DEFAULT_MAX_RESPONSE_BYTES)));
        client = createClient(context, maxResponseBytes);
        executor = context.getExecutor();

        initializeAuthHeader(context.getPrivateKeyStore());

        Map<String, Object> metadata = Boolean.parseBoolean(System.getProperty(PROP_DISCOVERY, "false"))
                ? discover(baseUrl, baseUri) : Collections.emptyMap();

        evaluationUrl = resolveUrl(baseUrl, PROP_EVALUATION_PATH, DEFAULT_EVALUATION_PATH,
                metadata.get(META_EVALUATION_ENDPOINT));
        evaluationsUrl = resolveUrl(baseUrl, PROP_EVALUATIONS_PATH, DEFAULT_EVALUATIONS_PATH,
                metadata.get(META_EVALUATIONS_ENDPOINT));

        batchEnabled = resolveCapability(PROP_BATCH_ENABLED, true, metadata, META_EVALUATIONS_ENDPOINT);

        LOGGER.info("AuthZEN PDP initialized: endpoint={}, batch={}, discovery={}",
                baseUrl, batchEnabled, !metadata.isEmpty());
    }

    AuthZenHttpClient createClient(final ExternalPdpContext context, int maxResponseBytes) {
        return new AuthZenHttpClient(context.getSslContext(), context.getConnectTimeoutMs(),
                context.getReadTimeoutMs(), context.getMaxConnections(), maxResponseBytes);
    }

    static URI parseEndpoint(final String endpoint) throws ExternalPdpException {
        URI uri;
        try {
            uri = new URI(endpoint);
        } catch (URISyntaxException | NullPointerException ex) {
            throw new ExternalPdpException(ExternalPdpException.Code.INTERNAL, "invalid pdp endpoint", ex);
        }
        if (!SCHEME_HTTPS.equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            throw new ExternalPdpException(ExternalPdpException.Code.INTERNAL,
                    "pdp endpoint must be an https url with a host");
        }
        return uri;
    }

    static String stripTrailingSlash(final String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    Map<String, Object> discover(final String baseUrl, final URI baseUri) throws ExternalPdpException {
        final String body = client.getJson(baseUrl + DISCOVERY_PATH, requestHeaders(null));
        Map<String, Object> metadata = parse(body, Map.class);
        Map<String, Object> endpoints = new HashMap<>();
        for (String key : new String[] { META_EVALUATION_ENDPOINT, META_EVALUATIONS_ENDPOINT }) {
            Object value = metadata.get(key);
            if (value == null) {
                continue;
            }
            verifySameOrigin(baseUri, value.toString());
            endpoints.put(key, value.toString());
        }
        return endpoints;
    }

    static void verifySameOrigin(final URI baseUri, final String url) throws ExternalPdpException {
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException ex) {
            throw new ExternalPdpException(ExternalPdpException.Code.INVALID_RESPONSE,
                    "invalid discovered pdp endpoint", ex);
        }
        if (!SCHEME_HTTPS.equalsIgnoreCase(uri.getScheme()) || !baseUri.getHost().equalsIgnoreCase(uri.getHost())
                || effectivePort(baseUri) != effectivePort(uri)) {
            throw new ExternalPdpException(ExternalPdpException.Code.INVALID_RESPONSE,
                    "discovered pdp endpoint does not match the configured origin");
        }
    }

    static int effectivePort(final URI uri) {
        return uri.getPort() == -1 ? DEFAULT_HTTPS_PORT : uri.getPort();
    }

    static String resolveUrl(final String baseUrl, final String pathProperty, final String defaultPath,
            final Object discoveredUrl) {
        final String path = System.getProperty(pathProperty);
        if (path != null) {
            return baseUrl + path;
        }
        return discoveredUrl != null ? discoveredUrl.toString() : baseUrl + defaultPath;
    }

    static boolean resolveCapability(final String property, boolean defaultValue, final Map<String, Object> metadata,
            final String metadataKey) {
        final String value = System.getProperty(property);
        if (value != null) {
            return Boolean.parseBoolean(value);
        }
        return metadata.isEmpty() ? defaultValue : metadata.containsKey(metadataKey);
    }

    void initializeAuthHeader(final PrivateKeyStore keyStore) throws ExternalPdpException {
        authHeaderName = System.getProperty(PROP_AUTH_HEADER_NAME);
        if (authHeaderName == null || authHeaderName.isEmpty()) {
            authHeaderName = null;
            return;
        }
        if (keyStore == null) {
            throw new ExternalPdpException(ExternalPdpException.Code.INTERNAL,
                    "pdp auth header requires a private key store");
        }
        privateKeyStore = keyStore;
        authHeaderPrefix = System.getProperty(PROP_AUTH_HEADER_PREFIX, "");
        authSecretRefreshMs = TimeUnit.SECONDS.toMillis(Long.parseLong(
                System.getProperty(PROP_AUTH_SECRET_REFRESH_SECS, "3600")));
        authHeaderValue = fetchAuthHeaderValue();
        if (authHeaderValue == null) {
            throw new ExternalPdpException(ExternalPdpException.Code.INTERNAL,
                    "unable to retrieve pdp auth secret");
        }
        authSecretFetchTime = clock.getAsLong();
    }

    String fetchAuthHeaderValue() {
        char[] secret = privateKeyStore.getSecret(System.getProperty(PROP_AUTH_SECRET_APP_NAME),
                System.getProperty(PROP_AUTH_SECRET_KEYGROUP_NAME), System.getProperty(PROP_AUTH_SECRET_KEY_NAME));
        if (secret == null || secret.length == 0) {
            return null;
        }
        return authHeaderPrefix + new String(secret);
    }

    String currentAuthHeaderValue() {
        final long now = clock.getAsLong();
        if (now - authSecretFetchTime >= authSecretRefreshMs) {
            String value;
            try {
                value = fetchAuthHeaderValue();
            } catch (RuntimeException ex) {
                LOGGER.error("Unable to refresh pdp auth secret: {}", ex.getMessage());
                value = null;
            }
            if (value != null) {
                authHeaderValue = value;
            } else {
                LOGGER.error("Unable to refresh pdp auth secret, using the previous value");
            }
            authSecretFetchTime = now;
        }
        return authHeaderValue;
    }

    Map<String, String> requestHeaders(final Map<String, Object> context) {
        Map<String, String> headers = new HashMap<>();
        Object requestId = context == null ? null : context.get(CONTEXT_REQUEST_ID);
        headers.put(HDR_REQUEST_ID, requestId instanceof String ? (String) requestId : UUID.randomUUID().toString());
        if (authHeaderName != null) {
            headers.put(authHeaderName, currentAuthHeaderValue());
        }
        return headers;
    }

    @Override
    public EvaluationResponse evaluate(final EvaluationRequest request) throws ExternalPdpException {
        return post(evaluationUrl, request, request.getContext(), EvaluationResponse.class);
    }

    @Override
    public EvaluationsResponse evaluations(final EvaluationsRequest request) throws ExternalPdpException {
        if (!batchEnabled) {
            return ExternalPdpSupport.expandBatch(this, request, executor);
        }
        return post(evaluationsUrl, request, request.getContext(), EvaluationsResponse.class);
    }

    <T> T post(final String url, final Object request, final Map<String, Object> context, final Class<T> type)
            throws ExternalPdpException {
        String body;
        try {
            body = MAPPER.writeValueAsString(request);
        } catch (JsonProcessingException ex) {
            throw new ExternalPdpException(ExternalPdpException.Code.INTERNAL, "unable to serialize pdp request", ex);
        }
        return parse(client.postJson(url, body, requestHeaders(context)), type);
    }

    static <T> T parse(final String body, final Class<T> type) throws ExternalPdpException {
        T value;
        try {
            value = MAPPER.readValue(body, type);
        } catch (JsonProcessingException ex) {
            throw new ExternalPdpException(ExternalPdpException.Code.INVALID_RESPONSE, "unable to parse pdp response", ex);
        }
        if (value == null) {
            throw new ExternalPdpException(ExternalPdpException.Code.INVALID_RESPONSE, "empty pdp response");
        }
        return value;
    }

    @Override
    public void close() {
        if (client != null) {
            client.close();
        }
    }

    boolean isBatchEnabled() {
        return batchEnabled;
    }

    String getEvaluationUrl() {
        return evaluationUrl;
    }

    String getEvaluationsUrl() {
        return evaluationsUrl;
    }
}
