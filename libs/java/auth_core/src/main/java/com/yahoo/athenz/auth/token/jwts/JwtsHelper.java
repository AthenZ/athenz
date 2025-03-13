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
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import com.yahoo.athenz.zts.AthenzJWKConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.source.JWKSource;

public class JwtsHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtsHelper.class);
    private static final ObjectMapper JSON_MAPPER = initJsonMapper();

    public static final String TYPE_JWT    = "jwt";
    public static final String TYPE_AT_JWT = "at+jwt";

    public static final Set<JWSAlgorithm> JWS_SUPPORTED_ALGORITHMS = Set.of(
            JWSAlgorithm.RS256,
            JWSAlgorithm.RS384,
            JWSAlgorithm.RS512,
            JWSAlgorithm.ES256,
            JWSAlgorithm.ES384,
            JWSAlgorithm.ES512
    );

    public static final DefaultJOSEObjectTypeVerifier<SecurityContext> JWT_TYPE_VERIFIER =
            new DefaultJOSEObjectTypeVerifier<>(
                new JOSEObjectType(TYPE_AT_JWT),
                new JOSEObjectType(TYPE_JWT),
                null);

    public static ObjectMapper initJsonMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }

    public String extractJwksUri(final String openIdConfigUri, final SSLContext sslContext) {
        return extractJwksUri(openIdConfigUri, sslContext, null);
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

    String getHttpData(final String serverUri, final SSLContext sslContext, final String proxyUrl) {

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
                String line = br.readLine();
                while (line != null) {
                    sb.append(line);
                    line = br.readLine();
                }

                return sb.toString();
            }
        } catch (Exception ex) {
            LOGGER.error("Unable to get http data from {} error: {}", serverUri, ex.getMessage());
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

    public static JWSSigner getJWSSigner(PrivateKey privateKey) throws JOSEException {
        switch (privateKey.getAlgorithm()) {
            case Crypto.RSA:
                return new RSASSASigner(privateKey);
            case Crypto.EC:
            case Crypto.ECDSA:
                return new ECDSASigner((ECPrivateKey) privateKey);
        }
        throw new JOSEException("Unsupported algorithm: " + privateKey.getAlgorithm());
    }

    public static JWSVerifier getJWSVerifier(PublicKey publicKey) throws JOSEException {
        switch (publicKey.getAlgorithm()) {
            case Crypto.RSA:
                return new RSASSAVerifier((RSAPublicKey) publicKey);
            case Crypto.EC:
            case Crypto.ECDSA:
                return new ECDSAVerifier((ECPublicKey) publicKey);
        }
        throw new JOSEException("Unsupported algorithm: " + publicKey.getAlgorithm());
    }

    public static JWSVerifier getJWSVerifier(byte[] secret) throws JOSEException {
        return new MACVerifier(secret);
    }

    public static ConfigurableJWTProcessor<SecurityContext> getJWTProcessor(JwtsSigningKeyResolver keyResolver) {

        // we're going to allow all possible types of tokens
        // at+jwt, jwt, and null (typ not specified, e.g. id tokens)

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSTypeVerifier(JWT_TYPE_VERIFIER);

        jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(JwtsHelper.JWS_SUPPORTED_ALGORITHMS,
                keyResolver.getKeySource()));
        return jwtProcessor;
    }

    public static int getIntegerClaim(JWTClaimsSet claims, final String claim, int defaultValue) {
        try {
            Integer value = claims.getIntegerClaim(claim);
            return value == null ? defaultValue : value;
        } catch (ParseException ex) {
            return defaultValue;
        }
    }

    public static long getLongClaim(JWTClaimsSet claims, final String claim, long defaultValue) {
        try {
            Long value = claims.getLongClaim(claim);
            return value == null ? defaultValue : value;
        } catch (ParseException ex) {
            return defaultValue;
        }
    }

    public static String getStringClaim(JWTClaimsSet claims, final String claim) {
        try {
            return claims.getStringClaim(claim);
        } catch (ParseException e) {
            return null;
        }
    }

    public static List<String> getStringListClaim(JWTClaimsSet claims, final String claim) {
        try {
            return claims.getStringListClaim(claim);
        } catch (ParseException e) {
            return null;
        }
    }

    public static String getAudience(JWTClaimsSet claims) {
        List<String> audiences = claims.getAudience();
        if (audiences == null || audiences.isEmpty()) {
            return null;
        }
        return audiences.get(0);
    }

    public static JWTClaimsSet parseJWTWithoutSignature(final String token) {

        try {
            Base64URL[] parts = JOSEObject.split(token);
            if (parts.length != 3 || !parts[2].toString().isEmpty()) {
                throw new CryptoException("Token has a signature but no key resolver");
            }
            return JWTClaimsSet.parse(parts[1].decodeToString());
        } catch (ParseException ex) {
            throw new CryptoException("Unable to parse token: " + ex.getMessage());
        }
    }

    public static class CompositeJWKSource<C extends SecurityContext> implements JWKSource<C> {

        private final List<JWKSource<C>> keySources;

        public CompositeJWKSource() {
            this.keySources = new ArrayList<>();
        }

        public void addKeySource(JWKSource<C> keySource) {
            keySources.add(keySource);
        }

        @Override
        public List<JWK> get(JWKSelector selector, C context) throws KeySourceException {
            for (JWKSource<C> keySource : keySources) {
                try {
                    List<JWK> jwks = keySource.get(selector, context);
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("key-source {} match set: {}", keySource, jwks);
                    }
                    if (jwks != null && !jwks.isEmpty()) {
                        return jwks;
                    }
                } catch (Exception ex) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Unable to process key source: {}, {}/{}", keySource, ex.getClass(), ex.getMessage());
                    }
                }
            }
            return null;
        }
    }

    public static class SiaJwkResourceRetriever implements ResourceRetriever {

        @Override
        public Resource retrieveResource(URL url) {

            try {
                Path path = Paths.get(url.getPath());
                if (!path.toFile().exists()) {
                    LOGGER.info("conf file {} does not exist", url.getPath());
                    return null;
                }

                AthenzJWKConfig jwkConf = JSON_MAPPER.readValue(Files.readAllBytes(path), AthenzJWKConfig.class);
                final String keysJson = "{\"keys\":" + JSON_MAPPER.writeValueAsString(jwkConf.zts.getKeys()) + "}";
                return new Resource(keysJson, "application/json");

            } catch (Exception ex) {
                LOGGER.error("Unable to extract athenz jwk config {}", url.getPath(), ex);
            }
            return null;
        }
    }
}
