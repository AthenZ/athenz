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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;

import com.nimbusds.jose.util.ResourceRetriever;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.net.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.auth.AuthorityConsts.AUTH_PROP_MILLIS_BETWEEN_ZTS_CALLS;

public class JwtsSigningKeyResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtsSigningKeyResolver.class);

    public static final String ZTS_PROP_ATHENZ_CONF           = "athenz.athenz_conf";
    public static final String ZTS_PROP_JWK_ATHENZ_CONF       = "athenz.jwk_athenz_conf";
    public static final String ZTS_PROP_JWK_CONNECT_TIMEOUT   = "athenz.auth.jwk_connect_timeout";
    public static final String ZTS_PROP_JWK_READ_TIMEOUT      = "athenz.auth.jwk_read_timeout";
    private static final String ZTS_DEFAULT_ATHENZ_CONFIG     = "/conf/athenz/athenz.conf";
    private static final String ZTS_DEFAULT_JWK_ATHENZ_CONFIG = "/var/lib/sia/athenz.conf";

    private static final ObjectMapper JSON_MAPPER = JwtsHelper.initJsonMapper();
    JwtsHelper.CompositeJWKSource<SecurityContext> keySource;
    private int jwkConnectTimeout;
    private int jwkReadTimeout;
    private long millisBetweenZtsCalls;

    public JwtsSigningKeyResolver(final String jwksUri, final SSLContext sslContext) {
        createKeyResolver(jwksUri, sslContext, null, false);
    }

    public JwtsSigningKeyResolver(final String jwksUri, final SSLContext sslContext, final String proxyUrl) {
        createKeyResolver(jwksUri, sslContext, proxyUrl, false);
    }

    public JwtsSigningKeyResolver(final String jwksUri, final SSLContext sslContext, boolean skipConfig) {
        createKeyResolver(jwksUri, sslContext, null, skipConfig);
    }

    public JwtsSigningKeyResolver(final String jwksUri, final SSLContext sslContext, final String proxyUrl, boolean skipConfig) {
        createKeyResolver(jwksUri, sslContext, proxyUrl, skipConfig);
    }

    public JwtsSigningKeyResolver(List<JwtsResolver> resolvers, boolean skipConfig)  {

        if (resolvers == null || resolvers.isEmpty()) {
            throw new CryptoException("At least one resolver must be specified");
        }

        // first create a resolver for the primary key source entry

        JwtsResolver jwtsResolver = resolvers.get(0);
        createKeyResolver(jwtsResolver.getJwksUri(), jwtsResolver.getSslContext(), jwtsResolver.getProxyUrl(), skipConfig);

        // iterate through the rest of the entries and add
        // them as additional key sources

        for (int i = 1; i < resolvers.size(); i++) {
            jwtsResolver = resolvers.get(i);
            addJwksUriKeySource(jwtsResolver.getJwksUri(), jwtsResolver.getProxyUrl(), jwtsResolver.getSslContext());
        }
    }

    private void createKeyResolver(final String jwksUri, final SSLContext sslContext, final String proxyUrl, boolean skipConfig) {

        // our jwks uri is required

        if (jwksUri == null || jwksUri.isEmpty()) {
            throw new CryptoException("Jwks uri must be specified");
        }

        // extract our configuration settings

        millisBetweenZtsCalls = Long.parseLong(System.getProperty(AUTH_PROP_MILLIS_BETWEEN_ZTS_CALLS, "86400000"));
        jwkConnectTimeout = Integer.parseInt(System.getProperty(ZTS_PROP_JWK_CONNECT_TIMEOUT, "10000"));
        jwkReadTimeout = Integer.parseInt(System.getProperty(ZTS_PROP_JWK_READ_TIMEOUT, "20000"));

        // create our key source list

        keySource = new JwtsHelper.CompositeJWKSource<>();

        if (!skipConfig) {

            // if not disabled, then we need to add our local jwks
            // file which is auto-updated by the service identity
            // agent running in the workload as a key source

            loadSiaConfAsKeySource();

            // for backward compatibility we're going to keep the
            // old athenz conf file as a key source as well

            loadAthenzConfAsKeySource();
        }

        addJwksUriKeySource(jwksUri, proxyUrl, sslContext);
    }

    void addJwksUriKeySource(final String jwksUri, final String proxyUrl, final SSLContext sslContext) {
        ResourceRetriever resourceRetriever = getResourceRetriever(proxyUrl, sslContext);
        addKeySource(jwksUri, resourceRetriever);
    }

    ResourceRetriever getResourceRetriever(final String proxyUrl, SSLContext sslContext) {

        DefaultResourceRetriever resourceRetriever;
        if (sslContext != null) {
            resourceRetriever = new DefaultResourceRetriever(jwkConnectTimeout, jwkReadTimeout, 0, true,
                    sslContext.getSocketFactory());
        } else {
            resourceRetriever = new DefaultResourceRetriever(jwkConnectTimeout, jwkReadTimeout);
        }

        // check to see if we have an http proxy url specified,
        // and if we do then we need to set the proxy for our
        // resource retriever

        if (proxyUrl != null && !proxyUrl.isEmpty()) {
            final URI uri = URI.create(proxyUrl);
            SocketAddress addr = new InetSocketAddress(uri.getHost(), uri.getPort());
            resourceRetriever.setProxy(new Proxy(Proxy.Type.HTTP, addr));
        }

        return resourceRetriever;
    }

    void addKeySource(final String jwksUri, ResourceRetriever resourceRetriever) {

        try {
            JWKSource<SecurityContext> jwksUriKeySource = JWKSourceBuilder
                    .create(new URL(jwksUri), resourceRetriever)
                    .cache(TimeUnit.DAYS.toMillis(7), TimeUnit.DAYS.toMillis(1))
                    .rateLimited(millisBetweenZtsCalls)
                    .outageTolerantForever()
                    .retrying(true)
                    .build();

            keySource.addKeySource(jwksUriKeySource);

        } catch (MalformedURLException ex) {
            LOGGER.error("Invalid jwks uri: {}", jwksUri);
            throw new CryptoException("Invalid jwks uri: " + jwksUri);
        }
    }

    public JWKSource<SecurityContext> getKeySource() {
        return keySource;
    }

    public void setMillisBetweenZtsCalls(long millis) {
        millisBetweenZtsCalls = millis;
    }

    void loadAthenzConfAsKeySource() {

        String rootDir = System.getenv("ROOT");
        if (rootDir == null) {
            rootDir = "/home/athenz";
        }

        final String confFileName = System.getProperty(ZTS_PROP_ATHENZ_CONF,
                rootDir + ZTS_DEFAULT_ATHENZ_CONFIG);

        Path path = Paths.get(confFileName);
        if (!path.toFile().exists()) {
            LOGGER.info("Conf file {} does not exist", confFileName);
            return;
        }

        AthenzConfig conf;
        try {
            conf = JSON_MAPPER.readValue(Files.readAllBytes(path), AthenzConfig.class);
            final ArrayList<ZTSPublicKey> ztsPublicKeys = conf.getZtsPublicKeys();
            List<JWK> jwkList = new ArrayList<>();
            if (ztsPublicKeys != null) {
                for (ZTSPublicKey ztsPublicKey : ztsPublicKeys) {
                    final String id = ztsPublicKey.getId();
                    final String key = ztsPublicKey.getKey();
                    if (key == null || id == null) {
                        LOGGER.error("Missing required zts public key attributes: {}/{}", id, key);
                        continue;
                    }
                    PublicKey publicKey = Crypto.loadPublicKey(Crypto.ybase64DecodeString(key));
                    if (publicKey != null) {
                        if (Crypto.RSA.equals(publicKey.getAlgorithm())) {
                            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey).keyID(id).build();
                            jwkList.add(rsaKey);
                        } else {
                            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
                            ECKey ecKey = new ECKey.Builder(Curve.forECParameterSpec(ecPublicKey.getParams()), ecPublicKey)
                                    .keyID(id).build();
                            jwkList.add(ecKey);
                        }
                    }
                }
            }
            if (jwkList.isEmpty()) {
                LOGGER.error("No valid public json web keys in conf file: {}", confFileName);
            } else {
                JWKSet jwkSet = new JWKSet(jwkList);
                ImmutableJWKSet<SecurityContext> immutableJWKSet = new ImmutableJWKSet<>(jwkSet);
                keySource.addKeySource(immutableJWKSet);
            }
        } catch (IOException ex) {
            LOGGER.error("Unable to parse conf file {}, error: {}", confFileName, ex.getMessage());
        }
    }

    void loadSiaConfAsKeySource() {

        final String jwkConfFileName = System.getProperty(ZTS_PROP_JWK_ATHENZ_CONF, ZTS_DEFAULT_JWK_ATHENZ_CONFIG);
        File jwksFile = new File(jwkConfFileName);
        if (!jwksFile.exists()) {
            LOGGER.info("jwks athenz conf file {} does not exist", jwkConfFileName);
            return;
        }

        addKeySource("file://" + jwkConfFileName, new JwtsHelper.SiaJwkResourceRetriever());
    }

    public PublicKey getPublicKey(final String keyId) {
        List<JWK> jwks = null;
        try {
            jwks = keySource.get(new JWKSelector(new JWKMatcher.Builder().keyID(keyId).build()), null);
        } catch (KeySourceException ex) {
            LOGGER.error("Unable to retrieve public key for id: {}: {}", keyId, ex.getMessage());
        }
        if (jwks == null || jwks.isEmpty()) {
            LOGGER.error("No public key found for id: {}", keyId);
            return null;
        }
        JWK jwk = jwks.get(0);
        try {
            KeyType keyType = jwk.getKeyType();
            if (keyType.equals(KeyType.RSA)) {
                return jwk.toRSAKey().toRSAPublicKey();
            } else if (keyType.equals(KeyType.EC)) {
                return jwk.toECKey().toECPublicKey();
            } else {
                LOGGER.error("Unsupported key type: {}", jwk.getKeyType());
            }
        } catch (Exception ex) {
            LOGGER.error("Unable to extract public key for id: {}: {}", keyId, ex.getMessage());
        }
        return null;
    }

    static class ZTSPublicKey {
        private String id;
        private String key;

        public String getId() {
            return id;
        }
        public void setId(String id) {
            this.id = id;
        }
        public String getKey() {
            return key;
        }
        public void setKey(String key) {
            this.key = key;
        }
    }

    static class AthenzConfig {
        private ArrayList<ZTSPublicKey> ztsPublicKeys;

        public ArrayList<ZTSPublicKey> getZtsPublicKeys() {
            return ztsPublicKeys;
        }
        public void setZtsPublicKeys(ArrayList<ZTSPublicKey> ztsPublicKeys) {
            this.ztsPublicKeys = ztsPublicKeys;
        }
    }
}
