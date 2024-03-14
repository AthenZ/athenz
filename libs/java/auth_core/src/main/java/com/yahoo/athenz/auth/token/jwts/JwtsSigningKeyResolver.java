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
import com.yahoo.athenz.auth.util.Crypto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import static com.yahoo.athenz.auth.AuthorityConsts.AUTH_PROP_MILLIS_BETWEEN_ZTS_CALLS;

public class JwtsSigningKeyResolver implements SigningKeyResolver {

    public static final String ZTS_PROP_ATHENZ_CONF           = "athenz.athenz_conf";
    public static final String ZTS_PROP_JWK_ATHENZ_CONF       = "athenz.jwk_athenz_conf";
    private static final String ZTS_DEFAULT_ATHENZ_CONFIG     = "/conf/athenz/athenz.conf";
    private static final String ZTS_DEFAULT_JWK_ATHENZ_CONFIG = "/var/lib/sia/athenz.conf";
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtsSigningKeyResolver.class);
    private static final ObjectMapper JSON_MAPPER = initJsonMapper();
    private final SSLContext sslContext;
    private final String jwksUri;
    private final String proxyUrl;
    private static long lastZtsJwkFetchTime;
    private static long millisBetweenZtsCalls;

    ConcurrentHashMap<String, PublicKey> publicKeys;

    static {
        setMillisBetweenZtsCalls(Long.parseLong(System.getProperty(AUTH_PROP_MILLIS_BETWEEN_ZTS_CALLS, "86400000")));
    }

    static ObjectMapper initJsonMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }

    public JwtsSigningKeyResolver(final String jwksUri, final SSLContext sslContext) {
        this(jwksUri, sslContext, false);
    }

    public JwtsSigningKeyResolver(final String jwksUri, final SSLContext sslContext, final String proxyUrl) {
        this(jwksUri, sslContext, proxyUrl, false);
    }

    public JwtsSigningKeyResolver(final String jwksUri, final SSLContext sslContext, boolean skipConfig) {
        this(jwksUri, sslContext, null, skipConfig);
    }

    public JwtsSigningKeyResolver(final String jwksUri, final SSLContext sslContext, final String proxyUrl, boolean skipConfig) {
        this.jwksUri = jwksUri;
        this.sslContext = sslContext;
        this.publicKeys = new ConcurrentHashMap<>();
        this.proxyUrl = proxyUrl;
        if (!skipConfig) {
            loadPublicKeysFromConfig();
            loadJwksFromConfig();
        }
        lastZtsJwkFetchTime = System.currentTimeMillis();
        loadPublicKeysFromServer();
    }

    public String getJwksUri() {
        return jwksUri;
    }

    @Override
    public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
        return resolveSigningKey(jwsHeader);
    }

    @Override
    public Key resolveSigningKey(JwsHeader jwsHeader, String body) {
        return resolveSigningKey(jwsHeader);
    }

    private Key resolveSigningKey(JwsHeader jwsHeader) {
        return getPublicKey(jwsHeader.getKeyId());
    }

    public static void setMillisBetweenZtsCalls(long millis) {
        millisBetweenZtsCalls = millis;
    }

    public static boolean canFetchLatestJwksFromZts() {
        long now = System.currentTimeMillis();
        long millisDiff = now - lastZtsJwkFetchTime;
        return millisDiff > millisBetweenZtsCalls;
    }

    public PublicKey getPublicKey(String keyId) {
        PublicKey key = publicKeys.get(keyId);

        if (key == null && canFetchLatestJwksFromZts()) {
            lastZtsJwkFetchTime = System.currentTimeMillis();
            loadPublicKeysFromServer();
            key = publicKeys.get(keyId);
        }

        return key;
    }

    public void addPublicKey(final String keyId, final PublicKey publicKey) {
        publicKeys.put(keyId, publicKey);
    }

    public int publicKeyCount() {
        return publicKeys.size();
    }

    public void loadPublicKeysFromServer() {

        final String jwksData = getHttpData(jwksUri, sslContext, proxyUrl);
        if (jwksData == null) {
            return;
        }

        try {
            Keys keys = JSON_MAPPER.readValue(jwksData, Keys.class);
            for (com.yahoo.athenz.auth.token.jwts.Key key : keys.getKeys()) {
                try {
                    publicKeys.put(key.getKid(), key.getPublicKey());
                } catch (Exception ex) {
                    LOGGER.error("Unable to generate json web key for key-id {}", key.getKid());
                }
            }
        } catch (Exception ex) {
            LOGGER.error("Unable to extract json web keys from {}", jwksUri, ex);
        }
    }
    
    String getHttpData(final String jwksUri, final SSLContext sslContext, final String proxyUrl) {
        JwtsHelper jwtsHelper = new JwtsHelper();
        return jwtsHelper.getHttpData(jwksUri, sslContext, proxyUrl);
    }

    void loadPublicKeysFromConfig() {

        String rootDir = System.getenv("ROOT");
        if (rootDir == null) {
            rootDir = "/home/athenz";
        }

        final String confFileName = System.getProperty(ZTS_PROP_ATHENZ_CONF,
                rootDir + ZTS_DEFAULT_ATHENZ_CONFIG);

        Path path = Paths.get(confFileName);
        if (!path.toFile().exists()) {
            LOGGER.info("conf file {} does not exist", confFileName);
            return;
        }

        AthenzConfig conf;
        try {
            conf = JSON_MAPPER.readValue(Files.readAllBytes(path), AthenzConfig.class);
            final ArrayList<ZTSPublicKey> ztsPublicKeys = conf.getZtsPublicKeys();
            if (ztsPublicKeys == null) {
                LOGGER.error("Conf file {} has no json web keys", confFileName);
                return;
            }
            for (ZTSPublicKey publicKey : ztsPublicKeys) {
                final String id = publicKey.getId();
                final String key = publicKey.getKey();
                if (key == null || id == null) {
                    LOGGER.error("Missing required zts public key attributes: {}/{}", id, key);
                    continue;
                }
                publicKeys.put(id, Crypto.loadPublicKey(Crypto.ybase64DecodeString(key)));
            }
            if (publicKeys.isEmpty()) {
                LOGGER.error("No valid public json web keys in conf file: {}", confFileName);
            }
        } catch (IOException ex) {
            LOGGER.error("Unable to parse conf file {}, error: {}", confFileName, ex.getMessage());
        }
    }

    private void loadJwksFromConfig() {

        String jwkConfFileName = System.getProperty(ZTS_PROP_JWK_ATHENZ_CONF, ZTS_DEFAULT_JWK_ATHENZ_CONFIG);
        try {
            Path path = Paths.get(jwkConfFileName);
            if (!path.toFile().exists()) {
                LOGGER.info("conf file {} does not exist", jwkConfFileName);
                return;
            }

            AthenzJWKConfig jwkConf = JSON_MAPPER.readValue(Files.readAllBytes(path), AthenzJWKConfig.class);
            for (com.yahoo.athenz.auth.token.jwts.Key key : jwkConf.zts.keys) {
                try {
                    publicKeys.put(key.getKid(), key.getPublicKey());
                } catch (Exception ex) {
                    LOGGER.warn("failed to load jwk id: {}", key.getKid(), ex);
                }
            }
        } catch (Exception ex) {
            LOGGER.error("Unable to extract athenz jwk config {}", jwkConfFileName, ex);
        }
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

    static class JWKList {
        List<com.yahoo.athenz.auth.token.jwts.Key> keys;

        public void setKeys(List<com.yahoo.athenz.auth.token.jwts.Key> keys) {
            this.keys = keys;
        }
    }
    static class AthenzJWKConfig {
        JWKList zts;
        public void setZts(JWKList zts) {
            this.zts = zts;
        }
    }
}
