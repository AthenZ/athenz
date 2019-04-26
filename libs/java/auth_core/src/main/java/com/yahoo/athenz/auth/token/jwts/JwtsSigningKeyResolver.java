/*
 * Copyright 2019 Oath Holdings Inc.
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

import com.yahoo.athenz.auth.util.Crypto;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

public class JwtsSigningKeyResolver implements SigningKeyResolver {

    public static final String ZTS_PROP_ATHENZ_CONF = "athenz.athenz_conf";

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtsSigningKeyResolver.class);
    private static final ObjectMapper JSON_MAPPER = initJsonMapper();

    ConcurrentHashMap<String, PublicKey> publicKeys;

    static ObjectMapper initJsonMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }

    public JwtsSigningKeyResolver(final String serverUrl, final SSLContext sslContext) {
        publicKeys = new ConcurrentHashMap<>();
        loadPublicKeysFromConfig();
        loadPublicKeysFromServer(serverUrl, sslContext);
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
        return publicKeys.get(jwsHeader.getKeyId());
    }

    public void addPublicKey(final String keyId, final PublicKey publicKey) {
        publicKeys.put(keyId, publicKey);
    }

    void loadPublicKeysFromServer(final String serverUrl, final SSLContext sslContext) {

        if (serverUrl == null || serverUrl.isEmpty()) {
            LOGGER.info("No URL specified to fetch Json Web Keys");
            return;
        }

        try {
            HttpsURLConnection con = getConnection(serverUrl);
            con.setRequestMethod("GET");
            con.setRequestProperty("Accept", "application/json");
            con.setReadTimeout(15000);
            con.setDoOutput(true);
            SSLSocketFactory sslSocketFactory = getSocketFactory(sslContext);
            if (sslSocketFactory != null) {
                con.setSSLSocketFactory(sslSocketFactory);
            }
            con.connect();

            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                LOGGER.error("Unable to extract json web keys from {} error: {}", serverUrl,
                        con.getResponseCode());
                return;
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

                Keys keys = JSON_MAPPER.readValue(sb.toString(), Keys.class);
                for (com.yahoo.athenz.auth.token.jwts.Key key : keys.getKeys()) {
                    try {
                        publicKeys.put(key.getKid(), key.getPublicKey());
                    } catch (Exception ex) {
                        LOGGER.error("Unable to generate json web key for key-id {}", key.getKid());
                    }
                }
            }
        } catch (Exception ex) {
            LOGGER.error("Unable to extract json web keys from {} error: {}", serverUrl, ex.getMessage());
        }
    }

    ///CLOVER:OFF
    SSLSocketFactory getSocketFactory(SSLContext sslContext) {
        return (sslContext == null) ? null : sslContext.getSocketFactory();
    }
    ///CLOVER:ON

    HttpsURLConnection getConnection(final String serverUrl) throws IOException {
        return (HttpsURLConnection) new URL(serverUrl).openConnection();
    }

    void loadPublicKeysFromConfig() {

        final String confFileName = System.getProperty(ZTS_PROP_ATHENZ_CONF);
        if (confFileName == null || confFileName.isEmpty()) {
            LOGGER.info("No conf file configured for json web keys");
            return;
        }
        Path path = Paths.get(confFileName);
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
            if (publicKeys.size() == 0) {
                LOGGER.error("No valid public json web keys in conf file: {}", confFileName);
                return;
            }
        } catch (IOException ex) {
            LOGGER.error("Unable to parse conf file {}, error: {}", confFileName, ex.getMessage());
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
}
