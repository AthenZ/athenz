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
package com.yahoo.athenz.zpe.pkey.file;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yahoo.athenz.auth.token.jwts.Key;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.athenz.zpe.ZpeConsts;
import com.yahoo.athenz.zpe.pkey.PublicKeyStore;
import com.yahoo.athenz.zts.AthenzJWKConfig;
import com.yahoo.athenz.zts.JWK;
import com.yahoo.rdl.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.yahoo.athenz.zpe.ZpeConsts.ZPE_PROP_MILLIS_BETWEEN_RELOAD_CONFIG;

public class FilePublicKeyStore implements PublicKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(FilePublicKeyStore.class);

    private static final String ZPE_ATHENZ_CONFIG = "/conf/athenz/athenz.conf";
    private static final String ZPE_JWK_ATHENZ_CONFIG = "/var/lib/sia/athenz.conf";

    private Map<String, PublicKey> ztsPublicKeyMap = new ConcurrentHashMap<>();
    private Map<String, PublicKey> zmsPublicKeyMap = new ConcurrentHashMap<>();
    protected long millisBetweenReloadAthenzConfig;
    private long lastReloadAthenzConfigTime;
    
    public void init() {
        initAthenzConfig();
        initAthenzJWKConfig();
        if (ztsPublicKeyMap.size() == 0 && zmsPublicKeyMap.size() == 0) {
            LOG.error("Could not find any available public key");
        }
        millisBetweenReloadAthenzConfig = Long.parseLong(System.getProperty(ZPE_PROP_MILLIS_BETWEEN_RELOAD_CONFIG, Long.toString(30 * 1000 * 60)));
    }
    
    private void initAthenzConfig() {
        String rootDir = System.getenv("ROOT");
        if (rootDir == null) {
            rootDir = "/home/athenz";
        }

        String confFileName = System.getProperty(ZpeConsts.ZPE_PROP_ATHENZ_CONF,
                rootDir + ZPE_ATHENZ_CONFIG);
        try {
            Path path = Paths.get(confFileName);
            AthenzConfig conf = JSON.fromBytes(Files.readAllBytes(path), AthenzConfig.class);
            
            loadPublicKeys(conf.getZtsPublicKeys(), ztsPublicKeyMap);
            loadPublicKeys(conf.getZmsPublicKeys(), zmsPublicKeyMap);
            
        } catch (Exception ex) {
            LOG.warn("Unable to extract ZMS Url from {} exc: {}",
                    confFileName, ex.getMessage());
        }
    }

    private void initAthenzJWKConfig() {
        
        String jwkConfFileName = System.getProperty(ZpeConsts.ZPE_PROP_JWK_ATHENZ_CONF, ZPE_JWK_ATHENZ_CONFIG);
        try {
            Path path = Paths.get(jwkConfFileName);
            AthenzJWKConfig jwkConf = JSON.fromBytes(Files.readAllBytes(path), AthenzJWKConfig.class);
            loadJwkList(jwkConf.getZts().getKeys(), ztsPublicKeyMap);
            loadJwkList(jwkConf.getZms().getKeys(), zmsPublicKeyMap);
            lastReloadAthenzConfigTime = System.currentTimeMillis();
        } catch (Exception ex) {
            LOG.warn("Unable to extract athenz jwk config {} exc: {}", jwkConfFileName, ex.getMessage(), ex);
        }
    }

    private void loadJwkList(List<JWK> jwkList, Map<String, PublicKey> keysMap) {
        for (JWK jwk : jwkList) {
            try {
                PublicKey publicKey = jwkToPubKey(jwk);
                keysMap.put(jwk.kid, publicKey);
            } catch (Exception e) {
                LOG.warn("failed to load jwk id : {}, ex: {}", jwk.kid, e.getMessage(), e);
            }
        }
    }

    protected PublicKey jwkToPubKey(JWK jwk) throws NoSuchAlgorithmException, JsonProcessingException, InvalidKeySpecException, InvalidParameterSpecException {
        String jwkStr = JSON.string(jwk);
        Key key = Key.fromString(jwkStr);
        return key.getPublicKey();
    }

    void loadPublicKeys(ArrayList<PublicKeyEntry> publicKeys, Map<String, PublicKey> keyMap) {
        
        if (publicKeys == null) {
            return;
        }
        
        for (PublicKeyEntry publicKey : publicKeys) { 
            String id = publicKey.getId();
            String key = publicKey.getKey();
            if (key == null || id == null) {
                continue;
            }
            PublicKey pubKey;
            try {
                pubKey = Crypto.loadPublicKey(Crypto.ybase64DecodeString(key));
            } catch (Exception e) {
                LOG.error("Invalid ZTS public key for id: {} - {}", id, e.getMessage());
                continue;
            }
            keyMap.put(id, pubKey);
        }
    }
    
    @Override
    public PublicKey getZtsKey(String keyId) {
        return getPublicKey(keyId, ztsPublicKeyMap);
    }

    @Override
    public PublicKey getZmsKey(String keyId) {
        return getPublicKey(keyId, zmsPublicKeyMap);
    }

    private PublicKey getPublicKey(String keyId, Map<String, PublicKey> ztsPublicKeyMap) {
        if (keyId == null) {
            return null;
        }
        PublicKey publicKey = ztsPublicKeyMap.get(keyId);
        if (publicKey == null && canReloadAthenzConfig()) {
            // reload athenz jwks from disk and try again
            LOG.debug("key id: {} does not exist in public keys map, reload athenz jwks from disk", keyId);
            initAthenzJWKConfig();
            publicKey = ztsPublicKeyMap.get(keyId);
        }
        return publicKey;
    }

    protected boolean canReloadAthenzConfig() {
        long now = System.currentTimeMillis();
        long millisDiff = now - lastReloadAthenzConfigTime;
        return millisDiff > millisBetweenReloadAthenzConfig;
    }
        
}
