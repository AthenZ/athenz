/*
 * Copyright 2016 Yahoo Inc.
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

public class FilePublicKeyStore implements PublicKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(FilePublicKeyStore.class);

    private static final String ZPE_ATHENZ_CONFIG = "/conf/athenz/athenz.conf";
    private static final String ZPE_JWK_ATHENZ_CONFIG = "/var/lib/sia/athenz.conf";

    private Map<String, PublicKey> ztsPublicKeyMap = new ConcurrentHashMap<>();
    private Map<String, PublicKey> zmsPublicKeyMap = new ConcurrentHashMap<>();

    public void init() {
        initAthenzConfig();
        initAthenzJWKConfig();
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
            LOG.error("Unable to extract ZMS Url from {} exc: {}",
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
        } catch (Exception ex) {
            LOG.error("Unable to extract athenz jwk config {} exc: {}", jwkConfFileName, ex.getMessage(), ex);
        }
    }

    private void loadJwkList(List<JWK> jwkList, Map<String, PublicKey> keysMap) {
        for (JWK jwkObj : jwkList) {
            try {
                PublicKey jwk = jwkToPubKey(jwkObj);
                keysMap.put(jwkObj.kid, jwk);
            } catch (Exception e) {
                LOG.warn("failed to load jwk id : {}, ex: {}", jwkObj.kid, e.getMessage(), e);
            }
        }
    }

    private PublicKey jwkToPubKey(JWK rdlObj) throws NoSuchAlgorithmException, JsonProcessingException, InvalidKeySpecException, InvalidParameterSpecException {
        String jwk = JSON.string(rdlObj);
        Key key = Key.fromString(jwk);
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
        if (keyId == null) {
            return null;
        }
        return ztsPublicKeyMap.get(keyId);
    }

    @Override
    public PublicKey getZmsKey(String keyId) {
        if (keyId == null) {
            return null;
        }
        PublicKey publicKey = zmsPublicKeyMap.get(keyId);
        if (publicKey == null) {
            // reload athenz jwks from disk and try again
            LOG.debug("key id: {} does not exist in public keys map, reload athenz jwks from disk", keyId);
            initAthenzJWKConfig();
            publicKey = zmsPublicKeyMap.get(keyId);
        }
        return publicKey;
    }
    
}
