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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.yahoo.athenz.zts.AthenzJWKConfig;
import com.yahoo.athenz.zts.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.athenz.zpe.ZpeConsts;
import com.yahoo.athenz.zpe.pkey.PublicKeyStore;
import com.yahoo.rdl.JSON;

import static com.yahoo.athenz.zpe.ZpeConsts.ZPE_PROP_MILLIS_BETWEEN_ZTS_CALLS;

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
                if (jwk != null) {
                    keysMap.put(jwkObj.kid, jwk);
                } else {
                    LOG.warn("failed to load jwk id : {}, type is: {}", jwkObj.kid, jwkObj.kty);
                }
            } catch (ParseException | JOSEException e) {
                LOG.warn("failed to load jwk id : {}, ex: {}", jwkObj.kid, e.getMessage(), e);
            }
        }
    }

    private PublicKey jwkToPubKey(JWK rdlObj) throws ParseException, JOSEException {
        String jwk = JSON.string(rdlObj);
        switch (rdlObj.kty) {
            case "RSA":
                RSAKey rsaKey = RSAKey.parse(jwk);
                return rsaKey.toRSAPublicKey();
            case "EC":
                ECKey ecKey = ECKey.parse(jwk);
                return ecKey.toECPublicKey();
        }
        return null;
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
            // first, reload athenz jwks from disk and try again
            LOG.debug("key id: {} does not exist in public keys map, reload athenz jwks from disk", keyId);
            initAthenzJWKConfig();
            publicKey = zmsPublicKeyMap.get(keyId);
            if (publicKey != null) {
                return publicKey;
            }
            if canFetchLatestJwksFromZts(config) {
                //  fetch all zts jwk keys and update config
                log.Debugf("key id: [%s] does not exist in also after reloading athenz jwks from disk, about to fetch directly from zts", ztsKeyID)
                rfc := true
                ztsJwkList, err := ztsClient.GetJWKList(&rfc)
                if err != nil {
                    return "", fmt.Errorf("unable to get the zts jwk keys, err: %v", err)
                }
                config.updateZtsJwks(ztsJwkList)
                lastZtsJwkFetchTime = time.Now()

                // after fetching all jwks from zts, try again
                ztsPublicKey = config.GetZtsPublicKey(ztsKeyID)
            } else {
                log.Printf("not allowed to fetch jwks from zts, last fetch time: %v", lastZtsJwkFetchTime)
            }
        }
        return publicKey;
    }

    protected boolean canFetchLatestJwksFromZts() {
        int minutesBetweenZtsCheck = Integer.parseInt(System.getProperty(ZPE_PROP_MILLIS_BETWEEN_ZTS_CALLS, "30000"));
        minutesBetweenZtsCheck := 30
        if config.MinutesBetweenZtsUpdates > 0 {
            minutesBetweenZtsCheck = config.MinutesBetweenZtsUpdates
        }
        now := time.Now()
        minDiff := int(now.Sub(lastZtsJwkFetchTime).Minutes())
        return minDiff > minutesBetweenZtsCheck
    }

}
