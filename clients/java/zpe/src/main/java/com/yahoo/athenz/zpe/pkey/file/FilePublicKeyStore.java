/**
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
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.athenz.zms.PublicKeyEntry;
import com.yahoo.athenz.zpe.ZpeConsts;
import com.yahoo.athenz.zpe.pkey.PublicKeyStore;
import com.yahoo.rdl.JSON;

public class FilePublicKeyStore implements PublicKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(FilePublicKeyStore.class);

    private static final String ZPE_ATHENZ_CONFIG = "/conf/athenz/athenz.conf";

    private Map<String, PublicKey> ztsPublicKeyMap = new ConcurrentHashMap<>();
    private Map<String, PublicKey> zmsPublicKeyMap = new ConcurrentHashMap<>();
    
    public void init() {
        
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
            return;
        }
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
            PublicKey pubKey = null;
            try {
                pubKey = Crypto.loadPublicKey(Crypto.ybase64DecodeString(key));
            } catch (Exception e) {
                LOG.error("Invalid ZTS public key for id: " + id + " - " + e.getMessage());
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
        return zmsPublicKeyMap.get(keyId);
    }

}
