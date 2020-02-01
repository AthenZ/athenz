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
package com.yahoo.athenz.auth.impl;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

import com.yahoo.athenz.auth.ServerPrivateKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.util.Crypto;

public class FilePrivateKeyStore implements PrivateKeyStore {
    
    private static final Logger LOG = LoggerFactory.getLogger(FilePrivateKeyStore.class);
    
    public static final String ATHENZ_PROP_PRIVATE_KEY = "athenz.auth.private_key_store.private_key";
    public static final String ATHENZ_PROP_PRIVATE_KEY_ID = "athenz.auth.private_key_store.private_key_id";
    public static final String ATHENZ_PROP_PRIVATE_EC_KEY = "athenz.auth.private_key_store.private_ec_key";
    public static final String ATHENZ_PROP_PRIVATE_EC_KEY_ID = "athenz.auth.private_key_store.private_ec_key_id";
    public static final String ATHENZ_PROP_PRIVATE_RSA_KEY = "athenz.auth.private_key_store.private_rsa_key";
    public static final String ATHENZ_PROP_PRIVATE_RSA_KEY_ID = "athenz.auth.private_key_store.private_rsa_key_id";
    private static final String ATHENZ_STR_JAR_RESOURCE = "JAR_RESOURCE:";

    private static final String ZMS_SERVICE = "zms";
    private static final String ZTS_SERVICE = "zts";

    private static final String ALGO_RSA = "RSA";
    private static final String ALGO_EC = "EC";

    public FilePrivateKeyStore() {
    }

    @Override
    public ServerPrivateKey getPrivateKey(String service, String serverHostName,
            String serverRegion, String algorithm) {

        // validate our service and algorithm values

        if (!ZMS_SERVICE.equalsIgnoreCase(service) && !ZTS_SERVICE.equalsIgnoreCase(service)) {
            LOG.error("FilePrivateKeyStore: unknown service: {}", service);
            return null;
        }

        if (!ALGO_RSA.equalsIgnoreCase(algorithm) && !ALGO_EC.equalsIgnoreCase(algorithm)) {
            LOG.error("FilePrivateKeyStore: unknown algorithm: {}", algorithm);
            return null;
        }

        String privKeyName;
        String privKeyId;
        if (ALGO_RSA.equalsIgnoreCase(algorithm)) {
            privKeyName = System.getProperty(ATHENZ_PROP_PRIVATE_RSA_KEY);
            privKeyId = System.getProperty(ATHENZ_PROP_PRIVATE_RSA_KEY_ID, "0");
        } else {
            privKeyName = System.getProperty(ATHENZ_PROP_PRIVATE_EC_KEY);
            privKeyId = System.getProperty(ATHENZ_PROP_PRIVATE_EC_KEY_ID, "0");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("FilePrivateKeyStore: private key file: {}, id: {}", privKeyName, privKeyId);
        }

        if (privKeyName == null) {
            return null;
        }

        // check to see if this is running in dev mode and thus it's
        // a resource in our jar file

        File privKeyFile = new File(privKeyName);
        PrivateKey pkey = Crypto.loadPrivateKey(privKeyFile);

        ServerPrivateKey privateKey = null;
        if (pkey != null) {
            privateKey = new ServerPrivateKey(pkey, privKeyId);
        }
        return privateKey;
    }

    @Override
    public PrivateKey getPrivateKey(String service, String serverHostName,
            StringBuilder privateKeyId) {
        
        final String privKeyName = System.getProperty(ATHENZ_PROP_PRIVATE_KEY);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("FilePrivateKeyStore: private key file=" + privKeyName);
        }
        
        if (privKeyName == null) {
            return null;
        }
        
        // check to see if this is running in dev mode and thus it's
        // a resource in our jar file
        
        String privKey;
        if (privKeyName.startsWith(ATHENZ_STR_JAR_RESOURCE)) {
            privKey = retrieveKeyFromResource(privKeyName.substring(ATHENZ_STR_JAR_RESOURCE.length()));
        } else {
            File privKeyFile = new File(privKeyName);
            privKey = Crypto.encodedFile(privKeyFile);
        }
        
        PrivateKey pkey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        if (pkey != null) {
            privateKeyId.append(System.getProperty(ATHENZ_PROP_PRIVATE_KEY_ID, "0"));
        }
        return pkey;
    }

    private String retrieveKeyFromResource(String resourceName) {
        
        String key = null;
        try (InputStream is = getClass().getResourceAsStream(resourceName)) {
            String resourceData = getString(is);
            if (resourceData != null) {
                key = Crypto.ybase64(resourceData.getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("FilePrivateKeyStore: Unable to read key from resource: " + resourceName);
            }
        }
        
        return key;
    }
    
    String getString(InputStream is) throws IOException {
        
        if (is == null) {
            return null;
        }
        
        int ch;
        StringBuilder sb = new StringBuilder();
        while ((ch = is.read()) != -1) {
            sb.append((char) ch);
        }
        return sb.toString();
    }
}
