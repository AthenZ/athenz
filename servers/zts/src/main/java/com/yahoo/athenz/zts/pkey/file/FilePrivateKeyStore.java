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
package com.yahoo.athenz.zts.pkey.file;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.pkey.PrivateKeyStore;

public class FilePrivateKeyStore implements PrivateKeyStore {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(FilePrivateKeyStore.class);

    String rootDir = null;
    
    public FilePrivateKeyStore() {
        
        // get the system  root directory
        
        rootDir = System.getenv(ZTSConsts.STR_ENV_ROOT);
        if (rootDir == null) {
            rootDir = ZTSConsts.STR_DEF_ROOT;
        }
    }

    @Override
    public PrivateKey getHostPrivateKey(StringBuilder privateKeyId) {
        
        String privKeyName = System.getProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY,
                rootDir + "/share/athenz/sys.auth/zts.key");
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("FilePrivateKeyStore: private key file=" + privKeyName);
        }
        
        File privKeyFile = new File(privKeyName);
        String key = Crypto.encodedFile(privKeyFile);
        PrivateKey pkey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(key));
        
        if (pkey == null) {
            throw new ResourceException(500, "Unable to retrieve ZTS Server private key");
        }

        privateKeyId.append(System.getProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_ID, "0"));
        return pkey;
    }
    
    @Override
    public PrivateKey getPrivateKey(String keyName, int keyVersion) {
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("FilePrivateKeyStore: private key file=" + keyName);
        }
        
        // if the version is 0 then we're going to take the keyname
        // as the filename otherwise we'll append ".v<keyVersion>"
        // to generated the versioned key filename
        
        String fileName = keyName;
        if (keyVersion != 0) {
            fileName += ".v" + keyVersion;
        }
        File privKeyFile = new File(fileName);
        String key = Crypto.encodedFile(privKeyFile);
        PrivateKey pkey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(key));
        
        if (pkey == null) {
            throw new ResourceException(500, "Unable to retrieve private key: " + fileName);
        }

        return pkey;
    }
    
    @Override
    public String getPublicKey(String keyName, int keyVersion) {
        
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("FilePrivateKeyStore: public key file=" + keyName);
        }
        
        // if the version is 0 then we're going to take the keyname
        // as the filename otherwise we'll append ".v<keyVersion>"
        // to generated the versioned key filename
        
        String fileName = keyName;
        if (keyVersion != 0) {
            fileName += ".v" + keyVersion;
        }
        Path path = Paths.get(fileName);
        String pkey = null;
        try {
            pkey = new String(Files.readAllBytes(path));
        } catch (IOException ex) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("FilePrivateKeyStore: unable to read public key", ex);
            }
        }
        
        if (pkey == null) {
            throw new ResourceException(500, "Unable to retrieve public key: " + fileName);
        }

        return pkey;
    }
}
