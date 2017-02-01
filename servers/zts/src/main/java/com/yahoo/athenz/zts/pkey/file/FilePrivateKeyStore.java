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
import java.security.PrivateKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;

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
    public PrivateKey getPrivateKey(String serverHostName, StringBuilder privateKeyId) {
        
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
}
