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
package com.yahoo.athenz.zms.pkey.file;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.ZMS;
import com.yahoo.athenz.zms.ZMSConsts;

public class FilePrivateKeyStore implements PrivateKeyStore {
    
    private static final Logger LOG = LoggerFactory.getLogger(FilePrivateKeyStore.class);
    
    public FilePrivateKeyStore() {
    }

    @Override
    public PrivateKey getPrivateKey(String serverHostName, StringBuilder privateKeyId) {
        
        String privKeyName = System.getProperty(ZMSConsts.ZMS_PROP_PRIVATE_KEY,
                ZMS.getRootDir() + "/share/athenz/sys.auth/zms.key");
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("FilePrivateKeyStore: private key file=" + privKeyName);
        }
        
        // check to see if this is running in dev mode and thus it's
        // a resource in our jar file
        
        String privKey = null;
        if (privKeyName.startsWith(ZMSConsts.STR_JAR_RESOURCE)) {
            privKey = retrieveKeyFromResource(privKeyName.substring(ZMSConsts.STR_JAR_RESOURCE.length()));
        } else {
            File privKeyFile = new File(privKeyName);
            privKey = Crypto.encodedFile(privKeyFile);
        }
        
        PrivateKey pkey = Crypto.loadPrivateKey(Crypto.ybase64DecodeString(privKey));
        
        if (pkey == null) {
            throw new ResourceException(500, "Unable to retrieve ZMS Server private key");
        }

        privateKeyId.append(System.getProperty(ZMSConsts.ZMS_PROP_PRIVATE_KEY_ID, "0"));
        return pkey;
    }
    
    String retrieveKeyFromResource(String resourceName) {
        
        String key = null;
        try (InputStream is = getClass().getResourceAsStream(resourceName)) {
            String resourceData = getString(is);
            if (resourceData != null) {
                key = Crypto.ybase64(resourceData.getBytes("UTF-8"));
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
