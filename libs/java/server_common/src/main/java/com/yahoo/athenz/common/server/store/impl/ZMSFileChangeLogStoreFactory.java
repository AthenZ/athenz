/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.common.server.store.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.store.ChangeLogStore;
import com.yahoo.athenz.common.server.store.ChangeLogStoreFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.PrivateKey;

import static com.yahoo.athenz.common.ServerCommonConsts.PROP_DATA_STORE_SUBDIR;

public class ZMSFileChangeLogStoreFactory implements ChangeLogStoreFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZMSFileChangeLogStoreFactory.class);

    // private/x.509 cert path settings

    private static final String ZTS_SERVER_PROP_KEY_PATH      = "athenz.common.server.clog.zts_server_key_path";
    private static final String ZTS_SERVER_PROP_CERT_PATH     = "athenz.common.server.clog.zts_server_cert_path";

    // truststore path and password settings

    private static final String ZTS_SERVER_PROP_TRUSTORE_PATH      = "athenz.common.server.clog.zts_server_trust_store_path";
    private static final String ZTS_SERVER_PROP_TRUSTORE_PWD_NAME  = "athenz.common.server.clog.zts_server_trust_store_password_name";
    private static final String ZTS_SERVER_PROP_TRUSTORE_PWD_APP   = "athenz.common.server.clog.zts_server_trust_store_password_app";

    // default truststore password used by the jdk, added as a char array directly to not have the string literal available.
    private static final char[] DEFAULT_JDK_TRUSTSTORE_PWD = new char[] {'c', 'h', 'a', 'n', 'g', 'e', 'i', 't'};

    PrivateKeyStore privateKeyStore;

    @Override
    public void setPrivateKeyStore(PrivateKeyStore privateKeyStore) {
        this.privateKeyStore = privateKeyStore;
    }

    @Override
    public ChangeLogStore create(String ztsHomeDir, PrivateKey privateKey, String privateKeyId) {

        // if we have mtls settings configured then we should use those
        // for our client otherwise we'll fall back to our private key access

        final String rootDirectory = ztsHomeDir + File.separator + System.getProperty(PROP_DATA_STORE_SUBDIR, "zts_store");
        ChangeLogStore store = mtlsClientChangeLogStore(rootDirectory);
        if (store == null) {
            LOGGER.info("mtls client change log store not available");
            store = new ZMSFileChangeLogStore(rootDirectory, privateKey, privateKeyId);
        }
        return store;
    }

    ChangeLogStore mtlsClientChangeLogStore(final String rootDirectory) {

        final String keyPath = System.getProperty(ZTS_SERVER_PROP_KEY_PATH, "");
        final String certPath = System.getProperty(ZTS_SERVER_PROP_CERT_PATH, "");
        final String trustStorePath = System.getProperty(ZTS_SERVER_PROP_TRUSTORE_PATH, "");

        // if we're missing any of the paths then we are not going
        // to use the mtls client for the change log store

        if (keyPath.isEmpty() || certPath.isEmpty() || trustStorePath.isEmpty()) {
            LOGGER.info("Missing mtls client settings: key({}), cert({}), truststore({})",
                    keyPath, certPath, trustStorePath);
            return null;
        }

        char[] trustStorePassword = DEFAULT_JDK_TRUSTSTORE_PWD;
        final String trustStorePwdName = System.getProperty(ZTS_SERVER_PROP_TRUSTORE_PWD_NAME, "");
        if (!trustStorePwdName.isEmpty()) {
            final String trustStorePwdApp = System.getProperty(ZTS_SERVER_PROP_TRUSTORE_PWD_APP);
            trustStorePassword = (privateKeyStore == null) ? trustStorePwdName.toCharArray() :
                    privateKeyStore.getSecret(trustStorePwdApp, trustStorePwdName);
        }

        // catch any exceptions thrown from the change log store and instead
        // throw a runtime exception to block the server from starting up

        try {
            return new ZMSFileMTLSChangeLogStore(rootDirectory, keyPath, certPath, trustStorePath, trustStorePassword);
        } catch (Exception ex) {
            LOGGER.error("Unable to initialize change log store", ex);
            throw new IllegalArgumentException(ex.getMessage());
        }
    }
}
