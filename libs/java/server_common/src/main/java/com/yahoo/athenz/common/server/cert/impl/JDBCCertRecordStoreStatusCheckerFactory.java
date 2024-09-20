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

package com.yahoo.athenz.common.server.cert.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.common.server.cert.CertRecordStore;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.status.StatusChecker;
import com.yahoo.athenz.common.server.status.StatusCheckerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;

public class JDBCCertRecordStoreStatusCheckerFactory implements StatusCheckerFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(JDBCCertRecordStoreStatusCheckerFactory.class);

    public static final String ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS = "athenz.zts.private_key_store_factory_class";
    public static final String ZTS_PKEY_STORE_FACTORY_CLASS = "com.yahoo.athenz.auth.impl.FilePrivateKeyStoreFactory";

    private final PrivateKeyStore keyStore = getKeyStore();

    @Override
    public StatusChecker create() throws ServerResourceException {
        CertRecordStore certRecordStore = new JDBCCertRecordStoreFactory().create(keyStore);
        return new JDBCCertRecordStoreStatusChecker((JDBCCertRecordStore) certRecordStore);
    }

    private PrivateKeyStore getKeyStore() {
        final String pkeyFactoryClass = System.getProperty(ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZTS_PKEY_STORE_FACTORY_CLASS);
        PrivateKeyStoreFactory pkeyFactory;
        try {
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).getDeclaredConstructor().newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException | NoSuchMethodException | InvocationTargetException e) {
            LOGGER.error("Invalid PrivateKeyStoreFactory class: {} error: {}", pkeyFactoryClass, e.getMessage());
            throw new IllegalArgumentException("Invalid private key store");
        }

        // extract the private key for our service - we're going to ask for our algorithm
        // specific keys and then if neither one is provided our generic one.

        return pkeyFactory.create();
    }
}
