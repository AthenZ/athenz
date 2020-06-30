/*
 *  Copyright 2020 Verizon Media
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

package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.common.server.status.StatusChecker;
import com.yahoo.athenz.common.server.status.StatusCheckerFactory;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DynamoDBStatusCheckerFactory implements StatusCheckerFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBStatusCheckerFactory.class);
    private final PrivateKeyStore keyStore = getKeyStore();

    @Override
    public StatusChecker create() {
        final String tableName = System.getProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME);
        if (tableName == null || tableName.isEmpty()) {
            LOGGER.error("Cert Store DynamoDB table name not specified");
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE, "DynamoDB table name not specified");
        }
        return new DynamoDBStatusChecker(tableName, keyStore);
    }

    private PrivateKeyStore getKeyStore() {
        final String pkeyFactoryClass = System.getProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS,
                ZTSConsts.ZTS_PKEY_STORE_FACTORY_CLASS);
        PrivateKeyStoreFactory pkeyFactory;
        try {
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid PrivateKeyStoreFactory class: " + pkeyFactoryClass
                    + " error: " + e.getMessage());
            throw new IllegalArgumentException("Invalid private key store");
        }

        // extract the private key for our service - we're going to ask for our algorithm
        // specific keys and then if neither one is provided our generic one.

        return pkeyFactory.create();
    }
}
