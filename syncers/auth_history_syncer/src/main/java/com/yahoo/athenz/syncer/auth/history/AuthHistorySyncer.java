/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.syncer.auth.history;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.PrivateKeyStoreFactory;
import com.yahoo.athenz.syncer_common.Config;
import com.yahoo.athenz.syncer_common.SyncTimeRange;
import com.yahoo.athenz.syncer_common.Syncer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.concurrent.TimeUnit;

public class AuthHistorySyncer {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthHistorySyncer.class);
    private static final Long MAX_SYNC_RANGE = TimeUnit.MINUTES.toMillis(30);
    private static final String PROP_REGION = "auth_history_syncer.aws.region";
    private static final String PROP_REGION_DEFAULT = "us-west-2";
    private static final String PROP_AUTH_HISTORY_USE_FILTER_PATTERN = "auth_history_syncer.use_filter_pattern";
    private static final String PROP_AUTH_HISTORY_USE_FILTER_PATTERN_DEFAULT = "true";
    private static final String PROP_AUTH_HISTORY_FETCH_FACTORY_CLASS = "auth_history_syncer.fetch_factory_class";
    private static final String PROP_AUTH_HISTORY_SEND_FACTORY_CLASS = "auth_history_syncer.send_factory_class";
    private static final String PROP_AUTH_HISTORY_SEND_FACTORY_CLASS_DEFAULT = "com.yahoo.athenz.syncer.auth.history.impl.DynamoDBAuthHistorySenderFactory";
    private static final String PROP_AUTH_HISTORY_PKEYSTORE_FACTORY_CLASS = "auth_history_syncer.private_key_store_factory_class";


    public static void main(String[] args) {
        if (args.length != 1) {
            usage();
            System.exit(1);
        }
        Config.loadProperties(args[0]);
        Syncer syncer = new Syncer();
        AuthHistorySyncer authHistorySyncer = new AuthHistorySyncer();
        syncer.sync(authHistorySyncer, (authSyncer, timeRange) -> authSyncer.sync(timeRange));
    }

    public boolean sync(SyncTimeRange syncTimeRange) {
        try {
            // Validate syncTimeRange
            if (syncTimeRange.getEndTime() - syncTimeRange.getStartTime() > MAX_SYNC_RANGE) {
                // If no successful run recorded, or time since last run is too big, sync for MAX_SYNC_RANGE milliseconds
                syncTimeRange.setStartTime(syncTimeRange.getEndTime() - MAX_SYNC_RANGE);
            }

            LOGGER.info("Start syncing. Range - {}", syncTimeRange);
            String region = System.getProperty(PROP_REGION, PROP_REGION_DEFAULT);
            boolean useFilterPattern = Boolean.parseBoolean(System.getProperty(PROP_AUTH_HISTORY_USE_FILTER_PATTERN, PROP_AUTH_HISTORY_USE_FILTER_PATTERN_DEFAULT));
            PrivateKeyStore privateKeyStore = getPrivateKeyStore();
            AuthHistoryFetcher authHistoryFetcher = getAuthHistoryFetcher(privateKeyStore, region);
            Set<AuthHistoryDynamoDBRecord> allRecords = authHistoryFetcher.getLogs(syncTimeRange.getStartTime(), syncTimeRange.getEndTime(), useFilterPattern);
            AuthHistorySender authHistorySender = getAuthHistorySender(privateKeyStore, region);
            authHistorySender.pushRecords(allRecords);
            LOGGER.info("Finished syncing successfully");
            return true;
        } catch (Exception ex) {
            LOGGER.info("Finished syncing with exception: ", ex);
            return false;
        }
    }

    PrivateKeyStore getPrivateKeyStore() {
        String pkeyFactoryClass = System.getProperty(PROP_AUTH_HISTORY_PKEYSTORE_FACTORY_CLASS);
        if (pkeyFactoryClass == null) {
            LOGGER.warn("No private keystore was loaded");
            return null;
        }
        PrivateKeyStoreFactory pkeyFactory;
        try {
            pkeyFactory = (PrivateKeyStoreFactory) Class.forName(pkeyFactoryClass).newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            LOGGER.error("Invalid PrivateKeyStoreFactory class: {}", pkeyFactoryClass, e);
            throw new IllegalArgumentException("Invalid private key store");
        }

        return pkeyFactory.create();
    }
        
    AuthHistoryFetcher getAuthHistoryFetcher(PrivateKeyStore privateKeyStore, String region) throws Exception {
        String authHistoryFetcherFactoryClass = System.getProperty(PROP_AUTH_HISTORY_FETCH_FACTORY_CLASS);
        if (authHistoryFetcherFactoryClass == null) {
            System.out.println("Error: " + PROP_AUTH_HISTORY_FETCH_FACTORY_CLASS + " system property is mandatory");
            throw new IllegalArgumentException(PROP_AUTH_HISTORY_FETCH_FACTORY_CLASS + " system property is mandatory");
        }
        AuthHistoryFetcherFactory authHistoryFetcherFactory;
        try {
            authHistoryFetcherFactory = (AuthHistoryFetcherFactory) Class.forName(authHistoryFetcherFactoryClass).newInstance();
            return authHistoryFetcherFactory.create(privateKeyStore, region);
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            System.out.println("Error: Invalid authHistoryFetcherFactory class: " + authHistoryFetcherFactoryClass + " error: " + e.getMessage());
            throw e;
        }
    }

    AuthHistorySender getAuthHistorySender(PrivateKeyStore privateKeyStore, String region) throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        String authHistorySenderFactoryClass = System.getProperty(PROP_AUTH_HISTORY_SEND_FACTORY_CLASS, PROP_AUTH_HISTORY_SEND_FACTORY_CLASS_DEFAULT);
        AuthHistorySenderFactory authHistorySenderFactory;
        try {
            authHistorySenderFactory = (AuthHistorySenderFactory) Class.forName(authHistorySenderFactoryClass).newInstance();
            return authHistorySenderFactory.create(privateKeyStore, region);
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            System.out.println("Error: Invalid authHistorySenderFactory class: " + authHistorySenderFactoryClass + " error: " + e.getMessage());
            throw e;
        }
    }

    public static void usage() {
        System.out.println("Required parameters: <properties file location>");
    }
}
