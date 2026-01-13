/*
 * Copyright The Athenz Authors
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
package io.athenz.server.gcp.common.cert.impl;

import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.FirestoreOptions;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.cert.CertRecordStore;
import com.yahoo.athenz.common.server.cert.CertRecordStoreFactory;
import com.yahoo.athenz.common.server.ServerResourceException;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FirestoreCertRecordStoreFactory implements CertRecordStoreFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(FirestoreCertRecordStoreFactory.class);

    public static final String ZTS_PROP_CERT_FIRESTORE_PROJECT_ID = "athenz.zts.cert_firestore_project_id";
    public static final String ZTS_PROP_CERT_FIRESTORE_COLLECTION_NAME = "athenz.zts.cert_firestore_collection_name";
    public static final String ZTS_PROP_CERT_FIRESTORE_DATABASE_ID = "athenz.zts.cert_firestore_database_id";

    @Override
    public CertRecordStore create(PrivateKeyStore keyStore) throws ServerResourceException {

        final String projectId = System.getProperty(ZTS_PROP_CERT_FIRESTORE_PROJECT_ID);
        if (StringUtil.isEmpty(projectId)) {
            LOGGER.error("Cert Store Firestore project ID not specified");
            throw new ServerResourceException(ServerResourceException.SERVICE_UNAVAILABLE,
                    "Firestore project ID not specified");
        }

        final String collectionName = System.getProperty(ZTS_PROP_CERT_FIRESTORE_COLLECTION_NAME);
        if (StringUtil.isEmpty(collectionName)) {
            LOGGER.error("Cert Store Firestore collection name not specified");
            throw new ServerResourceException(ServerResourceException.SERVICE_UNAVAILABLE,
                    "Firestore collection name not specified");
        }

        // Database ID is optional - defaults to "(default)"
        final String databaseId = System.getProperty(ZTS_PROP_CERT_FIRESTORE_DATABASE_ID, "(default)");

        Firestore firestore = getFirestoreClient(projectId, databaseId);
        return new FirestoreCertRecordStore(firestore, collectionName);
    }

    Firestore getFirestoreClient(String projectId, String databaseId) {
        try {
            FirestoreOptions firestoreOptions = FirestoreOptions.newBuilder()
                    .setProjectId(projectId)
                    .setDatabaseId(databaseId)
                    .build();
            return firestoreOptions.getService();
        } catch (Exception ex) {
            LOGGER.error("Failed to create Firestore client: {}", ex.getMessage(), ex);
            throw new RuntimeException("Failed to create Firestore client", ex);
        }
    }
}

