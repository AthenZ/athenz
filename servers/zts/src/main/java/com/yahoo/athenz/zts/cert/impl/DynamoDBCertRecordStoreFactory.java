/*
 * Copyright 2018 Oath, Inc.
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
package com.yahoo.athenz.zts.cert.impl;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.CertRecordStore;
import com.yahoo.athenz.zts.cert.CertRecordStoreFactory;

public class DynamoDBCertRecordStoreFactory implements CertRecordStoreFactory {

    @Override
    public CertRecordStore create(PrivateKeyStore keyStore) {

        final String tableName = System.getProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME);
        if (tableName == null || tableName.isEmpty()) {
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE, "DynamoDB table name not specified");
        }

        AmazonDynamoDB client = getDynamoDBClient();
        return new DynamoDBCertRecordStore(client, tableName);
    }

    AmazonDynamoDB getDynamoDBClient() {
        return AmazonDynamoDBClientBuilder.standard().build();
    }
}
