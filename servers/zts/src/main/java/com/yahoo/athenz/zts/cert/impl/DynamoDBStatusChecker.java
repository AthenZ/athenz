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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.status.StatusCheckException;
import com.yahoo.athenz.common.server.status.StatusChecker;
import org.apache.http.HttpStatus;

import java.io.IOException;

public class DynamoDBStatusChecker implements StatusChecker {

    private final String tableName;
    private final PrivateKeyStore keyStore;

    public DynamoDBStatusChecker(String tableName, PrivateKeyStore keyStore) {
        this.tableName = tableName;
        this.keyStore = keyStore;
    }

    @Override
    public void check() throws StatusCheckException {
        DynamoDBClientAndCredentials clientAndCreds = null;
        try {
            // Get DynamoDB client and temp credentials (if required)
            DynamoDBClientFetcher dynamoDBClientFetcher = getDynamoDBClientFetcher();
            clientAndCreds = dynamoDBClientFetcher.getDynamoDBClient(null, keyStore);
            AmazonDynamoDB amazonDynamoDB = clientAndCreds.getAmazonDynamoDB();

            // Get list of tables and verify our table appears
            boolean tableFound = amazonDynamoDB.listTables().getTableNames().stream()
                    .anyMatch(fetchedTableName -> fetchedTableName.equals(tableName));

            if (!tableFound) {
                throw new StatusCheckException(HttpStatus.SC_OK, "Table named " + tableName + " wasn't found in DynamoDB");
            }
        } catch (StatusCheckException ex) {
            throw ex;
        } catch (Throwable ex) {
            throw new StatusCheckException(ex);
        } finally {
            // Close resources
            if (clientAndCreds != null) {
                try {
                    if (clientAndCreds.getAmazonDynamoDB() != null) {
                        clientAndCreds.getAmazonDynamoDB().shutdown();
                    }
                    if (clientAndCreds.getAwsCredentialsProvider() != null) {
                        clientAndCreds.getAwsCredentialsProvider().close();
                    }
                } catch (IOException ignored) {

                }
            }
        }
    }

    DynamoDBClientFetcher getDynamoDBClientFetcher() {
        return DynamoDBClientFetcherFactory.getDynamoDBClientFetcher();
    }
}
