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

package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.status.StatusCheckException;
import com.yahoo.athenz.common.server.status.StatusChecker;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientAndCredentials;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientFetcher;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientFetcherFactory;
import org.apache.hc.core5.http.HttpStatus;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ListTablesRequest;
import software.amazon.awssdk.services.dynamodb.model.ListTablesResponse;

import java.util.List;

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
            ZTSDynamoDBClientSettingsFactory ztsDynamoDBClientSettingsFactory = new ZTSDynamoDBClientSettingsFactory(keyStore);
            clientAndCreds = dynamoDBClientFetcher.getDynamoDBClient(null,
                    ztsDynamoDBClientSettingsFactory.getDynamoDBClientSettings(false));
            DynamoDbClient dynamoDbClient = clientAndCreds.getDynamoDbClient();

            // Get list of tables and verify our table appears
            boolean tableFound = dynamoDbTablePresent(dynamoDbClient);

            if (!tableFound) {
                throw new StatusCheckException(HttpStatus.SC_OK, "Table named " + tableName + " wasn't found in DynamoDB");
            }
        } catch (StatusCheckException ex) {
            throw ex;
        } catch (Throwable ex) {
            throw new StatusCheckException(ex);
        } finally {
            if (clientAndCreds != null) {
                clientAndCreds.close();
            }
        }
    }

    DynamoDBClientFetcher getDynamoDBClientFetcher() {
        return DynamoDBClientFetcherFactory.getDynamoDBClientFetcher();
    }

    boolean dynamoDbTablePresent(DynamoDbClient ddb) {
        boolean moreTables = true;
        String lastEvaluatedTableName = null;

        while (moreTables) {
            ListTablesRequest request = ListTablesRequest.builder()
                    .limit(100)
                    .exclusiveStartTableName(lastEvaluatedTableName)
                    .build();

            ListTablesResponse response = ddb.listTables(request);
            List<String> tables = response.tableNames();

            for (String table : tables) {
                if (tableName.equals(table)) {
                    return true;
                }
            }

            lastEvaluatedTableName = response.lastEvaluatedTableName();
            moreTables = lastEvaluatedTableName != null;
        }
        return false;
    }
}
