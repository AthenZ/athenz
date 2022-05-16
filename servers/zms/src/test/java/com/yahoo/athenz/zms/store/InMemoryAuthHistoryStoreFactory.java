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

package com.yahoo.athenz.zms.store;

import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.impl.DynamoDBAuthHistoryStore;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import java.net.URI;

public class InMemoryAuthHistoryStoreFactory implements AuthHistoryStoreFactory {

    public final static String AUTH_HISTORY_IN_MEM_TABLE_NAME = "Athenz-Auth-History";

    @Override
    public AuthHistoryStore create() {
        DynamoDbClient dynamoDB = DynamoDbClient
                .builder()
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create("http://localhost:3312"))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("FAKE", "FAKE")))
                .build();

        createTable(dynamoDB, AUTH_HISTORY_IN_MEM_TABLE_NAME);
        return new DynamoDBAuthHistoryStore(AUTH_HISTORY_IN_MEM_TABLE_NAME, dynamoDB);
    }

    private static void createTable(DynamoDbClient dynamoDbClient, String tableName) {
        CreateTableRequest createTableRequest = CreateTableRequest.builder()
                .attributeDefinitions(
                        AttributeDefinition.builder()
                                .attributeName("domain")
                                .attributeType(ScalarAttributeType.S.toString())
                                .build(),
                        AttributeDefinition.builder()
                                .attributeName("principal")
                                .attributeType(ScalarAttributeType.S)
                                .build()
                )
                .keySchema(
                        KeySchemaElement.builder()
                                .attributeName("domain")
                                .keyType(KeyType.HASH)
                                .build(),
                        KeySchemaElement.builder()
                                .attributeName("principal")
                                .keyType(KeyType.RANGE)
                                .build())
                .billingMode(BillingMode.PAY_PER_REQUEST)
                .tableName(tableName)
                .build();

        try {
            dynamoDbClient.createTable(createTableRequest);
        } catch (ResourceInUseException resourceInUseException) {

        }
    }
}
