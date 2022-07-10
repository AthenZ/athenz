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

package com.yahoo.athenz.syncer.auth.history.impl;

import com.yahoo.athenz.syncer.auth.history.AuthHistoryDynamoDBRecord;
import com.yahoo.athenz.syncer.auth.history.DynamoDbAsyncClientFactory;
import com.yahoo.athenz.syncer.auth.history.LogsParserUtils;
import org.testng.annotations.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.*;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import static com.yahoo.athenz.syncer.auth.history.impl.DynamoDBAuthHistorySender.*;
import static org.testng.AssertJUnit.*;

public class DynamoDBAuthHistorySenderTest {

    @Test
    public void testDynamoDBAuthHistorySender() throws ExecutionException, InterruptedException {
        System.setProperty(PROP_CREATE_TABLE, "true");
        LocalDynamoDbAsyncClientFactory localDynamoDbAsyncClientFactory = new LocalDynamoDbAsyncClientFactory();
        localDynamoDbAsyncClientFactory.init();
        Set<AuthHistoryDynamoDBRecord> records = new HashSet<>();
        long ttl = System.currentTimeMillis() / 1000L + (3660 * 720);
        int numberOfRecords = 10000;
        for (int i = 0; i < numberOfRecords; ++i) {
            records.add(generateRecordForTest(i, ttl));
        }
        // Push to dynamoDB
        DynamoDbAsyncClientFactory dynamoDbAsyncClientFactory = new LocalDynamoDbAsyncClientFactory();
        DynamoDBAuthHistorySender dynamoDBAuthHistorySender = new DynamoDBAuthHistorySender(dynamoDbAsyncClientFactory.create(null));
        dynamoDBAuthHistorySender.pushRecords(records);

        // Verify querying by primary ket and by the two domain indexes
        DynamoDbTable<AuthHistoryDynamoDBRecord> nonAsynctable = getNonAsyncTable(LocalDynamoDbAsyncClientFactory.port);
        verifyItemsByPrimaryKey(nonAsynctable, 100);
        verifyItemsByUriDomainINdex(nonAsynctable, 100);
        verifyItemsByPrincipalDomainINdex(nonAsynctable, 100);

        // Scan all items and verify all items are accounted for
        DynamoDbAsyncClient dynamoDb = dynamoDbAsyncClientFactory.create(null);
        DynamoDbEnhancedAsyncClient dynamoDbEnhancedAsyncClient = DynamoDbEnhancedAsyncClient.builder()
                .dynamoDbClient(dynamoDb)
                .build();
        DynamoDbAsyncTable<AuthHistoryDynamoDBRecord> table = dynamoDbEnhancedAsyncClient.table(DynamoDBAuthHistorySender.PROP_TABLE_NAME_DEFAULT, TableSchema.fromBean(AuthHistoryDynamoDBRecord.class));
        table.scan().items().subscribe(item -> {
            records.remove(new AuthHistoryDynamoDBRecord(item.getPrimaryKey(), item.getUriDomain(), item.getPrincipalDomain(), item.getPrincipalName(), item.getEndpoint(), item.getTimestamp(), item.getTtl()));
        }).get();

        assertEquals(0, records.size());
        localDynamoDbAsyncClientFactory.terminate();
        System.clearProperty(PROP_CREATE_TABLE);
    }

    @Test
    public void testDynamoDBAuthHistorySenderNoTable() throws ExecutionException, InterruptedException {

        LocalDynamoDbAsyncClientFactory localDynamoDbAsyncClientFactory = new LocalDynamoDbAsyncClientFactory();
        localDynamoDbAsyncClientFactory.init();
        Set<AuthHistoryDynamoDBRecord> records = new HashSet<>();
        long ttl = System.currentTimeMillis() / 1000L + (3660 * 720);
        int numberOfRecords = 10000;
        for (int i = 0; i < numberOfRecords; ++i) {
            records.add(generateRecordForTest(i, ttl));
        }
        // Push to dynamoDB
        DynamoDbAsyncClientFactory dynamoDbAsyncClientFactory = new LocalDynamoDbAsyncClientFactory();
        DynamoDBAuthHistorySender dynamoDBAuthHistorySender = new DynamoDBAuthHistorySender(dynamoDbAsyncClientFactory.create(null));
        try {
            dynamoDBAuthHistorySender.pushRecords(records);
            fail();
        } catch (Exception ex) {
            assertTrue(ex.getMessage().startsWith("software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException: Cannot do operations on a non-existent table (Service: DynamoDb, Status Code: 400, Request ID"));
        }
        localDynamoDbAsyncClientFactory.terminate();
    }

    private DynamoDbTable<AuthHistoryDynamoDBRecord> getNonAsyncTable(int port) {
        DynamoDbClient dbClient = DynamoDbClient
                .builder()
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create("http://localhost:" + port))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("FAKE", "FAKE")))
                .build();
        DynamoDbEnhancedClient dynamoDbEnhancedClient = DynamoDbEnhancedClient.builder()
                .dynamoDbClient(dbClient)
                .build();

        // Fetch pushed items, verify everything is there
        DynamoDbTable<AuthHistoryDynamoDBRecord> nonAsynctable = dynamoDbEnhancedClient.table(DynamoDBAuthHistorySender.PROP_TABLE_NAME_DEFAULT, TableSchema.fromBean(AuthHistoryDynamoDBRecord.class));
        return nonAsynctable;
    }

    private void verifyItemsByPrimaryKey(DynamoDbTable<AuthHistoryDynamoDBRecord> table, int numberOfRecords) {
        for (int i = 0; i < numberOfRecords; ++i) {
            QueryConditional queryConditional = QueryConditional
                    .keyEqualTo(Key.builder().partitionValue("test.domain" + i + ":" + "principalDomain" + i + ":" + "principalName" + i)
                            .build());

            List<AuthHistoryDynamoDBRecord> records = table.query(r -> r.queryConditional(queryConditional))
                    .items().stream().collect(Collectors.toList());
            assertEquals(1, records.size());
            AuthHistoryDynamoDBRecord record = records.get(0);
            assertEquals(record.getPrimaryKey(), getPrimaryKeyForTest(i));
        }
    }

    private void verifyItemsByUriDomainINdex(DynamoDbTable<AuthHistoryDynamoDBRecord> table, int numberOfRecords) {
        DynamoDbIndex<AuthHistoryDynamoDBRecord> index = table.index(URI_DOMAIN_INDEX_NAME);
        for (int i = 0; i < numberOfRecords; ++i) {
            QueryConditional queryConditional = QueryConditional
                    .keyEqualTo(Key.builder().partitionValue("test.domain" + i)
                            .build());

            List<List<AuthHistoryDynamoDBRecord>> records = index.query(r -> r.queryConditional(queryConditional))
                    .stream()
                    .map(record -> record.items())
                    .collect(Collectors.toList());
            assertEquals(records.size(), 1);
            assertEquals(records.get(0).size(), 1);
            assertEquals(records.get(0).get(0).getPrimaryKey(), getPrimaryKeyForTest(i));
        }
    }

    private void verifyItemsByPrincipalDomainINdex(DynamoDbTable<AuthHistoryDynamoDBRecord> table, int numberOfRecords) {
        DynamoDbIndex<AuthHistoryDynamoDBRecord> index = table.index(PRINCIPAL_DOMAIN_INDEX_NAME);
        for (int i = 0; i < numberOfRecords; ++i) {
            QueryConditional queryConditional = QueryConditional
                    .keyEqualTo(Key.builder().partitionValue("principalDomain" + i)
                            .build());

            List<List<AuthHistoryDynamoDBRecord>> records = index.query(r -> r.queryConditional(queryConditional))
                    .stream()
                    .map(record -> record.items())
                    .collect(Collectors.toList());
            assertEquals(records.size(), 1);
            assertEquals(records.get(0).size(), 1);
            assertEquals(records.get(0).get(0).getPrimaryKey(), getPrimaryKeyForTest(i));
        }
    }

    private AuthHistoryDynamoDBRecord generateRecordForTest(int index, long ttl) {
        String uriDomain = "test.domain" + index;
        String principalDomain = "principalDomain" + index;
        String principalName = "principalName" + index;
        String primaryKey = getPrimaryKeyForTest(index);
        return new AuthHistoryDynamoDBRecord(primaryKey, uriDomain, principalDomain, principalName, "https://endpoint" + index + ".com", "19/Apr/2022:08:00:45", ttl);
    }

    private String getPrimaryKeyForTest(int index) {
        String uriDomain = "test.domain" + index;
        String principalDomain = "principalDomain" + index;
        String principalName = "principalName" + index;
        return LogsParserUtils.generatePrimaryKey(uriDomain, principalDomain, principalName);
    }
}
