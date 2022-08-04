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

import com.google.common.collect.Iterables;
import com.yahoo.athenz.syncer.auth.history.AuthHistoryDynamoDBRecord;
import com.yahoo.athenz.syncer.auth.history.AuthHistorySender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbAsyncTable;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedAsyncClient;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteResult;
import software.amazon.awssdk.enhanced.dynamodb.model.WriteBatch;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class DynamoDBAuthHistorySender implements AuthHistorySender {
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBAuthHistorySender.class);
    public static final String PROP_TABLE_NAME_DEFAULT = "Athenz-Auth-History";
    public static final String PROP_TABLE_NAME = "auth_history_syncer.table_name";
    public static final String URI_DOMAIN_INDEX_NAME = "uriDomain-index";
    public static final String PRINCIPAL_DOMAIN_INDEX_NAME = "principalDomain-index";
    public static final String PROP_CREATE_TABLE = "auth_history_syncer.create_table";
    public static final String PROP_CREATE_TABLE_DEFAULT = "false";
    private static final int MAX_WRITES_SINGLE_BATCH = 25;
    private static final int MAX_RETRIES = 8;

    private final DynamoDbEnhancedAsyncClient enhancedClient;
    private final DynamoDbAsyncTable<AuthHistoryDynamoDBRecord> mappedTable;

    public DynamoDBAuthHistorySender(DynamoDbAsyncClient dynamoDB) throws InterruptedException {
        enhancedClient = DynamoDbEnhancedAsyncClient.builder()
                .dynamoDbClient(dynamoDB)
                .build();

        String tableName = System.getProperty(PROP_TABLE_NAME, PROP_TABLE_NAME_DEFAULT);
        if (Boolean.parseBoolean(System.getProperty(PROP_CREATE_TABLE, PROP_CREATE_TABLE_DEFAULT))) {
            createTableIfNotExists(dynamoDB, tableName);
        }
        this.mappedTable = enhancedClient.table(tableName, TableSchema.fromBean(AuthHistoryDynamoDBRecord.class));
    }

    public DynamoDBAuthHistorySender(DynamoDbEnhancedAsyncClient enhancedClient, DynamoDbAsyncTable<AuthHistoryDynamoDBRecord> mappedTable) {
        this.enhancedClient = enhancedClient;
        this.mappedTable = mappedTable;
    }

    @Override
    public void pushRecords(Set<AuthHistoryDynamoDBRecord> logs) throws RuntimeException, ExecutionException, InterruptedException {
        LOGGER.info("Started Pushing to DB {} records", logs.size());
        Iterable<List<AuthHistoryDynamoDBRecord>> batchPartitions = splitToBatchSizePartitions(logs);
        List<CompletableFuture<BatchWriteResult>> futures = new ArrayList<>();
        batchPartitions.forEach(partition -> {
            futures.add(putBatchPartition(partition, 1));
        });

        futures.forEach(CompletableFuture::join);
        for (CompletableFuture<BatchWriteResult> future : futures) {
            if (future.isCompletedExceptionally()) {
                throw new RuntimeException("DynamoDB put completed exceptionally");
            }
            BatchWriteResult batchWriteResult = future.get();
            List<AuthHistoryDynamoDBRecord> authHistoryDynamoDBRecords = batchWriteResult.unprocessedPutItemsForTable(mappedTable);
            if (authHistoryDynamoDBRecords != null && !authHistoryDynamoDBRecords.isEmpty()) {
                throw new RuntimeException("Failed to write " + authHistoryDynamoDBRecords.size() + " records");
            }
        }
        LOGGER.info("Finished Pushing to DB {} records", logs.size());
    }

    private static void createTableIfNotExists(DynamoDbAsyncClient dynamoDbAsyncClient, String tableName) throws InterruptedException {
        GlobalSecondaryIndex principalDomainIndex = GlobalSecondaryIndex.builder()
                .indexName(PRINCIPAL_DOMAIN_INDEX_NAME)
                .keySchema(
                        KeySchemaElement.builder()
                                .attributeName("principalDomain")
                                .keyType(KeyType.HASH)
                                .build())
                .projection(p -> p.projectionType(ProjectionType.ALL))
                .build();

        GlobalSecondaryIndex uriDomainIndex = GlobalSecondaryIndex.builder()
                .indexName(URI_DOMAIN_INDEX_NAME)
                .keySchema(
                        KeySchemaElement.builder()
                                .attributeName("uriDomain")
                                .keyType(KeyType.HASH)
                                .build())
                .projection(p -> p.projectionType(ProjectionType.ALL))
                .build();

        CreateTableRequest createTableRequest = CreateTableRequest.builder()
                .attributeDefinitions(
                        AttributeDefinition.builder()
                                .attributeName("primaryKey")
                                .attributeType(ScalarAttributeType.S.toString())
                                .build(),
                        AttributeDefinition.builder()
                                .attributeName("uriDomain")
                                .attributeType(ScalarAttributeType.S.toString())
                                .build(),
                        AttributeDefinition.builder()
                                .attributeName("principalDomain")
                                .attributeType(ScalarAttributeType.S.toString())
                                .build()
                )
                .keySchema(
                        KeySchemaElement.builder()
                                .attributeName("primaryKey")
                                .keyType(KeyType.HASH)
                                .build())
                .billingMode(BillingMode.PAY_PER_REQUEST)
                .tableName(tableName)
                .globalSecondaryIndexes(principalDomainIndex, uriDomainIndex)
                .build();
        try {
            LOGGER.info("Trying to create table: {}", tableName);
            dynamoDbAsyncClient.createTable(createTableRequest).get();
        } catch (ExecutionException | DynamoDbException ex) {
            LOGGER.error("Table {} creation failed. Error: {}", tableName, ex.getMessage(), ex);
            // It is possible that the table already exists so if creation fails we will only log the error.
            // If the table doesn't exist, we will fail later during push.
        }

        TimeToLiveSpecification timeToLiveSpecification = TimeToLiveSpecification.builder()
                .attributeName("ttl")
                .enabled(true)
                .build();
        UpdateTimeToLiveRequest updateTimeToLiveRequest = UpdateTimeToLiveRequest
                .builder()
                .tableName(tableName)
                .timeToLiveSpecification(timeToLiveSpecification)
                .build();
        try {
            dynamoDbAsyncClient.updateTimeToLive(updateTimeToLiveRequest).get();
            LOGGER.info("Table {} TTL enabled successfully", tableName);
        } catch (ExecutionException | DynamoDbException ex) {
            LOGGER.error("Table {} ttl update failed. Error: {}", tableName, ex.getMessage(), ex);
        }
    }

    private CompletableFuture<BatchWriteResult> putBatchPartition(final List<AuthHistoryDynamoDBRecord> batchPartition, final int retryCount) {
        if (retryCount == MAX_RETRIES) {
            LOGGER.error("Failed to write to DB after {} retries", retryCount);
            return batchWriteMaxFailuresResult(retryCount);
        }

        CompletableFuture<BatchWriteResult> batchWriteResultCompletableFuture = getBatchWriteResultCompletableFuture(batchPartition);
        retryIfItemsRemaining(retryCount, batchWriteResultCompletableFuture);

        return batchWriteResultCompletableFuture;
    }

    private CompletableFuture<BatchWriteResult> batchWriteMaxFailuresResult(int retryCount) {
        CompletableFuture<BatchWriteResult> failResult = new CompletableFuture<>();
        String error = "Failed to write batch for " + retryCount + " times";
        LOGGER.error(error);
        failResult.completeExceptionally(new RuntimeException(error));
        return failResult;
    }

    private void retryIfItemsRemaining(int retryCount, CompletableFuture<BatchWriteResult> batchWriteResultCompletableFuture) {
        batchWriteResultCompletableFuture.thenApply(result -> {
            List<AuthHistoryDynamoDBRecord> unprocessedPutItems = result.unprocessedPutItemsForTable(mappedTable);
            if (unprocessedPutItems != null && !unprocessedPutItems.isEmpty()) {
                try {
                    TimeUnit.SECONDS.sleep(retryCount * 2);
                } catch (InterruptedException e) {
                    CompletableFuture<BatchWriteResult> failResult = new CompletableFuture<>();
                    String error = "Failed to write batch for " + retryCount + " times due to InterruptedException: " + e.getMessage();
                    LOGGER.error(error);
                    failResult.completeExceptionally(new RuntimeException(error));
                    return failResult;
                }
                return putBatchPartition(unprocessedPutItems, retryCount + 1);
            }
            return result;
        });
    }

    private CompletableFuture<BatchWriteResult> getBatchWriteResultCompletableFuture(List<AuthHistoryDynamoDBRecord> batchPartition) {
        WriteBatch.Builder<AuthHistoryDynamoDBRecord> writeBatchBuilder = WriteBatch.builder(AuthHistoryDynamoDBRecord.class).mappedTableResource(mappedTable);
        batchPartition.forEach(record -> {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Writing record: {}", record.toString());
            }
            writeBatchBuilder.addPutItem(record);
        });
        WriteBatch writeBatch = writeBatchBuilder.build();
        BatchWriteItemEnhancedRequest writeItemEnhancedRequest = BatchWriteItemEnhancedRequest.builder().addWriteBatch(writeBatch).build();
        CompletableFuture<BatchWriteResult> batchWriteResultCompletableFuture = enhancedClient.batchWriteItem(writeItemEnhancedRequest);
        return batchWriteResultCompletableFuture;
    }

    private Iterable<List<AuthHistoryDynamoDBRecord>> splitToBatchSizePartitions(Set<AuthHistoryDynamoDBRecord> logs) {
        return Iterables.partition(logs, MAX_WRITES_SINGLE_BATCH);
    }

}
