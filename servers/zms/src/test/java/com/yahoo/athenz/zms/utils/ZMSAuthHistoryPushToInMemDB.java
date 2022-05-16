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

package com.yahoo.athenz.zms.utils;

import com.google.common.collect.Iterables;
import com.yahoo.athenz.zms.store.AuthHistoryRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedAsyncClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteResult;
import software.amazon.awssdk.enhanced.dynamodb.model.WriteBatch;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class ZMSAuthHistoryPushToInMemDB {
    private static final Logger LOGGER = LoggerFactory.getLogger(ZMSAuthHistoryPushToInMemDB.class);
    private static final int MAX_WRITES_SINGLE_BATCH = 25;
    private static final int MAX_RETRIES = 8;

    private DynamoDbEnhancedAsyncClient getDynamoDBAsyncClient() {
        DynamoDbAsyncClient client = DynamoDbAsyncClient
                .builder()
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create("http://localhost:3312"))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("FAKE", "FAKE")))
                .build();

        return DynamoDbEnhancedAsyncClient.builder()
                .dynamoDbClient(client)
                .build();
    }

    public void pushToDB(Set<AuthHistoryRecord> logs, DynamoDbTable<AuthHistoryRecord> mappedTable) {
        DynamoDbEnhancedAsyncClient dynamoDBAsyncClient = getDynamoDBAsyncClient();
        LOGGER.info("Started Pushing to DB " + logs.size() + " records");
        Iterable<List<AuthHistoryRecord>> batchPartitions = splitToBatchSizePartitions(logs);
        List<CompletableFuture<BatchWriteResult>> futures = new ArrayList<>();
        batchPartitions.forEach(partition -> {
            futures.add(putBatchPartition(partition, mappedTable, dynamoDBAsyncClient, 1));
        });

        futures.forEach(CompletableFuture::join);
        LOGGER.info("Finished Pushing to DB " + logs.size() + " records");
    }

    private CompletableFuture<BatchWriteResult> putBatchPartition(final List<AuthHistoryRecord> batchPartition, DynamoDbTable<AuthHistoryRecord> mappedTable, DynamoDbEnhancedAsyncClient enhancedClient, final int retryCount) {
        if (retryCount == MAX_RETRIES) {
            return batchWriteMaxFailuresResult(retryCount);
        }

        CompletableFuture<BatchWriteResult> batchWriteResultCompletableFuture = getBatchWriteResultCompletableFuture(batchPartition, mappedTable, enhancedClient);
        retryIfItemsRemaining(retryCount, batchWriteResultCompletableFuture, mappedTable, enhancedClient);

        return batchWriteResultCompletableFuture;
    }

    private CompletableFuture<BatchWriteResult> batchWriteMaxFailuresResult(int retryCount) {
        CompletableFuture<BatchWriteResult> failResult = new CompletableFuture<>();
        String error = "Failed to write batch for " + retryCount + " times";
        LOGGER.error(error);
        failResult.completeExceptionally(new RuntimeException(error));
        return failResult;
    }

    private void retryIfItemsRemaining(int retryCount, CompletableFuture<BatchWriteResult> batchWriteResultCompletableFuture, DynamoDbTable<AuthHistoryRecord> mappedTable, DynamoDbEnhancedAsyncClient enhancedClient) {
        batchWriteResultCompletableFuture.thenApply(result -> {
            List<AuthHistoryRecord> unprocessedPutItems = result.unprocessedPutItemsForTable(mappedTable);
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
                return putBatchPartition(unprocessedPutItems, mappedTable, enhancedClient, retryCount + 1);
            }
            return result;
        });
    }

    private CompletableFuture<BatchWriteResult> getBatchWriteResultCompletableFuture(List<AuthHistoryRecord> batchPartition, DynamoDbTable<AuthHistoryRecord> mappedTable, DynamoDbEnhancedAsyncClient enhancedClient) {
        WriteBatch.Builder<AuthHistoryRecord> writeBatchBuilder = WriteBatch.builder(AuthHistoryRecord.class).mappedTableResource(mappedTable);
        batchPartition.forEach(record -> writeBatchBuilder.addPutItem(record));
        WriteBatch writeBatch = writeBatchBuilder.build();
        BatchWriteItemEnhancedRequest writeItemEnhancedRequest = BatchWriteItemEnhancedRequest.builder().addWriteBatch(writeBatch).build();
        CompletableFuture<BatchWriteResult> batchWriteResultCompletableFuture = enhancedClient.batchWriteItem(writeItemEnhancedRequest);
        return batchWriteResultCompletableFuture;
    }

    private Iterable<List<AuthHistoryRecord>> splitToBatchSizePartitions(Set<AuthHistoryRecord> logs) {
        return Iterables.partition(logs, MAX_WRITES_SINGLE_BATCH);
    }
}
