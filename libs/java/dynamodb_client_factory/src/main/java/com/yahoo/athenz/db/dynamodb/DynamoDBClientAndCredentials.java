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

package com.yahoo.athenz.db.dynamodb;

import com.yahoo.athenz.zts.AWSCredentialsProviderImplV2;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;

public class DynamoDBClientAndCredentials {

    private final DynamoDbClient dynamoDbClient;
    private final DynamoDbAsyncClient dynamoDbAsyncClient;
    private final AWSCredentialsProviderImplV2 awsCredentialsProvider;

    public DynamoDBClientAndCredentials(DynamoDbClient dynamoDbClient, DynamoDbAsyncClient dynamoDbAsyncClient,
            AWSCredentialsProviderImplV2 awsCredentialsProvider) {
        this.dynamoDbClient = dynamoDbClient;
        this.dynamoDbAsyncClient = dynamoDbAsyncClient;
        this.awsCredentialsProvider = awsCredentialsProvider;
    }

    public DynamoDbClient getDynamoDbClient() {
        return dynamoDbClient;
    }

    public DynamoDbAsyncClient getDynamoDbAsyncClient() {
        return dynamoDbAsyncClient;
    }

    public void close() {
        dynamoDbClient.close();
        dynamoDbAsyncClient.close();
        if (awsCredentialsProvider != null) {
            try {
                awsCredentialsProvider.close();
            } catch (Exception ignored) {
            }
        }
    }
}
