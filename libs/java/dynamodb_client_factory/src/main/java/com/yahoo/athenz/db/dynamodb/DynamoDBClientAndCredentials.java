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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.yahoo.athenz.zts.AWSCredentialsProviderImpl;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;

public class DynamoDBClientAndCredentials {
    private final AmazonDynamoDB amazonDynamoDB;
    private final DynamoDbAsyncClient amazonDynamoAsyncDB;
    private final AWSCredentialsProviderImpl awsCredentialsProvider;

    public DynamoDBClientAndCredentials(AmazonDynamoDB amazonDynamoDB, DynamoDbAsyncClient amazonDynamoAsyncDB, AWSCredentialsProviderImpl awsCredentialsProvider) {
        this.amazonDynamoDB = amazonDynamoDB;
        this.amazonDynamoAsyncDB = amazonDynamoAsyncDB;
        this.awsCredentialsProvider = awsCredentialsProvider;
    }

    public AmazonDynamoDB getAmazonDynamoDB() {
        return amazonDynamoDB;
    }

    public DynamoDbAsyncClient getAmazonDynamoAsyncDB() {
        return amazonDynamoAsyncDB;
    }

    public AWSCredentialsProviderImpl getAwsCredentialsProvider() {
        return awsCredentialsProvider;
    }
}
