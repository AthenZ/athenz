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

import org.mockito.Mockito;
import org.testng.annotations.Test;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.yahoo.athenz.zts.AWSCredentialsProviderImpl;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;

import static org.testng.Assert.assertEquals;

public class DynamoDBClientAndCredentialsTest {

    @Test
    public void testDynamoDBClientAndCredentials() {

        AmazonDynamoDB amazonDynamoDB = Mockito.mock(AmazonDynamoDB.class);
        DynamoDbAsyncClient amazonDynamoAsyncDB = Mockito.mock(DynamoDbAsyncClient.class);
        AWSCredentialsProviderImpl awsCredentialsProvider = Mockito.mock(AWSCredentialsProviderImpl.class);

        DynamoDBClientAndCredentials dynamoDBClientAndCredentials = new DynamoDBClientAndCredentials(
                amazonDynamoDB, amazonDynamoAsyncDB, awsCredentialsProvider);

        assertEquals(amazonDynamoDB, dynamoDBClientAndCredentials.getAmazonDynamoDB());
        assertEquals(amazonDynamoAsyncDB, dynamoDBClientAndCredentials.getAmazonDynamoAsyncDB());
        assertEquals(awsCredentialsProvider, dynamoDBClientAndCredentials.getAwsCredentialsProvider());
    }
}
