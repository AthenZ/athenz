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
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import java.io.IOException;

import static org.testng.Assert.assertEquals;

public class DynamoDBClientAndCredentialsTest {

    @Test
    public void testDynamoDBClientAndCredentials() throws IOException {

        DynamoDbClient dynamoDbClient = Mockito.mock(DynamoDbClient.class);
        Mockito.doNothing().when(dynamoDbClient).close();
        DynamoDbAsyncClient dynamoDbAsyncClient = Mockito.mock(DynamoDbAsyncClient.class);
        Mockito.doNothing().when(dynamoDbAsyncClient).close();
        AWSCredentialsProviderImplV2 credentialsProvider = Mockito.mock(AWSCredentialsProviderImplV2.class);
        Mockito.doNothing().when(credentialsProvider).close();
        DynamoDBClientAndCredentials dynamoDBClientAndCredentials =
                new DynamoDBClientAndCredentials(dynamoDbClient, dynamoDbAsyncClient, credentialsProvider);
        assertEquals(dynamoDbClient, dynamoDBClientAndCredentials.getDynamoDbClient());
        assertEquals(dynamoDbAsyncClient, dynamoDBClientAndCredentials.getDynamoDbAsyncClient());
        dynamoDBClientAndCredentials.close();
    }

    @Test
    public void testDynamoDBClientAndCredentialsNullProvider() {

        DynamoDbClient dynamoDbClient = Mockito.mock(DynamoDbClient.class);
        Mockito.doNothing().when(dynamoDbClient).close();
        DynamoDbAsyncClient dynamoDbAsyncClient = Mockito.mock(DynamoDbAsyncClient.class);
        Mockito.doNothing().when(dynamoDbAsyncClient).close();
        DynamoDBClientAndCredentials dynamoDBClientAndCredentials =
                new DynamoDBClientAndCredentials(dynamoDbClient, dynamoDbAsyncClient, null);
        assertEquals(dynamoDbClient, dynamoDBClientAndCredentials.getDynamoDbClient());
        assertEquals(dynamoDbAsyncClient, dynamoDBClientAndCredentials.getDynamoDbAsyncClient());
        dynamoDBClientAndCredentials.close();
    }

    @Test
    public void testDynamoDBClientAndCredentialsException() throws IOException {

        DynamoDbClient dynamoDbClient = Mockito.mock(DynamoDbClient.class);
        Mockito.doNothing().when(dynamoDbClient).close();
        DynamoDbAsyncClient dynamoDbAsyncClient = Mockito.mock(DynamoDbAsyncClient.class);
        Mockito.doNothing().when(dynamoDbAsyncClient).close();
        AWSCredentialsProviderImplV2 credentialsProvider = Mockito.mock(AWSCredentialsProviderImplV2.class);
        Mockito.doThrow(new IllegalArgumentException()).when(credentialsProvider).close();
        DynamoDBClientAndCredentials dynamoDBClientAndCredentials =
                new DynamoDBClientAndCredentials(dynamoDbClient, dynamoDbAsyncClient, credentialsProvider);
        assertEquals(dynamoDbClient, dynamoDBClientAndCredentials.getDynamoDbClient());
        assertEquals(dynamoDbAsyncClient, dynamoDBClientAndCredentials.getDynamoDbAsyncClient());
        dynamoDBClientAndCredentials.close();
    }
}
