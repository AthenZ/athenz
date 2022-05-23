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

package com.yahoo.athenz.zms.store.impl.dynamodb;

import com.yahoo.athenz.zms.AuthHistory;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.core.pagination.sync.SdkIterable;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.testng.AssertJUnit.*;

public class DynamoDBAuthHistoryStoreConnectionTest {

    @Test
    public void testGetAuthHistory() {
        PageIterable<AuthHistoryDynamoDBRecord> pageIterable = Mockito.mock(PageIterable.class);
        SdkIterable<AuthHistoryDynamoDBRecord> sdkIterable = Mockito.mock(SdkIterable.class);
        Mockito.when(pageIterable.items()).thenReturn(sdkIterable);
        Stream<AuthHistoryDynamoDBRecord> stream = Mockito.mock(Stream.class);
        Mockito.when(sdkIterable.stream()).thenReturn(stream);
        List<AuthHistory> recordsList = new ArrayList<>();
        AuthHistory authHistory = new AuthHistory();
        authHistory.setDomainName("test.domain");
        authHistory.setPrincipal("principal");
        authHistory.setEndpoint("https://endpoint.com");
        authHistory.setTimestamp(null);
        authHistory.setTtl(0L);
        recordsList.add(authHistory);
        Stream<Object> mappedRecord = Mockito.mock(Stream.class);
        Mockito.when(stream.map(Mockito.any())).thenReturn(mappedRecord);
        Mockito.when(mappedRecord.collect(Mockito.any())).thenReturn(recordsList);

        DynamoDbTable<AuthHistoryDynamoDBRecord> table = Mockito.mock(DynamoDbTable.class);
        DynamoDBAuthHistoryStoreConnection dynamoDBAuthHistoryStoreConnection = new DynamoDBAuthHistoryStoreConnection(table);
        Mockito.when(table.query(Mockito.any(Consumer.class))).thenReturn(pageIterable);
        List<AuthHistory> authHistoryList = dynamoDBAuthHistoryStoreConnection.getAuthHistory("test.domain");
        assertEquals(1, authHistoryList.size());
        assertEquals(authHistory, authHistoryList.get(0));

        dynamoDBAuthHistoryStoreConnection.setOperationTimeout(0);
        dynamoDBAuthHistoryStoreConnection.close();
    }

    @Test
    public void testGetAuthHistoryException() {
        DynamoDbTable<AuthHistoryDynamoDBRecord> table = Mockito.mock(DynamoDbTable.class);
        DynamoDBAuthHistoryStoreConnection dynamoDBAuthHistoryStoreConnection = new DynamoDBAuthHistoryStoreConnection(table);
        Mockito.when(table.query(Mockito.any(Consumer.class))).thenThrow(ResourceNotFoundException.builder().message("records do not exist").build());
        try {
            dynamoDBAuthHistoryStoreConnection.getAuthHistory("test.domain");
            fail();
        } catch (ResourceException resourceException) {
            assertEquals(resourceException.getMessage(), "ResourceException (404): {code: 404, message: \"records do not exist\"}");
        }
    }

    @Test
    public void testGetAuthHistoryTimeStamp() {
        DynamoDbTable<AuthHistoryDynamoDBRecord> table = Mockito.mock(DynamoDbTable.class);
        DynamoDBAuthHistoryStoreConnection dynamoDBAuthHistoryStoreConnection = new DynamoDBAuthHistoryStoreConnection(table);
        AuthHistoryDynamoDBRecord record = new AuthHistoryDynamoDBRecord();
        record.setTimestamp("bad.format");
        assertNull(dynamoDBAuthHistoryStoreConnection.getAuthHistoryTimeStamp(record));
        record.setTimestamp("23-04-2022:20:10");
        assertNull(dynamoDBAuthHistoryStoreConnection.getAuthHistoryTimeStamp(record));
        record.setTimestamp("23/APR/2022:20:10:00");
        Timestamp authHistoryTimeStamp = dynamoDBAuthHistoryStoreConnection.getAuthHistoryTimeStamp(record);
        assertNotNull(authHistoryTimeStamp);
        assertEquals(authHistoryTimeStamp.millis(), 1650744600000L);
    }
}
