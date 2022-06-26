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
import com.yahoo.athenz.zms.AuthHistoryDependencies;
import com.yahoo.athenz.zms.ResourceException;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.rdl.Timestamp;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.core.pagination.sync.SdkIterable;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.model.Page;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.testng.AssertJUnit.*;

public class DynamoDBAuthHistoryStoreConnectionTest {

    @Test
    public void testGetAuthHistory() {
        SdkIterable<Page<AuthHistoryDynamoDBRecord>> sdkIterable = Mockito.mock(SdkIterable.class);
        Stream<Page<AuthHistoryDynamoDBRecord>> stream = Mockito.mock(Stream.class);
        Stream<Object> listStream = Mockito.mock(Stream.class);
        Stream<Object> authHistoryDynamoDBRecordStream = Mockito.mock(Stream.class);
        Stream<Object> mappedRecord = Mockito.mock(Stream.class);

        Mockito.when(authHistoryDynamoDBRecordStream.map(Mockito.any())).thenReturn(mappedRecord);
        Mockito.when(listStream.flatMap(Mockito.any())).thenReturn(authHistoryDynamoDBRecordStream);
        Mockito.when(stream.map(Mockito.any())).thenReturn(listStream);
        Mockito.when(sdkIterable.stream()).thenReturn(stream);
        List<AuthHistory> recordsList = new ArrayList<>();
        AuthHistory authHistory = new AuthHistory();
        authHistory.setUriDomain("test.domain");
        authHistory.setPrincipalDomain("principal.domain");
        authHistory.setPrincipalName("principal");
        authHistory.setEndpoint("https://endpoint.com");
        authHistory.setTimestamp(null);
        authHistory.setTtl(0L);
        recordsList.add(authHistory);

        Mockito.when(mappedRecord.collect(Mockito.any())).thenReturn(recordsList);

        DynamoDbTable<AuthHistoryDynamoDBRecord> table = Mockito.mock(DynamoDbTable.class);
        DynamoDbIndex<AuthHistoryDynamoDBRecord> uriDomainIndex = Mockito.mock(DynamoDbIndex.class);
        DynamoDbIndex<AuthHistoryDynamoDBRecord> principalDomainIndex = Mockito.mock(DynamoDbIndex.class);

        Mockito.when(table.index(ZMSConsts.ZMS_DYNAMODB_URI_DOMAIN_INDEX_NAME)).thenReturn(uriDomainIndex);
        Mockito.when(table.index(ZMSConsts.ZMS_DYNAMODB_PRINCIPAL_DOMAIN_INDEX_NAME)).thenReturn(principalDomainIndex);
        Mockito.when(uriDomainIndex.query(Mockito.any(Consumer.class))).thenReturn(sdkIterable);
        Mockito.when(principalDomainIndex.query(Mockito.any(Consumer.class))).thenReturn(Mockito.mock(PageIterable.class));
        DynamoDBAuthHistoryStoreConnection dynamoDBAuthHistoryStoreConnection = new DynamoDBAuthHistoryStoreConnection(table);
        AuthHistoryDependencies authHistoryDependencies = dynamoDBAuthHistoryStoreConnection.getAuthHistory("test.domain");
        assertEquals(1, authHistoryDependencies.getIncomingDependencies().size());
        assertEquals(0, authHistoryDependencies.getOutgoingDependencies().size());
        assertEquals(authHistory, authHistoryDependencies.getIncomingDependencies().get(0));

        dynamoDBAuthHistoryStoreConnection.setOperationTimeout(0);
        dynamoDBAuthHistoryStoreConnection.close();
    }

    @Test
    public void testGetAuthHistoryException() {

        DynamoDbTable<AuthHistoryDynamoDBRecord> table = Mockito.mock(DynamoDbTable.class);
        DynamoDbIndex<AuthHistoryDynamoDBRecord> uriDomainIndex = Mockito.mock(DynamoDbIndex.class);
        DynamoDbIndex<AuthHistoryDynamoDBRecord> principalDomainIndex = Mockito.mock(DynamoDbIndex.class);
        Mockito.when(table.index(ZMSConsts.ZMS_DYNAMODB_URI_DOMAIN_INDEX_NAME)).thenReturn(uriDomainIndex);
        Mockito.when(table.index(ZMSConsts.ZMS_DYNAMODB_PRINCIPAL_DOMAIN_INDEX_NAME)).thenReturn(principalDomainIndex);

        DynamoDBAuthHistoryStoreConnection dynamoDBAuthHistoryStoreConnection = new DynamoDBAuthHistoryStoreConnection(table);
        Mockito.when(principalDomainIndex.query(Mockito.any(Consumer.class))).thenThrow(ResourceNotFoundException.builder().message("records do not exist").build());
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
