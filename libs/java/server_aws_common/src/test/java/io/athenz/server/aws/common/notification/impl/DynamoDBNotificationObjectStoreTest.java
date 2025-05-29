/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.athenz.server.aws.common.notification.impl;

import com.yahoo.athenz.common.server.ServerResourceException;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.core.pagination.sync.SdkIterable;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.Page;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.enhanced.dynamodb.model.PutItemEnhancedRequest;

import java.util.Iterator;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collector;
import java.util.stream.Stream;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

public class DynamoDBNotificationObjectStoreTest {

    @Test
    public void testRegisterReviewObjects() throws ServerResourceException {

        DynamoDbTable<DynamoDBNotificationObjectStoreRecord> recordTable = Mockito.mock(DynamoDbTable.class);
        Mockito.doNothing().when(recordTable).putItem(Mockito.any(PutItemEnhancedRequest.class));
        DynamoDBNotificationObjectStore store = new DynamoDBNotificationObjectStore(recordTable);

        // the call should succeed
        store.registerReviewObjects("user.joe", List.of("athenz:role.role1"));
    }

    @Test
    public void testRegisterReviewObjectsException() {

        DynamoDbTable<DynamoDBNotificationObjectStoreRecord> recordTable = Mockito.mock(DynamoDbTable.class);
        Mockito.doThrow(new RuntimeException("DynamoDB Error")).when(recordTable)
                .putItem(Mockito.any(DynamoDBNotificationObjectStoreRecord.class));
        DynamoDBNotificationObjectStore store = new DynamoDBNotificationObjectStore(recordTable);

        // second call should throw an exception
        try {
            store.registerReviewObjects("user.joe", List.of("athenz:role.role2"));
            fail();
        } catch (ServerResourceException ex) {
            assert ex.getMessage().contains("DynamoDB Error");
        }
    }

    @Test
    public void testGetReviewObjects() throws ServerResourceException {

        DynamoDbTable<DynamoDBNotificationObjectStoreRecord> recordTable = Mockito.mock(DynamoDbTable.class);
        PageIterable<DynamoDBNotificationObjectStoreRecord> pageIterable = Mockito.mock(PageIterable.class);
        SdkIterable<DynamoDBNotificationObjectStoreRecord> sdkIterable = Mockito.mock(SdkIterable.class);
        Mockito.when(recordTable.query(Mockito.any(Consumer.class))).thenReturn(pageIterable);
        Mockito.when(pageIterable.items()).thenReturn(sdkIterable);
        Iterator<DynamoDBNotificationObjectStoreRecord> iterator = Mockito.mock(Iterator.class);
        Mockito.when(sdkIterable.iterator()).thenReturn(iterator);
        Mockito.when(iterator.hasNext()).thenReturn(true, true, false);

        DynamoDBNotificationObjectStoreRecord record1 = new DynamoDBNotificationObjectStoreRecord();
        record1.setPrincipalName("user.joe");
        record1.setObjectArn("athenz:role.role1");
        record1.setTtl(System.currentTimeMillis() / 1000 + 30 * 24 * 60 * 60); // 30 days TTL
        DynamoDBNotificationObjectStoreRecord record2 = new DynamoDBNotificationObjectStoreRecord();
        record2.setPrincipalName("user.joe");
        record2.setObjectArn("athenz:role.role2");
        record2.setTtl(System.currentTimeMillis() / 1000 + 30 * 24 * 60 * 60); // 30 days TTL
        Mockito.when(iterator.next()).thenReturn(record1).thenReturn(record2);

        DynamoDBNotificationObjectStore store = new DynamoDBNotificationObjectStore(recordTable);
        List<String> reviewObjects = store.getReviewObjects("user.joe");
        assertEquals(reviewObjects, List.of("athenz:role.role1", "athenz:role.role2"));
    }

    @Test
    public void testGetReviewsObjectException() {
        DynamoDbTable<DynamoDBNotificationObjectStoreRecord> recordTable = Mockito.mock(DynamoDbTable.class);
        Mockito.when(recordTable.query(Mockito.any(Consumer.class)))
                .thenThrow(new RuntimeException("DynamoDB Error"));

        DynamoDBNotificationObjectStore store = new DynamoDBNotificationObjectStore(recordTable);

        try {
            store.getReviewObjects("user.joe");
        } catch (ServerResourceException ex) {
            assert ex.getMessage().contains("DynamoDB Error");
            assertEquals(ex.getCode(), ServerResourceException.INTERNAL_SERVER_ERROR);
        }
    }

    @Test
    public void testRemovePrincipal() throws ServerResourceException {
        DynamoDbTable<DynamoDBNotificationObjectStoreRecord> recordTable = Mockito.mock(DynamoDbTable.class);
        PageIterable<DynamoDBNotificationObjectStoreRecord> pageIterable = Mockito.mock(PageIterable.class);
        SdkIterable<DynamoDBNotificationObjectStoreRecord> sdkIterable = Mockito.mock(SdkIterable.class);
        Mockito.when(recordTable.query(Mockito.any(Consumer.class))).thenReturn(pageIterable);
        Mockito.when(pageIterable.items()).thenReturn(sdkIterable);
        Iterator<DynamoDBNotificationObjectStoreRecord> iterator = Mockito.mock(Iterator.class);
        Mockito.when(sdkIterable.iterator()).thenReturn(iterator);
        Mockito.when(iterator.hasNext()).thenReturn(true, false);

        DynamoDBNotificationObjectStoreRecord record = new DynamoDBNotificationObjectStoreRecord();
        record.setPrincipalName("user.joe");
        record.setObjectArn("athenz:role.role1");
        record.setTtl(System.currentTimeMillis() / 1000 + 30 * 24 * 60 * 60); // 30 days TTL
        Mockito.when(iterator.next()).thenReturn(record);

        DynamoDBNotificationObjectStore store = new DynamoDBNotificationObjectStore(recordTable);
        store.removePrincipal("user.joe");

        // Verify that the delete operation was called for each record
        Mockito.verify(recordTable, Mockito.times(1)).deleteItem(Mockito.any(Key.class));
    }

    @Test
    public void testRemovePrincipalException() {
        DynamoDbTable<DynamoDBNotificationObjectStoreRecord> recordTable = Mockito.mock(DynamoDbTable.class);
        Mockito.when(recordTable.query(Mockito.any(Consumer.class)))
                .thenThrow(new RuntimeException("DynamoDB Error"));

        DynamoDBNotificationObjectStore store = new DynamoDBNotificationObjectStore(recordTable);

        try {
            store.removePrincipal("user.joe");
        } catch (ServerResourceException ex) {
            assert ex.getMessage().contains("DynamoDB Error");
            assertEquals(ex.getCode(), ServerResourceException.INTERNAL_SERVER_ERROR);
        }
    }

    @Test
    public void testDeregisterReviewObject() throws ServerResourceException {
        DynamoDbTable<DynamoDBNotificationObjectStoreRecord> recordTable = Mockito.mock(DynamoDbTable.class);
        DynamoDbIndex<DynamoDBNotificationObjectStoreRecord> index = Mockito.mock(DynamoDbIndex.class);

        Mockito.when(recordTable.index(DynamoDBNotificationObjectStoreRecord.DYNAMODB_OBJECT_ARN_INDEX_NAME)).thenReturn(index);
        SdkIterable<Page<DynamoDBNotificationObjectStoreRecord>> sdkIterable = Mockito.mock(SdkIterable.class);
        Mockito.when(index.query(Mockito.any(Consumer.class))).thenReturn(sdkIterable);

        Stream<Page<DynamoDBNotificationObjectStoreRecord>> pageStream = Mockito.mock(Stream.class);
        Mockito.when(sdkIterable.stream()).thenReturn(pageStream);

        Stream<List<DynamoDBNotificationObjectStoreRecord>> listStream = Mockito.mock(Stream.class);
        Mockito.when(pageStream.map(Mockito.any(Function.class))).thenReturn(listStream);

        Stream<DynamoDBNotificationObjectStoreRecord> stream = Mockito.mock(Stream.class);
        Mockito.when(listStream.flatMap(Mockito.any(Function.class))).thenReturn(stream);

        Stream<String> stringStream = Mockito.mock(Stream.class);
        Mockito.when(stream.map(Mockito.any(Function.class))).thenReturn(stringStream);

        Mockito.when(stringStream.collect(Mockito.any(Collector.class))).thenReturn(List.of("user.joe", "user.john"));

        DynamoDBNotificationObjectStore store = new DynamoDBNotificationObjectStore(recordTable);
        store.deregisterReviewObject("athenz:role.role1");

        // Verify that the delete operation was called for each record
        Mockito.verify(recordTable, Mockito.times(2)).deleteItem(Mockito.any(Key.class));
    }

    @Test
    public void testDeregisterReviewObjectException() {
        DynamoDbTable<DynamoDBNotificationObjectStoreRecord> recordTable = Mockito.mock(DynamoDbTable.class);
        DynamoDbIndex<DynamoDBNotificationObjectStoreRecord> index = Mockito.mock(DynamoDbIndex.class);

        Mockito.when(recordTable.index(DynamoDBNotificationObjectStoreRecord.DYNAMODB_OBJECT_ARN_INDEX_NAME)).thenReturn(index);
        Mockito.when(index.query(Mockito.any(Consumer.class)))
                .thenThrow(new RuntimeException("DynamoDB Error"));

        DynamoDBNotificationObjectStore store = new DynamoDBNotificationObjectStore(recordTable);

        try {
            store.deregisterReviewObject("athenz:role.role1");
        } catch (ServerResourceException ex) {
            assert ex.getMessage().contains("DynamoDB Error");
            assertEquals(ex.getCode(), ServerResourceException.INTERNAL_SERVER_ERROR);
        }
    }
}
