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

package io.athenz.server.aws.common.cert.impl;

import io.athenz.server.aws.common.ServerCommonTestUtils;
import io.athenz.server.aws.common.utils.RetryDynamoDBCommand;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ProvisionedThroughputExceededException;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemResponse;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.testng.Assert.*;
import static org.mockito.ArgumentMatchers.any;

public class DynamoDBNotificationsHelperTest {

    @Test
    public void testIsMostUpdatedHostRecord() {
        Date now = new Date(1591706189000L);
        long nowL = now.getTime();
        long threeDaysAgo = nowL - 3 * 24 * 60 * 60 * 1000;
        long fiveDaysAgo = nowL - 5 * 24 * 60 * 60 * 1000;

        Map<String, AttributeValue> noCurrentTime = ServerCommonTestUtils.generateAttributeValues(
                "home.test.service2",
                "testInstance2",
                null,
                null,
                null,
                null,
                "testHost1");

        Map<String, AttributeValue> emptyCurrentTime = ServerCommonTestUtils.generateAttributeValues(
                "home.test.service2",
                "testInstance2",
                "",
                null,
                null,
                null,
                "testHost1");

        Map<String, AttributeValue> threeDaysAgoMap = ServerCommonTestUtils.generateAttributeValues(
                "home.test.service4",
                "testInstance4",
                Long.toString(threeDaysAgo),
                Long.toString(threeDaysAgo),
                "testServer",
                null,
                "testHost1");

        Map<String, AttributeValue> fiveDaysAgoMap = ServerCommonTestUtils.generateAttributeValues(
                "home.test.service3",
                "testInstance3",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost1");

        List<Map<String, AttributeValue>> allItems = Arrays.asList(emptyCurrentTime, fiveDaysAgoMap,
                threeDaysAgoMap, noCurrentTime);

        DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();

        assertFalse(dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(fiveDaysAgoMap,
                allItems, "currentTime", "primaryKey"));
        assertFalse(dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(noCurrentTime,
                allItems, "currentTime", "primaryKey"));
        assertFalse(dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(emptyCurrentTime,
                allItems, "currentTime", "primaryKey"));
        assertTrue(dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(threeDaysAgoMap,
                allItems, "currentTime", "primaryKey"));
    }

    @Test
    public void testIsMostUpdatedHostRecordSingleRecord() {
        Date now = new Date(1591706189000L);
        long nowL = now.getTime();
        long threeDaysAgo = nowL - 3 * 24 * 60 * 60 * 1000;

        Map<String, AttributeValue> threeDaysAgoMap = ServerCommonTestUtils.generateAttributeValues(
                "home.test.service4",
                "testInstance4",
                Long.toString(threeDaysAgo),
                Long.toString(threeDaysAgo),
                "testServer",
                null,
                "testHost1");

        List<Map<String, AttributeValue>> allItems = Collections.singletonList(threeDaysAgoMap);
        DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();

        assertTrue(dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(threeDaysAgoMap,
                allItems, "currentTime", "primaryKey"));
    }

    @Test
    public void testUpdateLastNotifiedItem() throws TimeoutException, InterruptedException {
        Date now = new Date(1591706189000L);
        long lastNotifiedTime = now.getTime();
        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);
        long fiveDaysAgo = lastNotifiedTime - 5 * 24 * 60 * 60 * 1000;

        DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();

        Map<String, AttributeValue> reNotified = ServerCommonTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");

        DynamoDbClient dynamoDbClient = Mockito.mock(DynamoDbClient.class);
        UpdateItemResponse response = UpdateItemResponse.builder().attributes(reNotified).build();
        Mockito.when(dynamoDbClient.updateItem(any(UpdateItemRequest.class))).thenReturn(response);
        Map<String, AttributeValue> updatedItem = dynamoDBNotificationsHelper.updateLastNotifiedItem(
                "lastNotifiedServer", lastNotifiedTime, yesterday, reNotified, "primaryKey",
                "tableName", dynamoDbClient);

        assertEquals(updatedItem, reNotified);
    }

    @Test
    public void testUpdateLastNotifiedItemRetry() throws TimeoutException, InterruptedException {
        Date now = new Date(1591706189000L);
        long lastNotifiedTime = now.getTime();
        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);
        long fiveDaysAgo = lastNotifiedTime - 5 * 24 * 60 * 60 * 1000;

        DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();

        Map<String, AttributeValue> reNotified = ServerCommonTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");

        DynamoDbClient dynamoDbClient = Mockito.mock(DynamoDbClient.class);
        UpdateItemResponse response = UpdateItemResponse.builder().attributes(reNotified).build();
        Mockito.when(dynamoDbClient.updateItem(any(UpdateItemRequest.class)))
                .thenThrow(ProvisionedThroughputExceededException.builder().build())
                .thenReturn(response);

        Map<String, AttributeValue> updatedItem = dynamoDBNotificationsHelper.updateLastNotifiedItem(
                "lastNotifiedServer", lastNotifiedTime, yesterday, reNotified, "primaryKey",
                "tableName", dynamoDbClient);

        assertEquals(updatedItem, reNotified);
    }

    @Test
    public void testUpdateLastNotifiedItemRetryFailed() throws InterruptedException {
        Date now = new Date(1591706189000L);
        long lastNotifiedTime = now.getTime();
        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);
        long fiveDaysAgo = lastNotifiedTime - 5 * 24 * 60 * 60 * 1000;

        System.setProperty(RetryDynamoDBCommand.ZTS_PROP_CERT_DYNAMODB_RETRIES, "2");
        System.setProperty(RetryDynamoDBCommand.ZTS_PROP_CERT_DYNAMODB_RETRIES_SLEEP_MILLIS, "1000");

        DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();
        Map<String, AttributeValue> reNotified = ServerCommonTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");

        DynamoDbClient dynamoDbClient = Mockito.mock(DynamoDbClient.class);
        Mockito.when(dynamoDbClient.updateItem(any(UpdateItemRequest.class)))
                .thenThrow(ProvisionedThroughputExceededException.builder().build());

        try {
            dynamoDBNotificationsHelper.updateLastNotifiedItem("lastNotifiedServer", lastNotifiedTime, yesterday,
                    reNotified, "primaryKey", "tableName", dynamoDbClient);
            fail();
        } catch (TimeoutException ex) {
            assertEquals(ex.getMessage(), "Failed too many retries. Check table provisioned throughput settings.");
        }

        System.clearProperty(RetryDynamoDBCommand.ZTS_PROP_CERT_DYNAMODB_RETRIES);
        System.clearProperty(RetryDynamoDBCommand.ZTS_PROP_CERT_DYNAMODB_RETRIES_SLEEP_MILLIS);
    }
}
