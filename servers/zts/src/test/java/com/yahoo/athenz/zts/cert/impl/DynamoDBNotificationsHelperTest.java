package com.yahoo.athenz.zts.cert.impl;

import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.ItemUtils;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.UpdateItemOutcome;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ProvisionedThroughputExceededException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.ZTSTestUtils;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.testng.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class DynamoDBNotificationsHelperTest {

    @Test
    public void testIsMostUpdatedHostRecord() {
        Date now = new Date(1591706189000L);
        long nowL = now.getTime();
        long threeDaysAgo = nowL - 3 * 24 * 60 * 60 * 1000;
        long fiveDaysAgo = nowL - 5 * 24 * 60 * 60 * 1000;

        Map<String, AttributeValue> noCurrentTime = ZTSTestUtils.generateAttributeValues(
                "home.test.service2",
                "testInstance2",
                null,
                null,
                null,
                null,
                "testHost1");

        Map<String, AttributeValue> emptyCurrentTime = ZTSTestUtils.generateAttributeValues(
                "home.test.service2",
                "testInstance2",
                "",
                null,
                null,
                null,
                "testHost1");

        Map<String, AttributeValue> threeDaysAgoMap = ZTSTestUtils.generateAttributeValues(
                "home.test.service4",
                "testInstance4",
                Long.toString(threeDaysAgo),
                Long.toString(threeDaysAgo),
                "testServer",
                null,
                "testHost1");

        Map<String, AttributeValue> fiveDaysAgoMap = ZTSTestUtils.generateAttributeValues(
                "home.test.service3",
                "testInstance3",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost1");

        Item itemNoCurrentTime = ItemUtils.toItem(noCurrentTime);
        Item itemEmptyCurrentTime = ItemUtils.toItem(emptyCurrentTime);
        Item itemFiveDaysAgo = ItemUtils.toItem(fiveDaysAgoMap);
        Item itemThreeDaysAgo = ItemUtils.toItem(threeDaysAgoMap);
        List<Item> allItems = Arrays.asList(itemEmptyCurrentTime, itemFiveDaysAgo, itemThreeDaysAgo, itemNoCurrentTime);

        DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();

        assertFalse(dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(itemFiveDaysAgo, allItems, "currentTime", "primaryKey"));
        assertFalse(dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(itemNoCurrentTime, allItems, "currentTime", "primaryKey"));
        assertFalse(dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(itemEmptyCurrentTime, allItems, "currentTime", "primaryKey"));
        assertTrue(dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(itemThreeDaysAgo, allItems, "currentTime", "primaryKey"));
    }

    @Test
    public void testIsMostUpdatedHostRecordSingleRecord() {
        Date now = new Date(1591706189000L);
        long nowL = now.getTime();
        long threeDaysAgo = nowL - 3 * 24 * 60 * 60 * 1000;

        Map<String, AttributeValue> threeDaysAgoMap = ZTSTestUtils.generateAttributeValues(
                "home.test.service4",
                "testInstance4",
                Long.toString(threeDaysAgo),
                Long.toString(threeDaysAgo),
                "testServer",
                null,
                "testHost1");

        Item itemThreeDaysAgo = ItemUtils.toItem(threeDaysAgoMap);
        List<Item> allItems = Collections.singletonList(itemThreeDaysAgo);
        DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();

        assertTrue(dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(itemThreeDaysAgo, allItems, "currentTime", "primaryKey"));
    }

    @Test
    public void testUpdateLastNotifiedItem() throws TimeoutException, InterruptedException {
        Date now = new Date(1591706189000L);
        long lastNotifiedTime = now.getTime();
        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);
        long fiveDaysAgo = lastNotifiedTime - 5 * 24 * 60 * 60 * 1000;

        DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();

        Map<String, AttributeValue> reNotified = ZTSTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");

        Item item = ItemUtils.toItem(reNotified);

        UpdateItemOutcome updateItemOutcome1 = Mockito.mock(UpdateItemOutcome.class);
        when(updateItemOutcome1.getItem()).thenReturn(item);
        Table table = Mockito.mock(Table.class);
        Mockito.when(table.updateItem(any(UpdateItemSpec.class))).thenReturn(updateItemOutcome1);
        Item updatedItem = dynamoDBNotificationsHelper.updateLastNotifiedItem("lastNotifiedServer", lastNotifiedTime, yesterday, item, "primaryKey", table);

        assertEquals(updatedItem, item);
    }

    @Test
    public void testUpdateLastNotifiedItemRetry() throws TimeoutException, InterruptedException {
        Date now = new Date(1591706189000L);
        long lastNotifiedTime = now.getTime();
        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);
        long fiveDaysAgo = lastNotifiedTime - 5 * 24 * 60 * 60 * 1000;

        DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();

        Map<String, AttributeValue> reNotified = ZTSTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");

        Item item = ItemUtils.toItem(reNotified);

        UpdateItemOutcome updateItemOutcome1 = Mockito.mock(UpdateItemOutcome.class);
        when(updateItemOutcome1.getItem()).thenReturn(item);
        Table table = Mockito.mock(Table.class);
        Mockito.when(table.updateItem(any(UpdateItemSpec.class))).thenThrow(new ProvisionedThroughputExceededException("Provisioned Throughput Exceeded")).thenReturn(updateItemOutcome1);
        Item updatedItem = dynamoDBNotificationsHelper.updateLastNotifiedItem("lastNotifiedServer", lastNotifiedTime, yesterday, item, "primaryKey", table);

        assertEquals(updatedItem, item);
    }

    @Test
    public void testUpdateLastNotifiedItemRetryFailed() throws InterruptedException {
        Date now = new Date(1591706189000L);
        long lastNotifiedTime = now.getTime();
        long yesterday = lastNotifiedTime - TimeUnit.DAYS.toMillis(1);
        long fiveDaysAgo = lastNotifiedTime - 5 * 24 * 60 * 60 * 1000;

        System.setProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_RETRIES, "2");
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_RETRIES_SLEEP_MILLIS, "1000");

        DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();
        Map<String, AttributeValue> reNotified = ZTSTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");

        Item item = ItemUtils.toItem(reNotified);

        UpdateItemOutcome updateItemOutcome1 = Mockito.mock(UpdateItemOutcome.class);
        when(updateItemOutcome1.getItem()).thenReturn(item);
        Table table = Mockito.mock(Table.class);
        // After getting this error twice, we stop retrying
        Mockito.when(table.updateItem(any(UpdateItemSpec.class)))
                .thenThrow(new ProvisionedThroughputExceededException("Provisioned Throughput Exceeded"))
                .thenThrow(new ProvisionedThroughputExceededException("Provisioned Throughput Exceeded"));

        try {
            dynamoDBNotificationsHelper.updateLastNotifiedItem("lastNotifiedServer", lastNotifiedTime, yesterday, item, "primaryKey", table);
            fail();
        } catch (TimeoutException ex) {
            assertEquals("Failed too many retries. Check table provisioned throughput settings.", ex.getMessage());
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_RETRIES);
        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_RETRIES_SLEEP_MILLIS);

    }
}
