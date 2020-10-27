package com.yahoo.athenz.zts.cert.impl;

import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.ItemUtils;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.yahoo.athenz.zts.ZTSTestUtils;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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
        List<Item> allItems = Arrays.asList(itemNoCurrentTime, itemEmptyCurrentTime, itemFiveDaysAgo, itemThreeDaysAgo);

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
        List<Item> allItems = Arrays.asList(itemThreeDaysAgo);
        DynamoDBNotificationsHelper dynamoDBNotificationsHelper = new DynamoDBNotificationsHelper();

        assertTrue(dynamoDBNotificationsHelper.isMostUpdatedRecordBasedOnAttribute(itemThreeDaysAgo, allItems, "currentTime", "primaryKey"));
    }
}
