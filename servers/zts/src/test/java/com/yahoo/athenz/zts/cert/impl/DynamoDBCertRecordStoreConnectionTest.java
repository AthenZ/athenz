/*
 * Copyright 2018 Oath Inc.
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
package com.yahoo.athenz.zts.cert.impl;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.document.*;
import com.amazonaws.services.dynamodbv2.document.internal.IteratorSupport;
import com.amazonaws.services.dynamodbv2.document.spec.QuerySpec;
import com.amazonaws.services.dynamodbv2.model.AmazonDynamoDBException;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.zts.utils.DynamoDBUtils;
import org.eclipse.jetty.util.StringUtil;
import org.mockito.*;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;

public class DynamoDBCertRecordStoreConnectionTest {

    private final String tableName = "cert-table";
    private final String indexName = "cert-table-index";

    @Mock private DynamoDB dynamoDB = Mockito.mock(DynamoDB.class);
    @Mock private Table table = Mockito.mock(Table.class);
    @Mock private Index index = Mockito.mock(Index.class);
    @Mock private Item item = Mockito.mock(Item.class);
    @Mock private PutItemOutcome putOutcome = Mockito.mock(PutItemOutcome.class);
    @Mock private DeleteItemOutcome deleteOutcome = Mockito.mock(DeleteItemOutcome.class);
    @Mock private UpdateItemOutcome updateOutcome = Mockito.mock(UpdateItemOutcome.class);


    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        Mockito.doReturn(table).when(dynamoDB).getTable(tableName);
        Mockito.doReturn(index).when(table).getIndex(indexName);
    }

    private DynamoDBCertRecordStoreConnection getDBConnection() {
        return new DynamoDBCertRecordStoreConnection(dynamoDB, tableName, indexName);
    }

    @Test
    public void testGetX509CertRecord() {

        Date now = new Date();
        long tstamp = mockNonNullableColumns(now);
        Mockito.doReturn(tstamp).when(item).getLong("lastNotifiedTime");
        Mockito.doReturn(tstamp).when(item).get("lastNotifiedTime");
        Mockito.doReturn("last-notified-server").when(item).getString("lastNotifiedServer");
        Mockito.doReturn(tstamp).when(item).getLong("expiryTime");
        Mockito.doReturn(tstamp).when(item).get("expiryTime");
        Mockito.doReturn("hostname").when(item).getString("hostName");

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        dbConn.setOperationTimeout(10);
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");

        assertNonNullableColumns(now, certRecord);
        assertEquals(certRecord.getLastNotifiedTime(), now);
        assertEquals(certRecord.getLastNotifiedServer(), "last-notified-server");
        assertEquals(certRecord.getExpiryTime(), now);
        assertEquals(certRecord.getHostName(), "hostname");

        dbConn.close();
    }

    @Test
    public void testGetX509CertRecordNullableColumns() {

        Date now = new Date();
        mockNonNullableColumns(now);
        Mockito.doReturn(true).when(item).isNull("lastNotifiedTime");
        Mockito.doReturn(true).when(item).isNull("lastNotifiedServer");
        Mockito.doReturn(true).when(item).isNull("expiryTime");
        Mockito.doReturn(true).when(item).isNull("hostName");

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        dbConn.setOperationTimeout(10);
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");

        assertNonNullableColumns(now, certRecord);
        assertNull(certRecord.getLastNotifiedTime());
        assertNull(certRecord.getLastNotifiedServer());
        assertNull(certRecord.getExpiryTime());
        assertNull(certRecord.getHostName());

        dbConn.close();
    }

    @Test
    public void testGetX509CertRecordNotFoundNull() {

        Mockito.doReturn(null).when(table).getItem("primaryKey", "athenz.provider:cn:1234");

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testGetX509CertRecordNotFoundException() {

        Mockito.doThrow(new AmazonDynamoDBException("item not found"))
                .when(table).getItem("primaryKey", "athenz.provider:cn:1234");

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testInsertX509Record() {

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName, indexName);

        Date now = new Date();
        String dateIsoFormat = DynamoDBUtils.getIso8601FromDate(now);
        X509CertRecord certRecord = getRecordNonNullableColumns(now);
        certRecord.setLastNotifiedTime(now);
        certRecord.setLastNotifiedServer("last-notified-server");
        certRecord.setExpiryTime(now);
        certRecord.setHostName("hostname");

        Item item = new Item()
                .withPrimaryKey("primaryKey", "athenz.provider:cn:1234")
                .withString("instanceId", certRecord.getInstanceId())
                .withString("provider", certRecord.getProvider())
                .withString("service", certRecord.getService())
                .withString("currentSerial", certRecord.getCurrentSerial())
                .withString("currentIP", certRecord.getCurrentIP())
                .withLong("currentTime", certRecord.getCurrentTime().getTime())
                .withString("currentDate", dateIsoFormat)
                .withString("prevSerial", certRecord.getPrevSerial())
                .withString("prevIP", certRecord.getPrevIP())
                .withLong("prevTime", certRecord.getPrevTime().getTime())
                .withBoolean("clientCert", certRecord.getClientCert())
                .withLong("ttl", certRecord.getCurrentTime().getTime() / 1000L + 3660 * 720)
                .withLong("lastNotifiedTime", certRecord.getLastNotifiedTime().getTime())
                .withString("lastNotifiedServer", certRecord.getLastNotifiedServer())
                .withLong("expiryTime", certRecord.getExpiryTime().getTime())
                .withString("hostName", certRecord.getHostName());

        Mockito.doReturn(putOutcome).when(table).putItem(item);
        boolean requestSuccess = dbConn.insertX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testInsertX509RecordNullableColumns() {

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName, indexName);

        Date now = new Date();
        String dateIsoFormat = DynamoDBUtils.getIso8601FromDate(now);
        X509CertRecord certRecord = getRecordNonNullableColumns(now);
        certRecord.setLastNotifiedTime(null);
        certRecord.setLastNotifiedServer(null);
        certRecord.setExpiryTime(null);
        certRecord.setHostName(null);

        Item item = new Item()
                .withPrimaryKey("primaryKey", "athenz.provider:cn:1234")
                .withString("instanceId", certRecord.getInstanceId())
                .withString("provider", certRecord.getProvider())
                .withString("service", certRecord.getService())
                .withString("currentSerial", certRecord.getCurrentSerial())
                .withString("currentIP", certRecord.getCurrentIP())
                .withLong("currentTime", certRecord.getCurrentTime().getTime())
                .withString("currentDate", dateIsoFormat)
                .withString("prevSerial", certRecord.getPrevSerial())
                .withString("prevIP", certRecord.getPrevIP())
                .withLong("prevTime", certRecord.getPrevTime().getTime())
                .withBoolean("clientCert", certRecord.getClientCert())
                .withLong("ttl", certRecord.getCurrentTime().getTime() / 1000L + 3660 * 720)
                .with("lastNotifiedTime", null)
                .with("lastNotifiedServer", null)
                .with("expiryTime", null)
                .with("hostName", null);

        Mockito.doReturn(putOutcome).when(table).putItem(item);
        boolean requestSuccess = dbConn.insertX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testInsertX509RecordException() {

        Date now = new Date();
        X509CertRecord certRecord = getRecordNonNullableColumns(now);

        Mockito.doThrow(new AmazonDynamoDBException("invalid operation"))
                .when(table).putItem(any(Item.class));

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        boolean requestSuccess = dbConn.insertX509CertRecord(certRecord);
        assertFalse(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateX509Record() {

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();

        Date now = new Date();
        X509CertRecord certRecord = getRecordNonNullableColumns(now);
        certRecord.setLastNotifiedTime(now);
        certRecord.setLastNotifiedServer("last-notified-server");
        certRecord.setExpiryTime(now);
        certRecord.setHostName("hostname");
        certRecord.setSvcDataUpdateTime(now);

        UpdateItemSpec item = new UpdateItemSpec()
                .withPrimaryKey("primaryKey", "athenz.provider:cn:1234")
                .withAttributeUpdate(
                        new AttributeUpdate("instanceId").put(certRecord.getInstanceId()),
                        new AttributeUpdate("provider").put(certRecord.getProvider()),
                        new AttributeUpdate("service").put(certRecord.getService()),
                        new AttributeUpdate("currentSerial").put(certRecord.getCurrentSerial()),
                        new AttributeUpdate("currentIP").put(certRecord.getCurrentIP()),
                        new AttributeUpdate("currentTime").put(certRecord.getCurrentTime().getTime()),
                        new AttributeUpdate("currentDate").put(DynamoDBUtils.getIso8601FromDate(certRecord.getCurrentTime())),
                        new AttributeUpdate("prevSerial").put(certRecord.getPrevSerial()),
                        new AttributeUpdate("prevIP").put(certRecord.getPrevIP()),
                        new AttributeUpdate("prevTime").put(certRecord.getPrevTime().getTime()),
                        new AttributeUpdate("clientCert").put(certRecord.getClientCert()),
                        new AttributeUpdate("ttl").put(certRecord.getCurrentTime().getTime() / 1000L + 3660 * 720),
                        new AttributeUpdate("svcDataUpdateTime").put(certRecord.getSvcDataUpdateTime().getTime()),
                        new AttributeUpdate("expiryTime").put(certRecord.getExpiryTime().getTime()),
                        new AttributeUpdate("hostName").put(certRecord.getHostName()));

        Mockito.doReturn(updateOutcome).when(table).updateItem(item);
        boolean requestSuccess = dbConn.updateX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateX509RecordNullableColumns() {

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();

        Date now = new Date();
        X509CertRecord certRecord = getRecordNonNullableColumns(now);
        certRecord.setLastNotifiedTime(null);
        certRecord.setLastNotifiedServer(null);
        certRecord.setExpiryTime(now);
        certRecord.setHostName(null);
        certRecord.setSvcDataUpdateTime(now);

        UpdateItemSpec item = new UpdateItemSpec()
                .withPrimaryKey("primaryKey", "athenz.provider:cn:1234")
                .withAttributeUpdate(
                        new AttributeUpdate("instanceId").put(certRecord.getInstanceId()),
                        new AttributeUpdate("provider").put(certRecord.getProvider()),
                        new AttributeUpdate("service").put(certRecord.getService()),
                        new AttributeUpdate("currentSerial").put(certRecord.getCurrentSerial()),
                        new AttributeUpdate("currentIP").put(certRecord.getCurrentIP()),
                        new AttributeUpdate("currentTime").put(certRecord.getCurrentTime().getTime()),
                        new AttributeUpdate("currentDate").put(DynamoDBUtils.getIso8601FromDate(certRecord.getCurrentTime())),
                        new AttributeUpdate("prevSerial").put(certRecord.getPrevSerial()),
                        new AttributeUpdate("prevIP").put(certRecord.getPrevIP()),
                        new AttributeUpdate("prevTime").put(certRecord.getPrevTime().getTime()),
                        new AttributeUpdate("clientCert").put(certRecord.getClientCert()),
                        new AttributeUpdate("ttl").put(certRecord.getCurrentTime().getTime() / 1000L + 3660 * 720),
                        new AttributeUpdate("svcDataUpdateTime").put(certRecord.getSvcDataUpdateTime().getTime()),
                        new AttributeUpdate("expiryTime").put(null));

        Mockito.doReturn(updateOutcome).when(table).updateItem(item);
        boolean requestSuccess = dbConn.updateX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateX509RecordException() {

        Date now = new Date();
        X509CertRecord certRecord = getRecordNonNullableColumns(now);

        Mockito.doThrow(new AmazonDynamoDBException("invalid operation"))
                .when(table).updateItem(any(UpdateItemSpec.class));

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        boolean requestSuccess = dbConn.updateX509CertRecord(certRecord);
        assertFalse(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testDeleteX509Record() {
        DeleteItemSpec deleteItemSpec = new DeleteItemSpec()
                .withPrimaryKey("primaryKey", "athenz.provider:cn:1234");
        Mockito.doReturn(deleteOutcome).when(table).deleteItem(deleteItemSpec);

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();

        boolean requestSuccess = dbConn.deleteX509CertRecord("athenz.provider", "12345", "cn");
        assertTrue(requestSuccess);
        dbConn.close();
    }

    @Test
    public void testDeleteX509RecordException() {

        Mockito.doThrow(new AmazonDynamoDBException("invalid operation"))
                .when(table).deleteItem(any(DeleteItemSpec.class));

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();

        boolean requestSuccess = dbConn.deleteX509CertRecord("athenz.provider", "12345", "cn");
        assertFalse(requestSuccess);
        dbConn.close();
    }

    @Test
    public void testdeleteExpiredX509CertRecords() {
        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        assertEquals(0, dbConn.deleteExpiredX509CertRecords(100));
        assertEquals(0, dbConn.deleteExpiredX509CertRecords(100000));
        dbConn.close();
    }

    private X509CertRecord getRecordNonNullableColumns(Date now) {
        X509CertRecord certRecord = new X509CertRecord();
        certRecord.setService("cn");
        certRecord.setProvider("athenz.provider");
        certRecord.setInstanceId("1234");
        certRecord.setCurrentIP("current-ip");
        certRecord.setCurrentSerial("current-serial");
        certRecord.setCurrentTime(now);
        certRecord.setPrevIP("prev-ip");
        certRecord.setPrevSerial("prev-serial");
        certRecord.setPrevTime(now);
        certRecord.setClientCert(false);
        return certRecord;
    }

    private void assertNonNullableColumns(Date now, X509CertRecord certRecord) {
        assertNotNull(certRecord);
        assertEquals(certRecord.getService(), "cn");
        assertEquals(certRecord.getCurrentIP(), "current-ip");
        assertEquals(certRecord.getCurrentSerial(), "current-serial");
        assertEquals(certRecord.getCurrentTime(), now);
        assertEquals(certRecord.getInstanceId(), "1234");
        assertEquals(certRecord.getPrevIP(), "prev-ip");
        assertEquals(certRecord.getPrevSerial(), "prev-serial");
        assertEquals(certRecord.getPrevTime(), now);
        assertEquals(certRecord.getProvider(), "athenz.provider");
        assertFalse(certRecord.getClientCert());
    }

    private long mockNonNullableColumns(Date now) {
        long tstamp = now.getTime();

        Mockito.doReturn(item).when(table).getItem("primaryKey", "athenz.provider:cn:1234");

        Mockito.doReturn("athenz.provider").when(item).getString("provider");
        Mockito.doReturn("1234").when(item).getString("instanceId");
        Mockito.doReturn("cn").when(item).getString("service");

        Mockito.doReturn(false).when(item).isNull("currentTime");
        Mockito.doReturn(false).when(item).isNull("prevTime");

        Mockito.doReturn("cn").when(item).getString("service");
        Mockito.doReturn("current-serial").when(item).getString("currentSerial");
        Mockito.doReturn("current-ip").when(item).getString("currentIP");
        Mockito.doReturn(tstamp).when(item).getLong("currentTime");
        Mockito.doReturn(tstamp).when(item).get("currentTime");
        Mockito.doReturn("prev-serial").when(item).getString("prevSerial");
        Mockito.doReturn("prev-ip").when(item).getString("prevIP");
        Mockito.doReturn(tstamp).when(item).getLong("prevTime");
        Mockito.doReturn(tstamp).when(item).get("prevTime");
        Mockito.doReturn(false).when(item).getBoolean("clientCert");
        return tstamp;
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestamp() {
        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        ItemCollection<QueryOutcome> itemCollection = Mockito.mock(ItemCollection.class);
        Date now = new Date(1591706189000L);
        long nowL = now.getTime();
        long fiveDaysAgo = nowL - 5 * 24 * 60 * 60 * 1000;

        Map<String, AttributeValue> unNotified = generateAttributeValues(
                "home.test.service2",
                "testInstance2",
                null,
                null,
                null,
                null,
                "testHost1");

        Map<String, AttributeValue> reNotified = generateAttributeValues(
                "home.test.service3",
                "testInstance3",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost1");

        Map<String, AttributeValue> willBeUpdatedByOtherZts = generateAttributeValues(
                "home.test.service4",
                "testInstance4",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost1");

        Item item1 = ItemUtils.toItem(unNotified);
        Item item2 = ItemUtils.toItem(reNotified);
        Item item3 = ItemUtils.toItem(willBeUpdatedByOtherZts);

        IteratorSupport<Item, QueryOutcome> iteratorSupport = Mockito.mock(IteratorSupport.class);
        when(itemCollection.iterator()).thenReturn(iteratorSupport);
        when(iteratorSupport.hasNext()).thenReturn(true, true, true, false);
        when(iteratorSupport.next()).thenReturn(item1).thenReturn(item2).thenReturn(item3);

        Mockito.doReturn(itemCollection).when(index).query(any(QuerySpec.class));

        AttributeValue lastNotifiedTimeAttrValue = new AttributeValue();
        lastNotifiedTimeAttrValue.setN(Long.toString(nowL));
        AttributeValue lastNotifiedServerAttrValue = new AttributeValue();
        lastNotifiedServerAttrValue.setS("localhost");
        AttributeValue lastNotifiedOtherServerAttrValue = new AttributeValue();
        lastNotifiedOtherServerAttrValue.setS("SomeOtherZTS");

        unNotified.put("lastNotifiedTime", lastNotifiedTimeAttrValue);
        unNotified.put("lastNotifiedServer", lastNotifiedServerAttrValue);

        reNotified.put("lastNotifiedTime", lastNotifiedTimeAttrValue);
        reNotified.put("lastNotifiedServer", lastNotifiedServerAttrValue);

        willBeUpdatedByOtherZts.put("lastNotifiedTime", lastNotifiedTimeAttrValue);
        willBeUpdatedByOtherZts.put("lastNotifiedServer", lastNotifiedOtherServerAttrValue);

        Item updatedItem1 = ItemUtils.toItem(unNotified);
        Item updatedItem2 = ItemUtils.toItem(reNotified);
        Item updatedItem3 = ItemUtils.toItem(willBeUpdatedByOtherZts);

        UpdateItemOutcome updateItemOutcome1 = Mockito.mock(UpdateItemOutcome.class);
        when(updateItemOutcome1.getItem()).thenReturn(updatedItem1);

        UpdateItemOutcome updateItemOutcome2 = Mockito.mock(UpdateItemOutcome.class);
        when(updateItemOutcome2.getItem()).thenReturn(updatedItem2);

        UpdateItemOutcome updateItemOutcome3 = Mockito.mock(UpdateItemOutcome.class);
        when(updateItemOutcome3.getItem()).thenReturn(updatedItem3);

        when(table.updateItem(any(UpdateItemSpec.class))).thenReturn(updateItemOutcome1).thenReturn(updateItemOutcome2).thenReturn(updateItemOutcome3);
        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "localhost",
                nowL,
                "provider");

        assertEquals(records.size(), 2);
        assertNull(records.get(0).getCurrentTime());
        assertEquals(records.get(0).getService(), "home.test.service2");
        assertEquals(records.get(0).getLastNotifiedTime(), now);
        assertEquals(records.get(1).getCurrentTime().getTime(), fiveDaysAgo);
        assertEquals(records.get(1).getService(), "home.test.service3");
        assertEquals(records.get(1).getLastNotifiedTime(), now);
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestampException() {
        Mockito.doThrow(new AmazonDynamoDBException("invalid operation"))
                .when(table).updateItem(any(UpdateItemSpec.class));

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        List<X509CertRecord> result = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "serverTest",
                1591706189000L,
                "providerTest");

        assertEquals(result.size(), 0);

        dbConn.close();
    }

    private Map<String, AttributeValue> generateAttributeValues(String service,
                                                                String instanceId,
                                                                String currentTime,
                                                                String lastNotifiedTime,
                                                                String lastNotifiedServer,
                                                                String expiryTime,
                                                                String hostName) {
        String provider = "provider";
        String primaryKey = provider + ":" + service + ":" + instanceId;
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("primaryKey", new AttributeValue(primaryKey));
        item.put("service", new AttributeValue(service));
        item.put("provider", new AttributeValue(provider));
        item.put("instanceId", new AttributeValue(instanceId));
        item.put("currentSerial", new AttributeValue("currentSerial"));

        AttributeValue currentTimeVal = new AttributeValue();
        currentTimeVal.setN(currentTime);

        if (!StringUtil.isEmpty(currentTime)) {
            item.put("currentTime", currentTimeVal);
            item.put("prevTime", currentTimeVal);
        }

        item.put("currentIP", new AttributeValue("currentIP"));
        item.put("prevSerial", new AttributeValue("prevSerial"));
        item.put("prevIP", new AttributeValue("prevIP"));

        AttributeValue clientCertVal = new AttributeValue();
        clientCertVal.setBOOL(false);
        item.put("clientCert", clientCertVal);

        if (!StringUtil.isEmpty(lastNotifiedTime)) {
            AttributeValue lastNotifiedTimeVal = new AttributeValue();
            lastNotifiedTimeVal.setN(lastNotifiedTime);
            item.put("lastNotifiedTime", lastNotifiedTimeVal);
        }

        if (!StringUtil.isEmpty(lastNotifiedServer)) {
            item.put("lastNotifiedServer", new AttributeValue(lastNotifiedServer));
        }

        if (!StringUtil.isEmpty(expiryTime)) {
            AttributeValue expiryTimeVal = new AttributeValue();
            expiryTimeVal.setN(expiryTime);
            item.put("expiryTime", expiryTimeVal);
        }

        if (!StringUtil.isEmpty(hostName)) {
            item.put("hostName", new AttributeValue(hostName));
        }

        return item;
    }
}
