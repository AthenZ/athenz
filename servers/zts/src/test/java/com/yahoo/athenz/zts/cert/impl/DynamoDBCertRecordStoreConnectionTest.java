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
package com.yahoo.athenz.zts.cert.impl;

import com.amazonaws.services.dynamodbv2.document.*;
import com.amazonaws.services.dynamodbv2.document.internal.IteratorSupport;
import com.amazonaws.services.dynamodbv2.document.spec.QuerySpec;
import com.amazonaws.services.dynamodbv2.model.AmazonDynamoDBException;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.TransactionConflictException;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.ZTSTestUtils;
import com.yahoo.athenz.zts.utils.DynamoDBUtils;
import org.mockito.*;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;
import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

public class DynamoDBCertRecordStoreConnectionTest {

    private final String tableName = "cert-table";
    private final String currentTimeIndexName = "cert-table-currenttime-index";
    private final String hostNameIndexName = "cert-table-hostname-index";


    @Mock private DynamoDB dynamoDB = Mockito.mock(DynamoDB.class);
    @Mock private Table table = Mockito.mock(Table.class);
    @Mock private Index currentTimeIndex = Mockito.mock(Index.class);
    @Mock private Index hostNameIndex = Mockito.mock(Index.class);
    @Mock private Item item = Mockito.mock(Item.class);
    @Mock private PutItemOutcome putOutcome = Mockito.mock(PutItemOutcome.class);
    @Mock private DeleteItemOutcome deleteOutcome = Mockito.mock(DeleteItemOutcome.class);
    @Mock private UpdateItemOutcome updateOutcome = Mockito.mock(UpdateItemOutcome.class);


    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        Mockito.doReturn(table).when(dynamoDB).getTable(tableName);
        Mockito.doReturn(currentTimeIndex).when(table).getIndex(currentTimeIndexName);
        Mockito.doReturn(hostNameIndex).when(table).getIndex(hostNameIndexName);
    }

    private DynamoDBCertRecordStoreConnection getDBConnection() {
        return new DynamoDBCertRecordStoreConnection(dynamoDB, tableName, currentTimeIndexName, hostNameIndexName);
    }

    @Test
    public void testGetX509CertRecord() {

        Date now = new Date();
        long tstamp = mockNonNullableColumns(now, false);
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
        assertEquals(certRecord.getClientCert(), false);

        dbConn.close();
    }

    @Test
    public void testGetX509CertRecordNullableColumns() {

        Date now = new Date();
        mockNonNullableColumns(now, true);
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

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName, currentTimeIndexName, hostNameIndexName);

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

        ArgumentCaptor<Item> itemCaptor = ArgumentCaptor.forClass(Item.class);
        Mockito.verify(table, times(1)).putItem(itemCaptor.capture());
        List<Item> allValues = itemCaptor.getAllValues();
        assertEquals(1, allValues.size());
        assertEquals(allValues.get(0).get("primaryKey"), item.get("primaryKey"));
        assertEquals(allValues.get(0).get("provider"), item.get("provider"));
        assertEquals(allValues.get(0).get("instanceId"), item.get("instanceId"));
        assertEquals(allValues.get(0).get("service"), item.get("service"));
        assertEquals(allValues.get(0).get("expiryTime"), item.get("expiryTime"));
        assertEquals(allValues.get(0).get("hostName"), item.get("hostName"));

        dbConn.close();
    }

    @Test
    public void testInsertX509RecordNoHostname() {

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName, currentTimeIndexName, hostNameIndexName);

        Date now = new Date();
        String dateIsoFormat = DynamoDBUtils.getIso8601FromDate(now);
        X509CertRecord certRecord = getRecordNonNullableColumns(now);
        certRecord.setLastNotifiedTime(now);
        certRecord.setLastNotifiedServer("last-notified-server");
        certRecord.setExpiryTime(now);

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
                .withLong("expiryTime", certRecord.getExpiryTime().getTime());

        Mockito.doReturn(putOutcome).when(table).putItem(item);
        boolean requestSuccess = dbConn.insertX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        ArgumentCaptor<Item> itemCaptor = ArgumentCaptor.forClass(Item.class);
        Mockito.verify(table, times(1)).putItem(itemCaptor.capture());
        List<Item> allValues = itemCaptor.getAllValues();
        assertEquals(1, allValues.size());
        assertEquals(allValues.get(0).get("primaryKey"), item.get("primaryKey"));
        assertEquals(allValues.get(0).get("provider"), item.get("provider"));
        assertEquals(allValues.get(0).get("instanceId"), item.get("instanceId"));
        assertEquals(allValues.get(0).get("service"), item.get("service"));
        assertEquals(allValues.get(0).get("expiryTime"), item.get("expiryTime"));

        // When hostname is null, primaryKey will be used
        assertEquals(allValues.get(0).get("hostName"), item.get("primaryKey"));

        dbConn.close();
    }

    @Test
    public void testInsertX509RecordNullableColumns() {

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName, currentTimeIndexName, hostNameIndexName);

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

        ArgumentCaptor<UpdateItemSpec> itemCaptor = ArgumentCaptor.forClass(UpdateItemSpec.class);
        Mockito.verify(table, times(1)).updateItem(itemCaptor.capture());
        List<UpdateItemSpec> allValues = itemCaptor.getAllValues();
        assertEquals(1, allValues.size());

        UpdateItemSpec capturedItem = allValues.get(0);
        assertEquals(capturedItem.getKeyComponents().toArray()[0].toString(), item.getKeyComponents().toArray()[0].toString());

        List<AttributeUpdate> capturedAttributes = capturedItem.getAttributeUpdate();
        List<AttributeUpdate> expectedAttributes = item.getAttributeUpdate();

        for (int i = 0; i < expectedAttributes.size(); ++i) {
            System.out.println("expected attr: " + expectedAttributes.get(i).getAttributeName() + ", value: " + expectedAttributes.get(i).getValue());
            assertEquals(capturedAttributes.get(i).getAttributeName(), expectedAttributes.get(i).getAttributeName());
            assertEquals(capturedAttributes.get(i).getValue(),  expectedAttributes.get(i).getValue());
        }

        dbConn.close();
    }

    @Test
    public void testUpdateX509RecordNoHostName() {

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();

        Date now = new Date();
        X509CertRecord certRecord = getRecordNonNullableColumns(now);
        certRecord.setLastNotifiedTime(now);
        certRecord.setLastNotifiedServer("last-notified-server");
        certRecord.setExpiryTime(now);
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
                        new AttributeUpdate("expiryTime").put(certRecord.getExpiryTime().getTime()));

        Mockito.doReturn(updateOutcome).when(table).updateItem(item);
        boolean requestSuccess = dbConn.updateX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        ArgumentCaptor<UpdateItemSpec> itemCaptor = ArgumentCaptor.forClass(UpdateItemSpec.class);
        Mockito.verify(table, times(1)).updateItem(itemCaptor.capture());
        List<UpdateItemSpec> allValues = itemCaptor.getAllValues();
        assertEquals(1, allValues.size());

        UpdateItemSpec capturedItem = allValues.get(0);
        assertEquals(capturedItem.getKeyComponents().toArray()[0].toString(), item.getKeyComponents().toArray()[0].toString());

        List<AttributeUpdate> capturedAttributes = capturedItem.getAttributeUpdate();
        List<AttributeUpdate> expectedAttributes = item.getAttributeUpdate();

        // Check everyone except the hostname (it will be filled with the primaryKey value as the hostName index doesn't allow nulls)
        for (int i = 0; i < capturedAttributes.size() - 1; ++i) {
            System.out.println("expected attr: " + expectedAttributes.get(i).getAttributeName() + ", value: " + expectedAttributes.get(i).getValue());
            assertEquals(capturedAttributes.get(i).getAttributeName(), expectedAttributes.get(i).getAttributeName());
            assertEquals(capturedAttributes.get(i).getValue(),  expectedAttributes.get(i).getValue());
        }

        // Make sure hostName received the value of the primaryKey
        System.out.println("expected attr: hostName, value: athenz.provider:cn:1234");
        assertEquals(capturedAttributes.get(capturedAttributes.size() - 1).getAttributeName(), "hostName");
        assertEquals(capturedAttributes.get(capturedAttributes.size() - 1).getValue(), "athenz.provider:cn:1234");

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

    private long mockNonNullableColumns(Date now, boolean clientCertHasValue) {
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
        if (clientCertHasValue) {
            Mockito.doReturn(false).when(item).getBoolean("clientCert");
        } else {
            Mockito.when(item.getBoolean(anyString())).thenThrow(new IncompatibleTypeException("Value not found"));
        }
        return tstamp;
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestamp() {
        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        Date now = new Date(1591706189000L);
        long nowL = now.getTime();
        long fiveDaysAgo = nowL - 5 * 24 * 60 * 60 * 1000;
        long sevenDaysAgo = nowL - 7 * 24 * 60 * 60 * 1000;

        Map<String, AttributeValue> unNotified = ZTSTestUtils.generateAttributeValues(
                "home.test.service2",
                "unNotified",
                null,
                null,
                null,
                null,
                "testHost1");

        Map<String, AttributeValue> reNotified = ZTSTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");

        Map<String, AttributeValue> rebootstrapped = ZTSTestUtils.generateAttributeValues(
                "home.test.service3",
                "rebootstrapped",
                Long.toString(sevenDaysAgo),
                Long.toString(sevenDaysAgo),
                "testServer",
                null,
                "testHost2");

        Map<String, AttributeValue> willBeUpdatedByOtherZts = ZTSTestUtils.generateAttributeValues(
                "home.test.service4",
                "willBeUpdatedByOtherZts",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost3");

        Item item1 = ItemUtils.toItem(unNotified);
        Item item2 = ItemUtils.toItem(reNotified);
        Item item3 = ItemUtils.toItem(willBeUpdatedByOtherZts);
        Item item4 = ItemUtils.toItem(rebootstrapped);

        ItemCollection<QueryOutcome> itemCollection = Mockito.mock(ItemCollection.class);
        IteratorSupport<Item, QueryOutcome> iteratorSupport = Mockito.mock(IteratorSupport.class);
        when(itemCollection.iterator()).thenReturn(iteratorSupport);
        when(iteratorSupport.hasNext()).thenReturn(true, true, true, true, false);
        when(iteratorSupport.next()).thenReturn(item1).thenReturn(item2).thenReturn(item3).thenReturn(item4);

        Mockito.doReturn(itemCollection).when(currentTimeIndex).query(any(QuerySpec.class));

        ItemCollection<QueryOutcome> itemCollection2 = Mockito.mock(ItemCollection.class);
        IteratorSupport<Item, QueryOutcome> iteratorSupport2 = Mockito.mock(IteratorSupport.class);
        when(itemCollection2.iterator()).thenReturn(iteratorSupport2);
        when(iteratorSupport2.hasNext()).thenReturn(
                true, false, // One record with host testHost1
                true, true, false, // Two records with host testHost2
                true, false, // One record with host testHost3
                true, true, false); // Two records with host testHost2

        when(iteratorSupport2.next())
                .thenReturn(item1)
                .thenReturn(item2).thenReturn(item4)
                .thenReturn(item3)
                .thenReturn(item2).thenReturn(item4);

        Mockito.doReturn(itemCollection2).when(hostNameIndex).query(any(QuerySpec.class));

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

        ArgumentCaptor<UpdateItemSpec> updateArguments = ArgumentCaptor.forClass(UpdateItemSpec.class);
        Mockito.verify(table, Mockito.times(3)).updateItem(updateArguments.capture());

        // Assert get filtered records
        List<UpdateItemSpec> allUpdateArguments = updateArguments.getAllValues();
        assertEquals(3, allUpdateArguments.size());
        assertEquals("{primaryKey: provider:home.test.service2:unNotified}", allUpdateArguments.get(0).getKeyComponents().toArray()[0].toString());
        assertEquals("{primaryKey: provider:home.test.service3:reNotified}", allUpdateArguments.get(1).getKeyComponents().toArray()[0].toString());
        assertEquals("{primaryKey: provider:home.test.service4:willBeUpdatedByOtherZts}", allUpdateArguments.get(2).getKeyComponents().toArray()[0].toString());

        // Assert Update
        assertEquals(records.size(), 2);
        assertNull(records.get(0).getCurrentTime());
        assertEquals(records.get(0).getService(), "home.test.service2");
        assertEquals(records.get(0).getLastNotifiedTime(), now);
        assertEquals(records.get(1).getCurrentTime().getTime(), fiveDaysAgo);
        assertEquals(records.get(1).getService(), "home.test.service3");
        assertEquals(records.get(1).getLastNotifiedTime(), now);
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestampUpdateDynamoDBException() {
        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        Date now = new Date(1591706189000L);
        long nowL = now.getTime();
        long fiveDaysAgo = nowL - 5 * 24 * 60 * 60 * 1000;

        Map<String, AttributeValue> reNotified = ZTSTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");

        Item item1 = ItemUtils.toItem(reNotified);

        ItemCollection<QueryOutcome> itemCollection = Mockito.mock(ItemCollection.class);
        IteratorSupport<Item, QueryOutcome> iteratorSupport = Mockito.mock(IteratorSupport.class);
        when(itemCollection.iterator()).thenReturn(iteratorSupport);
        when(iteratorSupport.hasNext()).thenReturn(true, false);
        when(iteratorSupport.next()).thenReturn(item1);

        Mockito.doReturn(itemCollection).when(currentTimeIndex).query(any(QuerySpec.class));

        ItemCollection<QueryOutcome> itemCollection2 = Mockito.mock(ItemCollection.class);
        IteratorSupport<Item, QueryOutcome> iteratorSupport2 = Mockito.mock(IteratorSupport.class);
        when(itemCollection2.iterator()).thenReturn(iteratorSupport2);
        when(iteratorSupport2.hasNext()).thenReturn(true, false);

        when(iteratorSupport2.next()).thenReturn(item1);

        Mockito.doReturn(itemCollection2).when(hostNameIndex).query(any(QuerySpec.class));

        Mockito.doThrow(new AmazonDynamoDBException("invalid operation"))
                .when(table).updateItem(any(UpdateItemSpec.class));

        List<X509CertRecord> result = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "serverTest",
                1591706189000L,
                "providerTest");

        assertEquals(result.size(), 0);

        dbConn.close();
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestampUpdateException() {
        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        Date now = new Date(1591706189000L);
        long nowL = now.getTime();
        long fiveDaysAgo = nowL - 5 * 24 * 60 * 60 * 1000;

        Map<String, AttributeValue> reNotified = ZTSTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");

        Item item1 = ItemUtils.toItem(reNotified);

        ItemCollection<QueryOutcome> itemCollection = Mockito.mock(ItemCollection.class);
        IteratorSupport<Item, QueryOutcome> iteratorSupport = Mockito.mock(IteratorSupport.class);
        when(itemCollection.iterator()).thenReturn(iteratorSupport);
        when(iteratorSupport.hasNext()).thenReturn(true, false);
        when(iteratorSupport.next()).thenReturn(item1);

        Mockito.doReturn(itemCollection).when(currentTimeIndex).query(any(QuerySpec.class));

        ItemCollection<QueryOutcome> itemCollection2 = Mockito.mock(ItemCollection.class);
        IteratorSupport<Item, QueryOutcome> iteratorSupport2 = Mockito.mock(IteratorSupport.class);
        when(itemCollection2.iterator()).thenReturn(iteratorSupport2);
        when(iteratorSupport2.hasNext()).thenReturn(true, false);

        when(iteratorSupport2.next()).thenReturn(item1);

        Mockito.doReturn(itemCollection2).when(hostNameIndex).query(any(QuerySpec.class));

        Mockito.doThrow(new TransactionConflictException("error"))
                .when(table).updateItem(any(UpdateItemSpec.class));

        List<X509CertRecord> result = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "serverTest",
                1591706189000L,
                "providerTest");

        assertEquals(result.size(), 0);

        dbConn.close();
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestampTimeException() {
        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();

        Mockito.doThrow(new TransactionConflictException("error"))
                .when(currentTimeIndex).query(any(QuerySpec.class));

        List<X509CertRecord> result = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "serverTest",
                1591706189000L,
                "providerTest");

        assertEquals(result.size(), 0);

        dbConn.close();
    }

    @Test
    public void testUpdateUnrefreshedCertificatesNotificationTimestampHostException() {
        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        Date now = new Date(1591706189000L);
        long nowL = now.getTime();
        long fiveDaysAgo = nowL - 5 * 24 * 60 * 60 * 1000;

        Map<String, AttributeValue> reNotified = ZTSTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");

        Item item1 = ItemUtils.toItem(reNotified);

        ItemCollection<QueryOutcome> itemCollection = Mockito.mock(ItemCollection.class);
        IteratorSupport<Item, QueryOutcome> iteratorSupport = Mockito.mock(IteratorSupport.class);
        when(itemCollection.iterator()).thenReturn(iteratorSupport);
        when(iteratorSupport.hasNext()).thenReturn(true, false);
        when(iteratorSupport.next()).thenReturn(item1);

        Mockito.doReturn(itemCollection).when(currentTimeIndex).query(any(QuerySpec.class));

        Mockito.doThrow(new TransactionConflictException("error"))
                .when(hostNameIndex).query(any(QuerySpec.class));

        List<X509CertRecord> result = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "serverTest",
                1591706189000L,
                "providerTest");

        assertEquals(result.size(), 0);

        dbConn.close();
    }
}
