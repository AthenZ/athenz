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

import com.amazonaws.services.dynamodbv2.document.*;
import com.amazonaws.services.dynamodbv2.model.AmazonDynamoDBException;
import com.yahoo.athenz.common.server.cert.X509CertRecord;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.testng.Assert.*;

public class DynamoDBCertRecordStoreConnectionTest {

    private final String tableName = "cert-table";

    @Mock private DynamoDB dynamoDB;
    @Mock private Table table;
    @Mock private Item item;
    @Mock private PutItemOutcome putOutcome;
    @Mock private DeleteItemOutcome deleteOutcome;
    @Mock private UpdateItemOutcome updateOutcome;

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        Mockito.doReturn(table).when(dynamoDB).getTable(tableName);
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

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);
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

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);
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

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testGetX509CertRecordNotFoundException() {

        Mockito.doThrow(new AmazonDynamoDBException("item not found"))
                .when(table).getItem("primaryKey", "athenz.provider:cn:1234");

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testInsertX509Record() {

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);

        Date now = new Date();
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

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);

        Date now = new Date();
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
                .when(table).putItem(ArgumentMatchers.any(Item.class));

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);
        boolean requestSuccess = dbConn.insertX509CertRecord(certRecord);
        assertFalse(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateX509Record() {

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);

        Date now = new Date();
        X509CertRecord certRecord = getRecordNonNullableColumns(now);
        certRecord.setLastNotifiedTime(now);
        certRecord.setLastNotifiedServer("last-notified-server");
        certRecord.setExpiryTime(now);
        certRecord.setHostName("hostname");

        UpdateItemSpec item = new UpdateItemSpec()
                .withPrimaryKey("primaryKey", "athenz.provider:cn:1234")
                .withAttributeUpdate(
                        new AttributeUpdate("instanceId").put(certRecord.getInstanceId()),
                        new AttributeUpdate("provider").put(certRecord.getProvider()),
                        new AttributeUpdate("service").put(certRecord.getService()),
                        new AttributeUpdate("currentSerial").put(certRecord.getCurrentSerial()),
                        new AttributeUpdate("currentIP").put(certRecord.getCurrentIP()),
                        new AttributeUpdate("currentTime").put(certRecord.getCurrentTime().getTime()),
                        new AttributeUpdate("prevSerial").put(certRecord.getPrevSerial()),
                        new AttributeUpdate("prevIP").put(certRecord.getPrevIP()),
                        new AttributeUpdate("prevTime").put(certRecord.getPrevTime().getTime()),
                        new AttributeUpdate("clientCert").put(certRecord.getClientCert()),
                        new AttributeUpdate("ttl").put(certRecord.getCurrentTime().getTime() / 1000L + 3660 * 720),
                        new AttributeUpdate("lastNotifiedTime").put(certRecord.getLastNotifiedTime().getTime()),
                        new AttributeUpdate("lastNotifiedServer").put(certRecord.getLastNotifiedServer()),
                        new AttributeUpdate("expiryTime").put(certRecord.getExpiryTime().getTime()),
                        new AttributeUpdate("hostName").put(certRecord.getHostName()));

        Mockito.doReturn(updateOutcome).when(table).updateItem(item);
        boolean requestSuccess = dbConn.updateX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateX509RecordNullableColumns() {

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);

        Date now = new Date();
        X509CertRecord certRecord = getRecordNonNullableColumns(now);
        certRecord.setLastNotifiedTime(null);
        certRecord.setLastNotifiedServer(null);
        certRecord.setExpiryTime(null);
        certRecord.setHostName(null);

        UpdateItemSpec item = new UpdateItemSpec()
                .withPrimaryKey("primaryKey", "athenz.provider:cn:1234")
                .withAttributeUpdate(
                        new AttributeUpdate("instanceId").put(certRecord.getInstanceId()),
                        new AttributeUpdate("provider").put(certRecord.getProvider()),
                        new AttributeUpdate("service").put(certRecord.getService()),
                        new AttributeUpdate("currentSerial").put(certRecord.getCurrentSerial()),
                        new AttributeUpdate("currentIP").put(certRecord.getCurrentIP()),
                        new AttributeUpdate("currentTime").put(certRecord.getCurrentTime().getTime()),
                        new AttributeUpdate("prevSerial").put(certRecord.getPrevSerial()),
                        new AttributeUpdate("prevIP").put(certRecord.getPrevIP()),
                        new AttributeUpdate("prevTime").put(certRecord.getPrevTime().getTime()),
                        new AttributeUpdate("clientCert").put(certRecord.getClientCert()),
                        new AttributeUpdate("ttl").put(certRecord.getCurrentTime().getTime() / 1000L + 3660 * 720),
                        new AttributeUpdate("lastNotifiedTime").put(null),
                        new AttributeUpdate("lastNotifiedServer").put(null),
                        new AttributeUpdate("expiryTime").put(null),
                        new AttributeUpdate("hostName").put(null));

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
                .when(table).updateItem(ArgumentMatchers.any(UpdateItemSpec.class));

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);
        boolean requestSuccess = dbConn.updateX509CertRecord(certRecord);
        assertFalse(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testDeleteX509Record() {
        DeleteItemSpec deleteItemSpec = new DeleteItemSpec()
                .withPrimaryKey("primaryKey", "athenz.provider:cn:1234");
        Mockito.doReturn(deleteOutcome).when(table).deleteItem(deleteItemSpec);

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);

        boolean requestSuccess = dbConn.deleteX509CertRecord("athenz.provider", "12345", "cn");
        assertTrue(requestSuccess);
        dbConn.close();
    }

    @Test
    public void testDeleteX509RecordException() {

        Mockito.doThrow(new AmazonDynamoDBException("invalid operation"))
                .when(table).deleteItem(ArgumentMatchers.any(DeleteItemSpec.class));

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);

        boolean requestSuccess = dbConn.deleteX509CertRecord("athenz.provider", "12345", "cn");
        assertFalse(requestSuccess);
        dbConn.close();
    }

    @Test
    public void testdeleteExpiredX509CertRecords() {
        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);
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
        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);
        long timestamp = System.currentTimeMillis();
        boolean result = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "localhost",
                timestamp,
                "provider");

        // For DynamoDB, unrefreshed certs unimplemented. Assert false
        assertFalse(result);
    }

    @Test
    public void testGetNotifyUnrefreshedCertificates() {
        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);
        long timestamp = System.currentTimeMillis();
        List<X509CertRecord> records = dbConn.getNotifyUnrefreshedCertificates("localhost", timestamp);

        // For DynamoDB, unrefreshed certs unimplemented. Assert empty collection
        assertEquals(records, new ArrayList<>());
    }
}
