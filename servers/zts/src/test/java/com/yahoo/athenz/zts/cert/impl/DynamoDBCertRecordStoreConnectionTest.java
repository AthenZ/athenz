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
import com.yahoo.athenz.zts.cert.X509CertRecord;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;

import java.util.Date;

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
        long tstamp = now.getTime();

        Mockito.doReturn(item).when(table).getItem("primaryKey", "athenz.provider:cn:1234");

        Mockito.doReturn("cn").when(item).getString("service");
        Mockito.doReturn("current-serial").when(item).getString("currentSerial");
        Mockito.doReturn("current-ip").when(item).getString("currentIP");
        Mockito.doReturn(tstamp).when(item).getLong("currentTime");
        Mockito.doReturn("prev-serial").when(item).getString("prevSerial");
        Mockito.doReturn("prev-ip").when(item).getString("prevIP");
        Mockito.doReturn(tstamp).when(item).getLong("prevTime");
        Mockito.doReturn(false).when(item).getBoolean("clientCert");

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName);
        dbConn.setOperationTimeout(10);
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");

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

        X509CertRecord certRecord = new X509CertRecord();
        Date now = new Date();

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
                .withLong("ttl", certRecord.getCurrentTime().getTime() / 1000L + 3660 * 720);

        Mockito.doReturn(putOutcome).when(table).putItem(item);
        boolean requestSuccess = dbConn.insertX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testInsertX509RecordException() {

        X509CertRecord certRecord = new X509CertRecord();
        Date now = new Date();

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

        X509CertRecord certRecord = new X509CertRecord();
        Date now = new Date();

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
                        new AttributeUpdate("ttl").put(certRecord.getCurrentTime().getTime() / 1000L + 3660 * 720));

        Mockito.doReturn(updateOutcome).when(table).updateItem(item);
        boolean requestSuccess = dbConn.updateX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateX509RecordException() {

        X509CertRecord certRecord = new X509CertRecord();
        Date now = new Date();

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
}
