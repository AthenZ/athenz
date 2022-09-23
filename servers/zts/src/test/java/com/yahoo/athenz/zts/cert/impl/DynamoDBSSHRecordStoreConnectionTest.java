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
import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;
import com.amazonaws.services.dynamodbv2.model.AmazonDynamoDBException;
import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class DynamoDBSSHRecordStoreConnectionTest {

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
    public void testGetSSHCertRecord() {

        Mockito.doReturn(item).when(table).getItem("primaryKey", "cn:1234");

        Mockito.doReturn("1234").when(item).getString("instanceId");
        Mockito.doReturn("cn").when(item).getString("service");
        Mockito.doReturn("host1,host2").when(item).getString("principals");
        Mockito.doReturn("10.10.10.11").when(item).getString("clientIP");
        Mockito.doReturn("10.10.10.12").when(item).getString("privateIP");

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);
        dbConn.setOperationTimeout(10);
        SSHCertRecord certRecord = dbConn.getSSHCertRecord("1234", "cn");

        assertEquals(certRecord.getInstanceId(), "1234");
        assertEquals(certRecord.getService(), "cn");
        assertEquals(certRecord.getPrincipals(), "host1,host2");
        assertEquals(certRecord.getClientIP(), "10.10.10.11");
        assertEquals(certRecord.getPrivateIP(), "10.10.10.12");

        dbConn.close();
    }

    @Test
    public void testGetSSHCertRecordNotFoundNull() {

        Mockito.doReturn(null).when(table).getItem("primaryKey", "cn:1234");

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);
        SSHCertRecord certRecord = dbConn.getSSHCertRecord("1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testGetSSHCertRecordNotFoundException() {

        Mockito.doThrow(new AmazonDynamoDBException("item not found"))
                .when(table).getItem("primaryKey", "cn:1234");

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);
        SSHCertRecord certRecord = dbConn.getSSHCertRecord("1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testInsertSSHRecord() {

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");
        certRecord.setPrincipals("host1,host2");
        certRecord.setClientIP("10.10.10.11");
        certRecord.setPrivateIP("10.10.10.12");

        Item item = new Item()
                .withPrimaryKey("primaryKey", "cn:1234")
                .withString("instanceId", certRecord.getInstanceId())
                .withString("service", certRecord.getService())
                .withString("principals", certRecord.getPrincipals())
                .withString("clientIP", certRecord.getClientIP())
                .withString("privateIP", certRecord.getPrivateIP());

        Mockito.doReturn(putOutcome).when(table).putItem(item);
        boolean requestSuccess = dbConn.insertSSHCertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testInsertSSHRecordException() {

        SSHCertRecord certRecord = new SSHCertRecord();

        Mockito.doThrow(new AmazonDynamoDBException("invalid operation"))
                .when(table).putItem(ArgumentMatchers.any(Item.class));

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);
        boolean requestSuccess = dbConn.insertSSHCertRecord(certRecord);
        assertFalse(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateSSHRecord() {

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);

        SSHCertRecord certRecord = new SSHCertRecord();
        certRecord.setInstanceId("1234");
        certRecord.setService("cn");
        certRecord.setPrincipals("host1,host2");
        certRecord.setClientIP("10.10.10.11");
        certRecord.setPrivateIP("10.10.10.12");

        UpdateItemSpec item = new UpdateItemSpec()
                .withPrimaryKey("primaryKey", "cn:1234")
                .withAttributeUpdate(
                        new AttributeUpdate("instanceId").put(certRecord.getInstanceId()),
                        new AttributeUpdate("service").put(certRecord.getService()),
                        new AttributeUpdate("principals").put(certRecord.getPrincipals()),
                        new AttributeUpdate("clientIP").put(certRecord.getClientIP()),
                        new AttributeUpdate("privateIP").put(certRecord.getPrivateIP()));

        Mockito.doReturn(updateOutcome).when(table).updateItem(item);
        boolean requestSuccess = dbConn.updateSSHCertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateSSHRecordException() {

        SSHCertRecord certRecord = new SSHCertRecord();

        Mockito.doThrow(new AmazonDynamoDBException("invalid operation"))
                .when(table).updateItem(ArgumentMatchers.any(UpdateItemSpec.class));

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);
        boolean requestSuccess = dbConn.updateSSHCertRecord(certRecord);
        assertFalse(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testDeleteSSHRecord() {
        DeleteItemSpec deleteItemSpec = new DeleteItemSpec()
                .withPrimaryKey("primaryKey", "cn:1234");
        Mockito.doReturn(deleteOutcome).when(table).deleteItem(deleteItemSpec);

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);

        boolean requestSuccess = dbConn.deleteSSHCertRecord("12345", "cn");
        assertTrue(requestSuccess);
        dbConn.close();
    }

    @Test
    public void testDeleteSSHRecordException() {

        Mockito.doThrow(new AmazonDynamoDBException("invalid operation"))
                .when(table).deleteItem(ArgumentMatchers.any(DeleteItemSpec.class));

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);

        boolean requestSuccess = dbConn.deleteSSHCertRecord("12345", "cn");
        assertFalse(requestSuccess);
        dbConn.close();
    }

    @Test
    public void testdeleteExpiredSSHCertRecords() {
        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);
        assertEquals(0, dbConn.deleteExpiredSSHCertRecords(100));
        assertEquals(0, dbConn.deleteExpiredSSHCertRecords(100000));
        dbConn.close();
    }
}
