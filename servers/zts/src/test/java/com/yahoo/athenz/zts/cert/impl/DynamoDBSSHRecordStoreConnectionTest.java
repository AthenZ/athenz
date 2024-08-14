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

import com.yahoo.athenz.common.server.ssh.SSHCertRecord;
import com.yahoo.athenz.zts.utils.DynamoDBUtils;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.*;

public class DynamoDBSSHRecordStoreConnectionTest {

    private final String tableName = "cert-table";

    @Mock private DynamoDbClient dynamoDB;
    @Mock private PutItemResponse putOutcome = Mockito.mock(PutItemResponse.class);
    @Mock private DeleteItemResponse deleteOutcome = Mockito.mock(DeleteItemResponse.class);
    @Mock private UpdateItemResponse updateOutcome = Mockito.mock(UpdateItemResponse.class);

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetSSHCertRecord() {

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put("primaryKey", AttributeValue.fromS("cn:1234"));

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName(tableName)
                .build();

        Map<String, AttributeValue> attrs = new HashMap<>();
        attrs.put("instanceId", AttributeValue.fromS("1234"));
        attrs.put("service", AttributeValue.fromS("cn"));
        attrs.put("principals", AttributeValue.fromS("host1,host2"));
        attrs.put("clientIP", AttributeValue.fromS("10.10.10.11"));
        attrs.put("privateIP", AttributeValue.fromS("10.10.10.12"));

        GetItemResponse response = GetItemResponse.builder().item(attrs).build();
        Mockito.doReturn(response).when(dynamoDB).getItem(request);

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

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put("primaryKey", AttributeValue.fromS("cn:1234"));

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName(tableName)
                .build();

        GetItemResponse response1 = GetItemResponse.builder().item(null).build();
        GetItemResponse response2 = GetItemResponse.builder().item(Collections.emptyMap()).build();
        Mockito.when(dynamoDB.getItem(request)).thenReturn(response1).thenReturn(response2);

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);
        // first time we should get null item
        SSHCertRecord certRecord = dbConn.getSSHCertRecord("1234", "cn");
        assertNull(certRecord);
        // second time we should get empty map
        certRecord = dbConn.getSSHCertRecord("1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testGetSSHCertRecordNotFoundException() {

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put("primaryKey", AttributeValue.fromS("cn:1234"));

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName(tableName)
                .build();

        Mockito.when(dynamoDB.getItem(request)).thenThrow(ResourceNotFoundException.builder().build());

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

        HashMap<String, AttributeValue> itemValues = new HashMap<>();
        itemValues.put("primaryKey", AttributeValue.fromS("cn:1234"));
        itemValues.put("instanceId", AttributeValue.fromS(certRecord.getInstanceId()));
        itemValues.put("service", AttributeValue.fromS(certRecord.getService()));
        itemValues.put("clientIP", AttributeValue.fromS(certRecord.getClientIP()));
        itemValues.put("principals", AttributeValue.fromS(certRecord.getPrincipals()));
        itemValues.put("privateIP", AttributeValue.fromS(certRecord.getPrivateIP()));

        PutItemRequest request = PutItemRequest.builder()
                .tableName(tableName)
                .item(itemValues)
                .build();

        Mockito.doReturn(putOutcome).when(dynamoDB).putItem(request);
        boolean requestSuccess = dbConn.insertSSHCertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testInsertSSHRecordException() {

        SSHCertRecord certRecord = new SSHCertRecord();

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).putItem(ArgumentMatchers.any(PutItemRequest.class));

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

        HashMap<String, AttributeValueUpdate> updatedValues = new HashMap<>();
        DynamoDBUtils.updateItemStringValue(updatedValues, "instanceId", certRecord.getInstanceId());
        DynamoDBUtils.updateItemStringValue(updatedValues, "service", certRecord.getService());
        DynamoDBUtils.updateItemStringValue(updatedValues, "clientIP", certRecord.getClientIP());
        DynamoDBUtils.updateItemStringValue(updatedValues, "principals", certRecord.getPrincipals());
        DynamoDBUtils.updateItemStringValue(updatedValues, "privateIP", certRecord.getPrivateIP());

        HashMap<String, AttributeValue> itemKey = new HashMap<>();
        itemKey.put("primaryKey", AttributeValue.fromS("cn:1234"));

        UpdateItemRequest request = UpdateItemRequest.builder()
                .tableName(tableName)
                .key(itemKey)
                .attributeUpdates(updatedValues)
                .build();

        Mockito.doReturn(updateOutcome).when(dynamoDB).updateItem(request);
        boolean requestSuccess = dbConn.updateSSHCertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateSSHRecordException() {

        SSHCertRecord certRecord = new SSHCertRecord();

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).updateItem(ArgumentMatchers.any(UpdateItemRequest.class));

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);
        boolean requestSuccess = dbConn.updateSSHCertRecord(certRecord);
        assertFalse(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testDeleteSSHRecord() {

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put("primaryKey", AttributeValue.fromS("cn:1234"));

        DeleteItemRequest request = DeleteItemRequest.builder()
                .tableName(tableName)
                .key(keyToGet)
                .build();

        Mockito.doReturn(deleteOutcome).when(dynamoDB).deleteItem(request);

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);

        boolean requestSuccess = dbConn.deleteSSHCertRecord("12345", "cn");
        assertTrue(requestSuccess);
        dbConn.close();
    }

    @Test
    public void testDeleteSSHRecordException() {

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).deleteItem(ArgumentMatchers.any(DeleteItemRequest.class));

        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);

        boolean requestSuccess = dbConn.deleteSSHCertRecord("12345", "cn");
        assertFalse(requestSuccess);
        dbConn.close();
    }

    @Test
    public void testDeleteExpiredSSHCertRecords() {
        DynamoDBSSHRecordStoreConnection dbConn = new DynamoDBSSHRecordStoreConnection(dynamoDB, tableName);
        assertEquals(0, dbConn.deleteExpiredSSHCertRecords(100));
        assertEquals(0, dbConn.deleteExpiredSSHCertRecords(100000));
        dbConn.close();
    }
}
