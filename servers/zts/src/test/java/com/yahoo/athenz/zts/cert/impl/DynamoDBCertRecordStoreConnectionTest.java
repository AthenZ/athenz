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

import com.yahoo.athenz.common.server.cert.X509CertRecord;
import com.yahoo.athenz.zts.ZTSTestUtils;
import com.yahoo.athenz.zts.utils.DynamoDBUtils;
import org.mockito.*;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;
import static org.testng.Assert.*;
import static org.testng.Assert.assertEquals;

public class DynamoDBCertRecordStoreConnectionTest {

    private final String tableName = "cert-table";
    private final String currentTimeIndexName = "cert-table-currenttime-index";
    private final String hostNameIndexName = "cert-table-hostname-index";

    @Mock private DynamoDbClient dynamoDB = Mockito.mock(DynamoDbClient.class);

    @Mock private PutItemResponse putOutcome = Mockito.mock(PutItemResponse.class);
    @Mock private DeleteItemResponse deleteOutcome = Mockito.mock(DeleteItemResponse.class);
    @Mock private UpdateItemResponse updateOutcome = Mockito.mock(UpdateItemResponse.class);

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    private DynamoDBCertRecordStoreConnection getDBConnection() {
        return new DynamoDBCertRecordStoreConnection(dynamoDB, tableName, currentTimeIndexName, hostNameIndexName);
    }

    @Test
    public void testGetX509CertRecord() {

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put("primaryKey", AttributeValue.fromS("athenz.provider:cn:1234"));

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName(tableName)
                .build();

        Map<String, AttributeValue> attrs = new HashMap<>();

        Date now = new Date();
        long tstamp = mockNonNullableColumns(attrs, now);

        attrs.put("lastNotifiedTime", AttributeValue.fromN(String.valueOf(tstamp)));
        attrs.put("hostName", AttributeValue.fromS("hostname"));
        attrs.put("expiryTime", AttributeValue.fromN(String.valueOf(tstamp)));
        attrs.put("lastNotifiedServer", AttributeValue.fromS("last-notified-server"));

        GetItemResponse response = GetItemResponse.builder().item(attrs).build();
        Mockito.doReturn(response).when(dynamoDB).getItem(request);

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        dbConn.setOperationTimeout(10);
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");

        assertNonNullableColumns(now, certRecord);
        assertEquals(certRecord.getLastNotifiedTime(), now);
        assertEquals(certRecord.getLastNotifiedServer(), "last-notified-server");
        assertEquals(certRecord.getExpiryTime(), now);
        assertEquals(certRecord.getHostName(), "hostname");
        assertFalse(certRecord.getClientCert());

        dbConn.close();
    }

    @Test
    public void testGetX509CertRecordNullableColumns() {

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put("primaryKey", AttributeValue.fromS("athenz.provider:cn:1234"));

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName(tableName)
                .build();

        Map<String, AttributeValue> attrs = new HashMap<>();

        Date now = new Date();
        mockNonNullableColumns(attrs, now);
        attrs.remove("lastNotifiedTime");
        attrs.remove("lastNotifiedServer");
        attrs.remove("expiryTime");
        attrs.remove("hostName");

        GetItemResponse response = GetItemResponse.builder().item(attrs).build();
        Mockito.doReturn(response).when(dynamoDB).getItem(request);

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

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put("primaryKey", AttributeValue.fromS("athenz.provider:cn:1234"));

        GetItemRequest request = GetItemRequest.builder()
                .key(keyToGet)
                .tableName(tableName)
                .build();

        GetItemResponse response = GetItemResponse.builder().item(null).build();
        Mockito.when(dynamoDB.getItem(request)).thenReturn(response).thenReturn(null);

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");
        assertNull(certRecord);

        certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");
        assertNull(certRecord);

        dbConn.close();
    }

    @Test
    public void testGetX509CertRecordNotFoundException() {

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).getItem(ArgumentMatchers.any(GetItemRequest.class));

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        X509CertRecord certRecord = dbConn.getX509CertRecord("athenz.provider", "1234", "cn");
        assertNull(certRecord);
        dbConn.close();
    }

    @Test
    public void testInsertX509Record() {

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName,
                currentTimeIndexName, hostNameIndexName);

        Date now = new Date();
        String dateIsoFormat = DynamoDBUtils.getIso8601FromDate(now);
        X509CertRecord certRecord = getRecordNonNullableColumns(now);
        certRecord.setLastNotifiedTime(now);
        certRecord.setLastNotifiedServer("last-notified-server");
        certRecord.setExpiryTime(now);
        certRecord.setHostName("hostname");

        HashMap<String, AttributeValue> itemValues = new HashMap<>();

        itemValues.put("primaryKey", AttributeValue.fromS("athenz.provider:cn:1234"));
        itemValues.put("instanceId", AttributeValue.fromS(certRecord.getInstanceId()));
        itemValues.put("provider", AttributeValue.fromS(certRecord.getProvider()));
        itemValues.put("service", AttributeValue.fromS(certRecord.getService()));
        itemValues.put("currentSerial", AttributeValue.fromS(certRecord.getCurrentSerial()));
        itemValues.put("currentIP", AttributeValue.fromS(certRecord.getCurrentIP()));
        itemValues.put("currentTime", AttributeValue.fromN(String.valueOf(certRecord.getCurrentTime().getTime())));
        itemValues.put("currentDate", AttributeValue.fromS(dateIsoFormat));
        itemValues.put("prevSerial", AttributeValue.fromS(certRecord.getPrevSerial()));
        itemValues.put("prevIP", AttributeValue.fromS(certRecord.getPrevIP()));
        itemValues.put("prevTime", AttributeValue.fromN(String.valueOf(certRecord.getPrevTime().getTime())));
        itemValues.put("clientCert", AttributeValue.fromBool(certRecord.getClientCert()));
        itemValues.put("ttl", AttributeValue.fromN(String.valueOf(certRecord.getCurrentTime().getTime() / 1000L + 3660 * 720)));
        itemValues.put("lastNotifiedTime", AttributeValue.fromN(String.valueOf(certRecord.getLastNotifiedTime().getTime())));
        itemValues.put("lastNotifiedServer", AttributeValue.fromS(certRecord.getLastNotifiedServer()));
        itemValues.put("expiryTime", AttributeValue.fromN(String.valueOf(certRecord.getExpiryTime().getTime())));
        itemValues.put("hostName", AttributeValue.fromS(certRecord.getHostName()));

        PutItemRequest request = PutItemRequest.builder()
                .tableName(tableName)
                .item(itemValues)
                .build();

        Mockito.doReturn(putOutcome).when(dynamoDB).putItem(request);
        boolean requestSuccess = dbConn.insertX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        ArgumentCaptor<PutItemRequest> itemCaptor = ArgumentCaptor.forClass(PutItemRequest.class);
        Mockito.verify(dynamoDB, times(1)).putItem(itemCaptor.capture());
        List<PutItemRequest> allValues = itemCaptor.getAllValues();
        assertEquals(1, allValues.size());
        Map<String, AttributeValue> item = allValues.get(0).item();
        assertEquals(DynamoDBUtils.getString(item, "primaryKey"), "athenz.provider:cn:1234");
        assertEquals(DynamoDBUtils.getString(item, "provider"), "athenz.provider");
        assertEquals(DynamoDBUtils.getString(item, "instanceId"),"1234");
        assertEquals(DynamoDBUtils.getString(item, "service"), "cn");
        assertEquals(DynamoDBUtils.getString(item, "hostName"), "hostname");

        dbConn.close();
    }

    @Test
    public void testInsertX509RecordNoHostname() {

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName,
                currentTimeIndexName, hostNameIndexName);

        Date now = new Date();
        String dateIsoFormat = DynamoDBUtils.getIso8601FromDate(now);
        X509CertRecord certRecord = getRecordNonNullableColumns(now);
        certRecord.setLastNotifiedTime(now);
        certRecord.setLastNotifiedServer("last-notified-server");
        certRecord.setExpiryTime(now);

        HashMap<String, AttributeValue> itemValues = new HashMap<>();

        itemValues.put("primaryKey", AttributeValue.fromS("athenz.provider:cn:1234"));
        itemValues.put("instanceId", AttributeValue.fromS(certRecord.getInstanceId()));
        itemValues.put("provider", AttributeValue.fromS(certRecord.getProvider()));
        itemValues.put("service", AttributeValue.fromS(certRecord.getService()));
        itemValues.put("currentSerial", AttributeValue.fromS(certRecord.getCurrentSerial()));
        itemValues.put("currentIP", AttributeValue.fromS(certRecord.getCurrentIP()));
        itemValues.put("currentTime", AttributeValue.fromN(String.valueOf(certRecord.getCurrentTime().getTime())));
        itemValues.put("currentDate", AttributeValue.fromS(dateIsoFormat));
        itemValues.put("prevSerial", AttributeValue.fromS(certRecord.getPrevSerial()));
        itemValues.put("prevIP", AttributeValue.fromS(certRecord.getPrevIP()));
        itemValues.put("prevTime", AttributeValue.fromN(String.valueOf(certRecord.getPrevTime().getTime())));
        itemValues.put("clientCert", AttributeValue.fromBool(certRecord.getClientCert()));
        itemValues.put("ttl", AttributeValue.fromN(String.valueOf(certRecord.getCurrentTime().getTime() / 1000L + 3660 * 720)));
        itemValues.put("lastNotifiedTime", AttributeValue.fromN(String.valueOf(certRecord.getLastNotifiedTime().getTime())));
        itemValues.put("lastNotifiedServer", AttributeValue.fromS(certRecord.getLastNotifiedServer()));
        itemValues.put("expiryTime", AttributeValue.fromN(String.valueOf(certRecord.getExpiryTime().getTime())));

        PutItemRequest request = PutItemRequest.builder()
                .tableName(tableName)
                .item(itemValues)
                .build();

        Mockito.doReturn(putOutcome).when(dynamoDB).putItem(request);
        boolean requestSuccess = dbConn.insertX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        ArgumentCaptor<PutItemRequest> itemCaptor = ArgumentCaptor.forClass(PutItemRequest.class);
        Mockito.verify(dynamoDB, times(1)).putItem(itemCaptor.capture());
        List<PutItemRequest> allValues = itemCaptor.getAllValues();
        assertEquals(1, allValues.size());
        Map<String, AttributeValue> item = allValues.get(0).item();
        assertEquals(DynamoDBUtils.getString(item, "primaryKey"), "athenz.provider:cn:1234");
        assertEquals(DynamoDBUtils.getString(item, "provider"), "athenz.provider");
        assertEquals(DynamoDBUtils.getString(item, "instanceId"), "1234");
        assertEquals(DynamoDBUtils.getString(item, "service"), "cn");

        // When hostname is null, primaryKey will be used
        assertEquals(DynamoDBUtils.getString(item, "hostName"), "athenz.provider:cn:1234");

        dbConn.close();
    }

    @Test
    public void testInsertX509RecordNullableColumns() {

        DynamoDBCertRecordStoreConnection dbConn = new DynamoDBCertRecordStoreConnection(dynamoDB, tableName,
                currentTimeIndexName, hostNameIndexName);

        Date now = new Date();
        String dateIsoFormat = DynamoDBUtils.getIso8601FromDate(now);
        X509CertRecord certRecord = getRecordNonNullableColumns(now);
        certRecord.setLastNotifiedTime(null);
        certRecord.setLastNotifiedServer(null);
        certRecord.setExpiryTime(null);
        certRecord.setHostName(null);

        HashMap<String, AttributeValue> itemValues = new HashMap<>();

        itemValues.put("primaryKey", AttributeValue.fromS("athenz.provider:cn:1234"));
        itemValues.put("instanceId", AttributeValue.fromS(certRecord.getInstanceId()));
        itemValues.put("provider", AttributeValue.fromS(certRecord.getProvider()));
        itemValues.put("service", AttributeValue.fromS(certRecord.getService()));
        itemValues.put("currentSerial", AttributeValue.fromS(certRecord.getCurrentSerial()));
        itemValues.put("currentIP", AttributeValue.fromS(certRecord.getCurrentIP()));
        itemValues.put("currentTime", AttributeValue.fromN(String.valueOf(certRecord.getCurrentTime().getTime())));
        itemValues.put("currentDate", AttributeValue.fromS(dateIsoFormat));
        itemValues.put("prevSerial", AttributeValue.fromS(certRecord.getPrevSerial()));
        itemValues.put("prevIP", AttributeValue.fromS(certRecord.getPrevIP()));
        itemValues.put("prevTime", AttributeValue.fromN(String.valueOf(certRecord.getPrevTime().getTime())));
        itemValues.put("clientCert", AttributeValue.fromBool(certRecord.getClientCert()));
        itemValues.put("ttl", AttributeValue.fromN(String.valueOf(certRecord.getCurrentTime().getTime() / 1000L + 3660 * 720)));
        itemValues.remove("lastNotifiedTime");
        itemValues.remove("lastNotifiedServer");
        itemValues.remove("expiryTime");

        PutItemRequest request = PutItemRequest.builder()
                .tableName(tableName)
                .item(itemValues)
                .build();

        Mockito.doReturn(putOutcome).when(dynamoDB).putItem(request);
        boolean requestSuccess = dbConn.insertX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testInsertX509RecordException() {

        Date now = new Date();
        X509CertRecord certRecord = getRecordNonNullableColumns(now);

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).putItem(ArgumentMatchers.any(PutItemRequest.class));

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

        Mockito.doReturn(updateOutcome).when(dynamoDB).updateItem(any(UpdateItemRequest.class));
        boolean requestSuccess = dbConn.updateX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        ArgumentCaptor<UpdateItemRequest> itemCaptor = ArgumentCaptor.forClass(UpdateItemRequest.class);
        Mockito.verify(dynamoDB, times(1)).updateItem(itemCaptor.capture());
        List<UpdateItemRequest> allValues = itemCaptor.getAllValues();
        assertEquals(1, allValues.size());

        assertEquals(allValues.get(0).attributeUpdates().get("provider").value().s(), "athenz.provider");
        assertEquals(allValues.get(0).attributeUpdates().get("instanceId").value().s(),"1234");
        assertEquals(allValues.get(0).attributeUpdates().get("service").value().s(), "cn");
        assertEquals(allValues.get(0).attributeUpdates().get("hostName").value().s(), "hostname");

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

        Mockito.doReturn(updateOutcome).when(dynamoDB).updateItem(any(UpdateItemRequest.class));
        boolean requestSuccess = dbConn.updateX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        ArgumentCaptor<UpdateItemRequest> itemCaptor = ArgumentCaptor.forClass(UpdateItemRequest.class);
        Mockito.verify(dynamoDB, times(1)).updateItem(itemCaptor.capture());
        List<UpdateItemRequest> allValues = itemCaptor.getAllValues();
        assertEquals(1, allValues.size());

        assertEquals(allValues.get(0).attributeUpdates().get("provider").value().s(), "athenz.provider");
        assertEquals(allValues.get(0).attributeUpdates().get("instanceId").value().s(),"1234");
        assertEquals(allValues.get(0).attributeUpdates().get("service").value().s(), "cn");
        assertEquals(allValues.get(0).attributeUpdates().get("hostName").value().s(), "athenz.provider:cn:1234");

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

        Mockito.doReturn(updateOutcome).when(dynamoDB).updateItem(any(UpdateItemRequest.class));
        boolean requestSuccess = dbConn.updateX509CertRecord(certRecord);
        assertTrue(requestSuccess);

        ArgumentCaptor<UpdateItemRequest> itemCaptor = ArgumentCaptor.forClass(UpdateItemRequest.class);
        Mockito.verify(dynamoDB, times(1)).updateItem(itemCaptor.capture());
        List<UpdateItemRequest> allValues = itemCaptor.getAllValues();
        assertEquals(1, allValues.size());

        assertEquals(allValues.get(0).attributeUpdates().get("provider").value().s(), "athenz.provider");
        assertEquals(allValues.get(0).attributeUpdates().get("instanceId").value().s(),"1234");
        assertEquals(allValues.get(0).attributeUpdates().get("service").value().s(), "cn");
        assertEquals(allValues.get(0).attributeUpdates().get("hostName").value().s(), "athenz.provider:cn:1234");

        dbConn.close();
    }

    @Test
    public void testUpdateX509RecordException() {

        Date now = new Date();
        X509CertRecord certRecord = getRecordNonNullableColumns(now);

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).updateItem(ArgumentMatchers.any(UpdateItemRequest.class));

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();
        boolean requestSuccess = dbConn.updateX509CertRecord(certRecord);
        assertFalse(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testDeleteX509Record() {

        HashMap<String, AttributeValue> keyToGet = new HashMap<>();
        keyToGet.put("primaryKey", AttributeValue.fromS("athenz.provider:cn:1234"));

        DeleteItemRequest request = DeleteItemRequest.builder()
                .tableName(tableName)
                .key(keyToGet)
                .build();

        Mockito.doReturn(deleteOutcome).when(dynamoDB).deleteItem(request);

        DynamoDBCertRecordStoreConnection dbConn = getDBConnection();

        boolean requestSuccess = dbConn.deleteX509CertRecord("athenz.provider", "12345", "cn");
        assertTrue(requestSuccess);
        dbConn.close();
    }

    @Test
    public void testDeleteX509RecordException() {

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).deleteItem(ArgumentMatchers.any(DeleteItemRequest.class));

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

    private long mockNonNullableColumns(Map<String, AttributeValue> attrs, Date now) {

        long tstamp = now.getTime();

        attrs.put("provider", AttributeValue.fromS("athenz.provider"));
        attrs.put("instanceId", AttributeValue.fromS("1234"));
        attrs.put("service", AttributeValue.fromS("cn"));
        attrs.put("currentSerial", AttributeValue.fromS("current-serial"));
        attrs.put("currentTime", AttributeValue.fromN(String.valueOf(tstamp)));
        attrs.put("currentIP", AttributeValue.fromS("current-ip"));
        attrs.put("prevSerial", AttributeValue.fromS("prev-serial"));
        attrs.put("prevIP", AttributeValue.fromS("prev-ip"));
        attrs.put("prevTime", AttributeValue.fromN(String.valueOf(tstamp)));

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
                "home.test.service2", "unNotified", null, null, null, null, "testHost1");

        Map<String, AttributeValue> reNotified = ZTSTestUtils.generateAttributeValues(
                "home.test.service3", "reNotified", Long.toString(fiveDaysAgo), Long.toString(fiveDaysAgo),
                "testServer", null, "testHost2");

        Map<String, AttributeValue> rebootstrapped = ZTSTestUtils.generateAttributeValues(
                "home.test.service3", "rebootstrapped", Long.toString(sevenDaysAgo), Long.toString(sevenDaysAgo),
                "testServer", null, "testHost2");

        Map<String, AttributeValue> willBeUpdatedByOtherZts = ZTSTestUtils.generateAttributeValues(
                "home.test.service4", "willBeUpdatedByOtherZts", Long.toString(fiveDaysAgo), Long.toString(fiveDaysAgo),
                "testServer", null, "testHost3");

        QueryResponse response1 = QueryResponse.builder().items(Collections.singleton(unNotified)).build();
        QueryResponse response2 = QueryResponse.builder().items(List.of(reNotified, rebootstrapped)).build();
        QueryResponse response3 = QueryResponse.builder().items(Collections.singleton(willBeUpdatedByOtherZts)).build();
        QueryResponse response4 = QueryResponse.builder().items(List.of(reNotified, rebootstrapped)).build();

        QueryResponse responseEmpty = QueryResponse.builder().build();
        QueryResponse responseFull = QueryResponse.builder().items(List.of(unNotified, reNotified,
                willBeUpdatedByOtherZts, rebootstrapped)).build();
        Mockito.when(dynamoDB.query(any(QueryRequest.class))).thenReturn(responseFull)
                .thenReturn(responseEmpty).thenReturn(responseEmpty).thenReturn(responseEmpty)
                .thenReturn(responseEmpty).thenReturn(responseEmpty).thenReturn(responseEmpty)
                .thenReturn(responseEmpty).thenReturn(responseEmpty).thenReturn(responseEmpty)
                .thenReturn(responseEmpty).thenReturn(responseEmpty).thenReturn(responseEmpty)
                .thenReturn(responseEmpty).thenReturn(responseEmpty).thenReturn(responseEmpty)
                .thenReturn(responseEmpty).thenReturn(response1).thenReturn(response2)
                .thenReturn(response3).thenReturn(response4);

        AttributeValue lastNotifiedTimeAttrValue = AttributeValue.fromN(Long.toString(nowL));
        AttributeValue lastNotifiedServerAttrValue = AttributeValue.fromS("localhost");
        AttributeValue lastNotifiedOtherServerAttrValue = AttributeValue.fromS("SomeOtherZTS");

        unNotified.put("lastNotifiedTime", lastNotifiedTimeAttrValue);
        unNotified.put("lastNotifiedServer", lastNotifiedServerAttrValue);

        reNotified.put("lastNotifiedTime", lastNotifiedTimeAttrValue);
        reNotified.put("lastNotifiedServer", lastNotifiedServerAttrValue);

        willBeUpdatedByOtherZts.put("lastNotifiedTime", lastNotifiedTimeAttrValue);
        willBeUpdatedByOtherZts.put("lastNotifiedServer", lastNotifiedOtherServerAttrValue);

        UpdateItemResponse updateItemOutcome1 = UpdateItemResponse.builder().attributes(unNotified).build();
        UpdateItemResponse updateItemOutcome2 = UpdateItemResponse.builder().attributes(reNotified).build();
        UpdateItemResponse updateItemOutcome3 = UpdateItemResponse.builder().attributes(willBeUpdatedByOtherZts).build();

        when(dynamoDB.updateItem(any(UpdateItemRequest.class)))
                .thenReturn(updateItemOutcome1)
                .thenReturn(updateItemOutcome2)
                .thenReturn(updateItemOutcome3);

        List<X509CertRecord> records = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "localhost",
                nowL,
                "provider");

        ArgumentCaptor<UpdateItemRequest> updateArguments = ArgumentCaptor.forClass(UpdateItemRequest.class);
        Mockito.verify(dynamoDB, Mockito.times(3)).updateItem(updateArguments.capture());

        // Assert get filtered records
        List<UpdateItemRequest> allUpdateArguments = updateArguments.getAllValues();
        assertEquals(allUpdateArguments.size(), 3);
        assertEquals(allUpdateArguments.get(0).key().get("primaryKey").toString(), "AttributeValue(S=provider:home.test.service2:unNotified)");
        assertEquals(allUpdateArguments.get(1).key().get("primaryKey").toString(), "AttributeValue(S=provider:home.test.service3:reNotified)");
        assertEquals(allUpdateArguments.get(2).key().get("primaryKey").toString(), "AttributeValue(S=provider:home.test.service4:willBeUpdatedByOtherZts)");

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

        List<Map<String, AttributeValue>> items = new ArrayList<>();
        Map<String, AttributeValue> reNotified = ZTSTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");
        items.add(reNotified);

        QueryResponse response = QueryResponse.builder().items(items).build();
        Mockito.doReturn(response).when(dynamoDB).query(any(QueryRequest.class));

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).updateItem(ArgumentMatchers.any(UpdateItemRequest.class));

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

        List<Map<String, AttributeValue>> items = new ArrayList<>();
        Map<String, AttributeValue> reNotified = ZTSTestUtils.generateAttributeValues(
                "home.test.service3",
                "reNotified",
                Long.toString(fiveDaysAgo),
                Long.toString(fiveDaysAgo),
                "testServer",
                null,
                "testHost2");
        items.add(reNotified);

        QueryResponse response = QueryResponse.builder().items(items).build();
        Mockito.doReturn(response).when(dynamoDB).query(any(QueryRequest.class));

        Mockito.doThrow(TransactionConflictException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).updateItem(ArgumentMatchers.any(UpdateItemRequest.class));

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

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).query(ArgumentMatchers.any(QueryRequest.class));

        List<X509CertRecord> result = dbConn.updateUnrefreshedCertificatesNotificationTimestamp(
                "serverTest",
                1591706189000L,
                "providerTest");

        assertEquals(result.size(), 0);

        dbConn.close();
    }
}
