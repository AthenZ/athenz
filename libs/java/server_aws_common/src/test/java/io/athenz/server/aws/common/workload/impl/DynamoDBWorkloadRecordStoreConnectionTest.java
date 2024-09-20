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
package io.athenz.server.aws.common.workload.impl;

import com.yahoo.athenz.common.server.workload.WorkloadRecord;
import io.athenz.server.aws.common.ServerCommonTestUtils;
import io.athenz.server.aws.common.utils.DynamoDBUtils;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DynamoDBWorkloadRecordStoreConnectionTest {

    private final String tableName = "workload-table";
    private final String serviceIndexName = "service-index";
    private final String ipIndexName = "ip-index";

    @Mock private DynamoDbClient dynamoDB;
    @Mock private PutItemResponse putOutcome = Mockito.mock(PutItemResponse.class);
    @Mock private UpdateItemResponse updateOutcome = Mockito.mock(UpdateItemResponse.class);

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    private DynamoDBWorkloadRecordStoreConnection getDBConnection() {
        return new DynamoDBWorkloadRecordStoreConnection(dynamoDB, tableName, serviceIndexName, ipIndexName);
    }

    @Test
    public void testGetWorkloadRecordsByService() {

        long currTime = System.currentTimeMillis();
        Map<String, AttributeValue> attrs = new HashMap<>();
        attrs.put("instanceId", AttributeValue.fromS("1234"));
        attrs.put("provider", AttributeValue.fromS("openstack"));
        attrs.put("ip", AttributeValue.fromS("10.10.10.11"));
        attrs.put("hostname", AttributeValue.fromS("test-host"));
        attrs.put("creationTime", AttributeValue.fromN(String.valueOf(currTime)));
        attrs.put("updateTime", AttributeValue.fromN(String.valueOf(currTime)));
        attrs.put("certExpiryTime", AttributeValue.fromN(String.valueOf(currTime)));

        HashMap<String, AttributeValue> attrValues = new HashMap<>();
        attrValues.put(":v_service", AttributeValue.fromS("athenz.api"));

        QueryRequest request = QueryRequest.builder()
                .tableName(tableName)
                .indexName(serviceIndexName)
                .keyConditionExpression("service = :v_service")
                .expressionAttributeValues(attrValues)
                .build();

        List<Map<String, AttributeValue>> items = new java.util.ArrayList<>();
        items.add(attrs);
        QueryResponse response = QueryResponse.builder().items(items).build();
        Mockito.doReturn(response).when(dynamoDB).query(request);

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();
        dbConn.setOperationTimeout(10);
        List<WorkloadRecord> wlRecordList = dbConn.getWorkloadRecordsByService("athenz", "api");

        Assert.assertNotNull(wlRecordList);
        Assert.assertEquals(wlRecordList.get(0).getInstanceId(), "1234");
        Assert.assertEquals(wlRecordList.get(0).getProvider(), "openstack");
        Assert.assertEquals(wlRecordList.get(0).getIp(), "10.10.10.11");
        Assert.assertEquals(wlRecordList.get(0).getHostname(), "test-host");
        Assert.assertEquals(wlRecordList.get(0).getUpdateTime(), new Date(currTime));
        Assert.assertEquals(wlRecordList.get(0).getCertExpiryTime(), new Date(currTime));

        dbConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByServiceNotFoundNull() {

        HashMap<String, AttributeValue> attrValues = new HashMap<>();
        attrValues.put(":v_service", AttributeValue.fromS("athenz.api"));

        QueryRequest request = QueryRequest.builder()
                .tableName(tableName)
                .indexName(serviceIndexName)
                .keyConditionExpression("service = :v_service")
                .expressionAttributeValues(attrValues)
                .build();

        Mockito.doReturn(null).when(dynamoDB).query(request);

        DynamoDBWorkloadRecordStoreConnection dbConn = new DynamoDBWorkloadRecordStoreConnection(dynamoDB,
                tableName, "service-index", "ip-index");
        List<WorkloadRecord> wlRecordList = dbConn.getWorkloadRecordsByService("athenz", "api");
        Assert.assertTrue(wlRecordList.isEmpty());
        dbConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByIp() {

        long currTime = System.currentTimeMillis();
        Map<String, AttributeValue> attrs = new HashMap<>();
        attrs.put("instanceId", AttributeValue.fromS("1234"));
        attrs.put("provider", AttributeValue.fromS("openstack"));
        attrs.put("service", AttributeValue.fromS("athenz.api"));
        attrs.put("creationTime", AttributeValue.fromN(String.valueOf(currTime)));
        attrs.put("updateTime", AttributeValue.fromN(String.valueOf(currTime)));

        HashMap<String, AttributeValue> attrValues = new HashMap<>();
        attrValues.put(":v_ip", AttributeValue.fromS("10.0.0.1"));

        QueryRequest request = QueryRequest.builder()
                .tableName(tableName)
                .indexName(ipIndexName)
                .keyConditionExpression("ip = :v_ip")
                .expressionAttributeValues(attrValues)
                .build();

        List<Map<String, AttributeValue>> items = new java.util.ArrayList<>();
        items.add(attrs);
        QueryResponse response = QueryResponse.builder().items(items).build();
        Mockito.doReturn(response).when(dynamoDB).query(request);

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();
        dbConn.setOperationTimeout(10);
        List<WorkloadRecord> wlRecordList = dbConn.getWorkloadRecordsByIp("10.0.0.1");

        Assert.assertNotNull(wlRecordList);
        Assert.assertEquals(wlRecordList.get(0).getInstanceId(), "1234");
        Assert.assertEquals(wlRecordList.get(0).getProvider(), "openstack");
        Assert.assertEquals(wlRecordList.get(0).getService(), "athenz.api");
        Assert.assertEquals(wlRecordList.get(0).getHostname(), "NA");
        Assert.assertEquals(wlRecordList.get(0).getUpdateTime(), new Date(currTime));
        Assert.assertEquals(wlRecordList.get(0).getCertExpiryTime(), new Date(0));

        dbConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByIpNotFoundNull() {

        Mockito.doReturn(null).when(dynamoDB).query(ArgumentMatchers.any(QueryRequest.class));

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();
        List<WorkloadRecord> wlRecordList = dbConn.getWorkloadRecordsByIp("10.0.0.1");
        Assert.assertTrue(wlRecordList.isEmpty());
        dbConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByServiceNotFoundException() {

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).query(ArgumentMatchers.any(QueryRequest.class));

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();
        List<WorkloadRecord> wlRecordList = dbConn.getWorkloadRecordsByService("athenz", "api");
        Assert.assertTrue(wlRecordList.isEmpty());
        dbConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByIpNotFoundException() {

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).query(ArgumentMatchers.any(QueryRequest.class));

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();
        List<WorkloadRecord> wlRecordList = dbConn.getWorkloadRecordsByIp("10.0.0.1");
        Assert.assertTrue(wlRecordList.isEmpty());
        dbConn.close();
    }

    @Test
    public void testInsertWorkloadRecord() {

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();

        WorkloadRecord workloadRecord = new WorkloadRecord();
        workloadRecord.setInstanceId("1234");
        workloadRecord.setService("athenz.api");
        workloadRecord.setProvider("openstack");
        workloadRecord.setIp("10.0.0.1");
        workloadRecord.setHostname("test-host.corp.yahoo.com");
        long currTime = System.currentTimeMillis();
        Date currDate = new Date(currTime);
        workloadRecord.setCreationTime(currDate);
        workloadRecord.setUpdateTime(currDate);

        PutItemRequest request = PutItemRequest.builder()
                .tableName(tableName)
                .item(ServerCommonTestUtils.generateWorkloadAttributeValues("athenz.api", "1234", "opensack",
                        "10.0.0.1", "test-host.corp.yahoo.com", Long.toString(currTime), Long.toString(currTime),
                        Long.toString(currTime)))
                .build();

        Mockito.doReturn(putOutcome).when(dynamoDB).putItem(request);

        boolean requestSuccess = dbConn.insertWorkloadRecord(workloadRecord);
        Assert.assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testInsertWorkloadRecordException() {

        WorkloadRecord workloadRecord = new WorkloadRecord();

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).putItem(ArgumentMatchers.any(PutItemRequest.class));

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();
        boolean requestSuccess = dbConn.insertWorkloadRecord(workloadRecord);
        Assert.assertFalse(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateWorkloadRecord() {

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();

        WorkloadRecord workloadRecord = new WorkloadRecord();
        workloadRecord.setProvider("openstack");
        long currTime = System.currentTimeMillis();
        Date currDate = new Date(currTime);
        workloadRecord.setUpdateTime(currDate);

        HashMap<String, AttributeValueUpdate> updatedValues = new HashMap<>();
        DynamoDBUtils.updateItemStringValue(updatedValues, "provider", workloadRecord.getProvider());
        DynamoDBUtils.updateItemLongValue(updatedValues, "updateTime", workloadRecord.getUpdateTime());

        HashMap<String, AttributeValue> itemKey = new HashMap<>();
        itemKey.put("primaryKey", AttributeValue.fromS("athenz.api#1234#10.0.0.1"));

        UpdateItemRequest request = UpdateItemRequest.builder()
                .tableName(tableName)
                .key(itemKey)
                .attributeUpdates(updatedValues)
                .build();

        Mockito.doReturn(updateOutcome).when(dynamoDB).updateItem(request);
        boolean requestSuccess = dbConn.updateWorkloadRecord(workloadRecord);
        Assert.assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateWorkloadRecordException() {

        WorkloadRecord workloadRecord = new WorkloadRecord();

        Mockito.doThrow(AwsServiceException.create("invalid operation", new Throwable("invalid operation")))
                .when(dynamoDB).updateItem(ArgumentMatchers.any(UpdateItemRequest.class));

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();
        boolean requestSuccess = dbConn.updateWorkloadRecord(workloadRecord);
        Assert.assertFalse(requestSuccess);

        dbConn.close();
    }

}
