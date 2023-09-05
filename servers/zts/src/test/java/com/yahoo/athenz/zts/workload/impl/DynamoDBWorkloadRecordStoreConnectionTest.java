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
package com.yahoo.athenz.zts.workload.impl;

import com.amazonaws.services.dynamodbv2.document.*;
import com.amazonaws.services.dynamodbv2.document.internal.IteratorSupport;
import com.amazonaws.services.dynamodbv2.document.spec.QuerySpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;
import com.amazonaws.services.dynamodbv2.model.AmazonDynamoDBException;
import com.yahoo.athenz.common.server.workload.WorkloadRecord;
import com.yahoo.athenz.zts.ZTSTestUtils;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Date;
import java.util.List;

import static org.mockito.Mockito.when;

public class DynamoDBWorkloadRecordStoreConnectionTest {

    private final String tableName = "workload-table";
    private final String serviceIndexName = "service-index";
    private final String ipIndexName = "ip-index";

    @Mock private DynamoDB dynamoDB = Mockito.mock(DynamoDB.class);
    @Mock private Table table = Mockito.mock(Table.class);
    @Mock private Index serviceIndex = Mockito.mock(Index.class);
    @Mock private Index ipIndex = Mockito.mock(Index.class);
    @Mock private Item item = Mockito.mock(Item.class);
    @Mock private PutItemOutcome putOutcome = Mockito.mock(PutItemOutcome.class);
    @Mock private DeleteItemOutcome deleteOutcome = Mockito.mock(DeleteItemOutcome.class);
    @Mock private UpdateItemOutcome updateOutcome = Mockito.mock(UpdateItemOutcome.class);

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        Mockito.doReturn(table).when(dynamoDB).getTable(tableName);
        Mockito.doReturn(serviceIndex).when(table).getIndex(serviceIndexName);
        Mockito.doReturn(ipIndex).when(table).getIndex(ipIndexName);
    }

    private DynamoDBWorkloadRecordStoreConnection getDBConnection() {
        return new DynamoDBWorkloadRecordStoreConnection(dynamoDB, tableName, serviceIndexName, ipIndexName);
    }

    @Test
    public void testGetWorkloadRecordsByService() {

        long currTime = System.currentTimeMillis();
        Mockito.doReturn("1234").when(item).getString("instanceId");
        Mockito.doReturn("openstack").when(item).getString("provider");
        Mockito.doReturn("10.10.10.11").when(item).getString("ip");
        Mockito.doReturn("test-host").when(item).getString("hostname");
        Mockito.doReturn(true).when(item).hasAttribute("hostname");
        Mockito.doReturn(currTime).when(item).get("creationTime");
        Mockito.doReturn(currTime).when(item).get("updateTime");
        Mockito.doReturn(currTime).when(item).get("certExpiryTime");
        Mockito.doReturn(currTime).when(item).getLong("creationTime");
        Mockito.doReturn(currTime).when(item).getLong("updateTime");
        Mockito.doReturn(currTime).when(item).getLong("certExpiryTime");
        Mockito.doReturn(true).when(item).hasAttribute("certExpiryTime");

        ItemCollection<QueryOutcome> itemCollection = Mockito.mock(ItemCollection.class);
        IteratorSupport<Item, QueryOutcome> iteratorSupport = Mockito.mock(IteratorSupport.class);
        when(itemCollection.iterator()).thenReturn(iteratorSupport);
        when(iteratorSupport.hasNext()).thenReturn(true, false);
        when(iteratorSupport.next()).thenReturn(item);
        Mockito.doReturn(itemCollection).when(serviceIndex).query(Mockito.any(QuerySpec.class));

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

        Mockito.doReturn(null).when(serviceIndex).query(Mockito.any(QuerySpec.class));

        DynamoDBWorkloadRecordStoreConnection dbConn = new DynamoDBWorkloadRecordStoreConnection(dynamoDB, tableName, "service-index", "ip-index");
        List<WorkloadRecord> wlRecordList = dbConn.getWorkloadRecordsByService("athenz", "api");
        Assert.assertTrue(wlRecordList.isEmpty());
        dbConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByIp() {

        long currTime = System.currentTimeMillis();
        Mockito.doReturn("1234").when(item).getString("instanceId");
        Mockito.doReturn("openstack").when(item).getString("provider");
        Mockito.doReturn("athenz.api").when(item).getString("service");
        Mockito.doReturn("test-host").when(item).getString("hostname");
        Mockito.doReturn(currTime).when(item).get("creationTime");
        Mockito.doReturn(currTime).when(item).get("updateTime");
        Mockito.doReturn(currTime).when(item).get("certExpiryTime");
        Mockito.doReturn(currTime).when(item).getLong("creationTime");
        Mockito.doReturn(currTime).when(item).getLong("updateTime");
        Mockito.doReturn(currTime).when(item).getLong("certExpiryTime");

        ItemCollection<QueryOutcome> itemCollection = Mockito.mock(ItemCollection.class);
        IteratorSupport<Item, QueryOutcome> iteratorSupport = Mockito.mock(IteratorSupport.class);
        when(itemCollection.iterator()).thenReturn(iteratorSupport);
        when(iteratorSupport.hasNext()).thenReturn(true, false);
        when(iteratorSupport.next()).thenReturn(item);
        Mockito.doReturn(itemCollection).when(ipIndex).query(Mockito.any(QuerySpec.class));

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

        Mockito.doReturn(null).when(ipIndex).query(Mockito.any(QuerySpec.class));

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();
        List<WorkloadRecord> wlRecordList = dbConn.getWorkloadRecordsByIp("10.0.0.1");
        Assert.assertTrue(wlRecordList.isEmpty());
        dbConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByServiceNotFoundException() {

        Mockito.doThrow(new AmazonDynamoDBException("item not found"))
                .when(serviceIndex).query(Mockito.any(QuerySpec.class));

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();
        List<WorkloadRecord> wlRecordList = dbConn.getWorkloadRecordsByService("athenz", "api");
        Assert.assertTrue(wlRecordList.isEmpty());
        dbConn.close();
    }

    @Test
    public void testGetWorkloadRecordsByIpNotFoundException() {

        Mockito.doThrow(new AmazonDynamoDBException("item not found"))
                .when(ipIndex).query(Mockito.any(QuerySpec.class));

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

        Item item = ItemUtils.toItem(ZTSTestUtils.generateWorkloadAttributeValues("athenz.api", "1234", "opensack", "10.0.0.1", "test-host.corp.yahoo.com",
                Long.toString(currTime), Long.toString(currTime),Long.toString(currTime)));

        Mockito.doReturn(putOutcome).when(table).putItem(item);
        boolean requestSuccess = dbConn.insertWorkloadRecord(workloadRecord);
        Assert.assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testInsertWorkloadRecordException() {

        WorkloadRecord workloadRecord = new WorkloadRecord();

        Mockito.doThrow(new AmazonDynamoDBException("invalid operation"))
                .when(table).putItem(ArgumentMatchers.any(Item.class));

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

        UpdateItemSpec item = new UpdateItemSpec()
                .withPrimaryKey("primaryKey", "athenz.api#1234#10.0.0.1")
                .withAttributeUpdate(
                        new AttributeUpdate("provider").put(workloadRecord.getProvider()),
                        new AttributeUpdate("updateTime").put(workloadRecord.getUpdateTime()));

        Mockito.doReturn(updateOutcome).when(table).updateItem(item);
        boolean requestSuccess = dbConn.updateWorkloadRecord(workloadRecord);
        Assert.assertTrue(requestSuccess);

        dbConn.close();
    }

    @Test
    public void testUpdateWorkloadRecordException() {

        WorkloadRecord workloadRecord = new WorkloadRecord();

        Mockito.doThrow(new AmazonDynamoDBException("invalid operation"))
                .when(table).updateItem(ArgumentMatchers.any(UpdateItemSpec.class));

        DynamoDBWorkloadRecordStoreConnection dbConn = getDBConnection();
        boolean requestSuccess = dbConn.updateWorkloadRecord(workloadRecord);
        Assert.assertFalse(requestSuccess);

        dbConn.close();
    }

}
