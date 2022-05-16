/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *  
 */

package com.yahoo.athenz.zms;

import com.yahoo.athenz.zms.store.AuthHistoryRecord;
import com.yahoo.athenz.zms.utils.ZMSAuthHistoryPushToInMemDB;
import org.testng.annotations.*;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.WriteBatch;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import static com.yahoo.athenz.zms.store.InMemoryAuthHistoryStoreFactory.AUTH_HISTORY_IN_MEM_TABLE_NAME;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

public class ZMSAuthHistoryTest {

    private final ZMSTestInitializer zmsTestInitializer = new ZMSTestInitializer();

    @BeforeClass
    public void startMemoryMySQL() {
        zmsTestInitializer.startMemoryDB();
    }

    @AfterClass
    public void stopMemoryMySQL() {
        zmsTestInitializer.stopMemoryDB();
    }

    @BeforeMethod
    public void setUp() throws Exception {
        zmsTestInitializer.setUp();
    }

    @AfterMethod
    public void clearConnections() {
        zmsTestInitializer.clearConnections();
    }

    @Test
    public void testGetAuthHistoryListEmpty() {
        AuthHistoryList authHistoryList = zmsTestInitializer.getZms().getAuthHistoryList(zmsTestInitializer.getMockDomRsrcCtx(), "test.domain");
        assertEquals(authHistoryList.getAuthHistoryList(), new ArrayList<>());
    }

    private DynamoDbEnhancedClient getDynamoDBClient() {
        DynamoDbClient client = DynamoDbClient
                .builder()
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create("http://localhost:3312"))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("FAKE", "FAKE")))
                .build();

        return DynamoDbEnhancedClient.builder()
                .dynamoDbClient(client)
                .build();
    }

    @Test
    public void testGetAuthHistoryList() {
        DynamoDbEnhancedClient dynamoDB = getDynamoDBClient();
        DynamoDbTable<AuthHistoryRecord> mappedTable = dynamoDB.table(AUTH_HISTORY_IN_MEM_TABLE_NAME, TableSchema.fromBean(AuthHistoryRecord.class));
        WriteBatch.Builder<AuthHistoryRecord> authHistoryRecordBuilder = WriteBatch.builder(AuthHistoryRecord.class).mappedTableResource(mappedTable);
        int numberOfRecords = 24;

        for (int i = 0; i < numberOfRecords; ++i) {
            AuthHistoryRecord authHistoryRecord = generateRecordForTest(i);
            authHistoryRecordBuilder.addPutItem(authHistoryRecord);
        }

        // Create a BatchWriteItemEnhancedRequest object
        BatchWriteItemEnhancedRequest batchWriteItemEnhancedRequest =
                BatchWriteItemEnhancedRequest.builder()
                        .writeBatches(authHistoryRecordBuilder.build())
                        .build();
        dynamoDB.batchWriteItem(batchWriteItemEnhancedRequest);

        // Verify records
        for (int i = 0; i < numberOfRecords; ++i) {
            AuthHistoryList authHistoryList = zmsTestInitializer.getZms().getAuthHistoryList(zmsTestInitializer.getMockDomRsrcCtx(), "test.domain" + i);
            assertEquals(authHistoryList.getAuthHistoryList().size(), 1);
            AuthHistory authHistory = authHistoryList.getAuthHistoryList().get(0);
            assertEquals(authHistory.getDomainName(), "test.domain" + i);

            // Remove record
            AuthHistoryRecord authHistoryRecord = new AuthHistoryRecord(authHistory.getDomainName(), authHistory.getPrincipal(), authHistory.getEndpoint(), authHistory.getTimestamp().toString(), authHistory.getTtl());
            mappedTable.deleteItem(authHistoryRecord);
        }
        assertEquals(mappedTable.scan().items().stream().count(), 0);
    }

    @Test
    public void testGetAuthHistoryListSameDomain() {
        DynamoDbEnhancedClient dynamoDB = getDynamoDBClient();
        DynamoDbTable<AuthHistoryRecord> mappedTable = dynamoDB.table(AUTH_HISTORY_IN_MEM_TABLE_NAME, TableSchema.fromBean(AuthHistoryRecord.class));
        int numberOfRecords = 1000;

        Set<AuthHistoryRecord> records = new HashSet<>();
        for (int i = 0; i < numberOfRecords; ++i) {
            AuthHistoryRecord authHistoryRecord = generateRecordForTest(i);
            authHistoryRecord.setDomain("test.domain");
            records.add(authHistoryRecord);
        }
        ZMSAuthHistoryPushToInMemDB zmsAuthHistoryPushToInMemDB = new ZMSAuthHistoryPushToInMemDB();
        zmsAuthHistoryPushToInMemDB.pushToDB(records, mappedTable);
        AuthHistoryList authHistoryList = zmsTestInitializer.getZms().getAuthHistoryList(zmsTestInitializer.getMockDomRsrcCtx(), "test.domain");
        assertEquals(authHistoryList.getAuthHistoryList().size(), numberOfRecords);
        // Verify records
        for (int i = 0; i < numberOfRecords; ++i) {
            AuthHistory authHistory = authHistoryList.getAuthHistoryList().get(i);
            assertEquals(authHistory.getDomainName(), "test.domain");

            // Remove record
            AuthHistoryRecord authHistoryRecord = new AuthHistoryRecord(authHistory.getDomainName(), authHistory.getPrincipal(), authHistory.getEndpoint(), authHistory.getTimestamp().toString(), authHistory.getTtl());
            mappedTable.deleteItem(authHistoryRecord);
        }

        // Verify all records removed
        authHistoryList = zmsTestInitializer.getZms().getAuthHistoryList(zmsTestInitializer.getMockDomRsrcCtx(), "test.domain");
        assertEquals(authHistoryList.getAuthHistoryList().size(), 0);
    }

    @Test
    public void testGetAuthHistoryListInvalidTimestamp() {
        DynamoDbEnhancedClient dynamoDB = getDynamoDBClient();
        DynamoDbTable<AuthHistoryRecord> mappedTable = dynamoDB.table(AUTH_HISTORY_IN_MEM_TABLE_NAME, TableSchema.fromBean(AuthHistoryRecord.class));
        String domainName = "test.domain";
        String principal = "principal";
        String endpoint = "https://endpoint.com";
        long ttl = 1655282257L;

        // Insert record with unexpected timestamp
        AuthHistoryRecord authHistoryRecord = new AuthHistoryRecord(domainName, principal, endpoint, "19-Apr-2022:08:00", ttl);
        Set<AuthHistoryRecord> records = new HashSet<>();
        records.add(authHistoryRecord);
        ZMSAuthHistoryPushToInMemDB zmsAuthHistoryPushToInMemDB = new ZMSAuthHistoryPushToInMemDB();
        zmsAuthHistoryPushToInMemDB.pushToDB(records, mappedTable);

        // We are still able to fetch the record but without the timestamp
        AuthHistoryList authHistoryList = zmsTestInitializer.getZms().getAuthHistoryList(zmsTestInitializer.getMockDomRsrcCtx(), "test.domain");
        assertEquals(authHistoryList.getAuthHistoryList().size(), 1);
        assertEquals(authHistoryList.getAuthHistoryList().get(0).getDomainName(), domainName);
        assertEquals(authHistoryList.getAuthHistoryList().get(0).getPrincipal(), principal);
        assertEquals(authHistoryList.getAuthHistoryList().get(0).getEndpoint(), endpoint);
        assertEquals(authHistoryList.getAuthHistoryList().get(0).getTtl(), 1655282257L);
        assertNull(authHistoryList.getAuthHistoryList().get(0).getTimestamp());

        // Remove the record
        mappedTable.deleteItem(authHistoryRecord);
    }

    private AuthHistoryRecord generateRecordForTest(int index) {
        return new AuthHistoryRecord("test.domain" + index, "principal" + index, "https://endpoint" + index + ".com", "19/Apr/2022:08:00:45", 1655282257L + index);
    }
}
