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
package io.athenz.server.aws.common.notification.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.common.server.notification.NotificationObjectStore;
import com.yahoo.athenz.common.server.notification.NotificationObjectStoreFactory;

import org.eclipse.jetty.util.StringUtil;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.internal.util.EC2MetadataUtils;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

public class DynamoDBNotificationObjectStoreFactory implements NotificationObjectStoreFactory {

    public static final String PROP_DDB_NOTIFICATION_OBJECT_STORE_TABLE     = "athenz.ddb_notification_object_store_table";
    public static final String DEFAULT_DDB_NOTIFICATION_OBJECT_STORE_TABLE  = "Athenz-Notification-Object-Store";
    public static final String PROP_DDB_NOTIFICATION_OBJECT_STORE_REGION    = "athenz.ddb_notification_object_store_region";

    @Override
    public NotificationObjectStore create(PrivateKeyStore privateKeyStore) throws ServerResourceException {

        final String tableName = System.getProperty(PROP_DDB_NOTIFICATION_OBJECT_STORE_TABLE,
                DEFAULT_DDB_NOTIFICATION_OBJECT_STORE_TABLE);
        String region = System.getProperty(PROP_DDB_NOTIFICATION_OBJECT_STORE_REGION);
        if (StringUtil.isEmpty(region)) {
            region = EC2MetadataUtils.getEC2InstanceRegion();
        }

        DynamoDbClient dynamoDB = DynamoDbClient.builder()
                .region(Region.of(region))
                .build();
        DynamoDbEnhancedClient client = DynamoDbEnhancedClient.builder()
                .dynamoDbClient(dynamoDB)
                .build();

        DynamoDbTable<DynamoDBNotificationObjectStoreRecord> table = client.table(tableName,
                TableSchema.fromBean(DynamoDBNotificationObjectStoreRecord.class));
        return new DynamoDBNotificationObjectStore(table);
    }
}
