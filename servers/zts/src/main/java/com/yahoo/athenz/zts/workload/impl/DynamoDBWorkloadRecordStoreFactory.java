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

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStore;
import com.yahoo.athenz.common.server.workload.WorkloadRecordStoreFactory;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientFetcher;
import com.yahoo.athenz.db.dynamodb.DynamoDBClientFetcherFactory;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import com.yahoo.athenz.zts.cert.impl.ZTSDynamoDBClientSettingsFactory;
import com.yahoo.athenz.zts.notification.ZTSClientNotificationSenderImpl;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DynamoDBWorkloadRecordStoreFactory implements WorkloadRecordStoreFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(DynamoDBWorkloadRecordStoreFactory.class);

    @Override
    public WorkloadRecordStore create(PrivateKeyStore keyStore) {

        final String tableName = System.getProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_TABLE_NAME);
        if (StringUtil.isEmpty(tableName)) {
            LOGGER.error("Workload Store DynamoDB table name not specified");
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE, "DynamoDB table name not specified");
        }

        final String serviceIndexName = System.getProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_SERVICE_NAME);
        if (StringUtil.isEmpty(serviceIndexName)) {
            LOGGER.error("Workload Store DynamoDB index by name service not specified");
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE, "DynamoDB index workload-service-index not specified");
        }

        final String ipIndexName = System.getProperty(ZTSConsts.ZTS_PROP_WORKLOAD_DYNAMODB_INDEX_IP_NAME);
        if (StringUtil.isEmpty(ipIndexName)) {
            LOGGER.error("Workload Store DynamoDB index by name ip not specified");
            throw new ResourceException(ResourceException.SERVICE_UNAVAILABLE, "DynamoDB index workload-ip-index not specified");
        }

        AmazonDynamoDB client = getDynamoDBClient(null, keyStore);

        return new DynamoDBWorkloadRecordStore(client, tableName, serviceIndexName, ipIndexName);
    }

    AmazonDynamoDB getDynamoDBClient(ZTSClientNotificationSenderImpl ztsClientNotificationSender, PrivateKeyStore keyStore) {
        DynamoDBClientFetcher dynamoDBClientFetcher = DynamoDBClientFetcherFactory.getDynamoDBClientFetcher();
        ZTSDynamoDBClientSettingsFactory ztsDynamoDBClientSettingsFactory = new ZTSDynamoDBClientSettingsFactory(keyStore);
        return dynamoDBClientFetcher.getDynamoDBClient(ztsClientNotificationSender, ztsDynamoDBClientSettingsFactory.getDynamoDBClientSettings()).getAmazonDynamoDB();
    }
}
