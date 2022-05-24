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

package com.yahoo.athenz.zms.store.impl.dynamodb;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.AuthHistoryStore;
import com.yahoo.athenz.zms.store.AuthHistoryStoreFactory;
import org.eclipse.jetty.util.StringUtil;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.internal.util.EC2MetadataUtils;

public class DynamoDBAuthHistoryStoreFactory implements AuthHistoryStoreFactory {

    @Override
    public AuthHistoryStore create(PrivateKeyStore pkeyStore) {
        final String tableName = System.getProperty(ZMSConsts.ZMS_PROP_AUTH_HISTORY_DYNAMODB_TABLE, ZMSConsts.ZMS_DEFAULT_AUTH_HISTORY_DYNAMODB_TABLE);
        String region = System.getProperty(ZMSConsts.ZMS_PROP_AUTH_HISTORY_DYNAMODB_REGION);
        if (StringUtil.isEmpty(region)) {
            region = EC2MetadataUtils.getEC2InstanceRegion();
        }
        return new DynamoDBAuthHistoryStore(tableName, Region.of(region));
    }
}
