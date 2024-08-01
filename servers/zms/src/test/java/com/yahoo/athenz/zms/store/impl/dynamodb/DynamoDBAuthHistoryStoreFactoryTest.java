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

import com.yahoo.athenz.zms.ZMSConsts;
import com.yahoo.athenz.zms.store.AuthHistoryStore;
import org.testng.annotations.Test;
import software.amazon.awssdk.core.exception.SdkClientException;

import static org.testng.AssertJUnit.*;

public class DynamoDBAuthHistoryStoreFactoryTest {
    @Test
    public void testCreateNoRegionException() {
        try {
            DynamoDBAuthHistoryStoreFactory dynamoDBAuthHistoryStoreFactory = new DynamoDBAuthHistoryStoreFactory();
            dynamoDBAuthHistoryStoreFactory.create(null);
            fail();
        } catch (Exception ignored) {
        }
    }

    @Test
    public void testCreateWithRegion() {
        System.setProperty(ZMSConsts.ZMS_PROP_AUTH_HISTORY_DYNAMODB_REGION, "us-west-2");
        DynamoDBAuthHistoryStoreFactory dynamoDBAuthHistoryStoreFactory = new DynamoDBAuthHistoryStoreFactory();
        AuthHistoryStore authHistoryStore = dynamoDBAuthHistoryStoreFactory.create(null);
        assertNotNull(authHistoryStore);
        System.clearProperty(ZMSConsts.ZMS_PROP_AUTH_HISTORY_DYNAMODB_REGION);
    }
}
