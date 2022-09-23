/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.cert.impl;

import com.yahoo.athenz.common.server.status.StatusChecker;
import com.yahoo.athenz.zts.ResourceException;
import com.yahoo.athenz.zts.ZTSConsts;
import org.testng.annotations.Test;

import static org.testng.AssertJUnit.*;

public class DynamoDBStatusCheckerFactoryTest {

    @Test
    public void testCreate() {
        System.setProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME, "testTable");
        DynamoDBStatusCheckerFactory dynamoDBStatusCheckerFactory = new DynamoDBStatusCheckerFactory();
        StatusChecker statusChecker = dynamoDBStatusCheckerFactory.create();
        assertNotNull(statusChecker);

        System.clearProperty(ZTSConsts.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME);
    }

    @Test
    public void testTableNameNotSpecified() {
        DynamoDBStatusCheckerFactory dynamoDBStatusCheckerFactory = new DynamoDBStatusCheckerFactory();
        try {
            dynamoDBStatusCheckerFactory.create();
            fail();
        } catch (ResourceException ex) {
            assertEquals("ResourceException (503): DynamoDB table name not specified", ex.getMessage());
            assertEquals(503, ex.getCode());
        }
    }

    @Test
    public void testBadKeyStoreClass() {
        System.setProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS, "unknownClassName");
        try {
            new DynamoDBStatusCheckerFactory();
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid private key store");
        }

        System.clearProperty(ZTSConsts.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);

    }
}
