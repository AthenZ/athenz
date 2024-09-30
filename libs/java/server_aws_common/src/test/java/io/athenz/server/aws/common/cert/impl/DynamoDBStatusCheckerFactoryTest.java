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

package io.athenz.server.aws.common.cert.impl;

import com.yahoo.athenz.common.server.status.StatusChecker;
import com.yahoo.athenz.common.server.ServerResourceException;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class DynamoDBStatusCheckerFactoryTest {

    @Test
    public void testCreate() throws ServerResourceException {
        System.setProperty(DynamoDBStatusCheckerFactory.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME, "testTable");
        DynamoDBStatusCheckerFactory dynamoDBStatusCheckerFactory = new DynamoDBStatusCheckerFactory();
        StatusChecker statusChecker = dynamoDBStatusCheckerFactory.create();
        assertNotNull(statusChecker);

        System.clearProperty(DynamoDBStatusCheckerFactory.ZTS_PROP_CERT_DYNAMODB_TABLE_NAME);
    }

    @Test
    public void testTableNameNotSpecified() {
        DynamoDBStatusCheckerFactory dynamoDBStatusCheckerFactory = new DynamoDBStatusCheckerFactory();
        try {
            dynamoDBStatusCheckerFactory.create();
            fail();
        } catch (ServerResourceException ex) {
            assertEquals("DynamoDB table name not specified", ex.getMessage());
            assertEquals(503, ex.getCode());
        }
    }

    @Test
    public void testBadKeyStoreClass() {
        System.setProperty(DynamoDBStatusCheckerFactory.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS, "unknownClassName");
        try {
            new DynamoDBStatusCheckerFactory();
            fail();
        } catch (IllegalArgumentException ex) {
            assertEquals(ex.getMessage(), "Invalid private key store");
        }

        System.clearProperty(DynamoDBStatusCheckerFactory.ZTS_PROP_PRIVATE_KEY_STORE_FACTORY_CLASS);

    }
}
