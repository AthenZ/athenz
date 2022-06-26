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

package com.yahoo.athenz.db.dynamodb;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.zts.ZTSClientNotificationSender;

public interface DynamoDBClientFetcher {
    /**
     * Returns a DynamoDBClient and the AWS credential provider used for authentication.
     * The credentialProvider should be closed after DynamoDBClient is no longer needed.
     * (GC might not run for a long period of time)
     * @param ztsClientNotificationSender notification sender object
     * @param keyStore private key store object for fetching any secrets
     * @return DynamoDBClientAndCredentials which contains both a DynamoDB client and the credentialProvider used
     */
    @Deprecated
    DynamoDBClientAndCredentials getDynamoDBClient(ZTSClientNotificationSender ztsClientNotificationSender, PrivateKeyStore keyStore);

    /**
     * Returns a DynamoDBClient and the AWS credential provider used for authentication.
     * The credentialProvider should be closed after DynamoDBClient is no longer needed.
     * (GC might not run for a long period of time)
     * @param ztsClientNotificationSender notification sender object
     * @param dynamoDBClientSettings contains private key store and client settings
     * @return DynamoDBClientAndCredentials which contains both a DynamoDB client and the credentialProvider used
     */
    DynamoDBClientAndCredentials getDynamoDBClient(ZTSClientNotificationSender ztsClientNotificationSender, DynamoDBClientSettings dynamoDBClientSettings);
}
