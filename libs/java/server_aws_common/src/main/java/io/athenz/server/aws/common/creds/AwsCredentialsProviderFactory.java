/*
 * Copyright The Athenz Authors.
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

package io.athenz.server.aws.common.creds;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.server.ServerResourceException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

public interface AwsCredentialsProviderFactory {

    /**
     * Set the private key store object for the factory in case the
     * implementation needs to read any secrets. This method is called
     * first before the create method call.
     * @param privateKeyStore Private Key Store object
     */
    default void setPrivateKeyStore(PrivateKeyStore privateKeyStore) {
    }

    /**
     * Create and return a new AwsCredentialsProvider instance. The provider
     * supplies the credentials the server uses to authenticate itself when
     * calling AWS STS on behalf of its clients.
     * The server closes providers implementing SdkAutoCloseable when the
     * cloud store is closed.
     * @return non-null AwsCredentialsProvider instance
     */
    AwsCredentialsProvider create() throws ServerResourceException;
}
