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
package com.yahoo.athenz.auth;

import java.security.PrivateKey;

public interface PrivateKeyStore {

    /**
     * Retrieve private key for this Athenz Server instance to sign its tokens
     * The private key identifier must be updated in the privateKeyId out
     * StringBuilder field.
     * @param service Athenz service (zms or zts) requesting private key
     * @param serverHostName hostname of the Athenz Server instance
     * @param privateKeyId - out argument - must be updated to include key id
     * @return private key for this ZMS Server instance.
     */
    @Deprecated
    default PrivateKey getPrivateKey(String service, String serverHostName,
            StringBuilder privateKeyId) {
        return null;
    }

    /**
     * Retrieve private key for this Athenz Server instance for the given
     * crypto algorithm to sign its tokens.
     * @param service Athenz service (zms or zts) requesting private key
     * @param serverHostName hostname of the Athenz Server instance
     * @param serverRegion Athenz server region
     * @param algorithm Requested algorithm - rsa or ec
     * @return private key for this ZMS Server instance.
     */
    default ServerPrivateKey getPrivateKey(String service, String serverHostName,
            String serverRegion, String algorithm) {
        return null;
    }

    /**
     * Retrieve the application secret based on the configured key name.
     * @deprecated
     * This method should not be used to get application secrets.
     * <p> Use {@link PrivateKeyStore#getSecret(String, String)} instead.</p>
     *
     * The application name specifies what component is this secret for;
     * for example, jdbc for accessing the secret for the jdbc user.
     * The default implementation assumes the key name is the secret.
     * @param appName application name for the secret
     * @param keyName configured value for the secret
     * @return secret for the given key and application
     */
    @Deprecated
    default String getApplicationSecret(String appName, String keyName) {
        return keyName;
    }

    /**
     * Retrieve the application secret based on the configured key name as char[].
     * The application name specifies what component is this secret for;
     * for example, jdbc for accessing the secret for the jdbc user.
     * The default implementation assumes the key name is the secret.
     * @param appName application name for the secret
     * @param keyName configured value for the secret
     * @return secret for the given key and application as char[]
     */
    default char[] getSecret(String appName, String keyName) {
        final String secret = getApplicationSecret(appName, keyName);
        return secret != null ? secret.toCharArray() : null;
    }
}
