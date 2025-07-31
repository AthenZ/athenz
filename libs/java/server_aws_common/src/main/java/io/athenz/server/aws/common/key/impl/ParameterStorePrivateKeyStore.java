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
package io.athenz.server.aws.common.key.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.util.PrivateKeyStoreUtil;
import software.amazon.awssdk.services.ssm.SsmClient;

public class ParameterStorePrivateKeyStore implements PrivateKeyStore {

    static final String CLOUD_NAME = "aws";

    private final SsmClient ssmClient;

    ParameterStorePrivateKeyStore(SsmClient ssmClient) {
        this.ssmClient = ssmClient;
    }

    @Override
    public char[] getSecret(String appName, String keygroupName, String keyName) {
        return getSsmParameter(keyName).toCharArray();
    }

    @Override
    public ServerPrivateKey getPrivateKey(String service, String serverHostName, String serverRegion, String algorithm) {
        return PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(CLOUD_NAME, service, serverRegion, algorithm, this::getSsmParameter);
    }

    private String getSsmParameter(final String keyName) {
        return ssmClient.getParameter(r -> r.name(keyName).withDecryption(true)).parameter().value();
    }

}
