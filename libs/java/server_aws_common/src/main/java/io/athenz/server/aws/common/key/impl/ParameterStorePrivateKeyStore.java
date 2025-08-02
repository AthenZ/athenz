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
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.auth.util.PrivateKeyStoreUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.ssm.SsmClient;

import java.lang.invoke.MethodHandles;
import java.security.PrivateKey;

public class ParameterStorePrivateKeyStore implements PrivateKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String ZMS_SERVICE = "zms";
    private static final String ZTS_SERVICE = "zts";
    private static final String MSD_SERVICE = "msd";

    private static final String ATHENZ_PROP_ZMS_KEY_NAME    = "athenz.aws.zms.key_name";
    private static final String ATHENZ_PROP_ZMS_KEY_ID_NAME = "athenz.aws.zms.key_id_name";
    private static final String ATHENZ_PROP_ZTS_KEY_NAME    = "athenz.aws.zts.key_name";
    private static final String ATHENZ_PROP_ZTS_KEY_ID_NAME = "athenz.aws.zts.key_id_name";
    private static final String ATHENZ_PROP_MSD_KEY_NAME    = "athenz.aws.msd.key_name";
    private static final String ATHENZ_PROP_MSD_KEY_ID_NAME = "athenz.aws.msd.key_id_name";

    private static final String ATHENZ_DEFAULT_KEY_NAME     = "service_private_key";
    private static final String ATHENZ_DEFAULT_KEY_ID_NAME  = "service_private_key_id";

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
        return PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(service, serverRegion, algorithm, this::getSsmParameter);
    }

    private String getSsmParameter(final String keyName) {
        return ssmClient.getParameter(r -> r.name(keyName).withDecryption(true)).parameter().value();
    }

}
