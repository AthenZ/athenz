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
package io.athenz.server.k8s.common.impl;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.util.Crypto;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.Configuration;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1Secret;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Optional;

public class KubernetesSecretPrivateKeyStore implements PrivateKeyStore {

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String ZMS_SERVICE = "zms";
    private static final String ZTS_SERVICE = "zts";
    private static final String MSD_SERVICE = "msd";

    private static final String ATHENZ_PROP_K8S_ZMS_KEY_NAME = "athenz.k8s.zms.key_name";
    private static final String ATHENZ_PROP_K8S_ZMS_KEY_ID_NAME = "athenz.k8s.zms.key_id_name";
    private static final String ATHENZ_PROP_K8S_ZTS_KEY_NAME = "athenz.k8s.zts.key_name";
    private static final String ATHENZ_PROP_K8S_ZTS_KEY_ID_NAME = "athenz.k8s.zts.key_id_name";
    private static final String ATHENZ_PROP_K8S_MSD_KEY_NAME = "athenz.k8s.msd.key_name";
    private static final String ATHENZ_PROP_K8S_MSD_KEY_ID_NAME = "athenz.k8s.msd.key_id_name";

    private static final String ATHENZ_K8S_DEFAULT_KEY_NAME = "service_k8s_private_key";
    private static final String ATHENZ_K8S_DEFAULT_KEY_ID_NAME = "service_k8s_private_key_id";

    private final ApiClient k8sClient;

    private static final String ATHENZ_K8S_CONNECT_TIMEOUT = "athenz.k8s.connect_timeout";
    private static final String ATHENZ_K8S_READ_TIMEOUT = "athenz.k8s.read_timeout";

    public KubernetesSecretPrivateKeyStore(ApiClient k8sClient) {
        this.k8sClient = k8sClient;
        this.k8sClient.setConnectTimeout(Integer.parseInt(System.getProperty(ATHENZ_K8S_CONNECT_TIMEOUT, "500")));
        this.k8sClient.setReadTimeout(Integer.parseInt(System.getProperty(ATHENZ_K8S_READ_TIMEOUT, "2000")));
        Configuration.setDefaultApiClient(k8sClient);
    }

    @Override
    public ServerPrivateKey getPrivateKey(String service, String namespace,
                                   String secretName, String algorithm) {
        String keyName;
        String keyIdName;
        final String objectSuffix = "." + algorithm.toLowerCase();
        if (ZMS_SERVICE.equals(service)) {
            keyName = System.getProperty(ATHENZ_PROP_K8S_ZMS_KEY_NAME, ATHENZ_K8S_DEFAULT_KEY_NAME) + objectSuffix;
            keyIdName = System.getProperty(ATHENZ_PROP_K8S_ZMS_KEY_ID_NAME, ATHENZ_K8S_DEFAULT_KEY_ID_NAME) + objectSuffix;
        } else if (ZTS_SERVICE.equals(service)) {
            keyName = System.getProperty(ATHENZ_PROP_K8S_ZTS_KEY_NAME, ATHENZ_K8S_DEFAULT_KEY_NAME) + objectSuffix;
            keyIdName = System.getProperty(ATHENZ_PROP_K8S_ZTS_KEY_ID_NAME, ATHENZ_K8S_DEFAULT_KEY_ID_NAME) + objectSuffix;
        } else if (MSD_SERVICE.equals(service)) {
            keyName = System.getProperty(ATHENZ_PROP_K8S_MSD_KEY_NAME, ATHENZ_K8S_DEFAULT_KEY_NAME) + objectSuffix;
            keyIdName = System.getProperty(ATHENZ_PROP_K8S_MSD_KEY_ID_NAME, ATHENZ_K8S_DEFAULT_KEY_ID_NAME) + objectSuffix;
        } else {
            LOG.error("Unknown service specified: {}", service);
            return null;
        }

        PrivateKey pkey = null;
        try {
            pkey = Crypto.loadPrivateKey(getSecretFromK8S(namespace, secretName, keyName));
        } catch (Exception ex) {
            LOG.error("unable to load private key", ex);
        }
        return pkey == null ? null : new ServerPrivateKey(pkey, getSecretFromK8S(namespace, secretName, keyIdName));
    }

    @Override
    public char[] getSecret(String namespace, String secretName, String keyName) {
        return getSecretFromK8S(namespace, secretName, keyName).toCharArray();
    }

    String getSecretFromK8S(String namespace, String secretName, String keyName) {
        try {
            CoreV1Api api = new CoreV1Api(k8sClient);
            V1Secret secret = api.readNamespacedSecret(secretName, namespace).execute();
            if (Optional.ofNullable(secret)
                    .map(V1Secret::getData)
                    .filter(map -> map.containsKey(keyName))
                    .isPresent()) {
                return new String(secret.getData().get(keyName), StandardCharsets.UTF_8);
            } else {
                LOG.error("Unable to retrieve secret={} for key={} from namespace={}", secretName, keyName, namespace);
                return "";
            }
        } catch (ApiException e) {
            LOG.error("Error in retrieving secret={} for key={} from namespace={}", secretName, keyName, namespace);
            throw new RuntimeException(e);
        }
    }
}
