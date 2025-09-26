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
package com.yahoo.athenz.auth.util;

import com.yahoo.athenz.auth.ServerPrivateKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.security.PrivateKey;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

public class PrivateKeyStoreUtil {
    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String ZMS_SERVICE = "zms";
    private static final String ZTS_SERVICE = "zts";
    private static final String MSD_SERVICE = "msd";

    private static final String ATHENZ_PROP_KEY_NAME_FORMAT = "athenz.%s.%s.key_name";
    private static final String ATHENZ_PROP_KEY_ID_NAME_FORMAT = "athenz.%s.%s.key_id_name";

    private static final String ATHENZ_DEFAULT_KEY_NAME     = "service_private_key";
    private static final String ATHENZ_DEFAULT_KEY_ID_NAME  = "service_private_key_id";

    private static final String GCP_CLOUD_NAME = "gcp";

    /**
     * Retrieves the private key for a given cloud provider, service, region, and algorithm.
     * The private key is fetched from a cloud parameter store using the provided function.
     *
     * @param cloudName the name of the cloud provider (e.g., aws, gcp)
     * @param service the service name (e.g., zms, zts, msd)
     * @param region the region where the service is hosted
     * @param algorithm the cryptographic algorithm (e.g., RSA, EC)
     * @param getParameterFn function to retrieve the parameter value from the cloud
     * @return ServerPrivateKey containing the private key and its ID, or null if not found
     */
    public static ServerPrivateKey getPrivateKeyFromCloudParameter(String cloudName, String service, String region, String algorithm, Function<String, String> getParameterFn) {
        if (region == null || region.isEmpty()) {
            LOG.error("server region not specified");
            return null;
        }

        final Set<String> supportedServices = Set.of(ZMS_SERVICE, ZTS_SERVICE, MSD_SERVICE);
        if (!supportedServices.contains(service)) {
            LOG.error("Unknown service specified: {}", service);
            return null;
        }

        BiFunction<String, String, String> parameterNameFn = getParameterNameProcessorFn(cloudName, service, algorithm);

        String keyName = parameterNameFn.apply(ATHENZ_PROP_KEY_NAME_FORMAT, ATHENZ_DEFAULT_KEY_NAME);
        String keyIdName = parameterNameFn.apply(ATHENZ_PROP_KEY_ID_NAME_FORMAT, ATHENZ_DEFAULT_KEY_ID_NAME);

        if (LOG.isDebugEnabled()) {
            LOG.debug("fetching private key from cloud: {}, service: {}, region: {}, algorithm: {}, keyName: {}, keyIdName: {}",
                cloudName, service, region, algorithm, keyName, keyIdName);
        }

        PrivateKey pkey = null;
        try {
            pkey = Crypto.loadPrivateKey(getParameterFn.apply(keyName));
        } catch (Exception ex) {
            LOG.error("unable to load private key: {}, error: {}", keyName, ex.getMessage());
        }

        return pkey == null
                ? null
                : new ServerPrivateKey(pkey, getParameterFn.apply(keyIdName));
    }

    /**
     * Returns a BiFunction that constructs a parameter name using the following logic:
     *   a) Expand the system property name with cloudName, service into the format supplied
     *   b) Retrieve the system property value or use the default value
     *   c) append the algorithm (in lowercase) as a suffix.
     *
     * @param cloudName the name of the cloud provider
     * @param service the service name (e.g., zms, zts, msd)
     * @param algorithm the cryptographic algorithm (e.g., RSA, EC)
     * @return a BiFunction that generates the full parameter name with algorithm suffix
     */
    static BiFunction<String, String, String> getParameterNameProcessorFn(String cloudName, String service, String algorithm) {
        return (format, def) -> {
            String expandedPropertyName = String.format(format, cloudName, service);

            // For GCP, parameter names can not contain ".", so we use _ instead
            String suffixDelimiter = GCP_CLOUD_NAME.equals(cloudName) ? "_" : ".";

            return System.getProperty(expandedPropertyName, def) + suffixDelimiter + algorithm.toLowerCase();
        };
    }
}
