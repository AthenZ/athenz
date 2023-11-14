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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.common.server.external.ExternalCredentialsProvider;
import com.yahoo.athenz.zts.external.gcp.GcpAccessTokenProvider;

import java.util.*;

public class ExternalCredentialsManager {

    protected Map<String, ExternalCredentialsProvider> externalCredentialsProviders;
    protected Set<String> enabledExternalCredentialsProviders;

    public ExternalCredentialsManager(Authorizer authorizer) {
        externalCredentialsProviders = new HashMap<>();
        ExternalCredentialsProvider gcpProvider = new GcpAccessTokenProvider();
        gcpProvider.setAuthorizer(authorizer);
        externalCredentialsProviders.put(ZTSConsts.ZTS_EXTERNAL_CREDS_PROVIDER_GCP, gcpProvider);

        // configure which providers are enabled

        final String providerList = System.getProperty(ZTSConsts.ZTS_PROP_EXTERNAL_CREDS_PROVIDERS,
                ZTSConsts.ZTS_EXTERNAL_CREDS_PROVIDER_GCP);
        enabledExternalCredentialsProviders = new HashSet<>(Arrays.asList(providerList.split(",")));
    }

    /**
     * Return the provider object for the given provider name if it's
     * enabled otherwise return null
     * @param provider name of the provider
     * @return provider object
     */
    public ExternalCredentialsProvider getProvider(final String provider) {
        return enabledExternalCredentialsProviders.contains(provider) ?
                externalCredentialsProviders.get(provider) : null;
    }

    /**
     * Set the provider object for the given provider name. Used for unit tests.
     * @param provider name of the provider
     * @param extCredsProvider provider implementation object
     */
    public void setProvider(final String provider, final ExternalCredentialsProvider extCredsProvider) {
        externalCredentialsProviders.put(provider, extCredsProvider);
    }

    /**
     * Enable the given provider. Used for unit tests.
     * @param provider name of the provider
     */
    public void enableProvider(final String provider) {
        enabledExternalCredentialsProviders.add(provider);
    }

    /**
     * Disable the given provider. Used for unit tests.
     * @param provider name of the provider
     */
    public void disableProvider(final String provider) {
        enabledExternalCredentialsProviders.remove(provider);
    }
}
