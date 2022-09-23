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
package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.InstanceProviderClient;
import com.yahoo.athenz.instance.provider.ProviderHostnameVerifier;

import javax.net.ssl.SSLContext;

public class InstanceHttpProvider implements InstanceProvider {

    InstanceProviderClient client;
    private static final String PROP_READ_TIMEOUT     = "athenz.instance.provider.client.read_timeout";
    private static final String PROP_CONNECT_TIMEOUT  = "athenz.instance.provider.client.connect_timeout";

    @Override
    public Scheme getProviderScheme() {
        return Scheme.HTTP;
    }

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext,
            KeyStore keyStore) {

        ProviderHostnameVerifier hostnameVerifier = new ProviderHostnameVerifier(provider);
        int readTimeout = Integer.parseInt(System.getProperty(PROP_READ_TIMEOUT, "30000"));
        int connectTimeout = Integer.parseInt(System.getProperty(PROP_CONNECT_TIMEOUT, "30000"));
        client = new InstanceProviderClient(providerEndpoint, sslContext, hostnameVerifier,
                connectTimeout, readTimeout);
    }

    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {
        return client.postInstanceConfirmation(confirmation);
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {
        return client.postRefreshConfirmation(confirmation);
    }
    
    @Override
    public void close() {
        client.close();
    }
}
