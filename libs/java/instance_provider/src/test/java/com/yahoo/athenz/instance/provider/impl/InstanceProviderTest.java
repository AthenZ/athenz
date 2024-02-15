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
import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;

import static org.testng.Assert.assertEquals;

public class InstanceProviderTest {

    @Test
    public void testProviderScheme() {
        InstanceProvider provider = new InstanceProvider() {
            @Override
            public void initialize(String provider, String endpoint, SSLContext sslContext, KeyStore keyStore) {
            }

            @Override
            public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {
                return null;
            }

            @Override
            public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {
                return null;
            }
        };

        provider.setHostnameResolver(null);
        provider.setAuthorizer(null);

        assertEquals(InstanceProvider.Scheme.UNKNOWN, provider.getProviderScheme());
        provider.close();
    }
}
