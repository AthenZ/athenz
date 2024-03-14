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
package com.yahoo.athenz.instance.provider;

import com.yahoo.athenz.auth.KeyStore;
import org.testng.annotations.Test;

import javax.net.ssl.SSLContext;

import static org.testng.Assert.*;

public class InstanceProviderTest {

    @Test
    public void testInstanceProvider() {

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

        // default methods with no validation

        provider.setPrivateKey(null, null, null);
        provider.setHostnameResolver(null);
        provider.setRolesProvider(null);
        provider.setExternalCredentialsProvider(null);
        provider.setPubKeysProvider(null);

        assertEquals(provider.getProviderScheme(), InstanceProvider.Scheme.UNKNOWN);

        try {
            provider.getInstanceRegisterToken(null);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), ResourceException.NOT_IMPLEMENTED);
        }
    }
}
