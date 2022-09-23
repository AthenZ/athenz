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

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import javax.net.ssl.SSLContext;

public class InstanceTestClassProvider implements InstanceProvider {

    public InstanceTestClassProvider() throws InstantiationException {
        boolean exc = Boolean.parseBoolean(System.getProperty("athenz.instance.test.class.exception", "false"));
        if (exc) {
            throw new InstantiationException();
        }
    }

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

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
}
