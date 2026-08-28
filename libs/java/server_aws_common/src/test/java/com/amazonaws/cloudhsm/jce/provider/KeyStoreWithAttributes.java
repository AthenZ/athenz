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
package com.amazonaws.cloudhsm.jce.provider;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.spec.KeySpec;

public class KeyStoreWithAttributes extends KeyStore {

    public static boolean throwOnGetInstance;
    public static boolean returnNonPrivateKey;
    public static boolean returnNullKey;

    public KeyStoreWithAttributes(Provider provider) {
        super(new StubKeyStoreSpi(), provider, provider.getName());
    }

    public static KeyStore getInstance(String type, Provider provider) {
        if (throwOnGetInstance) {
            throw new IllegalStateException("attribute lookup failed");
        }
        return new KeyStoreWithAttributes(provider);
    }

    public Object getKey(KeySpec spec) {
        if (returnNullKey) {
            return null;
        }
        if (returnNonPrivateKey) {
            return "not-a-private-key";
        }
        return StubKeyStoreSpi.key instanceof PrivateKey ? StubKeyStoreSpi.key : null;
    }
}
