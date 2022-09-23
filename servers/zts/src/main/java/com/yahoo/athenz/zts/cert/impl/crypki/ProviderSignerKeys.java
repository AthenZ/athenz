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
package com.yahoo.athenz.zts.cert.impl.crypki;

import java.util.List;

public class ProviderSignerKeys {

    private String defaultKeyId;
    private List<ProviderSignerKey> providerKeys;

    public String getDefaultKeyId() {
        return defaultKeyId;
    }

    public void setDefaultKeyId(String defaultKeyId) {
        this.defaultKeyId = defaultKeyId;
    }

    public List<ProviderSignerKey> getProviderKeys() {
        return providerKeys;
    }

    public void setProviderKeys(List<ProviderSignerKey> providerKeys) {
        this.providerKeys = providerKeys;
    }
}
