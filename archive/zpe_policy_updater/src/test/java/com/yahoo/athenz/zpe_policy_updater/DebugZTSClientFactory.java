/**
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
package com.yahoo.athenz.zpe_policy_updater;

import java.io.IOException;

import org.mockito.Mockito;

import com.yahoo.athenz.auth.ServiceIdentityProvider;
import com.yahoo.athenz.auth.impl.SimpleServiceIdentityProvider;
import com.yahoo.athenz.zpe_policy_updater.ZTSClientFactory;
import com.yahoo.athenz.zts.ZTSClient;

public class DebugZTSClientFactory implements ZTSClientFactory {

    private String keyId = "0";
    public void setPublicKeyId(String keyId) {
        this.keyId  = keyId;
    }
    
    @Override
    public ZTSClient create() throws IOException {
        ZTSMock zts = new ZTSMock();
        zts.setPublicKeyId(keyId);
        ServiceIdentityProvider siaProvider = Mockito.mock(SimpleServiceIdentityProvider.class);
        ZTSClient client = new ZTSClient("http://localhost:10080", "domain", "service", siaProvider);
        client.setZTSRDLGeneratedClient(zts);
        return client;
    }
}
