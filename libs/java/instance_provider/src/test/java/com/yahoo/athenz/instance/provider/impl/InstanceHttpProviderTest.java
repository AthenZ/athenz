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

import static org.testng.Assert.assertEquals;

import com.yahoo.athenz.instance.provider.InstanceProvider;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProviderClient;

import javax.net.ssl.*;
import java.security.*;

public class InstanceHttpProviderTest {

    @Test
    public void testInstanceHttpProviderConfirmInstance() throws NoSuchAlgorithmException {
        
        InstanceHttpProvider provider = new InstanceHttpProvider();
        provider.initialize("provider", "https://localhost:4443/instance", SSLContext.getDefault(), null);
        assertEquals(InstanceProvider.Scheme.HTTP, provider.getProviderScheme());

        InstanceProviderClient client = Mockito.mock(InstanceProviderClient.class);
        provider.client = client;
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("data").setDomain("athenz")
                .setProvider("provider").setService("service");
        Mockito.when(client.postInstanceConfirmation(confirmation)).thenReturn(confirmation);
        
        InstanceConfirmation result = provider.confirmInstance(confirmation);
        assertEquals(result.getAttestationData(), "data");
        assertEquals(result.getDomain(), "athenz");
        assertEquals(result.getProvider(), "provider");
        assertEquals(result.getService(), "service");
        
        provider.close();
    }
    
    @Test
    public void testInstanceHttpProviderRefreshInstance() throws NoSuchAlgorithmException {
        
        InstanceHttpProvider provider = new InstanceHttpProvider();
        provider.initialize("provider", "https://localhost:4443/instance", SSLContext.getDefault(), null);
        
        InstanceProviderClient client = Mockito.mock(InstanceProviderClient.class);
        provider.client = client;
        
        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("data").setDomain("athenz")
                .setProvider("provider").setService("service");
        Mockito.when(client.postRefreshConfirmation(confirmation)).thenReturn(confirmation);
        
        InstanceConfirmation result = provider.refreshInstance(confirmation);
        assertEquals(result.getAttestationData(), "data");
        assertEquals(result.getDomain(), "athenz");
        assertEquals(result.getProvider(), "provider");
        assertEquals(result.getService(), "service");
        
        provider.close();
    }
}
