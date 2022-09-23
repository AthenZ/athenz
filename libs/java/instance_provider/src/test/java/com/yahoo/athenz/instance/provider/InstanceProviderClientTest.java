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

import static org.testng.Assert.*;

import jakarta.ws.rs.*;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;

import org.mockito.Mockito;
import org.testng.annotations.Test;

public class InstanceProviderClientTest {

    @Test
    public void testInstanceProviderClientInstanceConfirmation() {
        String url = "http://localhost:10099/instance";
        ProviderHostnameVerifier hostnameVerifier = new ProviderHostnameVerifier("athenz.provider");
        InstanceProviderClient provClient = new InstanceProviderClient(url, null, hostnameVerifier, 10000, 10000);

        WebTarget base = Mockito.mock(WebTarget.class);
        provClient.setBase(base);

        WebTarget target = Mockito.mock(WebTarget.class);
        Mockito.when(base.path("/instance")).thenReturn(target);

        Invocation.Builder builder = Mockito.mock(Invocation.Builder.class);
        Mockito.when(target.request("application/json")).thenReturn(builder);
        Mockito.when(builder.header("Athenz-Principal-Token", "v=S1;d=athenz;n=service;s=signature")).thenReturn(builder);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("data").setDomain("athenz")
                .setProvider("provider").setService("service");
        Entity<?> entity = Entity.entity(confirmation, "application/json");
        Response response = Mockito.mock(Response.class);
        Mockito.when(builder.post(entity)).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.readEntity(InstanceConfirmation.class)).thenReturn(confirmation);
        
        InstanceConfirmation result = provClient.postInstanceConfirmation(confirmation);
        assertEquals(result.getAttestationData(), "data");
        assertEquals(result.getDomain(), "athenz");
        assertEquals(result.getProvider(), "provider");
        assertEquals(result.getService(), "service");
        
        provClient.close();
    }
    
    @Test
    public void testInstanceProviderClientInstanceConfirmationCookieHeader() {
        String url = "http://localhost:10099/instance";
        ProviderHostnameVerifier hostnameVerifier = new ProviderHostnameVerifier("athenz.provider");
        InstanceProviderClient provClient = new InstanceProviderClient(url, null, hostnameVerifier, 10000, 10000);

        WebTarget base = Mockito.mock(WebTarget.class);
        provClient.setBase(base);
        
        WebTarget target = Mockito.mock(WebTarget.class);
        Mockito.when(base.path("/instance")).thenReturn(target);

        Invocation.Builder builder = Mockito.mock(Invocation.Builder.class);
        Mockito.when(target.request("application/json")).thenReturn(builder);
        Mockito.when(builder.cookie("ntoken", "v=S1;d=athenz;n=service;s=signature")).thenReturn(builder);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("data").setDomain("athenz")
                .setProvider("provider").setService("service");
        Entity<?> entity = Entity.entity(confirmation, "application/json");
        Response response = Mockito.mock(Response.class);
        Mockito.when(builder.post(entity)).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.readEntity(InstanceConfirmation.class)).thenReturn(confirmation);
        
        InstanceConfirmation result = provClient.postInstanceConfirmation(confirmation);
        assertEquals(result.getAttestationData(), "data");
        assertEquals(result.getDomain(), "athenz");
        assertEquals(result.getProvider(), "provider");
        assertEquals(result.getService(), "service");
        
        provClient.close();
    }
    
    @Test
    public void testInstanceProviderClientRefreshConfirmation() {
        String url = "http://localhost:10099/instance";
        ProviderHostnameVerifier hostnameVerifier = new ProviderHostnameVerifier("athenz.provider");
        InstanceProviderClient provClient = new InstanceProviderClient(url, null, hostnameVerifier, 10000, 10000);

        WebTarget base = Mockito.mock(WebTarget.class);
        provClient.setBase(base);
        
        WebTarget target = Mockito.mock(WebTarget.class);
        Mockito.when(base.path("/refresh")).thenReturn(target);

        Invocation.Builder builder = Mockito.mock(Invocation.Builder.class);
        Mockito.when(target.request("application/json")).thenReturn(builder);
        Mockito.when(builder.header("Athenz-Principal-Token", "v=S1;d=athenz;n=service;s=signature")).thenReturn(builder);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("data").setDomain("athenz")
                .setProvider("provider").setService("service");
        Entity<?> entity = Entity.entity(confirmation, "application/json");
        Response response = Mockito.mock(Response.class);
        Mockito.when(builder.post(entity)).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.readEntity(InstanceConfirmation.class)).thenReturn(confirmation);
        
        InstanceConfirmation result = provClient.postRefreshConfirmation(confirmation);
        assertEquals(result.getAttestationData(), "data");
        assertEquals(result.getDomain(), "athenz");
        assertEquals(result.getProvider(), "provider");
        assertEquals(result.getService(), "service");
        
        provClient.close();
    }
    
    @Test
    public void testInstanceProviderClientRefreshConfirmationCookieHeader() {
        String url = "http://localhost:10099/instance";
        ProviderHostnameVerifier hostnameVerifier = new ProviderHostnameVerifier("athenz.provider");
        InstanceProviderClient provClient = new InstanceProviderClient(url, null, hostnameVerifier, 10000, 10000);
        
        WebTarget base = Mockito.mock(WebTarget.class);
        provClient.setBase(base);
        
        WebTarget target = Mockito.mock(WebTarget.class);
        Mockito.when(base.path("/refresh")).thenReturn(target);

        Invocation.Builder builder = Mockito.mock(Invocation.Builder.class);
        Mockito.when(target.request("application/json")).thenReturn(builder);
        Mockito.when(builder.cookie("NToken", "v=S1;d=athenz;n=service;s=signature")).thenReturn(builder);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("data").setDomain("athenz")
                .setProvider("provider").setService("service");
        Entity<?> entity = Entity.entity(confirmation, "application/json");
        Response response = Mockito.mock(Response.class);
        Mockito.when(builder.post(entity)).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.readEntity(InstanceConfirmation.class)).thenReturn(confirmation);
        
        InstanceConfirmation result = provClient.postRefreshConfirmation(confirmation);
        assertEquals(result.getAttestationData(), "data");
        assertEquals(result.getDomain(), "athenz");
        assertEquals(result.getProvider(), "provider");
        assertEquals(result.getService(), "service");
        
        provClient.close();
    }
    
    @Test
    public void testInstanceProviderClientHostnameVerifier() {
        String url = "http://localhost:10099/instance";
        ProviderHostnameVerifier hostnameVerifier = new ProviderHostnameVerifier("athenz.production");
        InstanceProviderClient provClient = new InstanceProviderClient(url, null, hostnameVerifier, 10000, 10000);
        
        WebTarget base = Mockito.mock(WebTarget.class);
        provClient.setBase(base);
        
        WebTarget target = Mockito.mock(WebTarget.class);
        Mockito.when(base.path("/instance")).thenReturn(target);

        Invocation.Builder builder = Mockito.mock(Invocation.Builder.class);
        Mockito.when(target.request("application/json")).thenReturn(builder);
        Mockito.when(builder.header("Athenz-Principal-Token", "v=S1;d=athenz;n=service;s=signature")).thenReturn(builder);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("data").setDomain("athenz")
                .setProvider("provider").setService("service");
        Entity<?> entity = Entity.entity(confirmation, "application/json");
        Response response = Mockito.mock(Response.class);
        Mockito.when(builder.post(entity)).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(200);
        Mockito.when(response.readEntity(InstanceConfirmation.class)).thenReturn(confirmation);
        
        InstanceConfirmation result = provClient.postInstanceConfirmation(confirmation);
        assertEquals(result.getAttestationData(), "data");
        assertEquals(result.getDomain(), "athenz");
        assertEquals(result.getProvider(), "provider");
        assertEquals(result.getService(), "service");
        
        provClient.close();
    }
    
    @Test
    public void testInstanceProviderClientFailure() {
        String url = "http://localhost:10099/instance";
        ProviderHostnameVerifier hostnameVerifier = new ProviderHostnameVerifier("athenz.provider");
        InstanceProviderClient provClient = new InstanceProviderClient(url, null, hostnameVerifier, 10000, 10000);
        
        WebTarget base = Mockito.mock(WebTarget.class);
        provClient.setBase(base);
        
        WebTarget target = Mockito.mock(WebTarget.class);
        Mockito.when(base.path("/instance")).thenReturn(target);
        Mockito.when(base.path("/refresh")).thenReturn(target);

        Invocation.Builder builder = Mockito.mock(Invocation.Builder.class);
        Mockito.when(target.request("application/json")).thenReturn(builder);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("data").setDomain("athenz")
                .setProvider("provider").setService("service");
        Entity<?> entity = Entity.entity(confirmation, "application/json");
        Response response = Mockito.mock(Response.class);
        Mockito.when(builder.post(entity)).thenReturn(response);
        Mockito.when(response.getStatus()).thenReturn(401);
        Mockito.when(response.readEntity(String.class))
                .thenReturn(null)
                .thenReturn("Bad request" + '\n' + "Bad data")
                .thenThrow(new RuntimeException("Bad request"));

        try {
            provClient.postInstanceConfirmation(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
            assertEquals(ex.getMessage(), "ResourceException (401): N/A");
        }
        
        try {
            provClient.postRefreshConfirmation(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
            assertEquals(ex.getMessage(), "ResourceException (401): Bad request Bad data");
        }

        try {
            provClient.postInstanceConfirmation(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 401);
            assertEquals(ex.getMessage(), "ResourceException (401): N/A");
        }

        provClient.close();
    }

    @Test
    public void testInstanceProviderClientException() {

        String url = "http://localhost:10099/instance";
        ProviderHostnameVerifier hostnameVerifier = new ProviderHostnameVerifier("athenz.provider");
        InstanceProviderClient provClient = new InstanceProviderClient(url, null, hostnameVerifier, 10000, 10000);

        WebTarget base = Mockito.mock(WebTarget.class);
        provClient.setBase(base);

        WebTarget target = Mockito.mock(WebTarget.class);
        Mockito.when(base.path("/instance")).thenReturn(target);
        Mockito.when(base.path("/refresh")).thenReturn(target);

        Invocation.Builder builder = Mockito.mock(Invocation.Builder.class);
        Mockito.when(target.request("application/json")).thenReturn(builder);

        InstanceConfirmation confirmation = new InstanceConfirmation()
                .setAttestationData("data").setDomain("athenz")
                .setProvider("provider").setService("service");
        Entity<?> entity = Entity.entity(confirmation, "application/json");
        Mockito.when(builder.post(entity)).thenThrow(new ProcessingException("Timeout"));

        try {
            provClient.postInstanceConfirmation(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 504);
        }

        try {
            provClient.postRefreshConfirmation(confirmation);
            fail();
        } catch (ResourceException ex) {
            assertEquals(ex.getCode(), 504);
        }

        provClient.close();
    }
}
