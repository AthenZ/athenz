/*
 * Copyright 2017 Yahoo Holdings, Inc.
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

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;

import org.glassfish.jersey.client.ClientProperties;

import javax.net.ssl.HostnameVerifier;

public class InstanceProviderClient {
    Client client;
    WebTarget base;

    public InstanceProviderClient(String url, HostnameVerifier hostnameVerifier,
            int connectTimeout, int readTimeout) {

        client = ClientBuilder.newBuilder()
            .hostnameVerifier(hostnameVerifier)
            .property(ClientProperties.CONNECT_TIMEOUT, connectTimeout)
            .property(ClientProperties.READ_TIMEOUT, readTimeout)
            .build();
        base = client.target(url);
    }

    public void close() {
        client.close();
    }

    public InstanceConfirmation postInstanceConfirmation(InstanceConfirmation confirmation) {
        WebTarget target = base.path("/instance");
        Invocation.Builder invocationBuilder = target.request("application/json");
        Response response = invocationBuilder.post(
                javax.ws.rs.client.Entity.entity(confirmation, "application/json"));
        int code = response.getStatus();
        switch (code) {
        case 200:
            return response.readEntity(InstanceConfirmation.class);
        default:
            throw new ResourceException(code, response.readEntity(ResourceError.class));
        }
    }

    public InstanceConfirmation postRefreshConfirmation(InstanceConfirmation confirmation) {
        WebTarget target = base.path("/refresh");
        Invocation.Builder invocationBuilder = target.request("application/json");
        Response response = invocationBuilder.post(
                javax.ws.rs.client.Entity.entity(confirmation, "application/json"));
        int code = response.getStatus();
        switch (code) {
        case 200:
            return response.readEntity(InstanceConfirmation.class);
        default:
            throw new ResourceException(code, response.readEntity(ResourceError.class));
        }
    }
}
