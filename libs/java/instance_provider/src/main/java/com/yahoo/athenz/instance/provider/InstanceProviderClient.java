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

import javax.net.ssl.SSLContext;
import javax.net.ssl.HostnameVerifier;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;

public class InstanceProviderClient {
    private final Client client;
    private WebTarget base;

    public InstanceProviderClient(String url, SSLContext sslContext,
            HostnameVerifier hostnameVerifier, int connectTimeout, int readTimeout) {

        final ClientConfig config = new ClientConfig()
                .property(ClientProperties.CONNECT_TIMEOUT, connectTimeout)
                .property(ClientProperties.READ_TIMEOUT, readTimeout)
                .connectorProvider(new ApacheConnectorProvider());

        ClientBuilder builder = ClientBuilder.newBuilder();
        if (sslContext != null) {
            builder = builder.sslContext(sslContext);
        }

        client = builder.hostnameVerifier(hostnameVerifier)
                .withConfig(config)
                .build();
        base = client.target(url);
    }

    public void close() {
        client.close();
    }

    void setBase(WebTarget base) {
        this.base = base;
    }

    /**
     * If we're given any response in our rejected provider
     * confirmation or refresh request, we're going to include
     * that as part of the resource exception text so it can
     * be logged. If there is no response or any exception
     * while trying to read the response, we'll just return
     * N/A as the response text.
     * @param response client response object
     * @return response text normalized.
     */
    private String responseText(final Response response) {
        String data = null;
        try {
            data = response.readEntity(String.class);
        } catch (Exception ignored) {
        }
        if (data == null) {
            return "N/A";
        }
        return data.replace('\n', ' ');
    }

    public InstanceConfirmation postInstanceConfirmation(InstanceConfirmation confirmation) {
        WebTarget target = base.path("/instance");
        Invocation.Builder invocationBuilder = target.request(MediaType.APPLICATION_JSON);
        Response response = invocationBuilder.post(
                javax.ws.rs.client.Entity.entity(confirmation, MediaType.APPLICATION_JSON));
        int code = response.getStatus();
        switch (code) {
            case 200:
                return response.readEntity(InstanceConfirmation.class);
            default:
                throw new ResourceException(code, responseText(response));
        }
    }

    public InstanceConfirmation postRefreshConfirmation(InstanceConfirmation confirmation) {
        WebTarget target = base.path("/refresh");
        Invocation.Builder invocationBuilder = target.request(MediaType.APPLICATION_JSON);
        Response response = invocationBuilder.post(
                javax.ws.rs.client.Entity.entity(confirmation, MediaType.APPLICATION_JSON));
        int code = response.getStatus();
        switch (code) {
            case 200:
                return response.readEntity(InstanceConfirmation.class);
            default:
                throw new ResourceException(code, responseText(response));
        }
    }
}
