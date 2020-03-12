/*
 * Copyright 2020 Verizon Media
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
package com.yahoo.athenz.zms;

import javax.ws.rs.client.ClientBuilder;

public class ZMSClientExt extends ZMSClient {

    private static ClientBuilder clientBuilder;

    public ZMSClientExt(String baseUri) {
        super(baseUri);
    }

    public static void setClientBuilder(ClientBuilder builder) {
        clientBuilder = builder;
    }

    @Override
    ClientBuilder getClientBuilder() {
        return (clientBuilder == null) ? ClientBuilder.newBuilder() : clientBuilder;
    }
}
