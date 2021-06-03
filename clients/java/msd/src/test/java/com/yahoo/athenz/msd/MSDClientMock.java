/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.yahoo.athenz.msd;

import javax.net.ssl.SSLContext;
import javax.ws.rs.client.ClientBuilder;

public class MSDClientMock extends MSDClient {

  private static ClientBuilder clientBuilder;

  public static void setClientBuilder(ClientBuilder builder) {
    clientBuilder = builder;
  }

  @Override
  ClientBuilder getClientBuilder() {
    return (clientBuilder == null) ? ClientBuilder.newBuilder() : clientBuilder;
  }
  /**
   * Constructs a new MSDClient object with the given SSLContext object and MSD Server Url. Default
   * read and connect timeout values are 30000ms (30sec). The application can change these values by
   * using the athenz.msd.client.read_timeout and athenz.msd.client.connect_timeout system properties.
   * The values specified for timeouts must be in milliseconds.
   *
   * @param url        MSD Server url (e.g. https://server1.athenzcompany.com:4443/msd/v1)
   * @param sslContext SSLContext that includes service's private key and x.509 certificate
   */
  public MSDClientMock(String url, SSLContext sslContext) {
    super(url, sslContext);
  }
}
